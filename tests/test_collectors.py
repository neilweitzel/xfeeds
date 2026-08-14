import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from xfeeds.collectors import fetch_source
from xfeeds.collectors.parsers import upstream_attribution
from xfeeds.models import DefaultsConfig, SourceConfig

DEFAULTS = DefaultsConfig()


def get_mock_config(
    name: str = "test_source",
    url: str = "https://example.com",
    parser: str = "plain_text",
    **kwargs: Any,
) -> SourceConfig:
    return SourceConfig(
        name=name, url=url, parser=parser, independence_class="test_class", weight=1.0, **kwargs
    )


def test_fetch_success(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(content=b"test data")
    config = get_mock_config()
    result = fetch_source(config, DEFAULTS)
    assert result.success is True
    assert result.content == b"test data"
    assert result.cached is False


def test_fetch_html_rejection(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        content=b"<html></html>", headers={"Content-Type": "text/html; charset=utf-8"}
    )
    config = get_mock_config()
    result = fetch_source(config, DEFAULTS)
    assert result.success is False
    assert result.error is not None
    assert "HTML" in result.error


def test_fetch_4xx_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=404)
    config = get_mock_config()
    result = fetch_source(config, DEFAULTS)
    assert result.success is False
    assert result.error is not None and "404" in result.error


def test_fetch_5xx_retry_and_fail(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=500)
    httpx_mock.add_response(status_code=500)
    httpx_mock.add_response(status_code=500)
    config = get_mock_config()
    result = fetch_source(config, DEFAULTS)
    assert result.success is False
    assert result.error is not None and "500" in result.error
    assert len(httpx_mock.get_requests()) == 3


def test_fetch_429_retry_and_success(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=429)
    httpx_mock.add_response(status_code=200, content=b"success")
    config = get_mock_config()
    result = fetch_source(config, DEFAULTS)
    assert result.success is True
    assert result.content == b"success"
    assert len(httpx_mock.get_requests()) == 2


def test_fetch_caching_and_interval(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Redirect the cache into tmp_path so the test never touches the real one.
    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")

    # First request
    httpx_mock.add_response(
        content=b"data1",
        headers={"ETag": '"etag1"', "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
    )
    config = get_mock_config(min_interval_seconds=60)
    result1 = fetch_source(config, DEFAULTS)
    assert result1.success is True
    assert result1.content == b"data1"

    # Second request immediately should be rate limited by interval
    result2 = fetch_source(config, DEFAULTS)
    assert result2.success is True
    assert result2.cached is True
    assert result2.skipped_by_interval is True
    assert result2.error is None
    # The cached BODY must come back, not an empty result - otherwise every
    # interval-suppressed run silently drops all records for this source.
    assert result2.content == b"data1"
    # No new requests sent
    assert len(httpx_mock.get_requests()) == 1

    # Fast forward time to bypass min_interval

    original_time = time.time

    def mock_time() -> float:
        return original_time() + 100

    monkeypatch.setattr(time, "time", mock_time)

    # Now it should request again, using ETag, and we mock a 304 response
    httpx_mock.add_response(status_code=304)
    result3 = fetch_source(config, DEFAULTS)
    assert result3.success is True
    assert result3.cached is True
    assert result3.not_modified is True
    # Same requirement on the 304 path.
    assert result3.content == b"data1"

    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    assert requests[1].headers.get("if-none-match") == '"etag1"'
    assert requests[1].headers.get("if-modified-since") == "Wed, 21 Oct 2015 07:28:00 GMT"


# Parser tests
from xfeeds.collectors.parsers import (
    bruteforceblocker,
    dshield,
    ipsum_levels,
    netset,
    plain_text,
    spamhaus_asn_json,
    spamhaus_json,
)


def test_plain_text_parser() -> None:
    content = b"""
# Some comment
1.2.3.4
5.6.7.8 # inline comment
10.0.0.1 # private IP should be skipped
invalid-ip
2001:4860:4860::8888
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))

    # 1.2.3.4, 5.6.7.8, 2001:4860:4860::8888 are global
    assert len(records) == 3
    assert str(records[0].ip_or_cidr) == "1.2.3.4"
    assert str(records[1].ip_or_cidr) == "5.6.7.8"
    assert str(records[2].ip_or_cidr) == "2001:4860:4860::8888"


def test_plain_text_with_crlf_and_semicolon() -> None:
    content = b"1.2.3.4\r\n; comment\r\n5.6.7.8"
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))
    assert len(records) == 2


def test_netset_parser() -> None:
    content = b"""
1.2.3.0/24
5.6.7.8
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(netset(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "1.2.3.0/24"


def test_spamhaus_json_parser_with_metadata() -> None:
    content = b"""{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}
{"type":"metadata","timestamp":123456,"records":1687,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(spamhaus_json(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "1.10.16.0/20"

    # Attribution is recorded in the registry, NOT written back into the config -
    # a parser mutating shared config makes attribution order-dependent.
    attribution = upstream_attribution(config.name)
    assert attribution["copyright"] == "(c) 2026 The Spamhaus Project SLU"
    assert attribution["terms"] == "https://www.spamhaus.org/drop/terms/"
    assert config.license is None


def test_spamhaus_asn_json_parser_with_metadata() -> None:
    content = b"""{"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}
{"type":"metadata","timestamp":123456,"records":1687,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(spamhaus_asn_json(content, config, fetch_time))
    assert len(records) == 0
    attribution = upstream_attribution(config.name)
    assert attribution["copyright"] == "(c) 2026 The Spamhaus Project SLU"
    assert attribution["terms"] == "https://www.spamhaus.org/drop/terms/"


def test_dshield_parser() -> None:
    content = b"""
# Some header
45.205.1.0	45.205.1.255	24	322	MULTA-ASN1	US	abuse@multacom.com
147.185.132.0	147.185.132.255	24	322	GOOGLE-CLOUD-PLATFORM	US	None
10.0.0.0 10.0.0.255 24 # private range should be skipped
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(dshield(content, config, fetch_time))

    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "45.205.1.0/24"
    assert str(records[1].ip_or_cidr) == "147.185.132.0/24"


def test_bruteforceblocker_parser() -> None:
    content = b"""# using cache
# Last-Modified: Wed, 12 Aug 2026 00:14:50 GMT
92.118.39.78\t\t# 2026-07-19 20:29:31\t\t25\t2839674
171.231.184.215\t\t# 2026-08-08 19:20:08\t\t23\t2844299
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(bruteforceblocker(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "92.118.39.78"
    assert str(records[1].ip_or_cidr) == "171.231.184.215"


def test_ipsum_levels_parser() -> None:
    content = b"""195.178.110.137
31.77.227.120
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(ipsum_levels(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "195.178.110.137"


def test_empty_source() -> None:
    content = b""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))
    assert len(records) == 0


# ---------------------------------------------------------------------------
# Regression tests for defects found in review. Each of these failed before the
# corresponding fix, so they are the guard rails rather than coverage padding.
# ---------------------------------------------------------------------------


def test_interval_skip_without_cached_body_is_a_failure_not_silent_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interval skip with no cached body must report failure.

    Returning success with empty content would make the pipeline believe the
    source legitimately had zero records, silently dropping it from the feed.
    """
    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    cache_dir = tmp_path / "sources"
    cache_dir.mkdir(parents=True)
    meta_path, _ = xfeeds.collectors.base._cache_paths(
        get_mock_config(name="interval_only", min_interval_seconds=3600)
    )
    meta_path.write_text(json.dumps({"last_fetch_time": time.time()}))

    config = get_mock_config(name="interval_only", min_interval_seconds=3600)
    result = fetch_source(config, DEFAULTS)
    assert result.success is False
    assert result.skipped_by_interval is True
    assert result.content == b""


def test_304_without_cached_body_is_a_failure(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 304 with no cached body must fail rather than yield zero records."""
    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    httpx_mock.add_response(status_code=304)
    result = fetch_source(get_mock_config(name="no_body"), DEFAULTS)
    assert result.success is False
    assert result.not_modified is True


def test_configured_user_agent_is_sent_not_a_spoofed_browser(httpx_mock: HTTPXMock) -> None:
    """We identify ourselves honestly. Never impersonate a browser."""
    httpx_mock.add_response(content=b"1.2.3.4")
    fetch_source(get_mock_config(require_user_agent=True), DEFAULTS)
    ua = httpx_mock.get_requests()[0].headers["user-agent"]
    assert ua == DEFAULTS.user_agent
    assert "Mozilla" not in ua
    assert "Chrome" not in ua


def test_source_timeout_overrides_default() -> None:
    """A per-source timeout must win over the registry default."""
    config = get_mock_config(timeout_seconds=5)
    assert config.timeout_seconds == 5
    assert DEFAULTS.timeout_seconds != 5


def test_malformed_and_non_global_are_counted_separately(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Private addresses are not malformed lines.

    Conflating them makes both counters useless for diagnosing an upstream that
    has started serving garbage.
    """
    content = b"not-an-ip\n10.0.0.1\n192.168.1.1\n8.8.8.8\n"
    records = list(plain_text(content, get_mock_config(), datetime.now(UTC)))
    # 8.8.8.8 is global and survives; the RFC1918 pair and the junk line do not.
    assert [str(r.ip_or_cidr) for r in records] == ["8.8.8.8"]


def test_ipsum_level_is_carried_onto_records() -> None:
    """The IPsum level is the upstream corroboration count (ADR-011).

    Dropping it would make IPsum indistinguishable from an ordinary source.
    """
    content = b"8.8.8.8\n1.1.1.1\n"
    config = get_mock_config(name="ipsum_levels", parser="ipsum_levels")
    records = list(ipsum_levels(content, config, datetime.now(UTC), level=5))
    assert records
    assert all("ipsum-level-5" in r.tags for r in records)


def test_tag_only_source_tags_from_categories_not_a_hardcoded_string() -> None:
    """tag_only sources derive tags from their configured categories."""
    config = get_mock_config(name="tor_exits", tag_only=True, categories=["tor-exit"])
    records = list(plain_text(b"8.8.8.8\n", config, datetime.now(UTC)))
    assert records[0].tags == ["tor-exit"]

    other = get_mock_config(name="something", tag_only=True, categories=["scanner"])
    records = list(plain_text(b"8.8.8.8\n", other, datetime.now(UTC)))
    assert records[0].tags == ["scanner"]


def test_missing_auth_secret_fails_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A keyed source with no key present must fail cleanly, never raise."""
    monkeypatch.delenv("XFEEDS_TEST_KEY", raising=False)
    config = get_mock_config(
        name="keyed", auth="header", auth_header="Key", auth_secret="XFEEDS_TEST_KEY"
    )
    result = fetch_source(config, DEFAULTS)
    assert result.success is False
    assert result.error is not None and "XFEEDS_TEST_KEY" in result.error


def test_auth_secret_is_sent_as_header_when_present(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XFEEDS_TEST_KEY", "s3cret")
    httpx_mock.add_response(content=b"8.8.8.8")
    config = get_mock_config(
        name="keyed2", auth="header", auth_header="Key", auth_secret="XFEEDS_TEST_KEY"
    )
    result = fetch_source(config, DEFAULTS)
    assert result.success is True
    assert httpx_mock.get_requests()[0].headers["Key"] == "s3cret"


def test_every_registered_parser_is_declared_in_valid_parsers() -> None:
    """PARSERS and VALID_PARSERS must not drift apart."""
    from xfeeds.collectors.parsers import PARSERS
    from xfeeds.models import VALID_PARSERS

    assert set(PARSERS) <= VALID_PARSERS


def test_turris_greylist_parses_tags_and_skips_header() -> None:
    """The Tags column drives category, and so severity."""
    from xfeeds.collectors.parsers import turris_greylist

    content = (
        b"# For the terms of use see https://view.sentinel.turris.cz/greylist-data/LICENSE.txt\r\n"
        b"Address,Tags\r\n"
        b"45.66.230.9,telnet\r\n"
        b'45.66.230.10,"http,smtp"\r\n'
        b"10.0.0.1,telnet\r\n"
        b"not-an-ip,telnet\r\n"
    )
    config = SourceConfig(
        name="turris_greylist",
        url="https://example.invalid/greylist.csv",
        parser="turris_greylist",
        independence_class="turris",
        weight=0.7,
        categories=["brute-force"],
        redistribute=False,
    )
    now = datetime(2026, 8, 12, tzinfo=UTC)
    records = list(turris_greylist(content, config, now))

    # The header, the private address and the malformed row are all dropped.
    assert [str(r.ip_or_cidr) for r in records] == ["45.66.230.9", "45.66.230.10"]
    assert records[0].categories == ["brute-force"]
    assert records[1].categories == ["spam-source", "web-attack"]
    assert records[0].tags == ["turris-telnet"]
    assert all(not r.carried for r in records)


# --------------------------------------------------------------------------
# AbuseIPDB
#
# The free tier allows five blacklist calls a day, so nothing here touches the
# network - the recorded response in tests/fixtures/sources/ is the only copy of
# a real payload this suite gets.
# --------------------------------------------------------------------------

ABUSEIPDB_FIXTURE = Path("tests/fixtures/sources/abuseipdb_blacklist.json")


def abuseipdb_config() -> SourceConfig:
    """Mirror the real sources.yaml entry, including redistribute:false."""
    return SourceConfig(
        name="abuseipdb_blacklist",
        url="https://api.abuseipdb.com/api/v2/blacklist",
        parser="abuseipdb",
        independence_class="abuseipdb",
        weight=0.9,
        categories=["reported-abuse"],
        auth="header",
        auth_header="Key",
        auth_secret="ABUSEIPDB_API_KEY",
        params={"confidenceMinimum": 100, "limit": 10000},
        min_interval_seconds=21600,
        cache_response=True,
        redistribute=False,
    )


def test_abuseipdb_parses_the_recorded_response() -> None:
    """Parse the real recorded payload, asserting behaviour rather than volume."""
    from xfeeds.collectors.parsers import abuseipdb

    content = ABUSEIPDB_FIXTURE.read_bytes()
    config = abuseipdb_config()
    now = datetime(2026, 8, 14, 16, tzinfo=UTC)
    records = list(abuseipdb(content, config, now))

    assert records, "the recorded fixture must yield records"
    assert str(records[0].ip_or_cidr) == "186.38.26.5"
    assert records[0].source == "abuseipdb_blacklist"
    assert records[0].independence_class == "abuseipdb"
    assert records[0].categories == ["reported-abuse"]

    # first_seen/last_seen come from the fetch, not from the upstream's dates.
    assert records[0].first_seen == now
    assert records[0].last_seen == now

    # lastReportedAt lands in source_last_reported, truncated to the day.
    assert records[0].source_last_reported == datetime(2026, 8, 14, tzinfo=UTC)

    # Confidence is bucketed, not restated verbatim; country travels as a tag.
    assert "abuseipdb-confidence-100" in records[0].tags
    assert "cc:AR" in records[0].tags


def test_abuseipdb_skips_malformed_and_non_global_entries() -> None:
    """Reserved space must never reach the scorer, and junk must not raise."""
    from xfeeds.collectors.parsers import abuseipdb

    content = json.dumps(
        {
            "meta": {"generatedAt": "2026-08-14T15:44:34+00:00"},
            "data": [
                {"ipAddress": "45.33.32.5", "countryCode": "US", "abuseConfidenceScore": 100},
                {"ipAddress": "10.0.0.1", "countryCode": "US", "abuseConfidenceScore": 100},
                {"ipAddress": "127.0.0.1", "abuseConfidenceScore": 100},
                {"ipAddress": "not-an-ip", "abuseConfidenceScore": 100},
                {"ipAddress": "45.33.32.0/24", "abuseConfidenceScore": 100},
                {"countryCode": "US"},
                "not-an-object",
                {"ipAddress": "2001:4860:4860::8888", "abuseConfidenceScore": 75},
            ],
        }
    ).encode()

    records = list(abuseipdb(content, abuseipdb_config(), datetime(2026, 8, 14, tzinfo=UTC)))

    # The CIDR is rejected too: this endpoint returns single addresses, so a
    # network here means the payload shape changed and should not be guessed at.
    assert [str(r.ip_or_cidr) for r in records] == ["45.33.32.5", "2001:4860:4860::8888"]
    assert "abuseipdb-confidence-75" in records[1].tags
    assert records[1].source_last_reported is None


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"<html>rate limited</html>",
        b"45.33.32.5\n45.33.32.6\n",  # the text/plain variant of this endpoint
        b'{"data": {"ipAddress": "45.33.32.5"}}',  # data present but not a list
        b'[{"ipAddress": "45.33.32.5"}]',  # top level is not an object
        b'{"errors":[{"detail":"Too many requests.","status":429}]}',
    ],
)
def test_abuseipdb_yields_nothing_rather_than_guessing(content: bytes) -> None:
    """An error or unexpected shape is a zero-record source, never a partial parse.

    A partial parse here would silently drop most of an independence class while
    still reporting the source as healthy, which is worse than reporting nothing.
    """
    from xfeeds.collectors.parsers import abuseipdb

    records = list(abuseipdb(content, abuseipdb_config(), datetime(2026, 8, 14, tzinfo=UTC)))
    assert records == []


def test_abuseipdb_sends_the_key_and_the_free_tier_params(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The key goes in a Key header and the tier limits go on the query string."""
    import xfeeds.collectors.base

    # Redirect the cache: this source has a 6-hour interval, so a body written
    # into the real cache would suppress every later fetch in the suite.
    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "s3cret")
    httpx_mock.add_response(content=ABUSEIPDB_FIXTURE.read_bytes())

    result = fetch_source(abuseipdb_config(), DEFAULTS)

    assert result.success is True
    request = httpx_mock.get_requests()[0]
    assert request.headers["Key"] == "s3cret"
    assert request.url.params["confidenceMinimum"] == "100"
    assert request.url.params["limit"] == "10000"


def test_abuseipdb_skips_cleanly_when_the_key_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enabling the source must stay safe on a clone with no secret configured.

    AGENTS.md rule 6: a keyed source with no key skips; it does not fail the run
    and it does not raise. The cache is redirected at an empty directory so this
    asserts the no-credential path rather than a cache hit from another test.
    """
    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = fetch_source(abuseipdb_config(), DEFAULTS)

    assert result.success is False
    assert result.skipped_no_credential is True
    assert result.error is not None and "ABUSEIPDB_API_KEY" in result.error


# --------------------------------------------------------------------------
# Dataplane.org
# --------------------------------------------------------------------------

DATAPLANE_FIXTURE = Path("tests/fixtures/sources/dataplane_sshpwauth.txt")


def dataplane_config() -> SourceConfig:
    """Mirror the real sources.yaml entry: scoring only in BOTH tiers."""
    return SourceConfig(
        name="dataplane_sshpwauth",
        url="https://dataplane.org/sshpwauth.txt",
        parser="dataplane",
        independence_class="dataplane",
        weight=0.7,
        categories=["ssh-attack", "brute-force"],
        redistribute=False,
        redistribute_noncommercial=False,
        noncommercial_compatible=False,
    )


def test_dataplane_parses_the_recorded_report() -> None:
    """Read the pipe-delimited columns and skip the 74-line licence header."""
    from xfeeds.collectors.parsers import dataplane

    config = dataplane_config()
    now = datetime(2026, 8, 14, 17, tzinfo=UTC)
    records = list(dataplane(DATAPLANE_FIXTURE.read_bytes(), config, now))

    assert records, "the recorded fixture must yield records"
    assert str(records[0].ip_or_cidr) == "149.13.96.133"
    assert records[0].independence_class == "dataplane"
    assert records[0].categories == ["ssh-attack", "brute-force"]

    # Column 1 is the ASN, not an address - the whole reason plain_text fails here.
    assert "asn:174" in records[0].tags
    assert all(not str(r.ip_or_cidr).isdigit() for r in records)

    # The per-row lastseen is real dated history, truncated to the day.
    assert records[0].source_last_reported == datetime(2026, 8, 14, tzinfo=UTC)
    assert records[0].first_seen == now


def test_dataplane_rejects_rows_that_are_not_the_expected_shape() -> None:
    """A layout change must drop rows, never invent an address from column one."""
    from xfeeds.collectors.parsers import dataplane

    content = (
        b"# Dataplane.org - for operators, by operators\n"
        b"# The sshpwauth report is free for non-commercial use ONLY.\n"
        b"174          |  COGENT-174  |  45.33.32.5      |  2026-08-14 15:59:46  |  sshpwauth\n"
        b"174          |  COGENT-174  |  10.0.0.1        |  2026-08-14 15:59:46  |  sshpwauth\n"
        b"174          |  COGENT-174  |  not-an-ip       |  2026-08-14 15:59:46  |  sshpwauth\n"
        b"65535\n"
        b"174 | COGENT-174\n"
        b"\n"
        b"AS174        |  COGENT-174  |  45.33.32.6      |  2026-08-14 15:59:46  |  sshpwauth\n"
    )
    records = list(dataplane(content, dataplane_config(), datetime(2026, 8, 14, tzinfo=UTC)))

    # The private address, the malformed address and the two short rows all go.
    assert [str(r.ip_or_cidr) for r in records] == ["45.33.32.5", "45.33.32.6"]
    # A non-numeric ASN column is tolerated but not tagged as one.
    assert records[1].tags == []


def test_dataplane_never_reaches_either_published_tier() -> None:
    """Their header forbids redistribution "in whole or in part", so both flags are off.

    This is the licensing obligation for this source, and it differs from every
    other restricted source here: greensnow and abuseipdb are excluded from the
    primary feed, but Dataplane is excluded from the non-commercial tier as well.
    """
    from pathlib import Path as _Path

    from xfeeds.config import load_registry

    registry = load_registry(_Path("sources.yaml"))
    source = next(s for s in registry.sources if s.name == "dataplane_sshpwauth")

    assert source.enabled is True
    assert source.vote is True, "it is enabled to corroborate, so it must vote"
    assert source.redistribute is False
    assert source.redistribute_noncommercial is False
    assert source.noncommercial_compatible is False


# --------------------------------------------------------------------------
# min_score, gzip, and the multi-report DataPlane shapes (ADR-050)
# --------------------------------------------------------------------------


def test_ipthreat_min_score_drops_low_confidence_rows() -> None:
    """threat-N.txt is a SCORE slice, not a day window, so the floor lives here.

    We fetch the widest file and filter locally; a row below the floor must not
    reach the scorer, because band assignment counts classes rather than weights,
    so a score-0 row would admit a record exactly as hard as a score-100 one.
    """
    from xfeeds.collectors.parsers import ipthreat

    content = (
        b"# Format: IP # ThreatLevel ThreatLevelTimestamp CountryCode\n"
        b"45.33.32.5 # 100 2026-08-14T22:59:09Z BD\n"
        b"45.33.32.6 # 15 2026-08-14T22:59:09Z GB\n"
        b"45.33.32.7 # 14 2026-08-14T22:59:09Z GB\n"
        b"45.33.32.8 # 0 2026-08-14T22:59:09Z CN\n"
        b"45.33.32.9 # notanumber 2026-08-14T22:59:09Z CN\n"
    )
    config = get_mock_config(name="ipthreat", parser="ipthreat", min_score=15)
    records = list(ipthreat(content, config, datetime(2026, 8, 14, tzinfo=UTC)))

    # 14 and 0 are below the floor; the unparseable score cannot clear it either.
    assert [str(r.ip_or_cidr) for r in records] == ["45.33.32.5", "45.33.32.6"]


def test_ipthreat_without_min_score_keeps_everything() -> None:
    """The floor is opt-in, so an unset value must not silently filter."""
    from xfeeds.collectors.parsers import ipthreat

    content = b"45.33.32.5 # 0 2026-08-14T22:59:09Z CN\n45.33.32.6 # 100 2026-08-14T22:59:09Z GB\n"
    config = get_mock_config(name="ipthreat", parser="ipthreat")
    records = list(ipthreat(content, config, datetime(2026, 8, 14, tzinfo=UTC)))
    assert len(records) == 2


def test_gzipped_source_is_inflated_before_parsing(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cache must hold INFLATED bytes so a cache hit matches a fresh fetch."""
    import gzip as _gzip

    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    payload = b"45.33.32.5\n45.33.32.6\n"
    httpx_mock.add_response(content=_gzip.compress(payload))

    config = get_mock_config(name="gz", gzipped=True, min_interval_seconds=3600)
    result = fetch_source(config, DEFAULTS)

    assert result.success is True
    assert result.content == payload

    # Second call is served from cache and must be identical, not double-inflated.
    again = fetch_source(config, DEFAULTS)
    assert again.cached is True
    assert again.content == payload


def test_corrupt_gzip_is_a_failure_not_an_empty_parse(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Handing compressed bytes to a parser would look like a quiet upstream."""
    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "CACHE_DIR", tmp_path / "sources")
    httpx_mock.add_response(content=b"this is not gzip")

    result = fetch_source(get_mock_config(name="gz2", gzipped=True), DEFAULTS)

    assert result.success is False
    assert result.error is not None and "decompress" in result.error


def test_dataplane_reads_the_timestamp_from_the_end_for_six_column_proto41() -> None:
    """proto41 inserts firstseen before lastseen; every other report has five columns.

    A fixed index would silently read firstseen as lastseen on that one report, so
    the parser counts from the end.
    """
    from xfeeds.collectors.parsers import dataplane

    five = b"174 | COGENT-174 | 45.33.32.5 | 2026-08-14 15:59:46 | sshpwauth\n"
    six = b"701 | UUNET | 45.33.32.6 | 2026-08-01 01:02:03 | 2026-08-14 15:59:46 | proto41\n"
    config = get_mock_config(name="dp", parser="dataplane")
    records = list(dataplane(five + six, config, datetime(2026, 8, 14, 17, tzinfo=UTC)))

    assert [str(r.ip_or_cidr) for r in records] == ["45.33.32.5", "45.33.32.6"]
    # Both must resolve to the 14th - the lastseen column - not proto41's firstseen.
    assert all(r.source_last_reported == datetime(2026, 8, 14, tzinfo=UTC) for r in records)

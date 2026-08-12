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

"""Evidence-age determination.

The risk-bearing behaviour here is not "can we read a date". It is that a source
whose evidence has frozen must be *detected* as frozen, using the priority order
in `docs/source-lifecycle.md` rather than whichever timestamp happens to be
easiest to reach. The abuse.ch tests below are the failure mode, not the happy
path: they encode a real upstream that reports a moving HTTP header over a
payload that has not changed since March.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytest_httpx import HTTPXMock

from xfeeds.freshness import (
    EvidenceAge,
    FreshnessLedger,
    content_digest,
    determine_evidence_age,
    extract_feed_timestamp,
    newest,
    parse_http_date,
)
from xfeeds.models import DefaultsConfig, Registry, SourceConfig
from xfeeds.pipeline import collect_all

FIXTURES = Path(__file__).parent / "fixtures" / "sources"
NOW = datetime(2026, 9, 1, tzinfo=UTC)


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# --------------------------------------------------------------------------
# Priority 1: the timestamp a feed declares about itself.
# Every case below is asserted against a real recorded response.
# --------------------------------------------------------------------------


def test_extracts_abusech_header_with_crlf() -> None:
    """Feodo's header is CRLF-terminated and padded to a box-drawing width."""
    assert extract_feed_timestamp(fixture("feodo_ipblocklist.txt")) == datetime(
        2026, 3, 4, 14, 28, 39, tzinfo=UTC
    )


def test_extracts_sslbl_header() -> None:
    assert extract_feed_timestamp(fixture("sslbl_ipblacklist.txt")) == datetime(
        2025, 1, 2, 1, 9, 6, tzinfo=UTC
    )


def test_extracts_dshield_iso_timestamp() -> None:
    """DShield writes a naive ISO timestamp behind an `updated:` label."""
    assert extract_feed_timestamp(fixture("dshield_block.txt")) == datetime(
        2026, 8, 12, 0, 0, 26, 57308, tzinfo=UTC
    )


def test_extracts_http_date_from_spamhaus_text_comment() -> None:
    """Spamhaus repeats Last-Modified inside the payload, behind a `;` comment."""
    assert extract_feed_timestamp(fixture("spamhaus_drop.txt")) == datetime(
        2026, 8, 11, 11, 17, 49, tzinfo=UTC
    )


def test_extracts_http_date_from_bruteforceblocker_comment() -> None:
    assert extract_feed_timestamp(fixture("bruteforceblocker.txt")) == datetime(
        2026, 8, 12, 0, 14, 50, tzinfo=UTC
    )


def test_extracts_dataplane_window_end_not_start() -> None:
    """Dataplane states a reporting window; the end is the evidence time.

    Reading the start would overstate the age by the width of the window, which
    for sshpwauth is a full week - enough to trip a 10-day threshold on a feed
    that is publishing normally.
    """
    assert extract_feed_timestamp(fixture("dataplane_sshpwauth.txt")) == datetime(
        2026, 8, 14, 16, 0, tzinfo=UTC
    )


def test_extracts_firehol_file_date() -> None:
    """FireHOL carries two dates; the generation date is the feed's own."""
    assert extract_feed_timestamp(fixture("firehol_level1.netset")) == datetime(
        2026, 8, 11, 14, 33, 7, tzinfo=UTC
    )


def test_extracts_abuseipdb_generated_at() -> None:
    """AbuseIPDB sends no Last-Modified at all - this is its only timestamp."""
    assert extract_feed_timestamp(fixture("abuseipdb_blacklist.json")) == datetime(
        2026, 8, 14, 15, 44, 34, tzinfo=UTC
    )


def test_extracts_spamhaus_ndjson_metadata_timestamp() -> None:
    """The metadata record is the last line of a newline-delimited JSON body."""
    assert extract_feed_timestamp(fixture("spamhaus_drop_v4.json")) == datetime.fromtimestamp(
        123456, UTC
    )


@pytest.mark.parametrize(
    "name",
    [
        "blocklist_de_all.txt",
        "cins_ci-badguys.txt",
        "et_compromised.txt",
        "greensnow.txt",
        "ipsum_level3.txt",
        "tor_exits.txt",
    ],
)
def test_bare_lists_declare_no_timestamp(name: str) -> None:
    """Feeds that are just addresses must yield None, not a guess.

    These fall through to priority 2 or 3. Inventing a timestamp for them would
    be worse than having none.
    """
    assert extract_feed_timestamp(fixture(name)) is None


def test_does_not_read_a_per_row_date_as_the_feed_date() -> None:
    """The scan stops at the first data line.

    bruteforceblocker carries a `# Last Reported` date on every row. Sweeping the
    whole file would report one arbitrary row's date as the feed's.
    """
    body = b"# Last-Modified: Wed, 12 Aug 2026 00:14:50 GMT\n1.2.3.4\t# 2020-01-01 00:00:00\t1\t2\n"
    assert extract_feed_timestamp(body) == datetime(2026, 8, 12, 0, 14, 50, tzinfo=UTC)


def test_ignores_a_timestamp_below_the_header_block() -> None:
    body = b"1.2.3.4\n# Last updated: 2019-01-01 00:00:00 UTC\n"
    assert extract_feed_timestamp(body) is None


def test_empty_and_malformed_bodies_are_survivable() -> None:
    assert extract_feed_timestamp(b"") is None
    assert extract_feed_timestamp(b"# Last updated: not-a-date UTC\n1.2.3.4\n") is None
    assert extract_feed_timestamp(b"{ this is not json") is None
    assert extract_feed_timestamp(b"\xff\xfe\x00garbage") is None


# --------------------------------------------------------------------------
# The defect this module exists to fix.
# --------------------------------------------------------------------------


def test_payload_timestamp_beats_a_newer_http_header() -> None:
    """The regression test for the abuse.ch defect.

    On 2026-09-01 Feodo Tracker served `Last-Modified: Tue, 30 Jun 2026` over a
    payload declaring 2026-03-04. Before this fix the pipeline read the header and
    recorded the evidence as 63 days old; it is 180 - 181 calendar days, less the
    part-day lost to truncating observations to midnight UTC. Both exceed Feodo's
    7-day threshold, so the published output did not change - but a source whose
    CDN refreshed the header inside its threshold would have voted at full
    strength over frozen evidence forever, which is what ADR-052 forbids.
    """
    age = determine_evidence_age(
        fixture("feodo_ipblocklist.txt"),
        "Tue, 30 Jun 2026 04:53:05 GMT",
        None,
        "feodo_tracker",
        NOW,
    )
    assert age.basis == "payload"
    assert age.timestamp == datetime(2026, 3, 4, 14, 28, 39, tzinfo=UTC)
    assert age.age_days(NOW) == 180


def test_a_rotating_http_header_cannot_mask_a_frozen_payload() -> None:
    """Move the header forward to today; the age must not move with it."""
    for header in [
        "Tue, 01 Sep 2026 00:00:00 GMT",
        "Mon, 31 Aug 2026 23:59:59 GMT",
        "Tue, 30 Jun 2026 04:53:05 GMT",
    ]:
        age = determine_evidence_age(
            fixture("feodo_ipblocklist.txt"), header, None, "feodo_tracker", NOW
        )
        assert age.age_days(NOW) == 180, header


# --------------------------------------------------------------------------
# Priority order.
# --------------------------------------------------------------------------


def test_falls_back_to_http_header_when_payload_is_bare() -> None:
    age = determine_evidence_age(
        fixture("cins_ci-badguys.txt"), "Mon, 31 Aug 2026 12:00:00 GMT", None, "cins_army", NOW
    )
    assert age.basis == "http-last-modified"
    assert age.age_days(NOW) == 0


def test_falls_back_to_content_hash_when_neither_exists() -> None:
    """The gap that left three sources with no freshness gate at all."""
    ledger = FreshnessLedger()
    body = fixture("ipsum_level3.txt")
    first = NOW - timedelta(days=40)

    seen = determine_evidence_age(body, None, ledger, "ipsum_levels#3", first)
    assert seen.basis == "content-hash"
    assert seen.age_days(first) == 0

    # Forty days later, byte-identical body: the evidence is forty days old.
    later = determine_evidence_age(body, None, ledger, "ipsum_levels#3", NOW)
    assert later.basis == "content-hash"
    assert later.age_days(NOW) == 40


def test_a_changed_body_resets_the_hash_clock() -> None:
    ledger = FreshnessLedger()
    determine_evidence_age(b"1.2.3.4\n", None, ledger, "src", NOW - timedelta(days=40))
    age = determine_evidence_age(b"1.2.3.4\n5.6.7.8\n", None, ledger, "src", NOW)
    assert age.age_days(NOW) == 0


def test_unknown_age_is_reported_as_unknown_not_as_fresh() -> None:
    age = determine_evidence_age(fixture("cins_ci-badguys.txt"), None, None, "cins_army", NOW)
    assert age.basis == "unknown"
    assert age.timestamp is None
    assert age.age_days(NOW) is None
    assert not age.known


def test_ledger_accumulates_even_when_a_higher_priority_wins() -> None:
    """History must already exist on the day a source drops its header.

    If the ledger were only written when priority 3 was in use, a source that
    lost its timestamp would restart from zero at exactly the moment the fallback
    was needed.
    """
    ledger = FreshnessLedger()
    body = fixture("feodo_ipblocklist.txt")
    determine_evidence_age(body, "Tue, 30 Jun 2026 04:53:05 GMT", ledger, "feodo_tracker", NOW)

    later = determine_evidence_age(body, None, ledger, "feodo_tracker", NOW + timedelta(days=10))
    assert later.basis == "payload"

    stripped = b"\n".join(body.split(b"\n")[8:])
    fallback = determine_evidence_age(
        stripped, None, ledger, "feodo_tracker", NOW + timedelta(days=10)
    )
    assert fallback.basis == "content-hash"


# --------------------------------------------------------------------------
# Guards.
# --------------------------------------------------------------------------


def test_a_timestamp_from_the_future_is_discarded() -> None:
    """A broken upstream clock must not manufacture freshness."""
    body = b"# Last updated: 2030-01-01 00:00:00 UTC\n1.2.3.4\n"
    age = determine_evidence_age(body, "Mon, 31 Aug 2026 12:00:00 GMT", None, "src", NOW)
    assert age.basis == "http-last-modified"


def test_same_day_publication_is_not_treated_as_the_future() -> None:
    """Observations are truncated to midnight, so today's feed is 'ahead' of them.

    Spamhaus publishes around midday and stamps the payload accordingly. That must
    read as zero days old, not as a rejected future timestamp.
    """
    body = b"; Last-Modified: Tue, 01 Sep 2026 12:44:02 GMT\n1.2.3.0/24\n"
    age = determine_evidence_age(body, None, None, "spamhaus_drop", NOW)
    assert age.basis == "payload"
    assert age.age_days(NOW) == 0


def test_malformed_http_dates_do_not_raise() -> None:
    assert parse_http_date(None) is None
    assert parse_http_date("") is None
    assert parse_http_date("not a date") is None
    assert parse_http_date("Mon, 31 Aug 2026 12:00:00 GMT") == datetime(2026, 8, 31, 12, tzinfo=UTC)


def test_naive_http_date_is_treated_as_utc() -> None:
    parsed = parse_http_date("Mon, 31 Aug 2026 12:00:00 -0000")
    assert parsed is not None and parsed.tzinfo is not None


# --------------------------------------------------------------------------
# Multi-URL sources.
# --------------------------------------------------------------------------


def test_newest_evidence_wins_across_levels() -> None:
    """ipsum publishes six files; one moving means the upstream is alive."""
    old = EvidenceAge(NOW - timedelta(days=40), "content-hash")
    new = EvidenceAge(NOW - timedelta(days=1), "content-hash")
    assert newest(old, new) is new
    assert newest(new, old) is new


def test_unknown_never_displaces_a_known_age() -> None:
    known = EvidenceAge(NOW - timedelta(days=5), "payload")
    unknown = EvidenceAge(None, "unknown")
    assert newest(known, unknown) is known
    assert newest(unknown, known) is known
    assert newest(None, unknown) is unknown


# --------------------------------------------------------------------------
# Ledger persistence.
# --------------------------------------------------------------------------


def test_ledger_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "source-freshness.json"
    ledger = FreshnessLedger()
    changed = ledger.observe("src", content_digest(b"body"), NOW)
    ledger.save(path)

    reloaded = FreshnessLedger.load(path)
    assert reloaded.observe("src", content_digest(b"body"), NOW + timedelta(days=9)) == changed


def test_ledger_write_is_byte_identical_for_an_unchanged_body(tmp_path: Path) -> None:
    """Rule 4: the same input must produce the same bytes.

    The ledger is a committed artifact, so a field that moved on every run would
    add a diff four times a day and bury the one signal it exists to carry.
    """
    path = tmp_path / "source-freshness.json"
    first = FreshnessLedger()
    first.observe("b", content_digest(b"two"), NOW)
    first.observe("a", content_digest(b"one"), NOW)
    first.save(path)
    original = path.read_bytes()

    second = FreshnessLedger.load(path)
    second.observe("a", content_digest(b"one"), NOW + timedelta(days=3))
    second.observe("b", content_digest(b"two"), NOW + timedelta(days=3))
    second.save(path)
    assert path.read_bytes() == original


def test_a_corrupt_ledger_degrades_instead_of_failing(tmp_path: Path) -> None:
    path = tmp_path / "source-freshness.json"
    path.write_text("{ not json", encoding="utf-8")
    ledger = FreshnessLedger.load(path)
    assert ledger.observe("src", content_digest(b"body"), NOW) == NOW


def test_a_missing_ledger_is_an_empty_ledger(tmp_path: Path) -> None:
    ledger = FreshnessLedger.load(tmp_path / "absent.json")
    assert ledger.observe("src", content_digest(b"body"), NOW) == NOW


# --------------------------------------------------------------------------
# Pipeline integration: the manifest must report what actually decided.
# --------------------------------------------------------------------------


def _registry(dormant: bool = False) -> Registry:
    source = SourceConfig(
        name="frozen_source",
        url="https://example.com/list.txt",
        parser="plain_text",
        independence_class="test_class",
        weight=1.0,
        ttl_days=7,
        dormant=dormant,
    )
    return Registry(version=1, defaults=DefaultsConfig(), sources=[source], allowlist_sources=[])


def test_collect_all_marks_records_stale_from_the_payload(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a fresh HTTP header does not rescue a frozen payload.

    Forty days old - past the freshness threshold, well short of the 90-day
    expiry ceiling - so this is the damped, non-admitting middle state.
    """
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    httpx_mock.add_response(
        content=b"# Last updated: 2026-07-23 00:00:00 UTC\n1.2.3.4\n",
        headers={"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"},
    )

    records, status, warnings, expired = collect_all(_registry(), NOW, ledger=FreshnessLedger())

    entry = status["frozen_source"]
    assert entry["status"] == "stale"
    assert entry["evidence_basis"] == "payload"
    assert entry["evidence_age_days"] == 40
    # The transport signal is still reported, and is still visibly different.
    assert entry["last_modified"] == "2026-09-01T00:00:00+00:00"
    assert records and all(r.evidence_stale for r in records)
    assert any("40 days ago" in w for w in warnings)
    assert expired == set()


def test_collect_all_stays_quiet_for_a_dormant_source(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dormant source contributes nothing, and does not re-announce itself.

    Under ADR-059 dormant is manual expiry, not a damped vote: the records are
    dropped rather than marked. The silence is the point - it has been reviewed.
    """
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    httpx_mock.add_response(content=fixture("feodo_ipblocklist.txt"))

    records, status, warnings, expired = collect_all(
        _registry(dormant=True), NOW, ledger=FreshnessLedger()
    )

    assert status["frozen_source"]["status"] == "expired"
    assert status["frozen_source"]["dropped_records"] == 5
    assert records == []
    assert expired == {"frozen_source"}
    assert warnings == []


def test_collect_all_gates_a_source_that_has_no_timestamp_at_all(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three headerless sources were previously ungated entirely.

    A bare address list with no payload timestamp and no Last-Modified used to be
    exempt from the staleness gate no matter how long it had been frozen. With the
    ledger carrying its history, it is now caught.
    """
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    ledger = FreshnessLedger()
    body = fixture("cins_ci-badguys.txt")

    httpx_mock.add_response(content=body)
    _, first_status, _, _ = collect_all(_registry(), NOW - timedelta(days=40), ledger=ledger)
    assert first_status["frozen_source"]["status"] == "ok"
    assert first_status["frozen_source"]["evidence_basis"] == "content-hash"

    httpx_mock.add_response(content=body)
    records, status, _, _ = collect_all(_registry(), NOW, ledger=ledger)
    assert status["frozen_source"]["status"] == "stale"
    assert status["frozen_source"]["evidence_age_days"] == 40
    assert records and all(r.evidence_stale for r in records)


def test_a_source_that_keeps_publishing_is_never_marked_stale(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The false-positive direction. A live feed must not be damped."""
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    ledger = FreshnessLedger()

    for day in range(0, 40, 5):
        httpx_mock.add_response(content=f"1.2.3.{day}\n".encode())
        _, status, warnings, _ = collect_all(
            _registry(), NOW - timedelta(days=40 - day), ledger=ledger
        )
        assert status["frozen_source"]["status"] == "ok"
        assert not [w for w in warnings if "days ago" in w]

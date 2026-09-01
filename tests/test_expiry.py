"""Expiry: a source that stops publishing eventually stops counting.

Staleness used to be terminal. A source could sit damped and non-admitting
indefinitely — still fetched four times a day, still nudging scores with evidence
nobody had vouched for in months. Feodo Tracker sat in that state for 180 days.

ADR-059 puts a ceiling on it. Past `EXPIRY_DAYS` a source contributes nothing,
and it stays out until a maintainer records a review. The risk-bearing cases are
the ways that could leak: carrying from state, self-resurrection on fresh data,
and a review date that authorises an expiry it predates.
"""

import ipaddress
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from xfeeds.freshness import EvidenceAge, FreshnessLedger, classify_source
from xfeeds.models import Band, DefaultsConfig, IndicatorRecord, Registry, SourceConfig
from xfeeds.pipeline import EXPIRY_DAYS, STALENESS_DAYS, collect_all
from xfeeds.state import StateEntry, carried_observations

NOW = datetime(2026, 9, 1, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures" / "sources"


def evidence(days_old: int) -> EvidenceAge:
    return EvidenceAge(NOW - timedelta(days=days_old), "payload")


def classify(
    days_old: int | None = None,
    *,
    dormant: bool = False,
    reviewed_on: date | None = None,
    ledger: FreshnessLedger | None = None,
    observed_on: datetime = NOW,
    expiry_days: int = EXPIRY_DAYS,
    name: str = "src",
) -> Any:
    return classify_source(
        source_name=name,
        dormant=dormant,
        freshness_days=STALENESS_DAYS,
        expiry_days=expiry_days,
        reviewed_on=reviewed_on,
        evidence=evidence(days_old) if days_old is not None else None,
        ledger=ledger,
        observed_on=observed_on,
    )


# --------------------------------------------------------------------------
# The three states.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "expected"),
    [(0, "fresh"), (30, "fresh"), (31, "stale"), (89, "stale"), (90, "stale"), (91, "expired")],
)
def test_the_boundaries_are_where_they_are_documented(age: int, expected: str) -> None:
    assert classify(age, ledger=FreshnessLedger()).name == expected


def test_an_unknown_age_is_treated_as_fresh_not_expired() -> None:
    """A source nobody has measured yet must not be killed by the ceiling."""
    assert classify(None, ledger=FreshnessLedger()).name == "fresh"


def test_a_per_source_ceiling_overrides_the_global_one() -> None:
    assert classify(40, expiry_days=30, ledger=FreshnessLedger()).name == "expired"


def test_the_expiry_reason_says_what_happened() -> None:
    state = classify(200, ledger=FreshnessLedger())
    assert state.reason is not None
    assert "200 days old" in state.reason
    assert "90-day expiry ceiling" in state.reason


# --------------------------------------------------------------------------
# The latch. This is the half that makes "re-admitted upon review" real.
# --------------------------------------------------------------------------


def test_an_expired_source_does_not_resurrect_itself_on_fresh_data() -> None:
    """The whole point. Upstream publishing again is a prompt, not a decision."""
    ledger = FreshnessLedger()
    assert classify(200, ledger=ledger).name == "expired"

    # Upstream comes back to life with today's data.
    assert classify(0, ledger=ledger).name == "expired"
    assert classify(0, ledger=ledger).reason == "expired 0 days ago and not reviewed since"


def test_a_review_on_or_after_the_expiry_readmits() -> None:
    ledger = FreshnessLedger()
    state = classify(200, ledger=ledger, observed_on=NOW)
    assert state.expired_since is not None

    revived = classify(0, reviewed_on=date(2026, 9, 1), ledger=ledger)
    assert revived.name == "fresh"
    assert ledger.expired_since("src") is None


def test_a_review_predating_the_expiry_does_nothing() -> None:
    """Otherwise a review written in June could authorise an expiry in August."""
    ledger = FreshnessLedger()
    classify(200, ledger=ledger, observed_on=NOW)
    assert classify(0, reviewed_on=date(2026, 8, 31), ledger=ledger).name == "expired"


def test_a_review_readmits_to_stale_not_to_fresh_when_evidence_is_still_old() -> None:
    """Clearing the latch does not vouch for the data; freshness still governs."""
    ledger = FreshnessLedger()
    classify(200, ledger=ledger)
    assert classify(45, reviewed_on=date(2026, 9, 1), ledger=ledger).name == "stale"


def test_the_expiry_date_does_not_drift_while_a_source_stays_out() -> None:
    """ "How long has this been broken" has to stay answerable."""
    ledger = FreshnessLedger()
    first = classify(200, ledger=ledger, observed_on=NOW).expired_since
    later = classify(260, ledger=ledger, observed_on=NOW + timedelta(days=60)).expired_since
    assert first == later == NOW


def test_dormant_is_expiry_and_a_review_date_cannot_undo_it() -> None:
    """A maintainer's statement is only undone by a maintainer.

    `reviewed_on` clears a clock expiry. It must not clear a deliberate one, or a
    routine review date would quietly resurrect a source somebody killed on
    purpose — which is the failure mode the flag exists to prevent.
    """
    ledger = FreshnessLedger()
    state = classify(0, dormant=True, reviewed_on=date(2030, 1, 1), ledger=ledger)
    assert state.name == "expired"
    assert state.reason is not None and "dormant" in state.reason


def test_the_latch_survives_a_ledger_round_trip(tmp_path: Path) -> None:
    """It is worthless if a restart clears it."""
    path = tmp_path / "source-freshness.json"
    ledger = FreshnessLedger()
    classify(200, ledger=ledger)
    ledger.save(path)

    reloaded = FreshnessLedger.load(path)
    assert reloaded.expired_since("src") == NOW
    assert classify(0, ledger=reloaded).name == "expired"


# --------------------------------------------------------------------------
# The leak that would have made all of the above pointless.
# --------------------------------------------------------------------------


def test_an_expired_source_cannot_keep_voting_from_state() -> None:
    """Dropping it at collection achieves nothing if it carries forward.

    `carried_observations` re-casts recent sightings for sources that missed a
    run, reading them out of state rather than out of the fetch. An expired
    source has sightings in state by definition, so without an explicit exclusion
    it would go on voting for a further `ttl_days` — the exact behaviour the
    ceiling exists to end.
    """
    registry = Registry(
        version=1,
        defaults=DefaultsConfig(),
        sources=[
            SourceConfig(
                name="expired_one",
                url="https://example.com/a",
                parser="plain_text",
                independence_class="alpha",
                weight=0.8,
                ttl_days=10,
            ),
            SourceConfig(
                name="live_one",
                url="https://example.com/b",
                parser="plain_text",
                independence_class="beta",
                weight=0.8,
                ttl_days=10,
            ),
        ],
        allowlist_sources=[],
    )
    reported_now = [
        IndicatorRecord(
            ip_or_cidr=ipaddress.ip_address("45.33.32.156"),
            source="live_one",
            independence_class="beta",
            first_seen=NOW,
            last_seen=NOW,
            categories=["scanning"],
        )
    ]
    # The expired source saw this address yesterday, so it is sitting in state
    # inside its 10-day TTL and is eligible to carry.
    previous = {
        "45.33.32.156": StateEntry(
            first_seen=NOW - timedelta(days=5),
            last_seen=NOW,
            band=Band.MEDIUM,
            class_count=2,
            sightings={"expired_one": NOW - timedelta(days=1)},
        )
    }

    carried = carried_observations(reported_now, previous, registry, NOW)
    assert [c.source for c in carried] == ["expired_one"]

    blocked = carried_observations(reported_now, previous, registry, NOW, excluded={"expired_one"})
    assert blocked == []


# --------------------------------------------------------------------------
# End to end through the collector.
# --------------------------------------------------------------------------


def _registry(**kw: Any) -> Registry:
    return Registry(
        version=1,
        defaults=DefaultsConfig(),
        sources=[
            SourceConfig(
                name="frozen_source",
                url="https://example.com/list.txt",
                parser="plain_text",
                independence_class="alpha",
                weight=1.0,
                ttl_days=7,
                **kw,
            )
        ],
        allowlist_sources=[],
    )


def test_collect_all_drops_an_expired_source_and_says_so_loudly(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Feodo's real payload, 180 days old: dropped, and warned about every run."""
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    httpx_mock.add_response(content=(FIXTURES / "feodo_ipblocklist.txt").read_bytes())

    records, status, warnings, expired = collect_all(_registry(), NOW, ledger=FreshnessLedger())

    entry = status["frozen_source"]
    assert entry["status"] == "expired"
    assert entry["dropped_records"] == 5
    assert entry["records"] == 0
    assert records == []
    assert expired == {"frozen_source"}
    assert any("EXPIRED and contributing nothing" in w for w in warnings)
    assert any("retire it with enabled: false" in w for w in warnings)


def test_the_warning_repeats_because_it_is_an_open_action(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unlike a dormant source, an unreviewed expiry is not an accepted state."""
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    ledger = FreshnessLedger()
    for _ in range(3):
        httpx_mock.add_response(content=(FIXTURES / "feodo_ipblocklist.txt").read_bytes())
        _, _, warnings, _ = collect_all(_registry(), NOW, ledger=ledger)
        assert any("EXPIRED" in w for w in warnings)


def test_a_reviewed_source_rejoins_through_the_collector(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    ledger = FreshnessLedger()

    httpx_mock.add_response(content=(FIXTURES / "feodo_ipblocklist.txt").read_bytes())
    _, _, _, expired = collect_all(_registry(), NOW, ledger=ledger)
    assert expired == {"frozen_source"}

    httpx_mock.add_response(content=b"# Last updated: 2026-09-01 00:00:00 UTC\n1.2.3.4\n")
    records, status, warnings, expired = collect_all(
        _registry(reviewed_on=date(2026, 9, 1)), NOW, ledger=ledger
    )
    assert status["frozen_source"]["status"] == "ok"
    assert expired == set()
    assert len(records) == 1
    assert not [w for w in warnings if "EXPIRED" in w]


def test_a_healthy_source_is_untouched_by_any_of_this(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The false-positive direction, over a simulated four months of runs."""
    monkeypatch.setattr("xfeeds.collectors.base.CACHE_DIR", tmp_path / "cache")
    ledger = FreshnessLedger()
    start = NOW - timedelta(days=120)
    for day in range(0, 120, 6):
        httpx_mock.add_response(content=f"1.2.3.{day % 250}\n".encode())
        records, status, warnings, expired = collect_all(
            _registry(), start + timedelta(days=day), ledger=ledger
        )
        assert status["frozen_source"]["status"] == "ok", day
        assert expired == set(), day
        assert warnings == [], day
        assert len(records) == 1

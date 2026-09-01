"""What the manifest claims about corroboration capacity.

Voting and admitting are different rights. A class may vote — raising confidence
in a record that already stands on live corroboration — while being structurally
incapable of being one of the two classes that put an address into the feed.

The manifest published only the first, so `active_voting_classes` read as a
measure of corroboration capacity when it is not one. On 2026-09-01 it advertised
13 classes while 6 could admit, and four categories had no admitting source at
all. These tests exist so that cannot silently return.
"""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from xfeeds.emit import build_manifest
from xfeeds.models import (
    Band,
    DefaultsConfig,
    IndicatorRecord,
    Registry,
    ScoredIndicator,
    SourceConfig,
)
from xfeeds.score import MEDIUM_CONFIDENCE_CLASSES, score_indicators

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def src(name: str, cls: str, categories: list[str] | None = None, **kw: Any) -> SourceConfig:
    return SourceConfig(
        name=name,
        url=f"https://example.com/{name}",
        parser="plain_text",
        independence_class=cls,
        weight=kw.pop("weight", 0.8),
        categories=categories or ["scanning"],
        **kw,
    )


def registry_of(*sources: SourceConfig) -> Registry:
    return Registry(
        version=1, defaults=DefaultsConfig(), sources=list(sources), allowlist_sources=[]
    )


def ok(*names: str) -> dict[str, dict[str, Any]]:
    return {n: {"status": "ok", "records": 10} for n in names}


def manifest_for(
    registry: Registry, status: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    return build_manifest(
        registry,
        status if status is not None else ok(*[s.name for s in registry.sources]),
        [],
        [],
        [],
        NOW,
        {},
    )


# --------------------------------------------------------------------------
# The regression: a class that votes and can never admit.
# --------------------------------------------------------------------------


def test_the_abusech_shape_is_reported_as_voting_only() -> None:
    """Reproduces the real configuration that went unnoticed for two weeks.

    `feodo_tracker` is dormant and `threatfox` is `redistribute: false`, so the
    whole class votes and never admits — which leaves `botnet-c2` with no
    admitting source. The manifest said `active_voting_classes: [abusech, ...]`
    and nothing contradicted it.
    """
    registry = registry_of(
        src("feodo_tracker", "abusech", ["botnet-c2"], dormant=True),
        src("threatfox", "abusech", ["botnet-c2"], redistribute=False),
        src("cins_army", "cins", ["scanning"]),
    )
    manifest = manifest_for(registry)

    assert "abusech" in manifest["active_voting_classes"]
    assert "abusech" not in manifest["active_admitting_classes"]
    assert "abusech" in manifest["voting_only_classes"]
    assert manifest["category_coverage"]["botnet-c2"]["admitting_classes"] == 0
    assert manifest["category_coverage"]["botnet-c2"]["voting_classes"] == 1


def test_each_source_reports_why_it_cannot_admit() -> None:
    """\"Cannot admit\" is a fact; the reason is what makes it actionable."""
    registry = registry_of(
        src("dormant_one", "alpha", dormant=True),
        src("restricted", "beta", redistribute=False),
        src("silenced", "gamma", vote=False, weight=0.0),
        src("switched_off", "delta", enabled=False),
        src("healthy", "epsilon"),
    )
    sources = manifest_for(registry)["sources"]

    assert sources["dormant_one"]["admits"] is False
    assert "dormant" in sources["dormant_one"]["admitting_blocked_by"]
    assert sources["restricted"]["admits"] is False
    assert "redistribution" in sources["restricted"]["admitting_blocked_by"]
    assert sources["silenced"]["admits"] is False
    assert sources["silenced"]["admitting_blocked_by"] == "does not vote"
    assert sources["switched_off"]["admits"] is False
    assert sources["switched_off"]["admitting_blocked_by"] == "disabled"
    assert sources["healthy"]["admits"] is True
    assert sources["healthy"]["admitting_blocked_by"] is None


# --------------------------------------------------------------------------
# The two fields must stay coherent with each other and with the scorer.
# --------------------------------------------------------------------------


def test_admitting_is_always_a_subset_of_voting() -> None:
    """Admission is a strictly narrower right. A class cannot admit without voting."""
    registry = registry_of(
        src("a", "alpha"),
        src("b", "beta", redistribute=False),
        src("c", "gamma", dormant=True),
        src("d", "delta", vote=False, weight=0.0),
        src("e", "epsilon", enabled=False),
    )
    manifest = manifest_for(registry)
    voting = set(manifest["active_voting_classes"])
    admitting = set(manifest["active_admitting_classes"])

    assert admitting <= voting
    assert set(manifest["voting_only_classes"]) == voting - admitting


def test_reported_admitting_classes_match_what_the_scorer_will_publish() -> None:
    """The manifest's claim has to survive contact with the scorer.

    Two admitting classes are the threshold to publish at all. If the manifest
    names exactly two and the scorer withholds the record anyway, the manifest is
    lying in the direction that matters.
    """
    registry = registry_of(
        src("open_a", "alpha"),
        src("open_b", "beta"),
        src("restricted", "gamma", redistribute=False),
        src("dormant_one", "delta", dormant=True),
    )
    manifest = manifest_for(registry)
    assert len(manifest["active_admitting_classes"]) == MEDIUM_CONFIDENCE_CLASSES

    def observation(source: str, cls: str) -> IndicatorRecord:
        return IndicatorRecord(
            ip_or_cidr=ipaddress.ip_address("45.33.32.156"),
            source=source,
            independence_class=cls,
            first_seen=NOW,
            last_seen=NOW,
            categories=["scanning"],
        )

    # The two admitting classes alone are enough to publish.
    published = score_indicators(
        [observation("open_a", "alpha"), observation("open_b", "beta")], registry, NOW
    )
    assert published[0].band is not Band.WITHHELD

    # The two voting-only classes alone are not, however many of them there are.
    withheld = score_indicators(
        [observation("restricted", "gamma"), observation("dormant_one", "delta")], registry, NOW
    )
    assert withheld[0].band is Band.WITHHELD


# --------------------------------------------------------------------------
# Structural versus per-run. The distinction is deliberate.
# --------------------------------------------------------------------------


def test_a_transient_failure_does_not_read_as_a_structural_gap() -> None:
    """`active_admitting_classes` describes the configuration, not the weather.

    A source that failed to fetch this morning has not lost its licence. Dropping
    its class from the structural list would make a network blip look like a
    coverage gap, and the per-source `admits` already carries the per-run truth.
    """
    registry = registry_of(src("a", "alpha"), src("b", "beta"))
    manifest = manifest_for(
        registry, {"a": {"status": "failed", "records": 0}, "b": {"status": "ok", "records": 10}}
    )

    assert set(manifest["active_admitting_classes"]) == {"alpha", "beta"}
    assert manifest["sources"]["a"]["admits"] is False
    assert "no data this run" in manifest["sources"]["a"]["admitting_blocked_by"]


def test_a_stale_source_cannot_admit_this_run() -> None:
    """Staleness is transient, so it gates the source without moving the class."""
    registry = registry_of(src("a", "alpha"), src("b", "beta"))
    manifest = manifest_for(
        registry,
        {
            "a": {"status": "stale", "records": 5, "evidence_age_days": 180},
            "b": {"status": "ok", "records": 10},
        },
    )

    assert manifest["sources"]["a"]["admits"] is False
    assert "180 days old" in manifest["sources"]["a"]["admitting_blocked_by"]
    assert "alpha" in manifest["active_admitting_classes"]


# --------------------------------------------------------------------------
# The existing contract is not disturbed.
# --------------------------------------------------------------------------


def test_active_voting_classes_is_unchanged() -> None:
    """Consumers read this field. It keeps its exact previous meaning."""
    registry = registry_of(
        src("a", "alpha"),
        src("b", "beta", redistribute=False),
        src("c", "gamma", dormant=True),
        src("d", "delta", vote=False, weight=0.0),
        src("e", "epsilon", enabled=False),
    )
    assert manifest_for(registry)["active_voting_classes"] == ["alpha", "beta", "gamma"]


def test_category_coverage_names_the_classes_that_can_admit() -> None:
    registry = registry_of(
        src("a", "alpha", ["scanning", "brute-force"]),
        src("b", "beta", ["scanning"], redistribute=False),
    )
    coverage = manifest_for(registry)["category_coverage"]

    assert coverage["scanning"] == {
        "voting_classes": 2,
        "admitting_classes": 1,
        "admitting_class_names": ["alpha"],
    }
    assert coverage["brute-force"]["admitting_class_names"] == ["alpha"]


def test_disabled_sources_contribute_no_coverage() -> None:
    registry = registry_of(src("off", "alpha", ["botnet-c2"], enabled=False))
    assert manifest_for(registry, {})["category_coverage"] == {}


def test_manifest_survives_a_source_missing_from_the_registry() -> None:
    """Status can name a source the registry no longer has, mid-rename."""
    manifest = manifest_for(registry_of(src("a", "alpha")), ok("a", "ghost"))
    assert manifest["sources"]["ghost"]["admits"] is False
    assert manifest["sources"]["ghost"]["admitting_blocked_by"] == "not configured"


def test_manifest_is_deterministic() -> None:
    """Sets are involved; the output must not depend on iteration order."""
    registry = registry_of(
        src("a", "alpha", ["scanning", "abuse"]),
        src("b", "beta", ["abuse"], redistribute=False),
        src("c", "gamma", ["scanning"], dormant=True),
    )
    first = manifest_for(registry)
    second = manifest_for(registry)
    for key in (
        "active_voting_classes",
        "active_admitting_classes",
        "voting_only_classes",
        "category_coverage",
    ):
        assert first[key] == second[key]


def test_scored_records_still_round_trip() -> None:
    """Guard against the new block breaking manifest construction with real records."""
    registry = registry_of(src("a", "alpha"))
    record = ScoredIndicator(
        ip_or_cidr=ipaddress.ip_address("45.33.32.156"),
        first_seen=NOW,
        last_seen=NOW,
        score=50.0,
        band=Band.MEDIUM,
        independence_classes=["alpha"],
        sources=["a"],
        categories=["scanning"],
    )
    manifest = build_manifest(registry, ok("a"), [record], [], [], NOW, {})
    assert manifest["counts"]["published"] == 1


# --------------------------------------------------------------------------
# The public homepage made the same claim, more loudly.
# --------------------------------------------------------------------------


def test_homepage_quotes_admitting_classes_not_voting_classes() -> None:
    """The most public surface had the most overstated number.

    "13 independent evidence classes" is what a security team read on the front
    page while 6 could actually put an address into the feed.
    """
    from xfeeds.dashboard import _about_section

    html = _about_section(
        {
            "sources": {name: {} for name in "abcdefghijklmnopqrstuvw"},
            "active_voting_classes": [f"c{i}" for i in range(13)],
            "active_admitting_classes": [f"c{i}" for i in range(6)],
        }
    )
    assert "6 independent evidence classes that can publish a record" in html
    assert "plus 7 further classes that corroborate without ever admitting one" in html
    assert "13 independent evidence classes" not in html


def test_homepage_falls_back_when_the_field_is_absent() -> None:
    """An older manifest must still render rather than crash or show a blank."""
    from xfeeds.dashboard import _about_section

    html = _about_section({"sources": {"a": {}}, "active_voting_classes": ["x", "y"]})
    assert "1 sources across 2 independent evidence classes" in html


def test_homepage_omits_the_clause_when_every_class_admits() -> None:
    from xfeeds.dashboard import _about_section

    html = _about_section(
        {
            "sources": {"a": {}},
            "active_voting_classes": ["x", "y"],
            "active_admitting_classes": ["x", "y"],
        }
    )
    assert "2 independent evidence classes that can publish a record" in html
    assert "further classes" not in html

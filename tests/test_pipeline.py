"""Tests for scoring, filtering, state and emission.

The scoring tests matter more than the implementation. The one bug that would
quietly invalidate the whole product is summing weights within an independence
class instead of taking the maximum: the feed would look highly corroborated
while actually being one source echoed several times.
"""

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xfeeds.allowlist import Allowlist, AllowlistError, build_allowlist
from xfeeds.emit import (
    append_history,
    build_manifest,
    emit_all,
    write_noncommercial_license,
    write_text_feed,
)
from xfeeds.filters import apply_filters
from xfeeds.models import (
    AllowlistSourceConfig,
    Band,
    DefaultsConfig,
    IndicatorRecord,
    Registry,
    ScoredIndicator,
    SourceConfig,
)
from xfeeds.score import (
    noncommercial_sources,
    open_sources,
    recency_factor,
    score_indicators,
)
from xfeeds.state import StateEntry, carried_observations, merge_with_state

NOW = datetime(2026, 8, 12, tzinfo=UTC)


def src(name: str, cls: str, weight: float = 0.8, **kw: object) -> SourceConfig:
    return SourceConfig(
        name=name,
        url=f"https://example.com/{name}",
        parser="plain_text",
        independence_class=cls,
        weight=weight,
        **kw,  # type: ignore[arg-type]
    )


def registry_of(*sources: SourceConfig) -> Registry:
    return Registry(
        version=1, defaults=DefaultsConfig(), sources=list(sources), allowlist_sources=[]
    )


def obs(source: str, cls: str, ip: str = "45.33.32.156", **kw: object) -> IndicatorRecord:
    kw.setdefault("categories", ["scanning"])
    return IndicatorRecord(
        ip_or_cidr=ipaddress.ip_address(ip),
        source=source,
        independence_class=cls,
        first_seen=NOW,
        last_seen=NOW,
        **kw,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------
# Independence weighting - the core invariant
# --------------------------------------------------------------------------


def test_second_source_in_same_class_does_not_raise_the_score() -> None:
    """THE critical test.

    Adding a mirror of a source we already ingest must change nothing. If this
    fails, corroboration is meaningless and the feed is untrustworthy.
    """
    reg_one = registry_of(src("a1", "alpha"))
    one = score_indicators([obs("a1", "alpha")], reg_one, NOW)[0]

    reg_two = registry_of(src("a1", "alpha"), src("a2", "alpha"))
    two = score_indicators([obs("a1", "alpha"), obs("a2", "alpha")], reg_two, NOW)[0]

    assert two.score == one.score
    assert two.independence_classes == one.independence_classes == ["alpha"]


def test_source_in_a_new_class_does_raise_the_score() -> None:
    reg_one = registry_of(src("a1", "alpha"))
    one = score_indicators([obs("a1", "alpha")], reg_one, NOW)[0]

    reg_two = registry_of(src("a1", "alpha"), src("b1", "beta"))
    two = score_indicators([obs("a1", "alpha"), obs("b1", "beta")], reg_two, NOW)[0]

    assert two.score > one.score
    assert len(two.independence_classes) == 2


def test_one_class_never_reaches_the_high_band_on_score_alone() -> None:
    """Even at maximum weight and severity, a lone class cannot be safe-to-block."""
    reg = registry_of(src("loud", "alpha", weight=1.0))
    record = score_indicators([obs("loud", "alpha", categories=["botnet-c2"])], reg, NOW)[0]
    assert record.band is Band.WITHHELD
    assert record.score < 90


def test_three_classes_reach_high() -> None:
    reg = registry_of(src("a", "alpha"), src("b", "beta"), src("c", "gamma"))
    record = score_indicators([obs("a", "alpha"), obs("b", "beta"), obs("c", "gamma")], reg, NOW)[0]
    assert record.band is Band.HIGH


def test_non_voting_source_contributes_no_class() -> None:
    reg = registry_of(src("a", "alpha"), src("meta", "META", weight=0.0, vote=False))
    record = score_indicators([obs("a", "alpha"), obs("meta", "META")], reg, NOW)[0]
    assert record.independence_classes == ["alpha"]


def test_ipsum_bonus_alone_cannot_change_the_band() -> None:
    """IPsum aggregates our own sources, so it corroborates but must not decide."""
    reg = registry_of(src("a", "alpha"), src("ipsum_levels", "META", weight=0.0, vote=False))
    plain = score_indicators([obs("a", "alpha")], reg, NOW)[0]
    with_ipsum = score_indicators(
        [obs("a", "alpha"), obs("ipsum_levels", "META", tags=["ipsum-level-8"])], reg, NOW
    )[0]
    assert with_ipsum.score > plain.score  # it does help
    assert with_ipsum.band is plain.band  # but never enough to promote


def test_spamhaus_is_promoted_on_its_own() -> None:
    reg = registry_of(src("spamhaus_drop_v4", "spamhaus", weight=1.0))
    record = score_indicators([obs("spamhaus_drop_v4", "spamhaus", ip="45.79.1.1")], reg, NOW)[0]
    assert record.band is Band.HIGH
    assert record.promoted_by == "spamhaus_drop_v4"


def test_tor_exit_is_capped_below_high_even_with_many_classes() -> None:
    reg = registry_of(
        src("a", "alpha"), src("b", "beta"), src("c", "gamma"), src("tor", "tor", vote=False)
    )
    record = score_indicators(
        [
            obs("a", "alpha"),
            obs("b", "beta"),
            obs("c", "gamma"),
            obs("tor", "tor", tags=["tor-exit"]),
        ],
        reg,
        NOW,
    )[0]
    assert record.band is not Band.HIGH


def test_recency_factor_floors_at_02_and_never_goes_negative() -> None:
    assert recency_factor(NOW, NOW, 14) == pytest.approx(1.0)
    assert recency_factor(NOW - timedelta(days=7), NOW, 14) == pytest.approx(0.5)
    assert recency_factor(NOW - timedelta(days=999), NOW, 14) == pytest.approx(0.2)


# --------------------------------------------------------------------------
# Safety filters
# --------------------------------------------------------------------------


def scored(ip: str, sources: list[str], band: Band = Band.HIGH, **kw: object) -> ScoredIndicator:
    return ScoredIndicator(
        ip_or_cidr=ipaddress.ip_network(ip, strict=False)
        if "/" in ip
        else ipaddress.ip_address(ip),
        score=95.0,
        band=band,
        independence_classes=["alpha", "beta", "gamma"],
        sources=sources,
        categories=["scanning"],
        first_seen=NOW,
        last_seen=NOW,
        **kw,  # type: ignore[arg-type]
    )


def test_wide_prefix_rejected_unless_from_spamhaus() -> None:
    reg = registry_of(src("other", "alpha"), src("spamhaus_drop_v4", "spamhaus", weight=1.0))
    empty = Allowlist([])

    # 224.0.0.0/3 is what FireHOL level1 carries: 537 million addresses of
    # multicast space. It must be rejected; which rule catches it first is an
    # implementation detail, so assert only that nothing survives.
    kept, stats = apply_filters([scored("224.0.0.0/3", ["other"])], reg, empty)
    assert kept == []
    assert stats.non_global + stats.too_wide == 1

    kept, stats = apply_filters([scored("45.0.0.0/8", ["other"])], reg, empty)
    assert kept == []
    assert stats.too_wide == 1

    # Spamhaus DROP publishes whole hijacked netblocks; that is the point of it.
    kept, _ = apply_filters([scored("45.0.0.0/8", ["spamhaus_drop_v4"])], reg, empty)
    assert len(kept) == 1


def test_allowlisted_address_is_removed() -> None:
    reg = registry_of(src("a", "alpha"))
    allowlist = Allowlist([ipaddress.ip_network("8.8.8.0/24")])
    kept, stats = apply_filters([scored("8.8.8.8", ["a"])], reg, allowlist)
    assert kept == []
    assert stats.allowlisted == 1


def test_allowlist_catches_a_supernet_containing_an_allowlisted_range() -> None:
    """Blocking a /16 because it contains 8.8.8.8 would take out the resolver."""
    allowlist = Allowlist([ipaddress.ip_network("8.8.8.8/32")])
    assert allowlist.contains(ipaddress.ip_network("8.8.0.0/16"))


def test_record_sourced_only_from_non_redistributable_is_never_published() -> None:
    """A licensing obligation, enforced in code rather than documentation."""
    reg = registry_of(src("paid", "alpha", redistribute=False), src("open", "beta"))
    kept, stats = apply_filters([scored("45.33.32.5", ["paid"])], reg, Allowlist([]))
    assert kept == []
    assert stats.not_redistributable == 1

    kept, _ = apply_filters([scored("45.33.32.5", ["paid", "open"])], reg, Allowlist([]))
    assert len(kept) == 1


def test_tag_only_source_alone_never_produces_a_block() -> None:
    reg = registry_of(src("tor", "tor", vote=False, tag_only=True))
    kept, stats = apply_filters([scored("45.33.32.6", ["tor"])], reg, Allowlist([]))
    assert kept == []
    assert stats.tag_only + stats.not_redistributable == 1


def test_build_allowlist_raises_rather_than_returning_a_partial_list() -> None:
    """Publishing from a partial allowlist is how a feed blocks Cloudflare."""
    with pytest.raises(AllowlistError):
        build_allowlist(
            [AllowlistSourceConfig(name="missing", parser="plain_text", path="/nope.txt")],
            DefaultsConfig(),
        )


# --------------------------------------------------------------------------
# State and ageing
# --------------------------------------------------------------------------


def test_first_seen_survives_a_state_round_trip() -> None:
    reg = registry_of(src("a", "alpha"))
    old = NOW - timedelta(days=100)
    previous = {
        "45.33.32.156": StateEntry(first_seen=old, last_seen=NOW, band=Band.HIGH, class_count=3)
    }
    result = merge_with_state([scored("45.33.32.156", ["a"])], previous, reg, NOW)
    assert result.records[0].first_seen == old
    assert result.added == []


def test_indicator_nobody_reports_ages_out_after_the_ttl() -> None:
    reg = registry_of(src("a", "alpha", ttl_days=14))
    previous = {
        "45.33.32.156": StateEntry(
            first_seen=NOW - timedelta(days=90),
            last_seen=NOW - timedelta(days=60),
            band=Band.HIGH,
            class_count=3,
        )
    }
    result = merge_with_state([], previous, reg, NOW)
    assert result.removed == ["45.33.32.156"]
    assert result.aged_out == 1


# --------------------------------------------------------------------------
# Emission
# --------------------------------------------------------------------------


def test_output_is_sorted_by_integer_not_string(tmp_path: Path) -> None:
    """9.9.9.9 must come before 10.0.0.1; sorted as strings it does not."""
    reg = registry_of(src("a", "alpha"))
    records = [scored("10.0.0.1", ["a"]), scored("9.9.9.9", ["a"])]
    path = tmp_path / "feed.txt"
    write_text_feed(path, "test", records, reg, NOW)
    body = [ln for ln in path.read_text().splitlines() if not ln.startswith("#")]
    assert body == ["9.9.9.9", "10.0.0.1"]


def test_two_runs_over_identical_input_are_byte_identical(tmp_path: Path) -> None:
    reg = registry_of(src("a", "alpha"))
    records = [scored("45.33.1.1", ["a"]), scored("45.79.2.2", ["a"])]
    manifest = build_manifest(reg, {}, records, [], [], NOW, {})
    emit_all(records, reg, manifest, NOW, feeds_dir=tmp_path / "one")
    emit_all(records, reg, manifest, NOW, feeds_dir=tmp_path / "two")
    for name in ("high-confidence.txt", "all.csv", "all.json", "stix-bundle.json"):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_feed_header_separates_redistributed_from_scoring_only(tmp_path: Path) -> None:
    """The header must never imply non-redistributable data is in the file."""
    reg = registry_of(src("open", "alpha"), src("closed", "beta", redistribute=False))
    path = tmp_path / "feed.txt"
    write_text_feed(path, "test", [scored("45.33.1.1", ["open", "closed"])], reg, NOW)
    text = path.read_text()
    assert "corroboration only" in text
    assert "NO data from them appears in this file" in text


def test_history_is_capped_so_it_cannot_grow_forever(tmp_path: Path) -> None:
    path = tmp_path / "history.json"
    for i in range(12):
        manifest = {
            "generated_at": f"2026-08-{i + 1:02d}T00:00:00+00:00",
            "counts": {"published": i, "high": i, "medium": 0},
            "deltas": {"added": 0, "removed": 0},
            "sources": {},
        }
        history = append_history(path, manifest, limit=5)
    assert len(history) == 5
    assert json.loads(path.read_text())[-1]["published"] == 11


def test_compromised_host_is_not_promoted_by_abusech_alone() -> None:
    """A hacked legitimate server needs corroboration before we block it.

    ThreatFox flags these with is_compromised. They are victims hosting C2, not
    purpose-built attacker infrastructure, so blocking one can take out a real
    business. It still votes; it just cannot reach high confidence unaided.
    """
    reg = registry_of(src("threatfox", "abusech", weight=1.0))
    clean = score_indicators([obs("threatfox", "abusech", categories=["botnet-c2"])], reg, NOW)[0]
    assert clean.band is Band.HIGH
    assert clean.promoted_by == "threatfox"

    compromised = score_indicators(
        [obs("threatfox", "abusech", categories=["botnet-c2"], tags=["compromised-host"])],
        reg,
        NOW,
    )[0]
    assert compromised.band is not Band.HIGH
    assert compromised.promoted_by is None


def test_allowlist_falls_back_to_cache_when_a_provider_fails() -> None:
    """A transient provider outage must not abort the run if we have a cached copy.

    An out-of-date list of Cloudflare ranges still protects those ranges.
    Aborting every run because one provider returned a 403 is the worse outcome.
    """
    from xfeeds.collectors.base import _failure_or_stale
    from xfeeds.models import SourceConfig

    cfg = SourceConfig(
        name="al",
        url="https://example.com",
        parser="plain_text",
        independence_class="allowlist",
        weight=0.0,
        vote=False,
        allow_stale_fallback=True,
    )
    result = _failure_or_stale(cfg, b"1.2.3.0/24", {"last_fetch_time": 0}, "HTTP 403", 403)
    assert result.success is True
    assert result.stale_fallback is True
    assert result.content == b"1.2.3.0/24"


def test_threat_feeds_never_silently_fall_back_to_stale_data() -> None:
    """Only the allowlist opts in. A stale threat feed must surface as a failure."""
    from xfeeds.collectors.base import _failure_or_stale
    from xfeeds.models import SourceConfig

    cfg = SourceConfig(
        name="feed",
        url="https://example.com",
        parser="plain_text",
        independence_class="alpha",
        weight=0.8,
    )
    assert cfg.allow_stale_fallback is False
    result = _failure_or_stale(cfg, b"1.2.3.4", {"last_fetch_time": 0}, "HTTP 500", 500)
    assert result.success is False


# --------------------------------------------------------------------------
# Restricted (non-redistributable) corroboration: ADR-035
# --------------------------------------------------------------------------


def _restricted_source(name: str, cls: str, weight: float, redistribute: bool) -> SourceConfig:
    return SourceConfig(
        name=name,
        url="https://example.invalid/x",
        parser="plain_text",
        independence_class=cls,
        weight=weight,
        ttl_days=10,
        redistribute=redistribute,
    )


def _registry_with_restricted() -> Registry:
    """Two redistributable classes plus one we may consume but not republish."""
    return Registry(
        version=1,
        defaults=DefaultsConfig(),
        sources=[
            _restricted_source("open_a", "a", 0.8, True),
            _restricted_source("open_b", "b", 0.8, True),
            _restricted_source("open_c", "c", 0.8, True),
            _restricted_source("restricted", "restricted", 0.7, False),
        ],
        allowlist_sources=[],
    )


def _obs(source: str, cls: str, when: datetime, ip: str = "203.0.113.7") -> IndicatorRecord:
    return IndicatorRecord(
        ip_or_cidr=ipaddress.ip_address(ip),
        source=source,
        independence_class=cls,
        first_seen=when,
        last_seen=when,
        categories=["scanning"],
    )


def test_restricted_source_cannot_admit_a_withheld_record() -> None:
    """One open class plus one restricted class must stay withheld.

    This is the load-bearing licensing guarantee. If a restricted vote could lift a
    record into the feed, our decision to publish would have been caused by a list
    we are not allowed to republish.
    """
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()
    scored = score_indicators(
        [_obs("open_a", "a", now), _obs("restricted", "restricted", now)], registry, now
    )
    assert len(scored) == 1
    assert scored[0].band is Band.WITHHELD


def test_restricted_source_can_upgrade_medium_to_high() -> None:
    """Two open classes plus a restricted one reaches the safe-to-block tier."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()
    without = score_indicators([_obs("open_a", "a", now), _obs("open_b", "b", now)], registry, now)
    assert without[0].band is Band.MEDIUM

    with_restricted = score_indicators(
        [
            _obs("open_a", "a", now),
            _obs("open_b", "b", now),
            _obs("restricted", "restricted", now),
        ],
        registry,
        now,
    )
    assert with_restricted[0].band is Band.HIGH


def test_restricted_source_name_is_never_published() -> None:
    """The feed must not disclose membership of a list we cannot republish."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()
    scored = score_indicators(
        [
            _obs("open_a", "a", now),
            _obs("open_b", "b", now),
            _obs("restricted", "restricted", now),
        ],
        registry,
        now,
    )
    record = scored[0]
    assert "restricted" not in record.sources
    assert "restricted" not in record.independence_classes
    assert record.restricted_corroboration == 1


# --------------------------------------------------------------------------
# Carrying a vote through a source outage: ADR-037
# --------------------------------------------------------------------------


def test_carried_vote_decays_but_holds_the_band() -> None:
    """A source that misses a run keeps voting at a reduced weight."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()
    fresh = [_obs("open_a", "a", now), _obs("open_b", "b", now)]

    three_days_ago = now - timedelta(days=3)
    carried = _obs("open_c", "c", three_days_ago)
    carried.carried = True

    both = score_indicators([*fresh, carried], registry, now)
    assert both[0].band is Band.HIGH, "three classes, one of them carried"

    only_fresh = score_indicators(fresh, registry, now)
    assert only_fresh[0].band is Band.MEDIUM
    assert both[0].score > only_fresh[0].score

    current = _obs("open_c", "c", now)
    fully_current = score_indicators([*fresh, current], registry, now)
    assert fully_current[0].score > both[0].score, "a carried vote must be worth less"


def test_carried_observation_cannot_promote() -> None:
    """Promotion asserts a source vouches for an address now, not two weeks ago."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = Registry(
        version=1,
        defaults=DefaultsConfig(),
        sources=[
            SourceConfig(
                name="spamhaus_drop_v4",
                url="https://example.invalid/x",
                parser="plain_text",
                independence_class="spamhaus",
                weight=1.0,
                ttl_days=30,
            )
        ],
        allowlist_sources=[],
    )
    current = _obs("spamhaus_drop_v4", "spamhaus", now)
    assert score_indicators([current], registry, now)[0].band is Band.HIGH

    stale = _obs("spamhaus_drop_v4", "spamhaus", now - timedelta(days=5))
    stale.carried = True
    result = score_indicators([stale], registry, now)[0]
    assert result.promoted_by is None
    assert result.band is Band.WITHHELD


def test_carried_observations_never_resurrect_a_dead_indicator() -> None:
    """No source reporting an address this run means nothing is carried for it."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()
    previous = {
        "203.0.113.7": StateEntry(
            first_seen=now - timedelta(days=20),
            last_seen=now - timedelta(days=2),
            band=Band.MEDIUM,
            class_count=2,
            sightings={"open_a": now - timedelta(days=2), "open_b": now - timedelta(days=2)},
        )
    }
    assert carried_observations([], previous, registry, now) == []

    still_reported = [_obs("open_a", "a", now)]
    carried = carried_observations(still_reported, previous, registry, now)
    assert [c.source for c in carried] == ["open_b"], "only the absent source is carried"
    assert all(c.carried for c in carried)


def test_carried_votes_expire_at_the_source_ttl() -> None:
    """Beyond ttl_days a sighting stops counting entirely."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _registry_with_restricted()  # ttl_days=10 throughout
    previous = {
        "203.0.113.7": StateEntry(
            first_seen=now - timedelta(days=60),
            last_seen=now - timedelta(days=40),
            band=Band.MEDIUM,
            class_count=2,
            sightings={"open_b": now - timedelta(days=40)},
        )
    }
    carried = carried_observations([_obs("open_a", "a", now)], previous, registry, now)
    assert carried == [], "a 40-day-old sighting is past a 10-day TTL"


# --------------------------------------------------------------------------
# Two-tier publication: ADR-041
# --------------------------------------------------------------------------


def _tiered_registry() -> Registry:
    """One open source, one NC-only source, one ShareAlike source."""
    return Registry(
        version=1,
        defaults=DefaultsConfig(),
        sources=[
            _restricted_source("open_a", "a", 0.8, True),
            _restricted_source("open_b", "b", 0.8, True),
            SourceConfig(
                name="nc_only",
                url="https://example.invalid/x",
                parser="plain_text",
                independence_class="nc",
                weight=0.7,
                ttl_days=10,
                redistribute=False,
                redistribute_noncommercial=True,
            ),
            SourceConfig(
                name="sharealike",
                url="https://example.invalid/x",
                parser="plain_text",
                independence_class="sa",
                weight=0.8,
                ttl_days=10,
                redistribute=True,
                noncommercial_compatible=False,
            ),
        ],
        allowlist_sources=[],
    )


def test_tier_membership_is_computed_from_licences() -> None:
    registry = _tiered_registry()
    assert open_sources(registry) == {"open_a", "open_b", "sharealike"}
    # nc_only joins; sharealike drops out because CC BY-SA forbids adding the
    # NonCommercial term to an adaptation.
    assert noncommercial_sources(registry) == {"open_a", "open_b", "nc_only"}


def test_noncommercial_tier_publishes_what_the_primary_feed_cannot() -> None:
    """One open source plus one NC source: withheld in primary, medium in the NC tier."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _tiered_registry()
    observations = [_obs("open_a", "a", now), _obs("nc_only", "nc", now)]

    primary = score_indicators(observations, registry, now, redistributable=open_sources(registry))
    assert primary[0].band is Band.WITHHELD
    assert "nc_only" not in primary[0].sources

    nc = score_indicators(
        observations, registry, now, redistributable=noncommercial_sources(registry)
    )
    assert nc[0].band is Band.MEDIUM
    assert "nc_only" in nc[0].sources, "the NC tier may name and publish it"


def test_sharealike_source_is_absent_from_the_noncommercial_tier() -> None:
    """A CC BY-SA source must not leak into a CC BY-NC-SA output."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _tiered_registry()
    observations = [
        _obs("open_a", "a", now),
        _obs("sharealike", "sa", now),
        _obs("nc_only", "nc", now),
    ]
    nc = score_indicators(
        observations, registry, now, redistributable=noncommercial_sources(registry)
    )
    assert "sharealike" not in nc[0].sources
    assert "sa" not in nc[0].independence_classes


def test_noncommercial_files_carry_the_licence_banner(tmp_path: Path) -> None:
    """Nobody reads a licence they are not shown. The banner is in every file."""
    now = datetime(2026, 8, 12, tzinfo=UTC)
    registry = _tiered_registry()
    record = ScoredIndicator(
        ip_or_cidr=ipaddress.ip_address("45.66.230.9"),
        score=75.0,
        band=Band.MEDIUM,
        independence_classes=["a", "nc"],
        sources=["open_a", "nc_only"],
        categories=["scanning"],
        first_seen=now,
        last_seen=now,
    )
    path = tmp_path / "high-confidence.txt"
    write_text_feed(
        path,
        "high confidence (non-commercial tier)",
        [record],
        registry,
        now,
        tier="noncommercial",
        redistributable=noncommercial_sources(registry),
    )
    text = path.read_text()
    assert "NON-COMMERCIAL USE ONLY" in text
    assert "CC BY-NC-SA 4.0" in text
    assert "use the primary feed one directory up" in text

    write_noncommercial_license(tmp_path / "LICENSE.txt", registry, {"open_a", "nc_only"})
    licence = (tmp_path / "LICENSE.txt").read_text()
    assert "nc_only" in licence
    assert "may not" in licence.lower()
    assert "open_a" not in licence, "only restricted sources need calling out here"

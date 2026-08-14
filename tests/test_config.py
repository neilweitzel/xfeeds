from pathlib import Path

import pytest
from pydantic import ValidationError

from xfeeds.config import get_active_voting_classes, load_registry


def test_load_real_sources_yaml() -> None:
    """Load the real sources.yaml and verify its content."""
    yaml_path = Path("sources.yaml")
    registry = load_registry(yaml_path)

    active_classes = get_active_voting_classes(registry)

    # Voting classes active on a fresh clone. Several vote while being
    # redistribute:false, so they can upgrade a band and never admit a record -
    # see test_pipeline. abuseipdb joined when its key landed; dshield and
    # dataplane joined in ADR-048 after the licence re-read.
    assert len(active_classes) == 13
    for expected in ("abuseipdb", "dshield", "dataplane"):
        assert expected in active_classes

    abuseipdb = next((s for s in registry.sources if s.name == "abuseipdb_blacklist"), None)
    threatfox = next((s for s in registry.sources if s.name == "threatfox"), None)

    assert abuseipdb is not None, "abuseipdb_blacklist source missing from sources.yaml"
    assert abuseipdb.enabled is True

    assert threatfox is not None, "threatfox source missing from sources.yaml"
    assert threatfox.enabled is True


def test_keyed_sources_declare_their_secret_and_never_inline_it() -> None:
    """Keyed sources must read the key from the environment, per AGENTS.md rule 6.

    Enabling a keyed source is the moment a hard-coded key is most likely to get
    committed, so this asserts the config still names an env var and that the name
    does not look like a value.
    """
    registry = load_registry(Path("sources.yaml"))

    keyed = [s for s in registry.sources if s.auth == "header"]
    assert keyed, "expected at least one header-authenticated source"

    for source in keyed:
        assert source.auth_header, f"{source.name} sets auth: header without auth_header"
        assert source.auth_secret, f"{source.name} sets auth: header without auth_secret"
        # Env var names are SHOUT_CASE; an actual key would not be.
        assert source.auth_secret == source.auth_secret.upper(), (
            f"{source.name} auth_secret does not look like an env var name"
        )
        assert len(source.auth_secret) < 64, (
            f"{source.name} auth_secret looks like an inlined secret, not a variable name"
        )


def test_abuseipdb_is_rate_limited_and_cached() -> None:
    """The free tier allows five blacklist calls a day; the config must respect it.

    The 6-hour cron gives four scheduled runs plus room for a manual dispatch, but
    only because min_interval_seconds and the response cache keep a re-run from
    spending another call. Both are load-bearing, so both are asserted.
    """
    registry = load_registry(Path("sources.yaml"))
    source = next(s for s in registry.sources if s.name == "abuseipdb_blacklist")

    assert source.min_interval_seconds is not None
    assert source.min_interval_seconds >= 21600, "6h floor keeps us inside 5 calls/day"
    assert source.cache_response is True
    assert source.auth_secret == "ABUSEIPDB_API_KEY"
    assert source.auth_header == "Key"

    # ADR-012: strong signal, not republishable.
    assert source.redistribute is False
    assert source.params is not None
    assert source.params.get("confidenceMinimum") == 100


def test_dshield_is_noncommercial_tier_only() -> None:
    """CC BY-NC-SA permits redistribution but forbids commercial use.

    So DShield may be republished in the non-commercial tier and must never reach
    the primary feed, which commercial consumers download. ADR-048.
    """
    registry = load_registry(Path("sources.yaml"))
    source = next(s for s in registry.sources if s.name == "dshield_block")

    assert source.enabled is True
    assert source.redistribute is False, "the primary feed is consumed commercially"
    assert source.redistribute_noncommercial is True
    assert source.noncommercial_compatible is True
    assert source.attribution_required is True
    assert source.credit is not None and "DShield" in source.credit
    # It publishes /24 blocks, so one vote covers 256 hosts. Keep the weight low.
    assert source.weight <= 0.5


def test_no_source_is_flagged_for_a_tier_its_licence_forbids() -> None:
    """Guard the two flag combinations that would be a licensing violation.

    Both are easy to introduce by copying an adjacent YAML block, and neither is
    caught by any other test: a source cannot be simultaneously restricted from
    the primary feed for a NonCommercial reason and marked compatible with a tier
    it is not allowed in, and redistribute_noncommercial is meaningless - and
    dangerously misleading - when redistribute is already true.
    """
    registry = load_registry(Path("sources.yaml"))

    for source in registry.sources:
        if source.redistribute:
            assert not source.redistribute_noncommercial, (
                f"{source.name}: redistribute_noncommercial is ignored when "
                "redistribute is true; drop it rather than implying a restriction"
            )
        if source.redistribute_noncommercial:
            assert source.noncommercial_compatible, (
                f"{source.name}: flagged for the non-commercial tier while also "
                "marked incompatible with it"
            )


def test_duplicate_source_name() -> None:
    with pytest.raises(ValidationError, match="Duplicate source name found: dup"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "dup",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 1.0,
                    },
                    {
                        "name": "dup",
                        "url": "b",
                        "parser": "plain_text",
                        "independence_class": "b",
                        "weight": 1.0,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_invalid_weight() -> None:
    with pytest.raises(ValidationError, match="Weight must be between 0.0 and 1.0"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 1.5,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_invalid_parser() -> None:
    with pytest.raises(ValidationError, match="Unknown parser"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "magic_parser",
                        "independence_class": "a",
                        "weight": 1.0,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_voting_source_weight_zero() -> None:
    with pytest.raises(ValidationError, match="voting source but has weight 0.0"):
        from xfeeds.models import Registry

        Registry.model_validate(
            {
                "version": 1,
                "defaults": {},
                "sources": [
                    {
                        "name": "valid1",
                        "url": "a",
                        "parser": "plain_text",
                        "independence_class": "a",
                        "weight": 0.0,
                        "vote": True,
                    },
                ],
                "allowlist_sources": [],
            }
        )


def test_xfeeds_validate_from_other_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure `xfeeds validate` works when run from a different directory."""
    monkeypatch.chdir(tmp_path)
    from typer.testing import CliRunner

    from xfeeds.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 0
    assert "Successfully loaded" in result.stdout
    assert "Active voting classes: 13" in result.stdout


def test_multi_report_sources_are_class_pinned_to_one_vote() -> None:
    """Several files from ONE operator must never become several independent votes.

    This is the failure mode independence classes exist to prevent, and it is now
    easy to introduce by accident: DataPlane publishes 17 IP-bearing reports and
    Blocklist.de publishes several lists, so a copied YAML block with a fresh
    independence_class would manufacture corroboration out of a single operator's
    telemetry. Asserted per operator rather than generically, because the mapping
    from URL host to correct class is a judgement this test needs to encode.
    """
    registry = load_registry(Path("sources.yaml"))
    by_name = {s.name: s for s in registry.sources}

    dataplane = [s for s in registry.sources if s.url.startswith("https://dataplane.org/")]
    assert len(dataplane) >= 2, "expected several DataPlane reports"
    assert {s.independence_class for s in dataplane} == {"dataplane"}

    blocklist_de = [s for s in registry.sources if "blocklist.de" in s.url]
    assert len(blocklist_de) >= 2, "expected several Blocklist.de lists"
    assert {s.independence_class for s in blocklist_de} == {"blocklist_de"}

    # And every DataPlane report carries the same scoring-only posture, since they
    # share one licence header that prohibits redistribution outright.
    for source in dataplane:
        assert source.redistribute is False, f"{source.name} would be republished"
        assert source.noncommercial_compatible is False, f"{source.name} reaches the NC tier"
    assert by_name["dataplane_sshpwauth"].enabled is True


def test_stopforumspam_is_scoring_only_in_both_tiers() -> None:
    """Their No-Derivative-Works clause forbids building upon the data at all.

    The same page also grants "To Share - to copy, distribute and transmit", so the
    licence contradicts itself; AGENTS.md says bias toward publishing less, so this
    must stay out of BOTH published tiers. ADR-050.
    """
    registry = load_registry(Path("sources.yaml"))
    source = next(s for s in registry.sources if s.independence_class == "stopforumspam")

    assert source.enabled is True
    assert source.vote is True
    assert source.redistribute is False
    assert source.redistribute_noncommercial is False
    assert source.noncommercial_compatible is False
    # 2 downloads per IP per day is a published cap; 4 runs a day must not exceed it.
    assert source.min_interval_seconds is not None
    assert source.min_interval_seconds >= 43200


def test_ipthreat_uses_the_full_corpus_with_an_explicit_floor() -> None:
    """threat-N.txt is a minimum SCORE, not a day window.

    Fetching a pre-filtered URL hid the threshold in a filename. The floor must be
    a reviewable number, and the URL must be the widest file so the floor can move
    without changing the endpoint.
    """
    registry = load_registry(Path("sources.yaml"))
    source = next(s for s in registry.sources if s.independence_class == "ipthreat")

    assert source.url.endswith("threat-0.txt"), "must fetch the full corpus"
    assert source.min_score is not None, "the floor must be explicit, not implied by the URL"
    # Below 15 the feed leaves the 2,000-4,000 high-confidence range ADR-015 committed
    # to. Lowering it is a deliberate policy change that needs its own measurement.
    assert source.min_score >= 15


def test_every_clean_tier_source_can_actually_name_its_licence() -> None:
    """The clean tier's entire promise is that each contributor has a NAMED licence.

    This is the guard that keeps the promise honest. The first draft of the tier
    shipped with Tor in it, inferring CC0 from metrics.torproject.org while the
    source's own licence field still read "No licence stated on the endpoint", and
    with et_compromised carrying no licence fields at all so the generated
    LICENSE.txt rendered "Licence: n.a." to the reader. Both were caught only by
    looking at the output. A tier that claims every source has a grant must not
    contain a source whose own metadata says otherwise.
    """
    registry = load_registry(Path("sources.yaml"))
    granted = [s for s in registry.sources if s.explicit_grant]
    assert granted, "expected at least one source with an explicit licence grant"

    forbidden = ("no licence", "no license", "n.a.", "unclear", "not stated", "see terms")
    for source in granted:
        assert source.license, f"{source.name}: explicit_grant with no licence name"
        assert source.license_url, f"{source.name}: explicit_grant with no licence URL"
        lowered = source.license.lower()
        for phrase in forbidden:
            assert phrase not in lowered, (
                f"{source.name}: explicit_grant but its licence reads {source.license!r}, "
                f"which contains {phrase!r}. Absence of a prohibition is not a grant."
            )


def test_clean_tier_is_a_strict_subset_of_the_primary_feed() -> None:
    """A source we may not republish at all cannot appear in a MORE permissive tier.

    Guards the ordering invariant between the three tiers, which is easy to break
    by setting explicit_grant on a scoring-only source.
    """
    from xfeeds.score import noncommercial_sources, open_sources, permissive_sources

    registry = load_registry(Path("sources.yaml"))
    clean = permissive_sources(registry)
    primary = open_sources(registry)
    noncommercial = noncommercial_sources(registry)

    assert clean, "the clean tier must not be empty"
    assert clean <= primary, f"clean tier escapes the primary feed: {sorted(clean - primary)}"
    assert primary <= noncommercial, "the NC tier must contain everything the primary does"


def test_clean_tier_excludes_re_aggregators() -> None:
    """A permissive licence over a re-publication does not launder what it contains.

    IPsum is public domain via the Unlicense and duggytuxy is GPLv3, and both are
    built from upstream lists whose own terms are restrictive. Including either
    would defeat the point of the tier while looking perfectly correct.
    """
    from xfeeds.score import permissive_sources

    registry = load_registry(Path("sources.yaml"))
    clean = permissive_sources(registry)

    aggregators = {s.name for s in registry.sources if s.independence_class == "META_aggregate"}
    assert aggregators, "expected the aggregate sources to still be configured"
    assert not (clean & aggregators), (
        f"re-aggregators in the clean tier: {sorted(clean & aggregators)}"
    )

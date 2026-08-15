"""Independence-weighted confidence scoring.

This is the core of the product and the easiest thing to get subtly wrong.

Most public IP blocklists are not independent of each other. Measured overlaps
show IPsum contains 35% of Blocklist.de and 64% of Binary Defense; Emerging
Threats' compromised-ips list is 95% identical to bruteforceblocker. If you count
each file as a separate vote, one source echoed five times looks like unanimous
agreement across five sources.

So confidence is a function of distinct *independence classes*, never of distinct
files. Within a class we take the maximum contribution, never the sum. Adding a
mirror of a source we already ingest must not change any score.
"""

import math
from collections import defaultdict
from datetime import datetime

import structlog

from xfeeds.models import Band, IndicatorRecord, IPOrNet, Registry, ScoredIndicator

logger = structlog.get_logger(__name__)

HIGH_CONFIDENCE_CLASSES = 3
"""Distinct independence classes required for the safe-to-block tier."""

MEDIUM_CONFIDENCE_CLASSES = 2
"""Distinct classes required to publish at all.

Counted over *redistributable* classes only. See ``_band`` for why.
"""

HIGH_SCORE_FLOOR = 90.0
"""Score a promoted record receives, and the cap applied to tagged records."""

IPSUM_PRIOR_LEVEL = 5
"""IPsum level at or above which a bounded bonus applies (ADR-011)."""

IPSUM_PRIOR_BONUS = 0.15
"""Deliberately small. IPsum aggregates our own sources, so it corroborates but
must never be able to move a record between bands on its own."""

CATEGORY_SEVERITY = {
    "botnet-c2": 1.0,
    "malware-infrastructure": 1.0,
    "hijacked-netblock": 1.0,
    "criminal-hosting": 1.0,
    "malicious-tls": 0.9,
    "web-attack": 0.8,
    "brute-force": 0.7,
    "ssh-attack": 0.7,
    "scanning": 0.6,
    "reported-abuse": 0.7,
    "spam-source": 0.5,
    "abuse": 0.5,
}
DEFAULT_SEVERITY = 0.6


def _severity(categories: list[str]) -> float:
    """Highest severity among a source's categories."""
    if not categories:
        return DEFAULT_SEVERITY
    return max(CATEGORY_SEVERITY.get(c, DEFAULT_SEVERITY) for c in categories)


def recency_factor(last_seen: datetime, now: datetime, ttl_days: int) -> float:
    """Linear decay from 1.0 to a floor of 0.2 over the source's TTL.

    Floored rather than zeroed because an address seen three weeks ago is still
    evidence, just weaker. Aging out entirely is handled by state.py.

    This only does useful work on carried observations. Everything collected in
    the current run has ``last_seen == now`` and so scores at 1.0.
    """
    if ttl_days <= 0:
        return 1.0
    age_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
    return max(0.2, 1.0 - (age_days / ttl_days))


def _band(open_classes: int, restricted_classes: int) -> Band:
    """Assign a band, letting restricted sources upgrade but never admit.

    ``open_classes`` counts classes we are licensed to republish; the rest are
    sources such as the Turris greylist (CC BY-NC-SA) that we may consume but not
    redistribute.

    A restricted class can raise medium to high. It can never turn a lone sighting
    into a published record. That asymmetry is the whole point: if one restricted
    vote could lift a record from withheld to medium, then our decision to publish
    that address would have been *caused* by a list we are not allowed to
    republish, and the published feed would leak its membership one address at a
    time. Restricting them to upgrades keeps the question they answer to "how
    confident are we?" rather than "is this address on the list?".

    Cheap in practice as well as principled: measured against the live feed, 477
    of 1,837 medium records would be corroborated by Turris, and those are exactly
    the medium-to-high upgrades this permits.
    """
    if open_classes >= HIGH_CONFIDENCE_CLASSES:
        return Band.HIGH
    if open_classes >= MEDIUM_CONFIDENCE_CLASSES:
        total = open_classes + restricted_classes
        return Band.HIGH if total >= HIGH_CONFIDENCE_CLASSES else Band.MEDIUM
    return Band.WITHHELD


def open_sources(registry: Registry) -> set[str]:
    """Sources publishable in the primary feed."""
    return {s.name for s in registry.sources if s.redistribute}


def noncommercial_sources(registry: Registry) -> set[str]:
    """Sources publishable in the non-commercial tier.

    Everything in the primary feed, plus sources whose licence permits
    redistribution but forbids commercial use, minus anything under a plain
    ShareAlike licence that cannot legally accept the extra NonCommercial term.
    """
    return {
        s.name
        for s in registry.sources
        if (s.redistribute or s.redistribute_noncommercial) and s.noncommercial_compatible
    }


def permissive_sources(registry: Registry) -> set[str]:
    """Sources for the clean-provenance tier.

    Requires BOTH that we may redistribute it AND that the publisher issued a
    written licence affirmatively permitting redistribution. The second condition
    is what the tier sells: a practitioner can hand the file to their own legal
    review with a named licence per contributing source, instead of a list of
    publishers who merely never objected.

    Deliberately much smaller than the primary feed. That is the product, not a
    defect - see ADR-051.
    """
    return {s.name for s in registry.sources if s.redistribute and s.explicit_grant}


def score_indicators(
    records: list[IndicatorRecord],
    registry: Registry,
    now: datetime,
    redistributable: set[str] | None = None,
) -> list[ScoredIndicator]:
    """Collapse per-source observations into one scored record per indicator.

    ``redistributable`` names the sources publishable in the tier being built; it
    decides which classes count toward the publication threshold and which are
    merely corroboration. Defaults to the primary feed.
    """
    if redistributable is None:
        redistributable = open_sources(registry)
    by_source = {s.name: s for s in registry.sources}

    grouped: dict[IPOrNet, list[IndicatorRecord]] = defaultdict(list)
    for record in records:
        grouped[record.ip_or_cidr].append(record)

    scored: list[ScoredIndicator] = []
    for indicator, observations in grouped.items():
        # Best contribution per class - NOT the sum. This single line is what
        # makes corroboration meaningful; see the module docstring.
        best_per_class: dict[str, float] = {}
        open_classes: set[str] = set()
        restricted_classes: set[str] = set()
        categories: set[str] = set()
        tags: set[str] = set()
        sources: set[str] = set()
        # Dates are taken from redistributable observations where we have any, so
        # that a published record's timeline does not disclose when a restricted
        # source saw the address. Falls back to all observations for withheld
        # records, which are never emitted but do drive state accounting.
        datable = [o for o in observations if o.source in redistributable] or observations
        first_seen = min(o.first_seen for o in datable)
        last_seen = max(o.last_seen for o in datable)
        ipsum_level = 0
        promoted_by: str | None = None
        # (source name, value) pairs, resolved after the loop by sorting on the
        # source name. Taking the first observation to arrive would make the
        # output depend on collector ordering and break byte-identical reruns.
        reference_candidates: list[tuple[str, str]] = []
        registry_candidates: list[tuple[str, str]] = []

        for observation in observations:
            config = by_source.get(observation.source)
            if config is None:  # pragma: no cover - defensive
                continue
            # Names of sources we may not republish are withheld from the output;
            # see ScoredIndicator.restricted_corroboration.
            publishable_source = observation.source in redistributable
            if publishable_source:
                sources.add(observation.source)
                categories.update(observation.categories)
                tags.update(observation.tags)
                # A citation may only come from a source we are allowed to name.
                # Publishing a reference from a restricted source would disclose
                # its membership exactly as listing it in `sources` would.
                if observation.source_reference:
                    reference_candidates.append((observation.source, observation.source_reference))
                if observation.source_registry:
                    registry_candidates.append((observation.source, observation.source_registry))

            for tag in observation.tags:
                if tag.startswith("ipsum-level-"):
                    with_suffix = tag.rsplit("-", 1)[-1]
                    if with_suffix.isdigit():
                        ipsum_level = max(ipsum_level, int(with_suffix))

            if not config.vote:
                continue

            contribution = (
                config.weight
                * recency_factor(observation.last_seen, now, config.ttl_days)
                * _severity(observation.categories)
            )
            class_name = config.independence_class
            best_per_class[class_name] = max(best_per_class.get(class_name, 0.0), contribution)
            if publishable_source:
                open_classes.add(class_name)
            else:
                restricted_classes.add(class_name)

            # Precision-based promotions. Justified by the source's own accuracy
            # rather than by agreement: Spamhaus DROP lists hijacked netblocks,
            # and an active abuse.ch C2 listing is a live command-and-control
            # server. Neither needs a second opinion.
            # A ThreatFox "compromised" host is a legitimate server somebody
            # hacked and is now using as C2. Blocking it may block a real
            # business, so it votes normally but must not reach the
            # safe-to-block tier on abuse.ch's word alone - it needs
            # corroboration like anything else.
            # A carried observation cannot promote. Promotion is an assertion that
            # this source's word alone is enough, which requires it to be saying so
            # in the current run rather than up to 30 days ago.
            is_compromised = "compromised-host" in observation.tags
            promotes = (
                not observation.carried
                and config.redistribute
                and (
                    observation.source in {"spamhaus_drop_v4", "spamhaus_drop_v6"}
                    or (config.independence_class == "abusech" and not is_compromised)
                )
            )
            if promotes:
                promoted_by = observation.source

        source_reference = min(reference_candidates)[1] if reference_candidates else None
        source_registry = min(registry_candidates)[1] if registry_candidates else None

        raw = sum(best_per_class.values())
        if ipsum_level >= IPSUM_PRIOR_LEVEL:
            raw += IPSUM_PRIOR_BONUS

        # Saturating transform: no single class can approach the high band alone,
        # because exp(-w) for any w <= 1.0 leaves score well below 90.
        score = 100.0 * (1.0 - math.exp(-raw))

        # Restricted classes are excluded from the count that admits a record and
        # may only upgrade one that already qualifies.
        restricted_only = restricted_classes - open_classes
        if promoted_by:
            score = max(score, HIGH_SCORE_FLOOR)
            band = Band.HIGH
        else:
            band = _band(len(open_classes), len(restricted_only))

        # Tor exits are capped below the high band no matter how many classes saw
        # them. Exit nodes carry other people's traffic, so an attack from one is
        # not evidence about the node itself.
        if "tor-exit" in tags and band is Band.HIGH:
            band = Band.MEDIUM
            score = min(score, HIGH_SCORE_FLOOR - 0.1)

        scored.append(
            ScoredIndicator(
                ip_or_cidr=indicator,
                score=round(score, 2),
                band=band,
                independence_classes=sorted(open_classes),
                sources=sorted(sources),
                restricted_corroboration=len(restricted_only),
                categories=sorted(categories),
                tags=sorted(tags),
                first_seen=first_seen,
                last_seen=last_seen,
                promoted_by=promoted_by,
                source_reference=source_reference,
                source_registry=source_registry,
            )
        )

    logger.info(
        "scoring_complete",
        indicators=len(scored),
        high=sum(1 for s in scored if s.band is Band.HIGH),
        medium=sum(1 for s in scored if s.band is Band.MEDIUM),
        withheld=sum(1 for s in scored if s.band is Band.WITHHELD),
    )
    return scored

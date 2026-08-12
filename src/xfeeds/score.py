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
"""Distinct classes required to publish at all."""

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
    """
    if ttl_days <= 0:
        return 1.0
    age_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
    return max(0.2, 1.0 - (age_days / ttl_days))


def score_indicators(
    records: list[IndicatorRecord],
    registry: Registry,
    now: datetime,
) -> list[ScoredIndicator]:
    """Collapse per-source observations into one scored record per indicator."""
    by_source = {s.name: s for s in registry.sources}

    grouped: dict[IPOrNet, list[IndicatorRecord]] = defaultdict(list)
    for record in records:
        grouped[record.ip_or_cidr].append(record)

    scored: list[ScoredIndicator] = []
    for indicator, observations in grouped.items():
        # Best contribution per class - NOT the sum. This single line is what
        # makes corroboration meaningful; see the module docstring.
        best_per_class: dict[str, float] = {}
        categories: set[str] = set()
        tags: set[str] = set()
        sources: set[str] = set()
        first_seen = min(o.first_seen for o in observations)
        last_seen = max(o.last_seen for o in observations)
        ipsum_level = 0
        promoted_by: str | None = None

        for observation in observations:
            config = by_source.get(observation.source)
            if config is None:  # pragma: no cover - defensive
                continue
            sources.add(observation.source)
            categories.update(observation.categories)
            tags.update(observation.tags)

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

            # Precision-based promotions. Justified by the source's own accuracy
            # rather than by agreement: Spamhaus DROP lists hijacked netblocks,
            # and an active abuse.ch C2 listing is a live command-and-control
            # server. Neither needs a second opinion.
            # A ThreatFox "compromised" host is a legitimate server somebody
            # hacked and is now using as C2. Blocking it may block a real
            # business, so it votes normally but must not reach the
            # safe-to-block tier on abuse.ch's word alone - it needs
            # corroboration like anything else.
            is_compromised = "compromised-host" in observation.tags
            promotes = observation.source in {"spamhaus_drop_v4", "spamhaus_drop_v6"} or (
                config.independence_class == "abusech" and not is_compromised
            )
            if promotes:
                promoted_by = observation.source

        raw = sum(best_per_class.values())
        if ipsum_level >= IPSUM_PRIOR_LEVEL:
            raw += IPSUM_PRIOR_BONUS

        # Saturating transform: no single class can approach the high band alone,
        # because exp(-w) for any w <= 1.0 leaves score well below 90.
        score = 100.0 * (1.0 - math.exp(-raw))
        class_count = len(best_per_class)

        if promoted_by:
            score = max(score, HIGH_SCORE_FLOOR)
            band = Band.HIGH
        elif class_count >= HIGH_CONFIDENCE_CLASSES:
            band = Band.HIGH
        elif class_count >= MEDIUM_CONFIDENCE_CLASSES:
            band = Band.MEDIUM
        else:
            band = Band.WITHHELD

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
                independence_classes=sorted(best_per_class),
                sources=sorted(sources),
                categories=sorted(categories),
                tags=sorted(tags),
                first_seen=first_seen,
                last_seen=last_seen,
                promoted_by=promoted_by,
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

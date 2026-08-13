"""Safety filters. Every rule here exists to prevent a specific kind of harm.

Order matters and is fixed:

1. non-global addresses  - reserved space must never be published
2. CIDR width cap        - one bad wide prefix can black-hole a whole ISP
3. allowlist             - legitimate infrastructure, applied last so nothing
                           downstream can reintroduce it
4. redistribution        - a licensing obligation, enforced in code

Filtering happens *after* scoring so that a non-redistributable source can still
contribute corroboration without its rows ever being emitted.
"""

import ipaddress
from dataclasses import dataclass, field

import structlog

from xfeeds.allowlist import Allowlist
from xfeeds.models import IPOrNet, Registry, ScoredIndicator
from xfeeds.score import open_sources

logger = structlog.get_logger(__name__)

MAX_IPV4_PREFIXLEN = 22
"""Reject IPv4 prefixes wider than /22 (1024 addresses) unless exempt."""

MAX_IPV6_PREFIXLEN = 48
"""Reject IPv6 prefixes wider than /48 unless exempt."""

WIDE_PREFIX_EXEMPT_SOURCES = frozenset({"spamhaus_drop_v4", "spamhaus_drop_v6"})
"""Spamhaus DROP publishes whole hijacked netblocks; that is the point of it.

No other source is trusted to assert that an entire wide network is malicious.
FireHOL level1, for example, carries 224.0.0.0/3 - 537 million addresses.
"""


@dataclass
class FilterStats:
    """Why records were dropped. Needed to explain a feed that came out small."""

    non_global: int = 0
    too_wide: int = 0
    allowlisted: int = 0
    not_redistributable: int = 0
    tag_only: int = 0
    below_threshold: int = 0
    examples: dict[str, list[str]] = field(default_factory=dict)

    def note(self, reason: str, item: IPOrNet) -> None:
        """Keep a few examples per reason so the run report is diagnosable."""
        bucket = self.examples.setdefault(reason, [])
        if len(bucket) < 5:
            bucket.append(str(item))


def _is_global(item: IPOrNet) -> bool:
    return not (
        item.is_private
        or item.is_loopback
        or item.is_link_local
        or item.is_reserved
        or item.is_multicast
    )


def _too_wide(item: IPOrNet, sources: set[str]) -> bool:
    """True if the prefix is wider than allowed and no exempt source vouches for it."""
    if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return False
    if sources & WIDE_PREFIX_EXEMPT_SOURCES:
        return False
    limit = MAX_IPV4_PREFIXLEN if item.version == 4 else MAX_IPV6_PREFIXLEN
    return item.prefixlen < limit


def apply_filters(
    scored: list[ScoredIndicator],
    registry: Registry,
    allowlist: Allowlist,
    redistributable: set[str] | None = None,
) -> tuple[list[ScoredIndicator], FilterStats]:
    """Return the records that are safe and legal to publish, plus drop stats.

    ``redistributable`` names the sources publishable in the tier being built.
    Defaults to the primary feed.
    """
    if redistributable is None:
        redistributable = open_sources(registry)
    tag_only_sources = {s.name for s in registry.sources if s.tag_only}
    stats = FilterStats()
    kept: list[ScoredIndicator] = []

    for record in scored:
        item = record.ip_or_cidr
        sources = set(record.sources)

        if not _is_global(item):
            stats.non_global += 1
            stats.note("non_global", item)
            continue

        if _too_wide(item, sources):
            stats.too_wide += 1
            stats.note("too_wide", item)
            continue

        if allowlist.contains(item):
            stats.allowlisted += 1
            stats.note("allowlisted", item)
            logger.info("filtered_allowlisted", indicator=str(item), sources=sorted(sources))
            continue

        # A record whose only evidence comes from sources we may not republish
        # cannot be published, however confident we are about it.
        if not (sources & redistributable):
            stats.not_redistributable += 1
            stats.note("not_redistributable", item)
            continue

        # Sources that exist only to annotate (Tor) never produce a block on
        # their own. Blocking Tor is the consumer's policy choice, not ours.
        if sources and sources <= tag_only_sources:
            stats.tag_only += 1
            stats.note("tag_only", item)
            continue

        kept.append(record)

    logger.info(
        "filters_applied",
        input=len(scored),
        kept=len(kept),
        non_global=stats.non_global,
        too_wide=stats.too_wide,
        allowlisted=stats.allowlisted,
        not_redistributable=stats.not_redistributable,
        tag_only=stats.tag_only,
    )
    return kept, stats

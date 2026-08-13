"""Aggregate statistics about the data, as a published artifact in their own right.

Why this exists, and why it is not a loophole.

Several good sources let us read their data but not republish it: GreenSnow
prohibits republication outright, ThreatFox grants no redistribution right,
AbuseIPDB restricts its blacklist. Until now those sources influenced a confidence
score and nothing else, so the work they did was invisible to anyone reading the
site.

Counts are not the data. "AS12345 has 412 listed addresses" is a fact derived from
a corpus; it is not an extract of that corpus, and nobody can block anything with
it. So the statistics here are computed over **every** observation from **every**
source, including the ones we may not republish, and they are the one place those
sources appear by name.

Two rules keep that honest, and both are enforced below rather than left to
discipline:

1. **No address is ever emitted.** Not as a "top offenders" list, not as an
   example, not in a tooltip. The moment a specific address attributable to a
   restricted source appears in output, this stops being a statistic and becomes
   redistribution by instalment.
2. **Small cells are suppressed.** An ASN with one listed address, named, is very
   nearly that address. Cells below ``MIN_CELL`` are folded into an "other"
   bucket, which is standard statistical disclosure control and costs nothing at
   the granularity anyone actually reads.

The deliberate consequence: this module can describe the whole corpus while the
feed files describe only the redistributable part.
"""

import ipaddress
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

import structlog

from xfeeds.enrich import AsnIndex
from xfeeds.models import Band, IndicatorRecord, Registry, ScoredIndicator

logger = structlog.get_logger(__name__)

MIN_CELL = 5
"""Smallest count reported against a named ASN or country.

Chosen to be small enough to keep the long tail visible and large enough that a
named cell can never identify a single address.
"""

TOP_ASN_LIMIT = 25
TOP_COUNTRY_LIMIT = 30


def _addresses_of(item: object) -> int:
    """Size of a published entry, so a /22 is not counted as one address."""
    if isinstance(item, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return item.num_addresses
    return 1


def _jaccard(a: set[str], b: set[str]) -> float:
    union = len(a | b)
    return round(len(a & b) / union, 4) if union else 0.0


def build_insights(
    observations: list[IndicatorRecord],
    scored: list[ScoredIndicator],
    registry: Registry,
    generated_at: datetime,
    asn_index: AsnIndex | None,
) -> dict[str, Any]:
    """Compute aggregate statistics over every source, restricted ones included."""
    by_source = {s.name: s for s in registry.sources}

    seen_by_source: dict[str, set[str]] = defaultdict(set)
    seen_by_class: dict[str, set[str]] = defaultdict(set)
    for observation in observations:
        key = str(observation.ip_or_cidr)
        seen_by_source[observation.source].add(key)
        config = by_source.get(observation.source)
        if config is not None and config.vote:
            seen_by_class[config.independence_class].add(key)

    all_keys = {k for keys in seen_by_source.values() for k in keys}

    # --- per-source contribution, including sources we cannot republish ---
    sources: list[dict[str, Any]] = []
    for name, keys in sorted(seen_by_source.items()):
        config = by_source.get(name)
        if config is None:
            continue
        unique = len(
            keys - {k for other, ks in seen_by_source.items() if other != name for k in ks}
        )
        sources.append(
            {
                "source": name,
                "credit": config.credit or config.license,
                "independence_class": config.independence_class,
                "addresses_reported": len(keys),
                "reported_only_by_this_source": unique,
                "republished": bool(config.redistribute),
                "republished_noncommercial_tier": bool(
                    config.redistribute or config.redistribute_noncommercial
                ),
            }
        )

    # --- how much independent agreement exists across the whole corpus ---
    per_key_classes: Counter[int] = Counter()
    classes_by_key: dict[str, int] = defaultdict(int)
    for keys in seen_by_class.values():
        for key in keys:
            classes_by_key[key] += 1
    for key in all_keys:
        per_key_classes[classes_by_key.get(key, 0)] += 1

    # --- pairwise overlap between independence classes ---
    class_names = sorted(seen_by_class)
    overlap_rows: list[tuple[float, dict[str, Any]]] = []
    for i, a in enumerate(class_names):
        for b in class_names[i + 1 :]:
            score = _jaccard(seen_by_class[a], seen_by_class[b])
            overlap_rows.append(
                (
                    score,
                    {
                        "a": a,
                        "b": b,
                        "jaccard": score,
                        "shared_addresses": len(seen_by_class[a] & seen_by_class[b]),
                    },
                )
            )
    overlap_rows.sort(key=lambda row: row[0], reverse=True)
    overlaps = [row for _, row in overlap_rows]

    insights: dict[str, Any] = {
        "generated_at": generated_at.isoformat(),
        "what_this_is": (
            "Aggregate statistics computed over every source, including sources whose "
            "licences do not permit us to republish their addresses. Counts are derived "
            "facts, not an extract of any feed. No individual address appears here."
        ),
        "disclosure_control": (
            f"Named ASNs and countries with fewer than {MIN_CELL} addresses are folded "
            "into an 'other' bucket so that no named cell can identify a single address."
        ),
        "corpus": {
            "addresses_observed": len(all_keys),
            "addresses_published_primary": sum(1 for r in scored if r.band is not Band.WITHHELD),
            "sources_contributing": len(sources),
            "independence_classes": len(class_names),
        },
        "agreement": {
            "by_independent_class_count": {str(k): v for k, v in sorted(per_key_classes.items())},
        },
        "sources": sources,
        "class_overlap": overlaps[:20],
        "attribution": {
            "note": (
                "Statistics above are derived from all contributing sources. Sources "
                "marked republished=false are credited here precisely because their "
                "data does not appear in any feed file."
            ),
        },
    }

    if asn_index is None:
        insights["networks"] = {"available": False, "reason": "ASN table unavailable"}
        return insights

    # --- ASN and country rollups over the whole corpus ---
    asn_addresses: Counter[int] = Counter()
    asn_meta: dict[int, tuple[str, str]] = {}
    country_addresses: Counter[str] = Counter()
    asn_sources: dict[int, set[str]] = defaultdict(set)
    unenriched = 0

    for observation in observations:
        item = observation.ip_or_cidr
        if isinstance(item, ipaddress.IPv6Address | ipaddress.IPv6Network):
            unenriched += 1
            continue
        info = asn_index.summarise(item)
        if info.asn == 0:
            unenriched += 1
            continue
        weight = min(_addresses_of(item), 1024)
        asn_addresses[info.asn] += weight
        country_addresses[info.country] += weight
        asn_meta[info.asn] = (info.country, info.name)
        asn_sources[info.asn].add(observation.source)

    def _rollup_asns() -> tuple[list[dict[str, Any]], int, int]:
        rows: list[dict[str, Any]] = []
        suppressed_count = 0
        suppressed_addresses = 0
        for asn, count in asn_addresses.most_common():
            if count < MIN_CELL:
                suppressed_count += 1
                suppressed_addresses += count
                continue
            country, name = asn_meta.get(asn, ("??", "unknown"))
            rows.append(
                {
                    "asn": asn,
                    "name": name,
                    "country": country,
                    "addresses": count,
                    "sources_reporting": len(asn_sources[asn]),
                }
            )
        return rows[:TOP_ASN_LIMIT], suppressed_count, suppressed_addresses

    top_asns, suppressed_asns, suppressed_asn_addresses = _rollup_asns()

    countries = [
        {"country": cc, "addresses": count}
        for cc, count in country_addresses.most_common()
        if count >= MIN_CELL
    ][:TOP_COUNTRY_LIMIT]
    suppressed_countries = sum(1 for c in country_addresses.values() if c < MIN_CELL)

    insights["networks"] = {
        "available": True,
        "attribution": ATTRIBUTION_NOTE,
        "distinct_asns_seen": len(asn_addresses),
        "unenriched_observations": unenriched,
        "top_asns": top_asns,
        "top_countries": countries,
        "suppressed": {
            "asns_below_threshold": suppressed_asns,
            "addresses_in_suppressed_asns": suppressed_asn_addresses,
            "countries_below_threshold": suppressed_countries,
            "threshold": MIN_CELL,
        },
    }
    logger.info(
        "insights_built",
        asns=len(asn_addresses),
        countries=len(country_addresses),
        suppressed_asns=suppressed_asns,
    )
    return insights


ATTRIBUTION_NOTE = {
    "ip_to_asn": "IP to ASN mapping by IPtoASN (Frank Denis), https://iptoasn.com/",
    "licence": "Public Domain (PDDL v1.0)",
}

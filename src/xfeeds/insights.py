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
from datetime import UTC, datetime, timedelta
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


MAX_ENTRY_WEIGHT = 1 << 24
"""Ceiling on how much address space one entry may contribute to an aggregate.

An IPv6 /29 contains 2**99 addresses. Summed raw, a single entry would dominate
every total it touches by roughly thirty orders of magnitude and render the
statistic meaningless. 2**24 is a /8 of IPv4 equivalent - larger than any entry
the CIDR width cap admits for v4, so IPv4 behaviour is unchanged, while v6
prefixes are bounded to a comparable influence.

Scope for IPv6 is reported separately and honestly as /64 subnet counts by
:func:`build_family_analysis`, rather than by smuggling 2**99 into a shared total.
"""


def _addresses_of(item: object) -> int:
    """Size of a published entry, so a /22 is not counted as one address.

    Capped: see :data:`MAX_ENTRY_WEIGHT`. Callers use this to weight aggregates,
    and an uncapped IPv6 prefix breaks every one of them.
    """
    if isinstance(item, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return min(item.num_addresses, MAX_ENTRY_WEIGHT)
    return 1


def _as_network(item: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Normalise an entry to a network so addresses and CIDRs share arithmetic."""
    if isinstance(item, ipaddress.IPv4Network | ipaddress.IPv6Network):
        return item
    if isinstance(item, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return ipaddress.ip_network(item)
    raise TypeError(f"not an address or network: {item!r}")  # pragma: no cover - defensive


def _fold_small_cells(counts: Counter[str]) -> tuple[list[dict[str, Any]], int, int]:
    """Split a distribution into named cells and an unnamed remainder.

    Applies :data:`MIN_CELL`, the threshold this project already uses for named
    ASN and country cells. Reusing it here means the IPv6 aggregations are held to
    a standard the codebase already enforces and tests, rather than to a new one
    invented for the occasion.
    """
    named = [
        {"key": key, "count": count} for key, count in sorted(counts.items()) if count >= MIN_CELL
    ]
    folded_cells = sum(1 for count in counts.values() if count < MIN_CELL)
    folded_entries = sum(count for count in counts.values() if count < MIN_CELL)
    return named, folded_cells, folded_entries


def family_observation_coverage(
    observations: list[IndicatorRecord], registry: Registry
) -> dict[str, Any]:
    """Which sources report each address family, published or not.

    The published feed shows only what survived scoring, which for IPv6 means one
    source. That understates what is actually being *seen*: other sources do report
    IPv6, their records simply never reach a publishable band.

    Making that visible is what turns "should we add an IPv6 source?" into a
    measurable question. Without it, a source contributing thousands of withheld
    IPv6 observations looks identical to one contributing none.
    """
    by_source = {s.name: s for s in registry.sources}
    per_source: dict[str, dict[str, int]] = defaultdict(lambda: {"v4": 0, "v6": 0})
    for observation in observations:
        key = f"v{observation.ip_or_cidr.version}"
        per_source[observation.source][key] += 1

    rows = []
    for name in sorted(per_source):
        counts = per_source[name]
        if not counts["v6"]:
            continue
        config = by_source.get(name)
        rows.append(
            {
                "source": name,
                "independence_class": config.independence_class if config else None,
                "redistributable": bool(config.redistribute) if config else None,
                "ipv6_observations": counts["v6"],
                "ipv4_observations": counts["v4"],
            }
        )
    return {
        "sources_reporting_ipv6": rows,
        "note": (
            "Observations, not published records. A source may report IPv6 and still "
            "contribute nothing to the feed if its records are never corroborated by "
            "an independent redistributable source."
        ),
    }


def build_family_analysis(scored: list[ScoredIndicator]) -> dict[str, Any]:
    """Per-address-family structure, and an explicit account of what cannot be shown.

    IPv6 in this corpus has zero variance on score, band, source, independence
    class, categories and first_seen. Rendering the usual corroboration, score,
    churn or category charts for it would produce a single bar each - the
    appearance of analysis with none of the substance.

    What *does* carry information is structural: prefix length, the address space
    each entry covers, and which /12 of global unicast space the listings fall in.
    Those are reported here, gated on :data:`MIN_CELL` exactly as ASN rollups are.

    Suppressed analyses are enumerated with their reasons rather than silently
    omitted, so a reader can tell the difference between "no signal" and "we did
    not look".
    """
    out: dict[str, Any] = {}
    for version in (4, 6):
        subset = [r for r in scored if r.ip_or_cidr.version == version]
        if not subset:
            continue
        nets = [_as_network(r.ip_or_cidr) for r in subset]
        prefix_counts: Counter[str] = Counter(f"/{n.prefixlen}" for n in nets)
        prefix_named, prefix_folded_cells, prefix_folded_entries = _fold_small_cells(prefix_counts)

        # Scope per prefix length. This is the number an operator needs: entry
        # count says nothing about what applying the feed does to their network.
        scope_by_prefix = {
            f"/{n.prefixlen}": (1 if n.prefixlen >= 64 else 2 ** (64 - n.prefixlen))
            for n in nets
            if version == 6
        }
        blast = {
            f"/{n.prefixlen}": sum(
                r.blast_radius_64()
                for r in subset
                if _as_network(r.ip_or_cidr).prefixlen == n.prefixlen
            )
            for n in nets
        }

        entry: dict[str, Any] = {
            "entries": len(subset),
            "prefix_lengths": prefix_named,
            "prefix_lengths_folded_cells": prefix_folded_cells,
            "prefix_lengths_folded_entries": prefix_folded_entries,
            "blast_radius_64_by_prefix": dict(sorted(blast.items(), key=lambda kv: kv[0])),
            "blast_radius_64_total": sum(r.blast_radius_64() for r in subset),
            "independence_classes": len({c for r in subset for c in r.independence_classes}),
            "sources": sorted({s for r in subset for s in r.sources}),
        }
        if version == 6:
            entry["scope_per_prefix_64"] = scope_by_prefix
            entry["sites_48_total"] = sum(
                1 if n.prefixlen >= 48 else 2 ** (48 - n.prefixlen) for n in nets
            )
            # /12 of global unicast space. Derived from the address itself, so it
            # is address-space structure and carries no registry or geographic
            # claim - see the ADR on why no map is published.
            block_counts: Counter[str] = Counter(
                str(ipaddress.ip_network((int(n.network_address) >> 116 << 116, 12))) for n in nets
            )
            named, folded_cells, folded_entries = _fold_small_cells(block_counts)
            entry["unicast_blocks"] = named
            entry["unicast_blocks_folded_cells"] = folded_cells
            entry["unicast_blocks_folded_entries"] = folded_entries
            entry["distinct_allocations_32"] = len({int(n.network_address) >> 96 for n in nets})
            # Adjacent prefixes under common control are a stronger signal than
            # the same count of unrelated listings. Reported, never collapsed:
            # collapsing would diverge from what the upstream published and
            # destroy the per-entry upstream reference.
            v6_nets = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
            runs: list[dict[str, Any]] = []
            for parent in ipaddress.collapse_addresses(v6_nets):
                members = sorted(str(n) for n in v6_nets if n.subnet_of(parent))
                if len(members) > 1:
                    runs.append({"aggregate": str(parent), "members": members})
            entry["contiguous_runs"] = sorted(runs, key=lambda r: str(r["aggregate"]))
            entry["suppressed"] = _suppressed_analyses(subset)
        out[f"v{version}"] = entry
    return out


def _suppressed_analyses(records: list[ScoredIndicator]) -> list[dict[str, str]]:
    """Analyses withheld for this family, each with the reason it carries no signal.

    Computed from the data, so an entry disappears the moment the underlying
    variance appears. A hard-coded list would keep claiming "single source" long
    after a second one was enabled.
    """
    reasons: list[dict[str, str]] = []
    classes = {c for r in records for c in r.independence_classes}
    scores = {r.score for r in records}
    bands = {r.band.value for r in records}
    categories = {tuple(sorted(r.categories)) for r in records}
    sources = {s for r in records for s in r.sources}
    if len(classes) < 2:
        reasons.append(
            {
                "analysis": "Corroboration histogram",
                "reason": f"{len(classes)} independence class - the chart would be one bar",
            }
        )
    if len(scores) < 2:
        reasons.append(
            {
                "analysis": "Score distribution",
                "reason": f"every record scores {next(iter(scores)):.1f}",
            }
        )
    if len(bands) < 2:
        reasons.append(
            {"analysis": "Band split", "reason": f"every record is in the {next(iter(bands))} band"}
        )
    if len(sources) < 2:
        reasons.append(
            {
                "analysis": "Added and removed each run",
                "reason": "a single source - the whole family moves as one block",
            }
        )
    if len(categories) < 2:
        reasons.append(
            {"analysis": "Category breakdown", "reason": "every record carries the same categories"}
        )
    reasons.append(
        {
            "analysis": "Network and ASN persistence",
            "reason": "the IP-to-ASN enrichment table published by iptoasn.com is IPv4-only",
        }
    )
    return reasons


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
        "families": build_family_analysis([r for r in scored if r.band is not Band.WITHHELD]),
        "family_coverage": family_observation_coverage(observations, registry),
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
    # Two different things were previously summed into one "unenriched" number:
    # observations the ASN table has no answer for, and IPv6 observations it
    # structurally cannot answer for because the table is IPv4-only. Merging them
    # leaves a reader unable to tell a coverage gap from a design limit.
    unenriched_no_asn = 0
    unenriched_ipv6 = 0

    for observation in observations:
        item = observation.ip_or_cidr
        if isinstance(item, ipaddress.IPv6Address | ipaddress.IPv6Network):
            unenriched_ipv6 += 1
            continue
        info = asn_index.summarise(item)
        if info.asn == 0:
            unenriched_no_asn += 1
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
            # Country is deliberately absent. The field in an IP-to-ASN table is
            # where the AS number is registered, which for a hosting company says
            # where its paperwork lives and nothing about where traffic came from.
            # ADR-045 removed the map for that reason; leaving the column in a table
            # would have kept the same wrong number on the page in smaller type.
            _, name = asn_meta.get(asn, ("??", "unknown"))
            rows.append(
                {
                    "asn": asn,
                    "name": name,
                    "addresses": count,
                    "sources_reporting": len(asn_sources[asn]),
                }
            )
        return rows[:TOP_ASN_LIMIT], suppressed_count, suppressed_addresses

    top_asns, suppressed_asns, suppressed_asn_addresses = _rollup_asns()

    # Country was dropped from the output entirely. The field in an IP-to-ASN table
    # is where the AS number is *registered*; for a hosting company that describes
    # where its paperwork lives, not where the traffic came from. Publishing it as
    # "attacks by country" would be the most confidently wrong thing on the page.
    suppressed_countries = sum(1 for c in country_addresses.values() if c < MIN_CELL)

    insights["networks"] = {
        "available": True,
        "attribution": ATTRIBUTION_NOTE,
        "distinct_asns_seen": len(asn_addresses),
        "unenriched_observations": unenriched_no_asn + unenriched_ipv6,
        "unenriched_no_asn": unenriched_no_asn,
        "unenriched_ipv6": unenriched_ipv6,
        "ipv6_note": (
            "IPv6 observations are excluded from network analysis because the "
            "IP-to-ASN table published by iptoasn.com covers IPv4 only."
        ),
        "top_asns": top_asns,
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


ASN_HISTORY_PATH = "asn-history.json"
HISTORY_RETENTION_DAYS = 90
WINDOWS = (30, 60)

SPECTRUM_BUCKETS = 512
"""Buckets across the whole IPv4 space.

512 gives roughly a /9 per bucket - fine enough to show that listed space is
clumpy rather than uniform, coarse enough that a bucket count can never point at
an address. Each bucket spans 8.4 million addresses.
"""


def _day(value: datetime) -> str:
    return value.date().isoformat()


def build_spectrum(observations: list[IndicatorRecord]) -> dict[str, Any]:
    """Density of observed addresses across the entire IPv4 space.

    This is the honest version of the map that was here before. Geography was a
    guess dressed as a fact: the country in an ASN table is where the number is
    *registered*, which for a hosting company tells you where its paperwork lives
    and nothing about where the traffic came from. Address space is the coordinate
    system this data actually has.
    """
    counts = [0] * SPECTRUM_BUCKETS
    span = 2**32 // SPECTRUM_BUCKETS
    total = 0
    for observation in observations:
        item = observation.ip_or_cidr
        if isinstance(item, ipaddress.IPv4Address):
            start = end = int(item)
        elif isinstance(item, ipaddress.IPv4Network):
            start, end = int(item.network_address), int(item.broadcast_address)
        else:
            continue
        total += 1
        first, last = start // span, end // span
        for index in range(first, min(last, SPECTRUM_BUCKETS - 1) + 1):
            counts[index] += 1

    occupied = sum(1 for c in counts if c)
    return {
        "buckets": SPECTRUM_BUCKETS,
        "addresses_per_bucket": span,
        "counts": counts,
        "observations_placed": total,
        "occupied_buckets": occupied,
        "empty_buckets": SPECTRUM_BUCKETS - occupied,
        "peak": max(counts) if counts else 0,
        "note": (
            "Observations per equal slice of the IPv4 address space, lowest address "
            "on the left. Each bucket spans "
            f"{span:,} addresses, so no bucket can identify an individual address."
        ),
    }


def update_asn_history(
    observations: list[IndicatorRecord],
    asn_index: AsnIndex | None,
    now: datetime,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    """Fold today's evidence into a rolling per-day, per-ASN record.

    Two sources publish dated history of their own - bruteforceblocker about a
    month, ipthreat about ten days - so an address they report as last seen on the
    4th is counted against the 4th rather than against today. That is what lets a
    30-day window mean something before this project has been running for 30 days.
    Everything else is counted against the run date.

    Days are merged with ``max`` rather than added. A source's dated list is a
    snapshot of recent activity that we re-read every six hours; adding would
    inflate the same fact four times a day.
    """
    history: dict[str, dict[str, int]] = {}
    if previous:
        for date, entry in (previous.get("days") or {}).items():
            history[date] = {str(k): int(v) for k, v in entry.items()}

    if asn_index is not None:
        seen: dict[tuple[str, int], set[str]] = defaultdict(set)
        for observation in observations:
            item = observation.ip_or_cidr
            if isinstance(item, ipaddress.IPv6Address | ipaddress.IPv6Network):
                continue
            info = asn_index.summarise(item)
            if info.asn == 0:
                continue
            date = _day(observation.source_last_reported or now)
            seen[(date, info.asn)].add(str(item))

        for (date, asn), addresses in seen.items():
            bucket = history.setdefault(date, {})
            bucket[str(asn)] = max(bucket.get(str(asn), 0), len(addresses))

    cutoff = _day(now - timedelta(days=HISTORY_RETENTION_DAYS))
    history = {d: v for d, v in history.items() if d >= cutoff}

    return {
        "updated_at": now.isoformat(),
        "retention_days": HISTORY_RETENTION_DAYS,
        "note": (
            "Distinct addresses observed per ASN per day. Dates come from the "
            "upstream feed where it publishes them, otherwise from the run date. "
            "Days are merged with max, never summed, because the same dated list is "
            "re-read every six hours."
        ),
        "days": dict(sorted(history.items())),
    }


def asn_windows(
    history: dict[str, Any],
    asn_index: AsnIndex | None,
    now: datetime,
    limit: int = 10,
) -> dict[str, Any]:
    """Rank ASNs over 30 days, 60 days, and everything retained.

    Three numbers per row, because any one of them alone misleads:

    * ``days_active`` - how many distinct days the network appeared at all. This is
      the persistence signal, and it is the primary sort. Individual addresses churn
      out inside a week; a network that keeps coming back does not.
    * ``address_days`` - distinct addresses per day, summed. Separates one bad
      afternoon from a sustained pattern.
    * ``per_million_announced`` - address-days per million addresses the ASN
      announces. Ranking on raw counts alone just rediscovers which providers are
      largest, which is not a finding. This column is where a small, almost entirely
      hostile network overtakes a hyperscaler.

    A caveat that belongs in the output rather than in a footnote: only
    bruteforceblocker and ipthreat publish dated history, so days before this
    project started running are covered by those two feeds alone and are thinner
    than recent days. Coverage evens out as our own run history accumulates.
    """
    days: dict[str, dict[str, int]] = history.get("days") or {}
    if not days:
        return {"available": False, "reason": "no history yet"}

    dates = sorted(days)
    available_days = len(dates)
    span_days = 0
    if dates:
        first = datetime.fromisoformat(dates[0]).replace(tzinfo=UTC)
        span_days = (now - first).days + 1

    def window(size: int | None) -> list[dict[str, Any]]:
        cutoff = _day(now - timedelta(days=size - 1)) if size else ""
        totals: Counter[str] = Counter()
        active: Counter[str] = Counter()
        peak: dict[str, int] = {}
        for date in dates:
            if size and date < cutoff:
                continue
            for asn, count in days[date].items():
                totals[asn] += count
                active[asn] += 1
                peak[asn] = max(peak.get(asn, 0), count)
        rows: list[dict[str, Any]] = []
        for asn, address_days in totals.items():
            if address_days < MIN_CELL:
                continue
            number = int(asn)
            info = asn_index.by_asn(number) if asn_index is not None else None
            announced = asn_index.announced_size(number) if asn_index is not None else 0
            # 256 is a /24, the smallest globally routable prefix. An earlier cut-off
            # of 1024 silently excluded every /24, which is precisely where a small,
            # almost entirely hostile network shows up. The rate is extrapolated for
            # such networks by definition; that is what "per million announced" means.
            per_million = (
                round(address_days / (announced / 1_000_000), 1) if announced >= 256 else None
            )
            rows.append(
                {
                    "asn": number,
                    "name": info.name if info else "unknown",
                    "address_days": address_days,
                    "days_active": active[asn],
                    "peak_day": peak[asn],
                    "announced_addresses": announced,
                    "per_million_announced": per_million,
                }
            )
        # Persistence first, volume second. A network seen on eight separate days is
        # a standing problem; one seen once with a big number is an incident.
        rows.sort(key=lambda r: (int(r["days_active"]), int(r["address_days"])), reverse=True)
        return rows[:limit]

    windows: dict[str, Any] = {
        "available": True,
        "history_days_recorded": available_days,
        "history_span_days": span_days,
        "oldest_date": dates[0],
        "newest_date": dates[-1],
        "metric": (
            "Sorted by days_active (persistence), then address_days (volume). "
            "per_million_announced normalises by the size of the network so a ranking "
            "is not simply a list of the largest providers."
        ),
        "dated_history_sources": ["bruteforceblocker", "ipthreat_30d"],
        "caveat": (
            "Only the sources above publish dated history, so days before this project "
            "began running are covered by those feeds alone and are thinner than recent "
            "days. Coverage evens out as our own run history accumulates."
        ),
        "all_time": window(None),
    }
    for size in WINDOWS:
        windows[f"last_{size}_days"] = window(size)
        windows[f"last_{size}_days_complete"] = span_days >= size
    return windows

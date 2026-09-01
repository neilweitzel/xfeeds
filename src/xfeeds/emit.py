"""Output generation.

Two rules govern everything here.

**Determinism.** Two runs over identical input must produce byte-identical files.
Otherwise every scheduled run commits noise, the churn guard fires on no-ops, and
the history charts become meaningless. Records are sorted by integer address and
no timestamp is written into the block feeds themselves.

**Attribution.** Spamhaus requires that credit and its date/copy text travel with
the data. Every emitted file carries per-source attribution for the sources that
actually contributed to it.
"""

import csv
import io
import ipaddress
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from xfeeds.collectors.parsers import upstream_attribution
from xfeeds.models import Band, IPNetwork, Registry, ScoredIndicator, SourceConfig

logger = structlog.get_logger(__name__)

FEEDS_DIR = Path("feeds")
PROJECT_URL = "https://github.com/neilweitzel/xfeeds"


def _attribution_lines(registry: Registry, contributing: set[str]) -> list[str]:
    """Build attribution comment lines for the sources that contributed."""
    lines: list[str] = []
    by_name = {s.name: s for s in registry.sources}
    for name in sorted(contributing):
        config = by_name.get(name)
        if config is None:
            continue
        upstream = upstream_attribution(name)
        # Prefer a curated human credit, then whatever the payload declared, then
        # the licence summary. A source that states no licence still gets named.
        credit = config.credit or upstream.get("copyright") or config.license
        parts = [f"#   {name}"]
        if credit:
            parts.append(f"- {credit}")
        terms = upstream.get("terms") or config.license_url
        if terms:
            parts.append(f"({terms})")
        lines.append(" ".join(parts))
        if config.credit and (config.license or upstream.get("copyright")):
            detail = upstream.get("copyright") or config.license
            lines.append(f"#     terms: {detail}")
    return lines


NONCOMMERCIAL_DIR = "noncommercial"
"""Subdirectory for the CC BY-NC-SA tier. Separate directory, separate LICENSE."""

NONCOMMERCIAL_LICENSE = "CC BY-NC-SA 4.0"

PERMISSIVE_DIR = "clean"
"""Subdirectory for the clean-provenance tier. Separate directory, separate LICENSE."""

PERMISSIVE_BANNER = [
    "# " + "=" * 74,
    "# CLEAN PROVENANCE TIER. Every contributing source below has issued a WRITTEN,",
    "# NAMED licence that affirmatively permits redistribution, commercially included.",
    "#",
    "# This is the file to use if you have to satisfy a legal review. It is much",
    "# smaller than the primary feed one directory up, and that is the point: the",
    "# primary feed also contains data from publishers who distribute freely but",
    "# never actually granted a reuse licence. Absence of a prohibition is not a",
    "# grant, and this tier contains only grants. Per-source licences are listed",
    "# below and in LICENSE.txt.",
    "# " + "=" * 74,
]

NONCOMMERCIAL_BANNER = [
    "# " + "!" * 74,
    "# NON-COMMERCIAL USE ONLY. This file is NOT the same as the primary feed.",
    "#",
    "# It includes data from sources licensed CC BY-NC-SA, so this file is licensed",
    f"# {NONCOMMERCIAL_LICENSE} and may NOT be used commercially - that includes using it",
    "# inside a paid product or a service anyone pays for. If you are a company or",
    "# your use is commercial in any way, use the primary feed one directory up",
    "# instead. Attribution is required; see LICENSE.txt in this directory.",
    "# " + "!" * 74,
]


def _tier_licence_line(tier: str) -> str:
    """What the Licence: header field says for each tier.

    The primary feed genuinely cannot name one licence, because it mixes publishers
    with incompatible or absent terms - saying so is more useful than inventing a
    single answer. That admission is what the permissive tier exists to fix.
    """
    if tier == "noncommercial":
        return NONCOMMERCIAL_LICENSE
    if tier == "permissive":
        return "per-source, all permissive and named below (see LICENSE.txt)"
    return "see individual source terms below"


FAMILY_LABEL: dict[int | None, str] = {
    4: "IPv4 only",
    6: "IPv6 only",
    None: "IPv4 and IPv6",
}


def _header(
    title: str,
    records: list[ScoredIndicator],
    registry: Registry,
    generated_at: datetime,
    tier: str = "primary",
    redistributable: set[str] | None = None,
    family: int | None = None,
) -> str:
    """Comment header for a plain-text feed.

    Only sources we are permitted to redistribute are credited as contributors.
    Sources used purely for corroboration are listed separately, so the header
    never implies that non-redistributable data is present in the file.
    """
    all_contributing = {s for r in records for s in r.sources}
    if redistributable is None:
        redistributable = {s.name for s in registry.sources if s.redistribute}
    contributing = all_contributing & redistributable
    scoring_only = sorted(all_contributing - redistributable)
    lines = [
        "#" * 78,
        f"# xfeeds - {title}",
        f"# {PROJECT_URL}",
        "#",
        f"# Generated: {generated_at.isoformat()}",
        f"# Entries:   {len(records)}",
        f"# Family:    {FAMILY_LABEL[family]}",
        f"# Licence:   {_tier_licence_line(tier)}",
        "#",
    ]
    if family == 6 and records:
        # Scope, not entry count. A /29 and a /48 are both "one entry" and differ
        # by a factor of half a million, so a v6 line count tells an operator
        # nothing about what applying this file does to their network.
        sites = sum(
            1 if _network_of(r).prefixlen >= 48 else 2 ** (48 - _network_of(r).prefixlen)
            for r in records
        )
        lines += [f"# Scope:     {sites:,} /48 sites", "#"]
    if tier == "noncommercial":
        lines += [*NONCOMMERCIAL_BANNER, "#"]
    elif tier == "permissive":
        lines += [*PERMISSIVE_BANNER, "#"]
    lines += [
        "# This list is compiled from public threat intelligence feeds. Each entry is",
        "# corroborated by multiple INDEPENDENT sources, or comes from a source whose",
        "# precision justifies it alone. Provided as-is with no warranty.",
        "#",
        "# Data in this file is compiled from these sources:",
        *_attribution_lines(registry, contributing),
        "#",
    ]
    if scoring_only:
        lines += [
            "# The following were consulted for corroboration only. Their licences do",
            "# not permit redistribution, so NO data from them appears in this file:",
            *[f"#   {name}" for name in scoring_only],
            "#",
        ]
    if family is not None:
        lines += _single_class_notice(records, FAMILY_LABEL[family].replace(" only", ""))
    lines += [
        "# Report a false positive: " + PROJECT_URL + "/issues",
        "#" * 78,
    ]
    return "\n".join(lines) + "\n"


def _sorted(records: list[ScoredIndicator]) -> list[ScoredIndicator]:
    return sorted(records, key=lambda r: r.sort_key())


def of_family(records: list[ScoredIndicator], version: int) -> list[ScoredIndicator]:
    """Records of one address family."""
    return [r for r in records if r.ip_or_cidr.version == version]


def family_stats(records: list[ScoredIndicator]) -> dict[str, Any]:
    """Per-family counts, scope and corroboration breadth.

    ``independence_classes`` is the field that makes the single-source notice in
    :func:`_header` testable, and makes "did corroboration ever improve for this
    family" a question the history can answer. ``blast_radius_64`` is reported
    because entry count is a poor proxy for scope in IPv6, where one /29 covers
    half a million times more subnets than one /48.
    """
    stats: dict[str, Any] = {}
    for version in (4, 6):
        subset = of_family(records, version)
        high = [r for r in subset if r.band is Band.HIGH]
        medium = [r for r in subset if r.band is Band.MEDIUM]
        classes = {c for r in subset for c in r.independence_classes}
        sources = {s for r in subset for s in r.sources}
        allocations = {
            int(_network_of(r).network_address) >> (128 - 32 if version == 6 else 32 - 16)
            for r in subset
        }
        stats[f"v{version}"] = {
            "published": len(subset),
            "high": len(high),
            "medium": len(medium),
            "independence_classes": len(classes),
            "sources": len(sources),
            "blast_radius_64": sum(r.blast_radius_64() for r in subset),
            "distinct_allocations": len(allocations),
        }
    return stats


def _network_of(record: ScoredIndicator) -> IPNetwork:
    """The record as a network, so bare addresses and CIDRs can share arithmetic."""
    item = record.ip_or_cidr
    if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ipaddress.ip_network(item)
    return item


def _single_class_notice(records: list[ScoredIndicator], family_label: str) -> list[str]:
    """Concentration notice for a family that rests on one independence class.

    Computed rather than written down. Hard-coding "IPv6 comes from Spamhaus"
    would silently go stale the day a second source is enabled, which is the exact
    failure mode this repository keeps hitting with documentation.

    The point being made is deliberately *not* "this data is weaker". A large share
    of the IPv4 feed is also promoted on one source's precision. The difference is
    that with a single class there is no second opinion and no fallback if that
    source degrades, which is a concentration risk and should be read as one.
    """
    if not records:
        return []
    classes = {c for r in records for c in r.independence_classes}
    if len(classes) >= 2:
        return []
    contributors = sorted({s for r in records for s in r.sources})
    return [
        f"# CONCENTRATION NOTICE - {family_label} coverage in this file rests on a",
        f"#   single independence class ({', '.join(contributors) or 'unknown'}).",
        "#   These records are published on that source's precision alone, which is",
        "#   the same basis used for a large share of the IPv4 feed. The limitation",
        "#   is concentration, not quality: nothing corroborates these entries, and",
        "#   nothing covers for them if that one source degrades or disappears.",
        "#",
    ]


def write_text_feed(
    path: Path,
    title: str,
    records: list[ScoredIndicator],
    registry: Registry,
    generated_at: datetime,
    tier: str = "primary",
    redistributable: set[str] | None = None,
    family: int | None = None,
) -> None:
    """One indicator per line with a commented header - the universal format.

    ``family`` restricts output to one address family. The combined files are kept
    unchanged because firewall URL tables point at those filenames; the suffixed
    files exist so a single-stack consumer has something correct to point at.
    """
    if family is not None:
        records = of_family(records, family)
    body = "\n".join(str(r.ip_or_cidr) for r in _sorted(records))
    header = _header(title, records, registry, generated_at, tier, redistributable, family)
    path.write_text(header + body + ("\n" if body else ""), encoding="utf-8")


def write_noncommercial_license(path: Path, registry: Registry, contributing: set[str]) -> None:
    """Write the LICENSE.txt that governs the non-commercial tier.

    A licence file beside the data is the minimum for a tier whose whole premise is
    that the terms differ. The audience for this project is explicitly people
    without a threat intelligence platform, so it says plainly what they may and may
    not do rather than only linking to the deed.
    """
    by_name = {s.name: s for s in registry.sources}
    nc_sources = sorted(
        name
        for name in contributing
        if (config := by_name.get(name)) is not None and not config.redistribute
    )
    lines = [
        "xfeeds - non-commercial tier",
        "=" * 60,
        "",
        f"These files are licensed {NONCOMMERCIAL_LICENSE}",
        "(Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International)",
        "https://creativecommons.org/licenses/by-nc-sa/4.0/",
        "",
        "WHY THIS TIER EXISTS",
        "",
        "Some good public threat feeds permit redistribution but forbid commercial",
        "use. We cannot put that data in the primary feed, because we cannot impose",
        "a non-commercial term on everybody who downloads a public file. We can",
        "republish it under the same licence in a clearly marked separate tier,",
        "which is what this is.",
        "",
        "WHAT YOU MAY DO",
        "",
        "  - Use these lists to protect your own networks and systems.",
        "  - Share them, provided you keep this licence and credit the sources.",
        "",
        "WHAT YOU MAY NOT DO",
        "",
        "  - Use them commercially. That includes inside a paid product, or any",
        "    service that somebody pays for.",
        "  - Redistribute them under more permissive terms than these.",
        "",
        "If your use is commercial, use the primary feed one directory up. It",
        "carries no non-commercial restriction.",
        "",
        "SOURCES REQUIRING ATTRIBUTION IN THIS TIER",
        "",
    ]
    for name in nc_sources:
        config = by_name[name]
        lines.append(f"  {name}")
        if config.license:
            lines.append(f"    licence: {config.license}")
        if config.license_url:
            lines.append(f"    terms:   {config.license_url}")
        lines.append("")
    lines += [
        "The primary feed's own source attributions also apply; see the header of",
        "any file in this directory.",
        "",
        f"Project: {PROJECT_URL}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csv(path: Path, records: list[ScoredIndicator]) -> None:
    """Flat CSV for MISP CSV feeds, OpenCTI CSV mappers, Splunk lookups."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "indicator",
            "address_family",
            "score",
            "band",
            "independence_classes",
            "sources",
            "categories",
            "tags",
            "first_seen",
            "last_seen",
            "source_reference",
        ]
    )
    for r in _sorted(records):
        writer.writerow(
            [
                str(r.ip_or_cidr),
                r.address_family,
                f"{r.score:.2f}",
                r.band.value,
                "|".join(r.independence_classes),
                "|".join(r.sources),
                "|".join(r.categories),
                "|".join(r.tags),
                r.first_seen.isoformat(),
                r.last_seen.isoformat(),
                r.source_reference or "",
            ]
        )
    path.write_text(buffer.getvalue(), encoding="utf-8")


def write_json(path: Path, records: list[ScoredIndicator], generated_at: datetime) -> None:
    """Full provenance. Also serves as the state file read back on the next run."""
    payload = {
        "generated_at": generated_at.isoformat(),
        "project": PROJECT_URL,
        "count": len(records),
        "indicators": [json.loads(r.model_dump_json()) for r in _sorted(records)],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_schema(path: Path) -> None:
    """Publish the record schema so consumers can validate all.json."""
    schema = ScoredIndicator.model_json_schema()
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_nftables(path: Path, records: list[ScoredIndicator], generated_at: datetime) -> None:
    """An nftables set, ready to include from a ruleset."""
    v4 = [str(r.ip_or_cidr) for r in _sorted(records) if r.ip_or_cidr.version == 4]
    v6 = [str(r.ip_or_cidr) for r in _sorted(records) if r.ip_or_cidr.version == 6]
    lines = [
        f"# xfeeds nftables sets - generated {generated_at.isoformat()}",
        f"# {PROJECT_URL}",
        "table inet xfeeds {",
        "  set blocklist4 {",
        "    type ipv4_addr",
        "    flags interval",
        "    elements = { " + ", ".join(v4) + " }" if v4 else "    elements = { }",
        "  }",
        "  set blocklist6 {",
        "    type ipv6_addr",
        "    flags interval",
        "    elements = { " + ", ".join(v6) + " }" if v6 else "    elements = { }",
        "  }",
        "}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_ipset(
    path: Path,
    records: list[ScoredIndicator],
    generated_at: datetime,
    family: int = 4,
    counterpart: str | None = None,
) -> None:
    """ipset restore format: pipe straight into `ipset restore`.

    One file per address family, because an ipset holds exactly one: `hash:net
    family inet` and `hash:net family inet6` are different sets and cannot be
    merged. Previously this emitted only IPv4 and dropped every v6 record with no
    comment, no count and no warning, while the dashboard reported the combined
    count against it. Excluded records are now stated in the header so a silent
    drop cannot recur.
    """
    included = of_family(_sorted(records), family)
    excluded = len(records) - len(included)
    set_name = "xfeeds" if family == 4 else "xfeeds6"
    inet = "inet" if family == 4 else "inet6"
    lines = [
        f"# xfeeds ipset ({FAMILY_LABEL[family]}) - generated {generated_at.isoformat()}",
        f"# {PROJECT_URL}",
    ]
    if excluded:
        lines.append(
            f"# {excluded} record(s) of the other address family are NOT in this file"
            + (f"; see {counterpart}" if counterpart else "")
        )
    lines += [
        f"create {set_name} hash:net family {inet} -exist",
        f"flush {set_name}",
    ]
    lines += [f"add {set_name} {r.ip_or_cidr}" for r in included]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_stix(path: Path, records: list[ScoredIndicator], generated_at: datetime) -> None:
    """STIX 2.1 bundle - the ingestion path for OpenCTI, Elastic and most TIPs.

    Hand-built rather than via the stix2 library so the output is deterministic;
    the library generates fresh UUIDs and timestamps on every call.
    """
    identity_id = "identity--9f2b1a6c-6a3e-5c8e-9e3a-0b7c4d5e6f70"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "xfeeds",
            "identity_class": "organization",
            "description": f"Aggregated public IP threat intelligence. {PROJECT_URL}",
        }
    ]
    for r in _sorted(records):
        version = "ipv4-addr" if r.ip_or_cidr.version == 4 else "ipv6-addr"
        # Deterministic id derived from the indicator itself.
        import hashlib
        import uuid

        digest = hashlib.sha256(str(r.ip_or_cidr).encode()).hexdigest()
        indicator_id = f"indicator--{uuid.UUID(digest[:32])}"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": r.first_seen.isoformat().replace("+00:00", "Z"),
                "modified": r.last_seen.isoformat().replace("+00:00", "Z"),
                "name": f"Malicious IP {r.ip_or_cidr}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[{version}:value = '{r.ip_or_cidr}']",
                "pattern_type": "stix",
                "valid_from": r.first_seen.isoformat().replace("+00:00", "Z"),
                "confidence": int(r.score),
                "labels": r.categories or ["malicious-activity"],
                "external_references": [
                    {"source_name": "xfeeds", "url": PROJECT_URL, "description": s}
                    for s in r.sources
                ],
            }
        )
    bundle = {
        "type": "bundle",
        "id": "bundle--" + "0" * 8 + "-0000-0000-0000-" + "0" * 12,
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_misp(path: Path, records: list[ScoredIndicator], generated_at: datetime) -> None:
    """MISP-compatible feed manifest plus a single event file."""
    event_uuid = "5f8c1b2e-0000-4000-8000-000000000001"
    manifest = {
        event_uuid: {
            "Orgc": {"name": "xfeeds", "uuid": "5f8c1b2e-0000-4000-8000-000000000002"},
            "info": "xfeeds aggregated public IP threat intelligence",
            "date": generated_at.date().isoformat(),
            "analysis": "2",
            "threat_level_id": "2",
            "timestamp": str(int(generated_at.timestamp())),
        }
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    event = {
        "Event": {
            "uuid": event_uuid,
            "info": "xfeeds aggregated public IP threat intelligence",
            "date": generated_at.date().isoformat(),
            "analysis": "2",
            "threat_level_id": "2",
            "Orgc": {"name": "xfeeds", "uuid": "5f8c1b2e-0000-4000-8000-000000000002"},
            "Attribute": [
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "to_ids": r.band is Band.HIGH,
                    "value": str(r.ip_or_cidr),
                    "comment": f"score={r.score:.0f} classes={','.join(r.independence_classes)}",
                }
                for r in _sorted(records)
            ],
        }
    }
    (path.parent / f"{event_uuid}.json").write_text(
        json.dumps(event, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _admission_block(
    config: SourceConfig | None, status: dict[str, Any]
) -> tuple[bool, str | None]:
    """Can this source be one of the two classes that publish an address today?

    Mirrors the ``publishable_source and evidence_vouched`` test in
    :func:`xfeeds.score.score_indicators`. Kept as a separate reader rather than
    imported from the scorer because the scorer decides per *observation* and this
    describes a *source*, but the conditions must not drift apart - if the scorer's
    admission rule changes, this changes with it.

    Returns ``(admits, reason_it_cannot)``. The reason is the operator-facing half:
    "votes but cannot admit" is a fact, "votes but cannot admit because its licence
    forbids redistribution" is actionable.
    """
    if config is None:
        return False, "not configured"
    if not config.enabled:
        return False, "disabled"
    if not config.vote:
        return False, "does not vote"
    if config.weight <= 0:
        return False, "zero weight"
    if not config.redistribute:
        return False, "licence forbids redistribution"
    if config.dormant:
        return False, "dormant: tracked threat reviewed and confirmed inactive"
    if status.get("status") == "stale":
        age = status.get("evidence_age_days")
        return False, f"stale: upstream evidence is {age} days old"
    if status.get("status") in {"failed", "skipped"}:
        return False, f"no data this run ({status.get('status')})"
    return True, None


def build_manifest(
    registry: Registry,
    source_status: dict[str, dict[str, Any]],
    records: list[ScoredIndicator],
    added: list[str],
    removed: list[str],
    generated_at: datetime,
    filter_stats: dict[str, Any],
    withheld: int = 0,
    benign_scanners_capped: int = 0,
) -> dict[str, Any]:
    """Machine-readable run summary. Drives the dashboard and the health checks."""
    bands = Counter(r.band.value for r in records)
    class_hist = Counter(len(r.independence_classes) for r in records)
    by_name = {s.name: s for s in registry.sources}

    sources_block: dict[str, Any] = {}
    for name, status in sorted(source_status.items()):
        config = by_name.get(name)
        admits, blocked_by = _admission_block(config, status)
        sources_block[name] = {
            **status,
            "independence_class": config.independence_class if config else None,
            "weight": config.weight if config else None,
            "votes": bool(config and config.vote and config.enabled),
            "admits": admits,
            "admitting_blocked_by": blocked_by,
            "redistributable": bool(config and config.redistribute),
            "license": config.license if config else None,
            "license_url": config.license_url if config else None,
            "license_risk": config.license_risk if config else None,
        }

    # Voting and admitting are different rights, and only the first was ever
    # published. A class can vote - contributing confidence to a record that
    # already stands on live corroboration - while being structurally incapable of
    # being one of the two classes that put an address into the feed. Reporting
    # only the first overstates the corroboration base to anyone reading this file.
    #
    # The abusech class is the worked example. feodo_tracker is dormant, sslbl is
    # retired and threatfox is redistribute:false, so the whole class votes and
    # never admits - which means botnet-c2 has no admitting source at all. That was
    # true for two weeks before anybody noticed, because the manifest said
    # "active_voting_classes: [... abusech ...]" and nothing contradicted it.
    voting_classes = {
        s.independence_class for s in registry.sources if s.enabled and s.vote and s.weight > 0
    }
    admitting_classes = {
        s.independence_class
        for s in registry.sources
        if s.enabled and s.vote and s.weight > 0 and s.redistribute and not s.dormant
    }

    # Per-category coverage, so a category losing its last admitting source is
    # visible as a zero rather than as an absence. Computed from configuration
    # rather than from this run, so a transient fetch failure does not read as a
    # structural gap.
    categories: dict[str, dict[str, Any]] = {}
    for source in registry.sources:
        if not (source.enabled and source.vote and source.weight > 0):
            continue
        can_admit = source.redistribute and not source.dormant
        for category in source.categories:
            entry = categories.setdefault(category, {"voting": set(), "admitting": set()})
            entry["voting"].add(source.independence_class)
            if can_admit:
                entry["admitting"].add(source.independence_class)

    return {
        "generated_at": generated_at.isoformat(),
        "project": PROJECT_URL,
        "counts": {
            "published": len(records),
            "high": bands.get("high", 0),
            "medium": bands.get("medium", 0),
            "withheld": withheld,
            "promoted": sum(1 for r in records if r.promoted_by),
            # How many records GreyNoise held back from the high band. An aggregate
            # count is the ONLY thing their terms let us publish about their data,
            # and it is also the health signal for the enrichment: this dropping to
            # zero while the feed grows means the lookup is failing silently.
            "benign_scanners_capped": benign_scanners_capped,
        },
        "corroboration_histogram": {str(k): v for k, v in sorted(class_hist.items())},
        "deltas": {
            "added": len(added),
            "removed": len(removed),
            "added_examples": sorted(added)[:20],
            "removed_examples": sorted(removed)[:20],
        },
        "filters": filter_stats,
        "sources": sources_block,
        # Unchanged, and deliberately so - it is a published contract and consumers
        # read it. It is now accompanied by the fields that make it honest.
        "active_voting_classes": sorted(voting_classes),
        "active_admitting_classes": sorted(admitting_classes),
        "voting_only_classes": sorted(voting_classes - admitting_classes),
        "category_coverage": {
            name: {
                "voting_classes": len(entry["voting"]),
                "admitting_classes": len(entry["admitting"]),
                "admitting_class_names": sorted(entry["admitting"]),
            }
            for name, entry in sorted(categories.items())
        },
    }


def append_history(path: Path, manifest: dict[str, Any], limit: int = 720) -> list[dict[str, Any]]:
    """Append this run to the rolling history that the dashboard charts.

    Capped so the file cannot grow without bound. At a 6-hour cadence, 720
    entries is about six months.
    """
    history: list[dict[str, Any]] = []
    if path.exists():
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []

    entry = {
        "generated_at": manifest["generated_at"],
        "published": manifest["counts"]["published"],
        "high": manifest["counts"]["high"],
        "medium": manifest["counts"]["medium"],
        "added": manifest["deltas"]["added"],
        "removed": manifest["deltas"]["removed"],
        "sources_ok": sum(1 for s in manifest["sources"].values() if s.get("status") == "ok"),
        "sources_total": len(manifest["sources"]),
        "by_class": {
            name: info.get("records", 0)
            for name, info in manifest["sources"].items()
            if info.get("records")
        },
    }
    # Replace an entry with the same timestamp so re-runs do not duplicate.
    history = [h for h in history if h.get("generated_at") != entry["generated_at"]]
    history.append(entry)
    history = history[-limit:]
    path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    return history


def emit_all(
    records: list[ScoredIndicator],
    registry: Registry,
    manifest: dict[str, Any],
    generated_at: datetime,
    feeds_dir: Path = FEEDS_DIR,
    tier: str = "primary",
    redistributable: set[str] | None = None,
) -> None:
    """Write every published artifact."""
    feeds_dir.mkdir(parents=True, exist_ok=True)
    high = [r for r in records if r.band is Band.HIGH]
    medium = [r for r in records if r.band is Band.MEDIUM]

    title_suffix = {
        "noncommercial": " (non-commercial tier)",
        "permissive": " (clean provenance tier)",
    }.get(tier, "")
    write_text_feed(
        feeds_dir / "high-confidence.txt",
        "high confidence" + title_suffix,
        high,
        registry,
        generated_at,
        tier,
        redistributable,
    )
    write_text_feed(
        feeds_dir / "medium-confidence.txt",
        "medium confidence" + title_suffix,
        medium,
        registry,
        generated_at,
        tier,
        redistributable,
    )
    contributing_sources = {s for r in records for s in r.sources}
    if tier == "noncommercial":
        write_noncommercial_license(feeds_dir / "LICENSE.txt", registry, contributing_sources)
    elif tier == "permissive":
        # Only the sources actually present, not every permissive source configured -
        # a licence file naming a source that contributed nothing is misleading.
        write_permissive_license(
            feeds_dir / "LICENSE.txt",
            registry,
            contributing_sources & (redistributable or set()),
        )
    # Family-suffixed variants. The combined files above are deliberately left
    # alone: firewall URL tables and cron jobs point at those exact filenames, so
    # changing what they return would break working deployments silently. These
    # are additive, and are what the README now recommends.
    for family in (4, 6):
        for band_name, subset in (("high confidence", high), ("medium confidence", medium)):
            slug = band_name.split()[0]
            write_text_feed(
                feeds_dir / f"{slug}-confidence-v{family}.txt",
                f"{band_name} (IPv{family})" + title_suffix,
                subset,
                registry,
                generated_at,
                tier,
                redistributable,
                family=family,
            )
    published = high + medium
    write_csv(feeds_dir / "all.csv", published)
    write_json(feeds_dir / "all.json", published, generated_at)
    write_schema(feeds_dir / "schema.json")
    write_nftables(feeds_dir / "nftables.conf", high, generated_at)
    write_ipset(feeds_dir / "iptables.ipset", high, generated_at, 4, "iptables6.ipset")
    write_ipset(feeds_dir / "iptables6.ipset", high, generated_at, 6, "iptables.ipset")
    write_stix(feeds_dir / "stix-bundle.json", high, generated_at)
    write_misp(feeds_dir / "misp-manifest.json", high, generated_at)
    manifest = {**manifest, "families": family_stats(published)}
    (feeds_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    logger.info(
        "emitted",
        high=len(high),
        medium=len(medium),
        v6=len(of_family(published, 6)),
        dir=str(feeds_dir),
    )


def write_permissive_license(path: Path, registry: Registry, contributing: set[str]) -> None:
    """Write the LICENSE.txt for the clean-provenance tier.

    This file is the deliverable. A practitioner's blocker is rarely "is this
    allowed" in the abstract - it is being asked by their own legal or procurement
    review to name the licence for every input, and not being able to. So this
    enumerates, per contributing source, the licence name and the URL where its text
    lives, and states plainly which obligations travel with the data.
    """
    by_name = {s.name: s for s in registry.sources}
    lines = [
        "xfeeds - clean provenance tier",
        "=" * 60,
        "",
        "WHY THIS TIER EXISTS",
        "",
        "The primary xfeeds feed is compiled from every usable public source. Several",
        "of those publishers distribute their data freely and openly but have never",
        "issued a licence granting reuse. That is fine for us and awkward for you:",
        "absence of a prohibition is not a grant, and it is not something you can put",
        "in front of a legal review.",
        "",
        "This tier contains ONLY sources that have issued a written, named licence",
        "affirmatively permitting redistribution, including commercial use. It is",
        "much smaller than the primary feed. That is the trade you are making, and it",
        "is deliberate.",
        "",
        "PER-SOURCE LICENCES",
        "",
    ]
    for name in sorted(contributing):
        config = by_name.get(name)
        if config is None:
            continue
        lines.append(f"  {name}")
        lines.append(f"    Licence: {config.license or 'n.a.'}")
        if config.license_url:
            lines.append(f"    Text:    {config.license_url}")
        if config.credit:
            lines.append(f"    Credit:  {config.credit}")
        lines.append("")
    lines += [
        "OBLIGATIONS THAT TRAVEL WITH THIS DATA",
        "",
        "  - Attribution. Some contributing licences (CC BY, MIT, BSD) require the",
        "    credit lines above to be retained. Keep them with the data.",
        "  - ShareAlike. At least one contributing source is CC BY-SA, which asks that",
        "    derived data be released under the same licence. If you redistribute a",
        "    modified version of this file, honour that.",
        "  - No warranty. This is threat intelligence compiled from third parties. It",
        "    can contain false positives. You are responsible for what you block.",
        "",
        "WHAT THIS TIER DOES NOT CONTAIN",
        "",
        "  - Anything from a publisher who states no licence.",
        "  - Anything non-commercial-only (that is the ../noncommercial tier).",
        "  - Anything we may read but not republish.",
        "  - Aggregations of other lists, even permissively licensed ones: a permissive",
        "    licence over a re-publication does not launder the terms of what it",
        "    contains, so re-aggregators are excluded on provenance grounds.",
        "",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

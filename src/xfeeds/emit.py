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
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from xfeeds.collectors.parsers import upstream_attribution
from xfeeds.models import Band, Registry, ScoredIndicator

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
        parts = [f"#   {name}"]
        credit = upstream.get("copyright") or config.license
        if credit:
            parts.append(f"- {credit}")
        terms = upstream.get("terms") or config.license_url
        if terms:
            parts.append(f"({terms})")
        lines.append(" ".join(parts))
    return lines


NONCOMMERCIAL_DIR = "noncommercial"
"""Subdirectory for the CC BY-NC-SA tier. Separate directory, separate LICENSE."""

NONCOMMERCIAL_LICENSE = "CC BY-NC-SA 4.0"

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


def _header(
    title: str,
    records: list[ScoredIndicator],
    registry: Registry,
    generated_at: datetime,
    tier: str = "primary",
    redistributable: set[str] | None = None,
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
        f"# Licence:   {NONCOMMERCIAL_LICENSE if tier == 'noncommercial' else 'see individual source terms below'}",
        "#",
    ]
    if tier == "noncommercial":
        lines += [*NONCOMMERCIAL_BANNER, "#"]
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
    lines += [
        "# Report a false positive: " + PROJECT_URL + "/issues",
        "#" * 78,
    ]
    return "\n".join(lines) + "\n"


def _sorted(records: list[ScoredIndicator]) -> list[ScoredIndicator]:
    return sorted(records, key=lambda r: r.sort_key())


def write_text_feed(
    path: Path,
    title: str,
    records: list[ScoredIndicator],
    registry: Registry,
    generated_at: datetime,
    tier: str = "primary",
    redistributable: set[str] | None = None,
) -> None:
    """One indicator per line with a commented header - the universal format."""
    body = "\n".join(str(r.ip_or_cidr) for r in _sorted(records))
    header = _header(title, records, registry, generated_at, tier, redistributable)
    path.write_text(header + body + "\n", encoding="utf-8")


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
            "score",
            "band",
            "independence_classes",
            "sources",
            "categories",
            "tags",
            "first_seen",
            "last_seen",
        ]
    )
    for r in _sorted(records):
        writer.writerow(
            [
                str(r.ip_or_cidr),
                f"{r.score:.2f}",
                r.band.value,
                "|".join(r.independence_classes),
                "|".join(r.sources),
                "|".join(r.categories),
                "|".join(r.tags),
                r.first_seen.isoformat(),
                r.last_seen.isoformat(),
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


def write_ipset(path: Path, records: list[ScoredIndicator], generated_at: datetime) -> None:
    """ipset restore format: pipe straight into `ipset restore`."""
    lines = [
        f"# xfeeds ipset - generated {generated_at.isoformat()}",
        f"# {PROJECT_URL}",
        "create xfeeds hash:net family inet -exist",
        "flush xfeeds",
    ]
    lines += [f"add xfeeds {r.ip_or_cidr}" for r in _sorted(records) if r.ip_or_cidr.version == 4]
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


def build_manifest(
    registry: Registry,
    source_status: dict[str, dict[str, Any]],
    records: list[ScoredIndicator],
    added: list[str],
    removed: list[str],
    generated_at: datetime,
    filter_stats: dict[str, Any],
    withheld: int = 0,
) -> dict[str, Any]:
    """Machine-readable run summary. Drives the dashboard and the health checks."""
    bands = Counter(r.band.value for r in records)
    class_hist = Counter(len(r.independence_classes) for r in records)
    by_name = {s.name: s for s in registry.sources}

    sources_block: dict[str, Any] = {}
    for name, status in sorted(source_status.items()):
        config = by_name.get(name)
        sources_block[name] = {
            **status,
            "independence_class": config.independence_class if config else None,
            "weight": config.weight if config else None,
            "votes": bool(config and config.vote and config.enabled),
            "redistributable": bool(config and config.redistribute),
            "license": config.license if config else None,
            "license_url": config.license_url if config else None,
            "license_risk": config.license_risk if config else None,
        }

    return {
        "generated_at": generated_at.isoformat(),
        "project": PROJECT_URL,
        "counts": {
            "published": len(records),
            "high": bands.get("high", 0),
            "medium": bands.get("medium", 0),
            "withheld": withheld,
            "promoted": sum(1 for r in records if r.promoted_by),
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
        "active_voting_classes": sorted(
            {
                s.independence_class
                for s in registry.sources
                if s.enabled and s.vote and s.weight > 0
            }
        ),
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

    title_suffix = " (non-commercial tier)" if tier == "noncommercial" else ""
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
    if tier == "noncommercial":
        write_noncommercial_license(
            feeds_dir / "LICENSE.txt", registry, {s for r in records for s in r.sources}
        )
    published = high + medium
    write_csv(feeds_dir / "all.csv", published)
    write_json(feeds_dir / "all.json", published, generated_at)
    write_schema(feeds_dir / "schema.json")
    write_nftables(feeds_dir / "nftables.conf", high, generated_at)
    write_ipset(feeds_dir / "iptables.ipset", high, generated_at)
    write_stix(feeds_dir / "stix-bundle.json", high, generated_at)
    write_misp(feeds_dir / "misp-manifest.json", high, generated_at)
    (feeds_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    logger.info("emitted", high=len(high), medium=len(medium), dir=str(feeds_dir))

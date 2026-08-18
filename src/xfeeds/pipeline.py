"""Pipeline orchestration.

Stage order is fixed and load-bearing:

    collect -> parse -> score -> merge with state -> filter -> emit

Scoring happens *before* filtering so that a source we may not redistribute can
still corroborate an indicator without its rows ever being published. Filtering
happens last so nothing downstream can reintroduce an allowlisted address.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from xfeeds.allowlist import build_allowlist
from xfeeds.collectors.base import fetch_source
from xfeeds.collectors.parsers import PARSERS
from xfeeds.emit import (
    NONCOMMERCIAL_DIR,
    NONCOMMERCIAL_LICENSE,
    PERMISSIVE_DIR,
    append_history,
    build_manifest,
    emit_all,
)
from xfeeds.enrich import load_asn_index
from xfeeds.filters import apply_filters
from xfeeds.greynoise import benign_addresses, cap_benign_scanners
from xfeeds.insights import (
    ASN_HISTORY_PATH,
    asn_windows,
    build_insights,
    build_spectrum,
    update_asn_history,
)
from xfeeds.models import Band, IndicatorRecord, Registry, ScoredIndicator
from xfeeds.score import (
    noncommercial_sources,
    open_sources,
    permissive_sources,
    score_indicators,
)
from xfeeds.state import carried_observations, load_state, merge_with_state, save_state

logger = structlog.get_logger(__name__)

CHURN_THRESHOLD = 0.25
"""Abort if a run would change more than this fraction of the high-confidence feed.

A sudden 25% swing almost always means an upstream broke or a parser regressed,
not that the internet changed. Better to publish yesterday's feed than a wrong one.
"""

STALENESS_DAYS = 30
"""Warn when a source's own last-updated header is older than this."""


class ChurnGuardTripped(RuntimeError):
    """Raised when a run would change too much of the feed at once."""


@dataclass
class RunReport:
    """Everything that happened during a run."""

    generated_at: datetime
    source_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    filters: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """Human-readable summary for logs and PR bodies."""
        ok = sum(1 for s in self.source_status.values() if s["status"] == "ok")
        skipped = sum(1 for s in self.source_status.values() if s["status"] == "skipped")
        configured = len(self.source_status) - skipped
        lines = [
            f"xfeeds run {self.generated_at.isoformat()}",
            f"  sources:   {ok}/{configured} ok"
            + (f" ({skipped} skipped, no API key)" if skipped else ""),
            (
                f"  published: {self.counts.get('published', 0)}"
                f" (high {self.counts.get('high', 0)}, medium {self.counts.get('medium', 0)})"
            ),
            f"  withheld:  {self.counts.get('withheld', 0)} single-source",
            f"  deltas:    +{len(self.added)} / -{len(self.removed)}",
        ]
        for name, status in sorted(self.source_status.items()):
            detail = (
                f"{status['records']} records" if status["status"] == "ok" else status["status"]
            )
            if status.get("error"):
                detail += f" ({status['error']})"
            lines.append(f"    {name:24s} {detail}")
        for warning in self.warnings:
            lines.append(f"  ! {warning}")
        return "\n".join(lines)


def _parse_last_modified(value: str | None) -> datetime | None:
    if not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def collect_all(
    registry: Registry, observed_on: datetime, only: str | None = None
) -> tuple[list[IndicatorRecord], dict[str, dict[str, Any]], list[str]]:
    """Fetch and parse every enabled source.

    A failing source is recorded and skipped. It never aborts the run - one dead
    upstream must not cost us the other eleven.
    """
    records: list[IndicatorRecord] = []
    status: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    for source in registry.sources:
        if not source.enabled:
            continue
        if only and source.name != only:
            continue

        entry: dict[str, Any] = {"status": "ok", "records": 0, "error": None, "cached": False}
        status[source.name] = entry

        levels: list[int | None] = list(source.levels) if source.levels else [None]
        for level in levels:
            url = source.url.format(level=level) if level is not None else source.url
            probe = source.model_copy(update={"url": url})
            result = fetch_source(probe, registry.defaults)

            if not result.success:
                if result.skipped_no_credential:
                    entry["status"] = "skipped"
                    entry["error"] = result.error
                    logger.info("source_skipped_no_key", source=source.name)
                else:
                    entry["status"] = "failed"
                    entry["error"] = result.error
                    warnings.append(f"{source.name}: {result.error}")
                    logger.warning("source_failed", source=source.name, error=result.error)
                continue

            entry["cached"] = result.cached
            last_modified = _parse_last_modified(result.last_modified_header)
            source_is_stale = False
            if last_modified:
                entry["last_modified"] = last_modified.isoformat()
                # ADR-052: freshness threshold is the shorter of the global ceiling
                # and the source's own TTL. A source whose evidence age exceeds this
                # cannot solo-promote, even when the fetch succeeded.
                freshness_days = min(STALENESS_DAYS, source.ttl_days)
                if observed_on - last_modified > timedelta(days=freshness_days):
                    age = (observed_on - last_modified).days
                    source_is_stale = True
                    entry["status"] = "stale"
                    if source.dormant:
                        # Reviewed-stale: the threat is confirmed inactive.
                        # Log quietly rather than raising a recurring warning.
                        logger.info(
                            "source_dormant_stale",
                            source=source.name,
                            age_days=age,
                        )
                    else:
                        warnings.append(
                            f"{source.name}: upstream last updated {age} days ago - "
                            "a dead feed is not the same as a quiet internet"
                        )

            parser = PARSERS.get(source.parser)
            if parser is None:
                entry["status"] = "failed"
                entry["error"] = f"no parser named {source.parser}"
                continue

            kwargs = {"level": level} if source.parser == "ipsum_levels" else {}
            parsed = list(parser(result.content, probe, observed_on, **kwargs))
            # Mark observations from a stale-evidence source so the scorer can
            # gate promotion (ADR-052). The records are still valid evidence
            # for corroboration; they just cannot put IPs into the feed on their
            # own while the upstream is frozen.
            if source_is_stale:
                for record in parsed:
                    record.evidence_stale = True
            records.extend(parsed)
            entry["records"] += len(parsed)

        if entry["status"] == "ok" and entry["records"] == 0:
            entry["status"] = "empty"
            warnings.append(f"{source.name}: returned zero usable records")

    return records, status, warnings


def check_churn(new_high: int, previous_high: int, force: bool) -> None:
    """Abort on an implausibly large change unless explicitly forced."""
    if previous_high == 0 or force:
        return
    delta = abs(new_high - previous_high) / previous_high
    if delta > CHURN_THRESHOLD:
        raise ChurnGuardTripped(
            f"high-confidence feed would move from {previous_high} to {new_high} "
            f"({delta:.0%} change, limit {CHURN_THRESHOLD:.0%}). This usually means an "
            "upstream broke or a parser regressed. Existing feeds left untouched. "
            "Re-run with --force if the change is intended."
        )


def run(
    registry: Registry,
    *,
    dry_run: bool = False,
    force: bool = False,
    only: str | None = None,
    feeds_dir: Path = Path("feeds"),
) -> RunReport:
    """Execute one full pipeline pass."""
    now = datetime.now(UTC)
    # Observation timestamps are truncated to the day. TTLs are measured in days,
    # so sub-day precision buys nothing - and with microsecond stamps every row in
    # all.json changes on every run, producing a 2 MB diff four times a day and
    # making the history useless to read.
    observed_on = now.replace(hour=0, minute=0, second=0, microsecond=0)
    report = RunReport(generated_at=now)

    # The allowlist is built first and fails hard, so we never do the expensive
    # work only to discover we cannot safely publish the result.
    allowlist = build_allowlist(registry.allowlist_sources, registry.defaults)

    records, status, warnings = collect_all(registry, observed_on, only=only)
    report.source_status = status
    report.warnings = warnings

    # State is loaded before scoring so a source that missed this run can still
    # vote, at a weight decayed by how long ago it last saw the address. Only
    # addresses something reported in this run are eligible; see
    # carried_observations.
    open_names = open_sources(registry)
    previous = load_state()
    carried = carried_observations(records, previous, registry, observed_on)
    observations = records + carried
    scored = score_indicators(observations, registry, observed_on)

    previous_high = sum(1 for r in previous.values() if r.band is Band.HIGH)
    previously_published = {k for k, v in previous.items() if v.band is not Band.WITHHELD}
    ageing = merge_with_state(scored, previous, registry, observed_on)

    kept, filter_stats = apply_filters(ageing.records, registry, allowlist)
    publishable = [r for r in kept if r.band is not Band.WITHHELD]

    # GreyNoise benign-scanner suppression runs here: after filtering, so we only
    # spend quota on addresses that would actually ship, and before the counts are
    # taken, so the report describes what was published rather than what was
    # scored. It is optional enrichment - no key or a failed call caps nothing and
    # the run continues. See src/xfeeds/greynoise.py for the licensing constraint:
    # this may only remove confidence, never annotate a record.
    benign = benign_addresses(publishable)
    benign_capped = cap_benign_scanners(publishable, benign)
    if benign_capped:
        report.warnings.append(f"{benign_capped} records capped high -> medium as benign scanners")

    high_count = sum(1 for r in publishable if r.band is Band.HIGH)

    report.counts = {
        "collected": len(records),
        "carried_forward": len(carried),
        "indicators": len(scored),
        "published": len(publishable),
        "high": high_count,
        "medium": sum(1 for r in publishable if r.band is Band.MEDIUM),
        "withheld": sum(1 for r in kept if r.band is Band.WITHHELD),
        # Aggregate only. A per-record marker would disclose GreyNoise membership
        # into a published file, which their terms do not permit.
        "benign_scanners_capped": benign_capped,
    }
    # Deltas describe the PUBLISHED feed. Counting every observation would report
    # tens of thousands of "additions" that were withheld and never shipped.
    published_keys = {str(r.ip_or_cidr) for r in publishable}
    report.added = sorted(published_keys - previously_published)
    report.removed = sorted(previously_published - published_keys)
    report.filters = {
        "non_global": filter_stats.non_global,
        "too_wide": filter_stats.too_wide,
        "allowlisted": filter_stats.allowlisted,
        "not_redistributable": filter_stats.not_redistributable,
        "tag_only": filter_stats.tag_only,
        "examples": filter_stats.examples,
    }

    if dry_run:
        logger.info("dry_run_no_files_written")
        return report

    check_churn(high_count, previous_high, force)

    manifest = build_manifest(
        registry,
        status,
        publishable,
        report.added,
        report.removed,
        now,
        report.filters,
        withheld=report.counts["withheld"],
        benign_scanners_capped=benign_capped,
    )
    emit_all(publishable, registry, manifest, now, feeds_dir=feeds_dir)

    # Second tier. Sources whose licence permits redistribution but forbids
    # commercial use cannot go in the primary feed, because we cannot impose that
    # term on everyone who downloads a public file. They can be republished under
    # the same licence in a separate, clearly labelled output - which is exactly
    # what CC BY-NC-SA permits. Built as its own pass because the set of
    # publishable sources differs, so bands and provenance differ too. See ADR-041.
    nc_names = noncommercial_sources(registry)
    if nc_names != open_names:
        nc_scored = score_indicators(observations, registry, observed_on, redistributable=nc_names)
        nc_ageing = merge_with_state(nc_scored, previous, registry, observed_on)
        nc_kept, nc_stats = apply_filters(
            nc_ageing.records, registry, allowlist, redistributable=nc_names
        )
        nc_publishable = [r for r in nc_kept if r.band is not Band.WITHHELD]
        nc_dir = feeds_dir / NONCOMMERCIAL_DIR
        nc_manifest = build_manifest(
            registry,
            status,
            nc_publishable,
            [],
            [],
            now,
            {
                "non_global": nc_stats.non_global,
                "too_wide": nc_stats.too_wide,
                "allowlisted": nc_stats.allowlisted,
                "not_redistributable": nc_stats.not_redistributable,
                "tag_only": nc_stats.tag_only,
                "examples": nc_stats.examples,
            },
            withheld=sum(1 for r in nc_kept if r.band is Band.WITHHELD),
        )
        nc_manifest["tier"] = "noncommercial"
        nc_manifest["license"] = NONCOMMERCIAL_LICENSE
        emit_all(
            nc_publishable,
            registry,
            nc_manifest,
            now,
            feeds_dir=nc_dir,
            tier="noncommercial",
            redistributable=nc_names,
        )
        report.counts["noncommercial_published"] = len(nc_publishable)
        report.counts["noncommercial_high"] = sum(1 for r in nc_publishable if r.band is Band.HIGH)

    # Third tier: clean provenance. Same machinery, a stricter membership test.
    # Every source here has issued a written, named licence affirmatively permitting
    # redistribution - not merely "publishes it freely and says nothing". That
    # distinction is invisible to us and decisive for a practitioner who has to name
    # a licence for every input in front of their own legal review. Much smaller than
    # the primary feed by design. See ADR-051.
    permissive_names = permissive_sources(registry)
    if permissive_names and permissive_names != open_names:
        pm_scored = score_indicators(
            observations, registry, observed_on, redistributable=permissive_names
        )
        pm_ageing = merge_with_state(pm_scored, previous, registry, observed_on)
        pm_kept, pm_stats = apply_filters(
            pm_ageing.records, registry, allowlist, redistributable=permissive_names
        )
        pm_publishable = [r for r in pm_kept if r.band is not Band.WITHHELD]
        # The same GreyNoise result is reused rather than looked up again: it is the
        # same addresses, and a second bulk call would double the quota spend for an
        # identical answer.
        cap_benign_scanners(pm_publishable, benign)
        pm_dir = feeds_dir / PERMISSIVE_DIR
        pm_manifest = build_manifest(
            registry,
            status,
            pm_publishable,
            [],
            [],
            now,
            {
                "non_global": pm_stats.non_global,
                "too_wide": pm_stats.too_wide,
                "allowlisted": pm_stats.allowlisted,
                "not_redistributable": pm_stats.not_redistributable,
                "tag_only": pm_stats.tag_only,
                "examples": pm_stats.examples,
            },
            withheld=sum(1 for r in pm_kept if r.band is Band.WITHHELD),
        )
        pm_manifest["tier"] = "permissive"
        pm_manifest["license"] = "per-source, all permissive - see clean/LICENSE.txt"
        emit_all(
            pm_publishable,
            registry,
            pm_manifest,
            now,
            feeds_dir=pm_dir,
            tier="permissive",
            redistributable=permissive_names,
        )
        report.counts["clean_published"] = len(pm_publishable)
        report.counts["clean_high"] = sum(1 for r in pm_publishable if r.band is Band.HIGH)
        logger.info(
            "clean_tier_emitted",
            sources=len(permissive_names),
            published=len(pm_publishable),
        )
        logger.info(
            "noncommercial_tier_emitted",
            published=len(nc_publishable),
            extra_over_primary=len(nc_publishable) - len(publishable),
        )
    # Compact state, including withheld sightings so a second independent source
    # can promote them later.
    save_state(kept, observations)
    append_history(feeds_dir / "history.json", manifest)
    (feeds_dir / "run-report.txt").write_text(report.summary() + "\n", encoding="utf-8")

    # Aggregate statistics over EVERY source, including the ones we may not
    # republish. Counts are derived facts rather than an extract, so this is the one
    # place a restricted source's work becomes visible. See insights.py and ADR-044.
    try:
        asn_index = load_asn_index()

        history_path = feeds_dir / ASN_HISTORY_PATH
        previous_history = (
            json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else None
        )
        asn_history = update_asn_history(observations, asn_index, now, previous_history)
        history_path.write_text(
            json.dumps(asn_history, indent=0, sort_keys=True) + "\n", encoding="utf-8"
        )

        insights = build_insights(observations, scored, registry, now, asn_index)
        insights["spectrum"] = build_spectrum(observations)
        insights["asn_windows"] = asn_windows(asn_history, asn_index, now)
        (feeds_dir / "insights.json").write_text(
            json.dumps(insights, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report.counts["asns_reported"] = int(
            insights.get("networks", {}).get("distinct_asns_seen", 0)
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # Insights are a reporting nicety. A statistics failure must never stop the
        # feed itself from publishing.
        logger.warning("insights_failed", error=str(exc))

    from xfeeds.dashboard import write_dashboard

    write_dashboard(feeds_dir)
    return report


def explain(registry: Registry, target: str, feeds_dir: Path = Path("feeds")) -> str:
    """Explain why an address is, or is not, in the feed.

    This is the tool for triaging a false-positive report, so it reads the
    published artifact (which carries full provenance) rather than the compact
    state file, and the output is written to be read by a human under pressure.
    """
    import ipaddress
    import json as _json

    published_path = feeds_dir / "all.json"
    if not published_path.exists():
        return f"No published feed at {published_path}. Run `xfeeds run` first."

    payload = _json.loads(published_path.read_text(encoding="utf-8"))
    records = [ScoredIndicator.model_validate(e) for e in payload.get("indicators", [])]
    by_key = {str(r.ip_or_cidr): r for r in records}

    record = by_key.get(target)
    if record is None:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return f"{target} is not a valid IP address."
        # The address may be covered by a published CIDR rather than listed alone.
        for candidate in records:
            item = candidate.ip_or_cidr
            is_net = isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network))
            if is_net and item.version == addr.version and addr in item:  # type: ignore[operator]
                record = candidate
                break

    if record is None:
        return (
            f"{target} is NOT in the published feed.\n\n"
            "That means one of:\n"
            "  - no source reported it\n"
            "  - only ONE independent source reported it, so it was withheld\n"
            "  - a safety filter removed it (allowlist, CIDR width cap, or the\n"
            "    licence rule that blocks non-redistributable-only records)\n\n"
            "Run `xfeeds run --dry-run` to see current filter counts."
        )

    by_name = {s.name: s for s in registry.sources}
    lines = [
        f"{record.ip_or_cidr}",
        f"  band:       {record.band.value}",
        f"  score:      {record.score:.2f}",
        (
            f"  classes:    {len(record.independence_classes)} independent "
            f"({', '.join(record.independence_classes)})"
        ),
        f"  first seen: {record.first_seen.isoformat()}",
        f"  last seen:  {record.last_seen.isoformat()}",
    ]
    if str(record.ip_or_cidr) != target:
        lines.insert(1, f"  matched:    {target} falls inside this published range")
    if record.promoted_by:
        lines.append(
            f"  promoted:   yes, by {record.promoted_by} (high-precision source, "
            "bypasses the corroboration threshold)"
        )
    if record.tags:
        lines.append(f"  tags:       {', '.join(record.tags)}")
    if record.categories:
        lines.append(f"  categories: {', '.join(record.categories)}")
    lines.append("  reported by:")
    for name in record.sources:
        config = by_name.get(name)
        if config is None:
            lines.append(f"    {name}")
            continue
        flags = []
        if not config.vote:
            flags.append("no vote")
        if not config.redistribute:
            flags.append("scoring only, not redistributed")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        lines.append(
            f"    {name:22s} class={config.independence_class:16s} weight={config.weight}{suffix}"
        )
    lines.append("")
    lines.append(
        "  To report this as a false positive, open an issue with the evidence that\n"
        "  this address is legitimate: " + "https://github.com/neilweitzel/xfeeds/issues"
    )
    return "\n".join(lines)

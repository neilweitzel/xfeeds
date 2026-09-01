"""Persisted state, so xfeeds has a memory across runs.

Two things need to survive between runs:

* ``first_seen`` - when we first observed an indicator. Recomputing it every run
  would make every address look brand new and destroy the history.
* aged-out records - an indicator no longer reported by anybody must eventually
  leave the feed, or the list grows forever and blocks addresses that were
  reassigned to somebody innocent years ago.

State lives in ``feeds/all.json``, the same file we publish. That keeps the repo
self-contained with no database, and makes every state change visible in a diff.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import structlog

from xfeeds.models import Band, IndicatorRecord, Registry, ScoredIndicator

logger = structlog.get_logger(__name__)

STATE_PATH = Path(".cache/state.json")
"""Full state including withheld single-source sightings.

NOT committed. At ~6.6 MB per run, committing it four times a day would add
gigabytes to the repository within a year. In CI it is restored via
actions/cache; if the cache is cold, first_seen is reseeded from the published
feeds/all.json so the history of everything we actually shipped still survives.
Only the first_seen of withheld sightings is lost, which is cosmetic.
"""

PUBLISHED_PATH = Path("feeds/all.json")


@dataclass
class StateEntry:
    """Minimal record of a previously seen indicator."""

    first_seen: datetime
    last_seen: datetime
    band: Band
    class_count: int
    sightings: dict[str, datetime] = field(default_factory=dict)
    """Per-source date of last sighting, used to carry a vote through an outage.

    Kept per *source* rather than per class because the decay window is the
    source's own ttl_days.
    """


@dataclass
class AgeingResult:
    """Outcome of merging new observations with prior state."""

    records: list[ScoredIndicator] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    retained_from_state: int = 0
    aged_out: int = 0


def save_state(
    records: list[ScoredIndicator],
    observations: list[IndicatorRecord] | None = None,
    path: Path = STATE_PATH,
) -> None:
    """Persist compact state.

    Deliberately minimal: only what the next run cannot recompute. Storing full
    provenance for every withheld single-source sighting produced a 24 MB file
    per run, which would bloat the repository within weeks. Short keys keep it
    small enough that git deltas stay cheap.

    ``observations`` carries the per-source sighting dates that
    :func:`carried_observations` needs on the next run. Without them a source that
    misses a fetch cannot be distinguished from a source that dropped the address
    deliberately.
    """
    sightings: dict[str, dict[str, str]] = {}
    for observation in observations or []:
        key = str(observation.ip_or_cidr)
        current = sightings.setdefault(key, {})
        stamp = observation.last_seen.isoformat()
        if stamp > current.get(observation.source, ""):
            current[observation.source] = stamp

    payload = {
        "version": 1,
        "note": "Compact run state. Published artifacts are all.json and the .txt feeds.",
        "indicators": {
            str(r.ip_or_cidr): {
                "f": r.first_seen.isoformat(),
                "l": r.last_seen.isoformat(),
                "b": r.band.value,
                "c": len(r.independence_classes),
                "s": sightings.get(str(r.ip_or_cidr), {}),
            }
            for r in sorted(records, key=lambda r: r.sort_key())
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=0, sort_keys=True) + "\n", encoding="utf-8")


def _seed_from_published(path: Path = PUBLISHED_PATH) -> dict[str, StateEntry]:
    """Rebuild what state we can from the committed published feed.

    Used when the CI cache is cold. Everything we have ever published carries its
    own first_seen in all.json, so the visible history is preserved.

    Per-source sightings are not recoverable this way, so ``sightings`` is empty
    and no votes are carried on the first run after a cold cache. That is the safe
    direction to fail: it under-reports confidence rather than over-reporting it.
    """
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    entries: dict[str, StateEntry] = {}
    for raw in payload.get("indicators", []):
        try:
            entries[str(raw["ip_or_cidr"])] = StateEntry(
                first_seen=datetime.fromisoformat(raw["first_seen"]),
                last_seen=datetime.fromisoformat(raw["last_seen"]),
                band=Band(raw["band"]),
                class_count=len(raw.get("independence_classes", [])),
            )
        except (KeyError, ValueError):
            continue
    if entries:
        logger.info("state_seeded_from_published_feed", indicators=len(entries))
    return entries


def load_state(path: Path = STATE_PATH) -> dict[str, StateEntry]:
    """Load previous state, falling back to the published feed if the cache is cold."""
    if not path.exists():
        logger.info("state_cache_absent_seeding_from_published", path=str(path))
        return _seed_from_published()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("state_unreadable_treating_as_first_run", error=str(e))
        return {}

    entries: dict[str, StateEntry] = {}
    for key, raw in payload.get("indicators", {}).items():
        try:
            entries[key] = StateEntry(
                first_seen=datetime.fromisoformat(raw["f"]),
                last_seen=datetime.fromisoformat(raw["l"]),
                band=Band(raw["b"]),
                class_count=int(raw.get("c", 0)),
                sightings={
                    name: datetime.fromisoformat(stamp)
                    for name, stamp in (raw.get("s") or {}).items()
                },
            )
        except (KeyError, ValueError) as e:
            logger.warning("state_entry_invalid", key=key, error=str(e))
    logger.info("state_loaded", indicators=len(entries))
    return entries


def carried_observations(
    fresh: list[IndicatorRecord],
    previous: dict[str, StateEntry],
    registry: Registry,
    now: datetime,
    excluded: set[str] | None = None,
) -> list[IndicatorRecord]:
    """Re-cast recent sightings from sources that missed the current run.

    Feeds are frequently briefly unavailable, and until now a source dropping out
    took its whole independence class with it, silently demoting every record that
    relied on it. Here a source that saw an address within its TTL keeps voting, at
    the decayed weight ``recency_factor`` produces, until that TTL expires.

    Two limits keep this honest:

    * Only indicators some source reported *in this run* are eligible. With no
      current evidence at all there is nothing to corroborate, so nothing is
      resurrected: the feed still contains only addresses somebody reports today.
    * Carried records are flagged, and a flagged record cannot promote.
    * ``excluded`` names sources that must not carry at all - in practice the ones
      that expired this run (ADR-059). Without this, dropping an expired source
      from collection would achieve nothing: its sightings are still in state, and
      it would keep voting from there for a further ``ttl_days``. Carrying an
      expired source is exactly the "still voting from evidence nobody vouches
      for" behaviour the expiry ceiling exists to end.
    """
    blocked = excluded or set()
    by_source = {
        s.name: s for s in registry.sources if s.enabled and s.vote and s.name not in blocked
    }
    reported_now: dict[str, set[str]] = {}
    for record in fresh:
        reported_now.setdefault(str(record.ip_or_cidr), set()).add(record.source)

    carried: list[IndicatorRecord] = []
    for key, seen_by in sorted(reported_now.items()):
        prior = previous.get(key)
        if prior is None:
            continue
        for source_name, last_seen in sorted(prior.sightings.items()):
            if source_name in seen_by:
                continue
            config = by_source.get(source_name)
            if config is None or config.ttl_days <= 0:
                continue
            age_days = (now - last_seen).total_seconds() / 86400.0
            # A zero age is the normal case, not an edge case. Observation
            # timestamps are truncated to the UTC day (pipeline.py), so every
            # sighting recorded earlier in the *same* day has an age of exactly
            # 0.0. Rejecting that -- as `<= 0.0` did -- disabled carry-forward on
            # every run except the first of each day, which silently reintroduced
            # the regression this function exists to prevent: a source missing
            # from one mid-day fetch took its whole independence class with it.
            # Only a negative age is nonsense, and that means clock skew or a
            # bad upstream timestamp, so keep rejecting it.
            if age_days < 0.0 or age_days > config.ttl_days:
                continue
            carried.append(
                IndicatorRecord(
                    ip_or_cidr=key,  # type: ignore[arg-type]
                    source=source_name,
                    independence_class=config.independence_class,
                    first_seen=prior.first_seen,
                    last_seen=last_seen,
                    categories=list(config.categories),
                    carried=True,
                )
            )

    logger.info("carried_forward", observations=len(carried))
    return carried


def merge_with_state(
    fresh: list[ScoredIndicator],
    previous: dict[str, StateEntry],
    registry: Registry,
    now: datetime,
) -> AgeingResult:
    """Carry first_seen forward, and age out indicators nobody reports any more.

    An indicator absent from this run is kept until the longest TTL of the
    sources that last reported it has elapsed. Feeds are frequently briefly
    unavailable; dropping an address the first time a source has a bad day would
    make the feed thrash.
    """
    result = AgeingResult()
    max_ttl = max((s.ttl_days for s in registry.sources if s.enabled), default=14)
    fresh_by_key = {str(r.ip_or_cidr): r for r in fresh}

    for key, record in fresh_by_key.items():
        prior = previous.get(key)
        if prior is None:
            result.added.append(key)
        else:
            # Preserve the original sighting date.
            record.first_seen = min(prior.first_seen, record.first_seen)
        result.records.append(record)

    cutoff = now - timedelta(days=max_ttl)
    for key, prior in previous.items():
        if key in fresh_by_key:
            continue
        if prior.last_seen >= cutoff:
            # Within its grace period. We keep the age accounting but do NOT
            # resurrect the record into the feed: with no source reporting it
            # this run there is no current evidence to publish.
            result.retained_from_state += 1
        else:
            result.removed.append(key)
            result.aged_out += 1

    logger.info(
        "state_merged",
        total=len(result.records),
        added=len(result.added),
        removed=len(result.removed),
        retained=result.retained_from_state,
        max_ttl_days=max_ttl,
    )
    return result

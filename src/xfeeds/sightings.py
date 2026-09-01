"""Repeat-sighting windows for sources that publish a daily snapshot.

Some sources publish what they saw *today* and nothing about what they saw last
week. The Turris Sentinel greylist is the case this was written for: one snapshot
holds about 10,000 addresses, while thirty daily snapshots hold 85,000. Eight
times the evidence is sitting in an archive we already have the right to read.

Taking the union of those thirty days would be a mistake, and the measurement in
`docs/turris-backfill-2026-09.md` says why: **49.5% of the union appears on
exactly one day**. Treating a single sighting from four weeks ago as current
corroboration is the address-reuse failure mode `docs/staleness-analysis.md`
measured against.

So the rule has two halves, and both are load-bearing:

* **Repeat** — an address must have been seen on at least ``min_days`` *distinct*
  days. This is the project's own idea applied inside a single source: one
  sighting is not corroboration, whether it comes from one source or one day.
* **Current** — its most recent sighting must be within the source's own
  ``ttl_days``. History establishes that an address is a repeat offender; it does
  not establish that it is still one. Reusing ``ttl_days`` rather than inventing
  a second number means this can never contradict the freshness the source is
  already configured with.

Measured against the 2026-09-01 feed, that pairing upgrades 604 records from
medium to high, against 694 for an unbounded thirty-day union — 87% of the
benefit for half the added addresses, and without asserting anything the source's
own TTL disagrees with.
"""

import json
from datetime import date, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

SIGHTING_WINDOW_PATH = Path(".cache/sighting-window.json")
"""Not committed, unlike ``feeds/source-freshness.json``.

The two files look similar and the choice differs, so the reasoning matters. The
freshness ledger is committed because losing it would release expiry latches and
make a frozen upstream look fresh — it fails *unsafe*. This one fails *safe*: a
cold cache drops the history, the source falls back to today's snapshot only, and
the window rebuilds over the following month. That under-reports confidence
rather than over-reporting it, which is the direction `state.py` already chose
for the same reason.
"""


class SightingWindow:
    """Per-source record of which days each address was reported on.

    Days are stored as :meth:`datetime.date.toordinal` integers rather than ISO
    strings. At roughly 85,000 addresses for a single source the difference is
    megabytes, and this file is rewritten on every run.
    """

    def __init__(self, sources: dict[str, dict[str, list[int]]] | None = None) -> None:
        self._sources: dict[str, dict[str, list[int]]] = {
            name: {ip: sorted(set(days)) for ip, days in entries.items()}
            for name, entries in (sources or {}).items()
        }

    @classmethod
    def load(cls, path: Path = SIGHTING_WINDOW_PATH) -> "SightingWindow":
        """Read the window, treating any damage as empty.

        A corrupt file must not fail the run. The cost is that affected sources
        fall back to today's snapshot until the window rebuilds.
        """
        if not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("sighting_window_unreadable", path=str(path), error=str(exc))
            return cls()
        sources = payload.get("sources") if isinstance(payload, dict) else None
        if not isinstance(sources, dict):
            return cls()
        cleaned: dict[str, dict[str, list[int]]] = {}
        for name, entries in sources.items():
            if not isinstance(entries, dict):
                continue
            cleaned[name] = {
                ip: [d for d in days if isinstance(d, int)]
                for ip, days in entries.items()
                if isinstance(days, list)
            }
        return cls(cleaned)

    def save(self, path: Path = SIGHTING_WINDOW_PATH) -> None:
        """Write the window deterministically."""
        payload = {
            "version": 1,
            "note": (
                "Which days each address was reported on, per source, as date ordinals. "
                "Backs the repeat-sighting rule in src/xfeeds/sightings.py. Not published."
            ),
            "sources": {
                name: {ip: self._sources[name][ip] for ip in sorted(self._sources[name])}
                for name in sorted(self._sources)
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")

    def record(
        self, source: str, addresses: set[str], observed_on: datetime, window_days: int
    ) -> None:
        """Add today's snapshot and drop anything older than the window.

        Pruning happens on write rather than on read so the file cannot grow
        without bound if a source is later reconfigured or removed.
        """
        today = observed_on.date().toordinal()
        cutoff = today - window_days
        entries = self._sources.setdefault(source, {})

        for address in addresses:
            days = entries.get(address)
            if days is None:
                entries[address] = [today]
            elif days[-1] != today:
                days.append(today)

        for address in list(entries):
            kept = [d for d in entries[address] if d > cutoff]
            if kept:
                entries[address] = kept
            else:
                del entries[address]

    def recurring(
        self, source: str, min_days: int, max_age_days: int, observed_on: datetime
    ) -> dict[str, date]:
        """Addresses that are both repeat offenders and still current.

        Returns each qualifying address with the date it was last seen, so the
        caller can date the observation honestly instead of stamping it today.
        """
        today = observed_on.date().toordinal()
        out: dict[str, date] = {}
        for address, days in self._sources.get(source, {}).items():
            if len(days) < min_days:
                continue
            last = days[-1]
            if today - last > max_age_days:
                continue
            out[address] = date.fromordinal(last)
        return out

    def tracked(self, source: str) -> int:
        """How many addresses are being tracked for a source, for the manifest."""
        return len(self._sources.get(source, {}))

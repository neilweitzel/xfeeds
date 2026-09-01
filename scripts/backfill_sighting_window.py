#!/usr/bin/env python3
"""Seed the repeat-sighting window from a source's daily archive.

Without this the window starts empty and takes a full ``sighting_window_days`` to
become useful — the feature would deliver nothing for a month. Turris keeps daily
snapshots back to 2020, so the history can simply be read once.

This is deliberately a one-time script and not part of the pipeline. Pulling
thirty archive files on every scheduled run would mean 120 requests a day against
a volunteer-run sensor network for data that changes once a day.

    uv run python scripts/backfill_sighting_window.py --source turris_greylist

Re-running is safe: days already recorded are not duplicated.
"""

import argparse
import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from xfeeds.config import load_registry
from xfeeds.sightings import SightingWindow

ARCHIVE = "https://view.sentinel.turris.cz/greylist-data/archive/{year}/greylist-{day}.csv"
UA = "xfeeds/1.0 (+https://github.com/neilweitzel/xfeeds)"


def parse_snapshot(text: str) -> set[str]:
    """Read a greylist CSV into addresses, skipping the comment and header rows."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "Address")):
            continue
        candidate = line.split(",")[0].strip().strip('"')
        try:
            out.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", default="turris_greylist")
    ap.add_argument("--days", type=int, default=None, help="defaults to the source's window")
    args = ap.parse_args()

    registry = load_registry(Path("sources.yaml"))
    source = next((s for s in registry.sources if s.name == args.source), None)
    if source is None:
        print(f"no such source: {args.source}", file=sys.stderr)
        return 1
    if not source.sighting_window_days:
        print(f"{args.source} has no sighting_window_days set", file=sys.stderr)
        return 1

    days = args.days or source.sighting_window_days
    window = SightingWindow.load()
    today = datetime.now(UTC)
    fetched = missing = 0

    # Oldest first, so pruning inside record() sees days in the order the
    # pipeline would have seen them.
    with httpx.Client(timeout=60, headers={"User-Agent": UA}, follow_redirects=True) as client:
        for offset in range(days - 1, -1, -1):
            when = today - timedelta(days=offset)
            url = ARCHIVE.format(year=when.year, day=when.date().isoformat())
            try:
                response = client.get(url)
            except httpx.HTTPError as exc:
                print(f"  {when.date()}  error: {exc}", file=sys.stderr)
                missing += 1
                continue
            if response.status_code != 200:
                print(f"  {when.date()}  HTTP {response.status_code}", file=sys.stderr)
                missing += 1
                continue
            addresses = parse_snapshot(response.text)
            window.record(source.name, addresses, when, source.sighting_window_days)
            fetched += 1
            print(f"  {when.date()}  {len(addresses):,} addresses")

    window.save()
    qualifying = window.recurring(
        source.name, source.sighting_min_days, source.ttl_days, today
    )
    print(
        f"\n{source.name}: {fetched} snapshots read, {missing} unavailable\n"
        f"  tracked addresses      : {window.tracked(source.name):,}\n"
        f"  qualifying right now   : {len(qualifying):,} "
        f"(>= {source.sighting_min_days} distinct days, last seen <= {source.ttl_days}d)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

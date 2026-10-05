"""Quota-aware admission for scheduled and manually dispatched refreshes.

Reserve an attempt before fetching so a failed pipeline still consumes its slot.
The workflow must commit that reservation before contacting any feed upstream.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

MAX_DAILY_ATTEMPTS = 4
MIN_INTERVAL = timedelta(hours=5, minutes=30)


def parse_timestamp(value: str) -> datetime:
    """Require an explicit timezone rather than silently counting in runner time."""
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("Refresh timestamp must include a timezone")
    return stamp.astimezone(UTC)


def decision(attempts: list[datetime], now: datetime) -> tuple[bool, str]:
    """Admit at most four UTC-day attempts with a half-hour cadence tolerance."""
    if now.tzinfo is None or any(stamp.tzinfo is None for stamp in attempts):
        raise ValueError("Refresh timestamps must include a timezone")
    now = now.astimezone(UTC)
    attempts = [stamp.astimezone(UTC) for stamp in attempts]
    if any(stamp > now for stamp in attempts):
        raise ValueError("Future refresh timestamp: refusing to fetch")
    today = sum(stamp.date() == now.date() for stamp in attempts)
    if today >= MAX_DAILY_ATTEMPTS:
        return False, f"Already {today} attempts today (UTC); limit is {MAX_DAILY_ATTEMPTS}"
    if attempts and now - max(attempts) < MIN_INTERVAL:
        return False, "Minimum spacing is 330 minutes (six-hour target, 30-minute tolerance)"
    return True, f"Refresh due; {today} attempts today (UTC)"


def reserve(ledger: Path, history: Path, now: datetime) -> tuple[bool, str]:
    """Fail closed on damaged state; bootstrap once from actual generation times."""
    if ledger.exists():
        data = json.loads(ledger.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("Invalid refresh-attempt ledger")
        stamps = data["attempts"]
    else:
        rows = json.loads(history.read_text(encoding="utf-8"))
        if not isinstance(rows, list) or not rows:
            raise ValueError("Nonempty feed history required to bootstrap quota state")
        stamps = [row["generated_at"] for row in rows]
    if not isinstance(stamps, list) or not stamps:
        raise ValueError("Nonempty refresh-attempt list required")
    attempts = [parse_timestamp(stamp) for stamp in stamps]
    allowed, reason = decision(attempts, now)
    if allowed:
        recent = [stamp for stamp in attempts if now - stamp <= timedelta(days=2)]
        recent.append(now.astimezone(UTC))
        ledger.write_text(
            json.dumps(
                {"version": 1, "attempts": [stamp.isoformat() for stamp in sorted(recent)]},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return allowed, reason


def main() -> None:
    """CLI boundary: reserve locally and communicate a skip decision to Actions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=Path("feeds/refresh-attempts.json"))
    parser.add_argument("--history", type=Path, default=Path("feeds/history.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    allowed, reason = reserve(args.ledger, args.history, datetime.now(UTC))
    print(reason)
    with args.output.open("a", encoding="utf-8") as output:
        output.write(f"skip={str(not allowed).lower()}\n")


if __name__ == "__main__":
    main()

"""Replay the release-day skip and enforce the quota around failure and midnight."""

import json
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest
import yaml

from xfeeds.refresh_guard import decision, parse_timestamp, reserve

NOW = datetime(2026, 10, 5, 5, 42, tzinfo=UTC)


def test_release_morning_replay_is_allowed() -> None:
    """Four rolling-day commits must not consume four new UTC-day slots."""
    attempts = [
        parse_timestamp(value)
        for value in [
            "2026-10-04T05:54:00Z",
            "2026-10-04T12:22:00Z",
            "2026-10-04T18:38:00Z",
            "2026-10-04T23:58:08Z",
        ]
    ]
    assert decision(attempts, NOW)[0]


def test_four_today_blocks_even_with_old_last_attempt() -> None:
    now = datetime(2026, 10, 5, 23, 59, tzinfo=UTC)
    assert not decision([now.replace(hour=h, minute=0) for h in [0, 6, 12, 18]], now)[0]


@pytest.mark.parametrize("minutes,allowed", [(0, False), (239, False), (329, False), (330, True)])
def test_spacing_boundary(minutes: int, allowed: bool) -> None:
    assert decision([NOW - timedelta(minutes=minutes)], NOW)[0] is allowed


def test_midnight_reset_does_not_bypass_spacing() -> None:
    midnight = datetime(2026, 10, 5, tzinfo=UTC)
    assert not decision([midnight - timedelta(minutes=1)], midnight)[0]
    assert decision([midnight - timedelta(hours=6)], midnight)[0]


def test_counts_utc_day_not_timestamp_local_day() -> None:
    attempts = [parse_timestamp(f"2026-10-04T{h:02d}:00:00-04:00") for h in [20, 21, 22, 23]]
    assert not decision(attempts, NOW.replace(hour=12))[0]


def test_future_or_naive_state_fails_closed() -> None:
    with pytest.raises(ValueError, match="Future"):
        decision([NOW + timedelta(seconds=1)], NOW)
    with pytest.raises(ValueError, match="timezone"):
        parse_timestamp("2026-10-05T00:00:00")


def test_failed_attempt_still_uses_slot_and_duplicate_does_not_rewrite(tmp_path: Path) -> None:
    history, ledger = tmp_path / "history.json", tmp_path / "attempts.json"
    history.write_text(json.dumps([{"generated_at": "2026-10-04T23:58:08Z"}]))
    assert reserve(ledger, history, NOW)[0]
    snapshot = ledger.read_bytes()
    # No successful refresh/history update follows the reservation.
    assert not reserve(ledger, history, NOW + timedelta(minutes=1))[0]
    assert ledger.read_bytes() == snapshot
    assert reserve(ledger, history, NOW + timedelta(hours=6))[0]
    assert len(json.loads(ledger.read_text())["attempts"]) == 3


@pytest.mark.parametrize("content", ["{", "[]", '{"version": 2}', '{"version": 1, "attempts": []}'])
def test_corrupt_ledger_never_falls_back_to_history(tmp_path: Path, content: str) -> None:
    history, ledger = tmp_path / "history.json", tmp_path / "attempts.json"
    history.write_text(json.dumps([{"generated_at": "2026-10-04T00:00:00Z"}]))
    ledger.write_text(content)
    with pytest.raises((ValueError, KeyError)):
        reserve(ledger, history, NOW)
    assert ledger.read_text() == content


def test_cli_bootstrap_and_second_trigger(tmp_path: Path) -> None:
    history, ledger, output = (tmp_path / name for name in ["history", "ledger", "output"])
    history.write_text(
        json.dumps([{"generated_at": (datetime.now(UTC) - timedelta(hours=7)).isoformat()}])
    )
    command = [
        sys.executable,
        "-m",
        "xfeeds.refresh_guard",
        "--history",
        str(history),
        "--ledger",
        str(ledger),
        "--output",
        str(output),
    ]
    subprocess.run(command, check=True, capture_output=True)
    subprocess.run(command, check=True, capture_output=True)
    assert output.read_text().splitlines() == ["skip=false", "skip=true"]


def test_workflow_cannot_bypass_guard_or_cancel_an_active_refresh() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/update-feeds.yml").read_text())
    # PyYAML's YAML 1.1 loader represents the Actions `on` key as True.
    triggers = workflow[True]
    assert triggers["schedule"] == [{"cron": "17 * * * *"}]
    assert "workflow_dispatch" in triggers
    assert "repository_dispatch" not in triggers
    assert workflow["concurrency"]["cancel-in-progress"] is False
    steps = workflow["jobs"]["refresh"]["steps"]
    guard = next(step for step in steps if step.get("id") == "due")
    assert "if" not in guard
    assert "xfeeds.refresh_guard" in guard["run"]
    reservation = next(step for step in steps if step.get("name") == "Commit refresh reservation")
    fetch = next(step for step in steps if step.get("id") == "refresh")
    assert steps.index(guard) < steps.index(reservation) < steps.index(fetch)
    assert "git push" in reservation["run"]
    assert reservation["if"] == fetch["if"] == "steps.due.outputs.skip != 'true'"
    assert "ref: main" in (root / ".github/workflows/update-feeds.yml").read_text()
    reviews = yaml.safe_load((root / ".github/workflows/source-review.yml").read_text())
    assert reviews[True]["schedule"] == [{"cron": "0 9 8 1,4,7,10 *"}]


def test_hourly_opportunities_recover_after_two_missed_slots_without_exceeding_cap() -> None:
    start = datetime(2026, 10, 5, 0, 17, tzinfo=UTC)
    attempts = [start - timedelta(hours=6)]
    for hour in range(24 * 7):
        if hour in {6, 7}:
            continue
        now = start + timedelta(hours=hour)
        if decision(attempts, now)[0]:
            attempts.append(now)
    assert attempts[2] == start + timedelta(hours=8)
    assert max(Counter(stamp.date() for stamp in attempts).values()) <= 4
    gaps = [b - a for a, b in pairwise(attempts)]
    assert min(gaps) >= timedelta(hours=5, minutes=30)
    assert max(gaps) == timedelta(hours=8)

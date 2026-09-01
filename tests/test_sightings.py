"""Tests for the repeat-sighting window (ADR-061)."""

import json
from datetime import UTC, date, datetime, timedelta

from xfeeds.sightings import SightingWindow

DAY = timedelta(days=1)
BASE = datetime(2026, 9, 1, tzinfo=UTC)


def _window_over(days: dict[int, set[str]], window_days: int = 30) -> SightingWindow:
    """Replay snapshots, keyed by how many days before BASE they were taken."""
    window = SightingWindow()
    for offset in sorted(days, reverse=True):
        window.record("turris_greylist", days[offset], BASE - offset * DAY, window_days)
    return window


def test_single_sighting_never_qualifies() -> None:
    """The whole point: one day is not corroboration.

    49.5% of the real Turris 30-day union appears on exactly one day, so this is
    the case that decides whether the feature is safe.
    """
    window = _window_over({5: {"1.1.1.1"}})
    assert window.recurring("turris_greylist", 2, 7, BASE) == {}


def test_two_distinct_days_qualifies() -> None:
    window = _window_over({5: {"1.1.1.1"}, 3: {"1.1.1.1"}})
    assert window.recurring("turris_greylist", 2, 7, BASE) == {"1.1.1.1": date(2026, 8, 29)}


def test_same_day_twice_is_one_sighting() -> None:
    """Four runs a day must not turn one day's evidence into corroboration."""
    window = SightingWindow()
    for hour in (0, 6, 12, 18):
        window.record("turris_greylist", {"1.1.1.1"}, BASE.replace(hour=hour), 30)
    assert window.recurring("turris_greylist", 2, 7, BASE) == {}


def test_repeat_offender_that_went_quiet_is_excluded() -> None:
    """Seen on plenty of days, but not lately.

    History establishes that an address was a repeat offender. It does not
    establish that it still is, so the source's own ttl_days bounds it.
    """
    window = _window_over({20: {"1.1.1.1"}, 19: {"1.1.1.1"}, 18: {"1.1.1.1"}})
    assert window.recurring("turris_greylist", 2, 7, BASE) == {}
    # Widening the recency bound past its age brings it back.
    assert "1.1.1.1" in window.recurring("turris_greylist", 2, 30, BASE)


def test_last_seen_is_the_real_date_not_today() -> None:
    """Re-cast observations must be dated honestly so recency decay applies."""
    window = _window_over({6: {"1.1.1.1"}, 4: {"1.1.1.1"}})
    assert window.recurring("turris_greylist", 2, 7, BASE)["1.1.1.1"] == date(2026, 8, 28)


def test_entries_are_pruned_out_of_the_window() -> None:
    window = _window_over({40: {"old.example"}, 39: {"old.example"}, 1: {"1.1.1.1"}})
    assert window.tracked("turris_greylist") == 1


def test_pruning_drops_days_but_keeps_recent_ones() -> None:
    """An address seen long ago and again recently keeps only the recent day."""
    window = _window_over({45: {"1.1.1.1"}, 44: {"1.1.1.1"}, 2: {"1.1.1.1"}})
    assert window.recurring("turris_greylist", 2, 7, BASE) == {}
    assert window.tracked("turris_greylist") == 1


def test_sources_are_independent() -> None:
    window = SightingWindow()
    window.record("turris_greylist", {"1.1.1.1"}, BASE - 2 * DAY, 30)
    window.record("other", {"1.1.1.1"}, BASE - 1 * DAY, 30)
    assert window.recurring("turris_greylist", 2, 7, BASE) == {}
    assert window.tracked("other") == 1


def test_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "sighting-window.json"
    window = _window_over({5: {"1.1.1.1"}, 3: {"1.1.1.1"}})
    window.save(path)
    assert SightingWindow.load(path).recurring("turris_greylist", 2, 7, BASE) == {
        "1.1.1.1": date(2026, 8, 29)
    }


def test_corrupt_file_falls_back_to_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A damaged cache must not fail the run, only cost history."""
    path = tmp_path / "sighting-window.json"
    path.write_text("{ not json")
    assert SightingWindow.load(path).tracked("turris_greylist") == 0


def test_missing_file_is_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert SightingWindow.load(tmp_path / "absent.json").tracked("turris_greylist") == 0


def test_saved_form_is_deterministic(tmp_path) -> None:  # type: ignore[no-untyped-def]
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    _window_over({5: {"1.1.1.1", "2.2.2.2"}, 3: {"2.2.2.2", "1.1.1.1"}}).save(a)
    _window_over({5: {"2.2.2.2", "1.1.1.1"}, 3: {"1.1.1.1", "2.2.2.2"}}).save(b)
    assert a.read_text() == b.read_text()
    assert json.loads(a.read_text())["version"] == 1

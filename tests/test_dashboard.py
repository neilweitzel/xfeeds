"""Regression tests for the published dashboard.

The dashboard had no dedicated test file before this one, which is how its layout
came to contradict its own module docstring: the docstring promised the page led
with firewall setup and a lookup box "rather than leading with statistics about
itself", while render() emitted four corpus-analysis panels ahead of the headline
numbers, the lookup and the downloads table. Nothing failed, because nothing
checked.

These tests pin the properties that manual review had to catch by eye:

* section order, because that is the defect that was actually fixed
* the on-page prose budget, because verbosity creeps back one helpful sentence at
  a time
* attribution strings, because those are licensing obligations rather than copy
* one history chart rather than three, because the duplicates were 800 pixels
  apart and nobody noticed
* churn bars staying inside the plot box, because the first attempt at the shared
  axis overhung it by 6.6px and covered a label
* tooltip accessibility, because a hover-only explanation strands touch and
  keyboard users
* byte-identical repeat renders, per the determinism rule in AGENTS.md
"""

import json
import re
from pathlib import Path
from typing import Any

from xfeeds import dashboard


def _manifest() -> dict[str, Any]:
    return {
        "generated_at": "2026-08-17T13:07:00Z",
        "counts": {
            "high": 4270,
            "medium": 841,
            "published": 5111,
            "withheld": 41000,
            "promoted": 2600,
        },
        "families": {"v4": {"high": 4179, "medium": 838}, "v6": {"high": 91, "medium": 3}},
        "deltas": {"added": 368, "removed": 447},
        "corroboration_histogram": {"1": 2600, "2": 1500, "3": 1011},
        "filters": {
            "allowlisted": 120,
            "too_wide": 8,
            "non_global": 3,
            "not_redistributable": 900,
            "tag_only": 1100,
        },
        "sources": {
            "spamhaus_drop": {
                "status": "ok",
                "records": 1200,
                "independence_class": "spamhaus",
                "votes": True,
                "redistributable": True,
            },
            "abuseipdb": {
                "status": "skipped",
                "records": 0,
                "independence_class": "abuseipdb",
                "votes": True,
                "redistributable": False,
            },
        },
    }


def _history() -> list[dict[str, Any]]:
    return [
        {
            "generated_at": f"2026-08-{day:02d}T01:00:00Z",
            "high": 4000 + day * 10,
            "medium": 800 + day,
            "added": 300 + day,
            "removed": 200 + day,
        }
        for day in range(10, 18)
    ]


def _insights() -> dict[str, Any]:
    return {
        "spectrum": {
            "counts": [0, 5, 90, 0, 400, 12],
            "occupied_buckets": 4,
            "buckets": 6,
            "addresses_per_bucket": 8388608,
        },
        "asn_windows": {
            "available": True,
            "history_span_days": 15,
            "last_30_days": [
                {
                    "asn": 4134,
                    "name": "CHINANET-BACKBONE",
                    "days_active": 8,
                    "address_days": 900,
                    "per_million_announced": 12.5,
                    "announced_addresses": 72000000,
                },
            ],
            "last_60_days": [],
            "all_time": [],
        },
        "families": {
            "v6": {
                "entries": 91,
                "sites_48_total": 40000,
                "distinct_allocations_32": 12,
                "independence_classes": 1,
                "sources": ["spamhaus_drop"],
                "prefix_lengths": [{"key": "/32", "count": 40}, {"key": "/48", "count": 51}],
                "blast_radius_64_by_prefix": {"/32": 2000000, "/48": 51},
                "blast_radius_64_total": 2000051,
                "unicast_blocks": [{"key": "2400::/12", "count": 60}],
                "contiguous_runs": [{"aggregate": "2a06:e480::/29", "members": ["2a06:e480::/32"]}],
                "suppressed": [{"analysis": "Score distribution", "reason": "no variance"}],
            }
        },
        "corpus": {"addresses_observed": 214000, "sources_contributing": 23},
        "networks": {
            "available": True,
            "distinct_asns_seen": 9100,
            "top_asns": [
                {"asn": 16276, "name": "OVH SAS", "addresses": 300, "sources_reporting": 9},
            ],
            "suppressed": {"threshold": 5, "asns_below_threshold": 4300},
        },
        "sources": [
            {
                "source": "abuseipdb",
                "credit": "AbuseIPDB",
                "addresses_reported": 50000,
                "reported_only_by_this_source": 12000,
                "republished_noncommercial_tier": False,
            }
        ],
    }


def _page() -> str:
    return dashboard.render(
        _manifest(),
        _history(),
        nc_counts={"published": 9000, "high": 7000, "medium": 2000},
        insights=_insights(),
    )


def _body(page: str) -> str:
    return page.split("<body>", 1)[1]


def _visible_prose(page: str) -> str:
    """On-page prose with tooltip contents removed.

    Tooltip text is excluded deliberately: the point of the restructure was to move
    rationale off the page surface and onto the label it explains, so counting tips
    against the budget would penalise exactly the fix.
    """
    return re.sub(r'<span class="tip">.*?</span>', "", _body(page), flags=re.DOTALL)


# --------------------------------------------------------------------------
# Section order - the defect this suite exists for
# --------------------------------------------------------------------------


def test_headline_numbers_precede_the_analysis_panels() -> None:
    """The cards must come before the IPv4 spectrum chart.

    This is the exact inversion that was shipped: a reader met a 512-slice
    log-scaled address-space chart before learning how many addresses were in the
    feed.
    """
    body = _body(_page())
    assert body.index('class="cards"') < body.index("Where in the IPv4 space we see activity")


def test_operational_path_precedes_the_threat_landscape() -> None:
    """Lookup, downloads and setup all come before the analysis section."""
    body = _body(_page())
    landscape = body.index('id="analysis"')
    for anchor in ('id="lookup"', 'id="downloads"', 'id="setup"'):
        assert body.index(anchor) < landscape, f"{anchor} must precede the analysis section"


def test_downloads_precede_setup_instructions() -> None:
    """Knowing which file to take comes before pasting a command that fetches it."""
    body = _body(_page())
    assert body.index('id="downloads"') < body.index('id="setup"')


def test_every_nav_target_exists() -> None:
    """A nav that points at a missing anchor silently scrolls nowhere."""
    body = _body(_page())
    targets = re.findall(r'<nav class="toc".*?</nav>', body, re.DOTALL)
    assert targets, "section nav is missing"
    for anchor in re.findall(r'href="#([^"]+)"', targets[0]):
        assert f'id="{anchor}"' in body, f"nav points at missing anchor #{anchor}"


def test_analysis_panels_share_one_heading_level() -> None:
    """All four analysis panels are h3.ptitle under a single section heading.

    One of them rendered as a 14px span while its three siblings were 17px
    headings, which read as a broken hierarchy.
    """
    body = _body(_page())
    titles = re.findall(r'<h3 class="ptitle">([^<]+)</h3>', body)
    assert "Where in the IPv4 space we see activity" in titles
    assert "Networks that keep coming back" in titles
    assert "IPv6 coverage" in titles
    assert "What the whole corpus looks like" in titles


# --------------------------------------------------------------------------
# One history chart, not three
# --------------------------------------------------------------------------


def test_history_is_charted_exactly_once() -> None:
    """history.json gets one visualisation, on one shared axis."""
    body = _body(_page())
    assert body.count('class="tl"') == 1, "expected exactly one history chart"
    assert "Safe-to-block list over time" not in body, "retired sparkline heading is back"
    assert "Added and removed each run" not in body, "retired bar-chart heading is back"


def test_history_chart_reports_size_and_churn_together() -> None:
    """One hover target per run, carrying both figures."""
    page = _page()
    titles = re.findall(r"<title>([^<]*this run)</title>", page)
    assert titles, "history chart has no per-run hover detail"
    for title in titles:
        assert "high" in title and "medium" in title
        assert "+" in title


def test_churn_bars_stay_inside_the_plot_box() -> None:
    """Bars must not overhang the axis they share with the area chart.

    The first attempt centred every bar on its data point, which pushed the first
    and last bars 6.6 units outside the 0..1000 viewBox - visibly misaligning the
    two halves of the chart and covering a label.
    """
    page = _page()
    chart = re.search(r'<svg viewBox="0 0 1000 \d+" class="tl".*?</svg>', page, re.DOTALL)
    assert chart is not None
    bars = re.findall(
        r'<rect x="([-\d.]+)" y="[-\d.]+" width="([\d.]+)" height="[\d.]+" class="c-(?:add|rem)"',
        chart.group(0),
    )
    assert bars, "no churn bars rendered"
    for x_text, w_text in bars:
        x, w = float(x_text), float(w_text)
        assert x >= 0.0, f"bar starts left of the plot box at x={x}"
        assert x + w <= 1000.0, f"bar ends right of the plot box at x={x + w}"


def test_history_chart_degrades_before_enough_runs_exist() -> None:
    """A single run gets a note, not a one-point chart."""
    out = dashboard._history_panel(
        [{"generated_at": "2026-08-17T01:00:00Z", "high": 1, "medium": 1, "added": 0, "removed": 0}]
    )
    assert 'class="tl"' not in out
    assert "refreshes every 6 hours" in out


# --------------------------------------------------------------------------
# Prose budget
# --------------------------------------------------------------------------


def test_on_page_prose_stays_within_budget() -> None:
    """Cap the page's explanatory prose.

    The page carried roughly 1,300 words of it. The ceiling here is deliberately
    above the current figure so ordinary edits are not blocked, but low enough that
    reinstating a section's worth of rationale fails. Detail belongs in
    docs/DASHBOARD.md, and one-sentence reasoning belongs in a tooltip.

    The count includes the copy-paste firewall instructions and the licence
    attributions, neither of which is verbosity, which is why the ceiling is not
    lower still.
    """
    prose = _visible_prose(_page())
    notes = re.findall(r'<p class="note[^"]*">(.*?)</p>', prose, re.DOTALL)
    notes += re.findall(r'<p class="sub"[^>]*>(.*?)</p>', prose, re.DOTALL)
    words = sum(len(re.sub(r"<[^>]+>", "", note).split()) for note in notes)
    assert words < 800, f"on-page prose has grown to {words} words"


def test_editorialising_does_not_return() -> None:
    """Phrases that argued with the reader rather than informing them."""
    page = _page()
    for phrase in ("not a nag", "wearing a hat", "needs no threat feed"):
        assert phrase not in page, f"editorialising phrase back on the page: {phrase!r}"


def test_load_bearing_explanations_survive() -> None:
    """Two explanations are guarantees, not padding, and must stay on the page.

    The IPv6 wide-prefix defence stops an analyst reading /32 entries as reckless
    aggregation, and the privacy statement is a promise about what this page will
    never publish. A word-count target must not eat either.
    """
    # Collapsed, because these sentences are wrapped by the template and a literal
    # substring match would fail on a newline rather than on missing content.
    flat = " ".join(_page().split())
    assert "No individual address appears in this section" in flat
    assert "Wide on purpose" in flat
    assert "review the widest entries" in flat
    assert "no top-offending-addresses list" in flat.lower()


# --------------------------------------------------------------------------
# Licensing obligations
# --------------------------------------------------------------------------


def test_required_attributions_are_present() -> None:
    """Attribution is contractual. Trimming prose must never trim credit.

    Spamhaus requires credit to travel with the data, IPThreat and Turris Sentinel
    are credited per their terms, and IPtoASN is credited for the network mapping
    even though it contributes no threat data.
    """
    page = _page()
    for credit in ("Spamhaus", "ipthreat.net", "Turris Sentinel", "iptoasn.com", "CC BY-NC-SA 4.0"):
        assert credit in page, f"missing required attribution: {credit}"


def test_scoring_only_sources_are_never_shown_as_republished() -> None:
    """A restricted source must read as scoring only wherever it appears."""
    page = _page()
    assert "scoring only" in page


def test_feed_filenames_are_unchanged() -> None:
    """Consumers have these paths in cron. A layout change must not rename them."""
    page = _page()
    for name in (
        "high-confidence.txt",
        "high-confidence-v4.txt",
        "high-confidence-v6.txt",
        "medium-confidence.txt",
        "all.csv",
        "all.json",
        "stix-bundle.json",
        "misp-manifest.json",
        "nftables.conf",
        "iptables.ipset",
        "iptables6.ipset",
        "manifest.json",
        "history.json",
    ):
        assert f'href="{name}"' in page, f"download link missing: {name}"


# --------------------------------------------------------------------------
# Tooltips
# --------------------------------------------------------------------------


def test_tooltips_are_reachable_without_a_mouse() -> None:
    """Every hint carries tabindex and aria-label.

    Hover alone would hide the reasoning from touch and screen-reader users, which
    would make moving prose into tooltips a regression rather than a tidy-up.
    """
    page = _page()
    hints = re.findall(r'<span class="hint"([^>]*)>', page)
    assert hints, "no tooltips rendered"
    for attrs in hints:
        assert 'tabindex="0"' in attrs, "hint is not focusable"
        assert "aria-label=" in attrs, "hint has no accessible label"


def test_no_tooltip_sits_inside_a_scrolling_container() -> None:
    """A tooltip inside `.tscroll` computes as visible and paints nowhere.

    `.tscroll` is `overflow:auto`, which clips absolutely positioned descendants
    that escape its box. Eight tooltips were first placed in scrollable table
    headers; every one of them reported display:block on hover and focus while
    rendering no visible box at all, for mouse and keyboard users alike - the worst
    kind of failure, because it looks correct from the CSS side.

    A hint inside a table is fine when that table has no scroll wrapper. This test
    draws the line where the clipping actually is.
    """
    body = _body(_page())
    for match in re.finditer(r'<div class="tscroll">', body):
        start = match.end()
        depth, index = 1, start
        while depth and index < len(body):
            opening = body.find("<div", index)
            closing = body.find("</div>", index)
            if closing == -1:
                break
            if opening != -1 and opening < closing:
                depth, index = depth + 1, opening + 4
            else:
                depth, index = depth - 1, closing + 6
        assert 'class="hint"' not in body[start:index], (
            "a tooltip is inside a .tscroll container, where overflow:auto clips it "
            "into invisibility - move it into the note beside the table"
        )


def test_tooltip_text_is_escaped() -> None:
    """Tip text goes into an attribute as well as the document."""
    out = dashboard._hint("label", 'quote " and <tag> & amp')
    assert "&quot;" in out and "&lt;tag&gt;" in out
    assert "<tag>" not in out


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_render_is_deterministic() -> None:
    """Two renders of one manifest must be byte-identical.

    Non-deterministic output would turn every scheduled refresh into diff noise,
    per the determinism rule in AGENTS.md.
    """
    assert _page() == _page()


# --------------------------------------------------------------------------
# The `xfeeds dashboard` command
# --------------------------------------------------------------------------


def test_dashboard_command_rerenders_without_network(tmp_path: Path) -> None:
    """`xfeeds dashboard` rebuilds the page from feeds already on disk.

    This command exists because the pipeline cannot simply be re-run to pick up a
    presentation change - AbuseIPDB allows five blacklist calls a day, so `run` is
    rationed - and because a merged generator change was otherwise invisible on
    the published page until the next scheduled refresh happened to regenerate it.

    Rendering must therefore depend on nothing but the committed feed files. The
    test asserts that by pointing the command at a directory containing only those
    files, with no network available to it.
    """
    from typer.testing import CliRunner

    from xfeeds.cli import app

    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (feeds / "history.json").write_text(json.dumps(_history()), encoding="utf-8")
    (feeds / "insights.json").write_text(json.dumps(_insights()), encoding="utf-8")
    (feeds / "all.json").write_text(json.dumps({"indicators": []}), encoding="utf-8")

    result = CliRunner().invoke(app, ["dashboard", "--feeds", str(feeds)])
    assert result.exit_code == 0, result.stdout

    page = (feeds / "index.html").read_text(encoding="utf-8")
    assert '<nav class="toc"' in page
    assert 'class="cards"' in page
    # The lookup index is written alongside, or the address box would 404.
    assert (feeds / "lookup.json").exists()


def test_dashboard_command_is_idempotent(tmp_path: Path) -> None:
    """Running it twice must produce identical bytes.

    The workflow that calls this commits only when the output changed, so a
    non-deterministic render would commit noise on every push to main.
    """
    from typer.testing import CliRunner

    from xfeeds.cli import app

    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (feeds / "history.json").write_text(json.dumps(_history()), encoding="utf-8")
    (feeds / "insights.json").write_text(json.dumps(_insights()), encoding="utf-8")
    (feeds / "all.json").write_text(json.dumps({"indicators": []}), encoding="utf-8")

    runner = CliRunner()
    assert runner.invoke(app, ["dashboard", "--feeds", str(feeds)]).exit_code == 0
    first = (feeds / "index.html").read_bytes()
    assert runner.invoke(app, ["dashboard", "--feeds", str(feeds)]).exit_code == 0
    assert (feeds / "index.html").read_bytes() == first


def test_dashboard_command_fails_clearly_without_a_manifest(tmp_path: Path) -> None:
    """A missing manifest is a readable error, not a traceback."""
    from typer.testing import CliRunner

    from xfeeds.cli import app

    result = CliRunner().invoke(app, ["dashboard", "--feeds", str(tmp_path)])
    assert result.exit_code == 1
    assert "no manifest.json" in result.stdout

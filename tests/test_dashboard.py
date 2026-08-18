"""Regression checks for the two self-contained Direction A dashboard surfaces."""

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from xfeeds import dashboard

FEED_FILENAMES = (
    "high-confidence.txt",
    "high-confidence-v4.txt",
    "high-confidence-v6.txt",
    "medium-confidence.txt",
    "medium-confidence-v4.txt",
    "medium-confidence-v6.txt",
    "all.csv",
    "all.json",
    "stix-bundle.json",
    "misp-manifest.json",
    "nftables.conf",
    "iptables.ipset",
    "iptables6.ipset",
    "manifest.json",
    "history.json",
)


class _HintLocationParser(HTMLParser):
    """Track clipping ancestors because a visible-looking tooltip can still never paint."""

    def __init__(self, overflow_classes: set[str]) -> None:
        super().__init__()
        self._overflow_classes = overflow_classes
        self._stack: list[bool] = []
        self.hint_in_overflow = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        overflow = bool(classes & self._overflow_classes) or "overflow:auto" in (
            values.get("style") or ""
        ).replace(" ", "")
        self._stack.append(overflow or any(self._stack))
        if "hint" in classes and self._stack[-1]:
            self.hint_in_overflow = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self._stack:
            self._stack.pop()


def _manifest() -> dict[str, Any]:
    return {
        "generated_at": "2026-08-17T13:07:00+00:00",
        "counts": {
            "high": 4224,
            "medium": 805,
            "published": 5029,
            "withheld": 43376,
            "promoted": 1781,
            "benign_scanners_capped": 589,
        },
        "corroboration_histogram": {"1": 1781, "2": 3045, "3": 179, "4": 23, "5": 1},
        "families": {
            "v4": {"high": 4133, "medium": 805, "published": 4938},
            "v6": {"high": 91, "medium": 0, "published": 91},
        },
        "filters": {
            "allowlisted": 4490,
            "not_redistributable": 205546,
            "tag_only": 1255,
            "too_wide": 0,
            "non_global": 0,
        },
        "deltas": {"added": 326, "removed": 408},
        "sources": {
            "spamhaus_drop_v4": {
                "status": "ok",
                "records": 1200,
                "independence_class": "spamhaus",
                "votes": True,
                "redistributable": True,
            },
            "feodo_tracker": {
                "status": "stale",
                "records": 5,
                "independence_class": "abusech",
                "votes": True,
                "redistributable": True,
            },
            "abuseipdb": {
                "status": "ok",
                "records": 10000,
                "independence_class": "abuseipdb",
                "votes": True,
                "redistributable": False,
            },
        },
    }


def _history() -> list[dict[str, Any]]:
    return [
        {
            "generated_at": f"2026-08-{day:02d}T01:00:00+00:00",
            "high": 4000 + day * 10,
            "medium": 800 + day,
            "published": 4800 + day * 11,
            "added": 300 + day,
            "removed": 200 + day,
            "sources_ok": 23,
            "sources_total": 24,
        }
        for day in range(10, 18)
    ]


def _insights() -> dict[str, Any]:
    return {
        "corpus": {"addresses_observed": 259696, "sources_contributing": 24},
        "spectrum": {
            "counts": [index % 17 for index in range(512)],
            "addresses_per_bucket": 8388608,
            "occupied_buckets": 409,
            "peak": 5441,
        },
        "networks": {
            "available": True,
            "distinct_asns_seen": 10844,
            "suppressed": {"threshold": 5, "asns_below_threshold": 4300},
            "top_asns": [
                {"asn": 16276, "name": "OVH SAS", "addresses": 300, "sources_reporting": 9},
            ],
        },
        "asn_windows": {
            "available": True,
            "history_span_days": 15,
            "caveat": "Dated upstream history is thinner at the left edge.",
            "dated_history_sources": ["bruteforceblocker", "ipthreat_30d"],
            "last_30_days": [
                {
                    "asn": 64500,
                    "name": "Persistent Network",
                    "days_active": 14,
                    "address_days": 240,
                    "announced_addresses": 100000,
                    "per_million_announced": 2400.0,
                },
                {
                    "asn": 64501,
                    "name": "No Denominator Network",
                    "days_active": 12,
                    "address_days": 150,
                    "announced_addresses": 0,
                    "per_million_announced": None,
                },
            ],
            "last_60_days": [],
            "all_time": [],
        },
        "agreement": {"by_independent_class_count": {"1": 236043, "2": 12894}},
        "class_overlap": [
            {"a": "abuseipdb", "b": "turris", "jaccard": 0.1854, "shared_addresses": 3998}
        ],
        "family_coverage": {
            "note": "Observations, not published records.",
            "sources_reporting_ipv6": [
                {
                    "source": "spamhaus_drop_v6",
                    "independence_class": "spamhaus",
                    "ipv6_observations": 91,
                    "redistributable": True,
                }
            ],
        },
        "families": {
            "v6": {
                "entries": 91,
                "prefix_lengths": [{"key": "/32", "count": 40}, {"key": "/48", "count": 51}],
            }
        },
    }


def _noncommercial_manifest() -> dict[str, Any]:
    return {"counts": {"published": 9000, "high": 7000, "medium": 2000}}


def _pages() -> tuple[str, str]:
    return (
        dashboard.render_console(_manifest(), _history()),
        dashboard.render_analysis(_manifest(), _history(), _insights(), _noncommercial_manifest()),
    )


def _overflow_classes(page: str) -> set[str]:
    return set(re.findall(r"\.([\w-]+)[^{]*\{[^}]*overflow(?:-x)?:\s*auto", page))


def test_both_surfaces_have_the_direction_a_structure() -> None:
    """Keep the concise operator flow separate from the analytical audit trail."""
    console, analysis = _pages()
    assert 'href="analysis.html"' in console
    assert 'id="lookup-form"' in console
    assert console.count('class="feed-group"') == 3
    assert 'class="analysis-nav"' in analysis
    for section in (
        "health",
        "method",
        "spectrum",
        "networks",
        "ipv6",
        "corpus",
        "sources",
        "licensing",
    ):
        assert f'id="{section}"' in analysis
    assert 'id="tier-filter"' in analysis and 'id="family-filter"' in analysis


def test_attributions_and_frozen_feed_paths_survive() -> None:
    """Preserve legal credit and cron-facing download paths through presentation work."""
    console, analysis = _pages()
    all_html = console + analysis
    for credit in ("Spamhaus", "ipthreat.net", "Turris Sentinel", "iptoasn.com", "CC BY-NC-SA 4.0"):
        assert credit in all_html
    for filename in FEED_FILENAMES:
        assert f'href="{filename}"' in all_html


def test_rendering_is_deterministic() -> None:
    """Static publishing must not introduce byte churn between identical inputs."""
    assert _pages() == _pages()


def test_hints_are_focusable_and_not_clipped() -> None:
    """Rationale moved into tips remains keyboard-reachable and visually renderable."""
    pages = _pages()
    all_hints = re.findall(r'<span class="hint"([^>]*)>', "".join(pages))
    assert all_hints
    for page in pages:
        hints = re.findall(r'<span class="hint"([^>]*)>', page)
        for attrs in hints:
            assert 'tabindex="0"' in attrs
            assert "aria-label=" in attrs
        parser = _HintLocationParser(_overflow_classes(page))
        parser.feed(page)
        assert not parser.hint_in_overflow
    assert "title=" not in "".join(_pages())


def test_load_bearing_safety_explanations_survive() -> None:
    """The privacy and IPv6 caveats are safety guarantees, not optional prose."""
    _, analysis = _pages()
    for phrase in (
        "Wide on purpose",
        "review the widest entries",
        "No individual address appears in this section",
    ):
        assert phrase in analysis


def test_persistence_and_corroboration_evidence_survive() -> None:
    """Keep normalised persistence and independence evidence from silently disappearing."""
    _, analysis = _pages()
    for phrase in (
        "Persistence, not provider size",
        "AS64500",
        "Per million",
        "Only 15 days of history",
        "Corroboration across independent classes",
        "1 independent class",
        "1,781 records",
        "589 indicators",
        "Highest class overlap",
        "Which sources report IPv6",
    ):
        assert phrase in analysis
    assert "&mdash;" in analysis


def test_no_external_resource_references() -> None:
    """Self-contained documents must not fetch styles, scripts, fonts, or embeds on load."""
    external_resource = re.compile(
        r"<(?:link|script|iframe)\b[^>]+(?:href|src)=[\"']https?://|@import\s+url\(\s*[\"']?https?://|url\(\s*[\"']?https?://",
        re.IGNORECASE,
    )
    for page in _pages():
        assert not external_resource.search(page)
        assert "<script src=" not in page
        assert "<link href=" not in page


def test_console_safe_to_block_uses_plain_hero_text() -> None:
    """The product value is not an alarm and must not inherit the danger band token.

    The hero numbers rail carries the same requirement as the old .stat rail: the
    "safe to block" count is the good news of the page, so it must not pick up any
    high-severity styling. This walks whichever wrapper actually renders the count.
    """
    console, _ = _pages()
    hero_num = re.search(
        r'<div class="hero-num[^"]*"[^>]*><b[^>]*>[^<]+</b>'
        r'<span class="hero-num-label">Safe to block</span>',
        console,
        re.IGNORECASE,
    )
    assert hero_num is not None, "Safe-to-block hero card not found"
    # Nothing on the card may inherit the .high danger colour token.
    card = re.search(
        r'<div class="hero-num[^"]*"[^>]*>(?:(?!</div>).)*Safe to block(?:(?!</div>).)*</div>',
        console,
        re.DOTALL,
    )
    assert card is not None
    assert 'class="high"' not in card.group(0)
    assert "var(--high)" not in card.group(0)


def test_print_rules_and_console_prose_budget() -> None:
    """Operators get a lean console while both documents remain useful on paper."""
    console, analysis = _pages()
    assert "@media print" in console and "@media print" in analysis
    console_text = re.sub(
        r"<[^>]+>", " ", re.sub(r"<(style|script).*?</\1>", "", console, flags=re.DOTALL)
    )
    analysis_text = re.sub(
        r"<[^>]+>", " ", re.sub(r"<(style|script).*?</\1>", "", analysis, flags=re.DOTALL)
    )
    assert len(console_text.split()) < len(analysis_text.split())


def _write_feed_fixture(feeds: Path) -> None:
    feeds.mkdir()
    (feeds / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    (feeds / "history.json").write_text(json.dumps(_history()), encoding="utf-8")
    (feeds / "insights.json").write_text(json.dumps(_insights()), encoding="utf-8")
    (feeds / "all.json").write_text(json.dumps({"indicators": []}), encoding="utf-8")
    noncommercial = feeds / "noncommercial"
    noncommercial.mkdir()
    (noncommercial / "manifest.json").write_text(
        json.dumps(_noncommercial_manifest()), encoding="utf-8"
    )


def test_dashboard_command_writes_all_surfaces_without_network(tmp_path: Path) -> None:
    """The explicit renderer command should work from disk-only artifacts."""
    from typer.testing import CliRunner

    from xfeeds.cli import app

    feeds = tmp_path / "feeds"
    _write_feed_fixture(feeds)
    result = CliRunner().invoke(app, ["dashboard", "--feeds", str(feeds)])
    assert result.exit_code == 0, result.stdout
    for filename in ("index.html", "analysis.html", "lookup.json"):
        assert (feeds / filename).exists()
    assert "analysis.html" in result.stdout


def test_dashboard_command_is_idempotent(tmp_path: Path) -> None:
    """The scheduler relies on rendering identical bytes when feed inputs have not changed."""
    from typer.testing import CliRunner

    from xfeeds.cli import app

    feeds = tmp_path / "feeds"
    _write_feed_fixture(feeds)
    runner = CliRunner()
    assert runner.invoke(app, ["dashboard", "--feeds", str(feeds)]).exit_code == 0
    first = {
        name: (feeds / name).read_bytes() for name in ("index.html", "analysis.html", "lookup.json")
    }
    assert runner.invoke(app, ["dashboard", "--feeds", str(feeds)]).exit_code == 0
    assert {name: (feeds / name).read_bytes() for name in first} == first


def test_dashboard_command_fails_clearly_without_a_manifest(tmp_path: Path) -> None:
    """A missing input should be actionable rather than becoming a renderer traceback."""
    from typer.testing import CliRunner

    from xfeeds.cli import app

    result = CliRunner().invoke(app, ["dashboard", "--feeds", str(tmp_path)])
    assert result.exit_code == 1
    assert "no manifest.json" in result.stdout


def test_ipv4_grid_is_one_tab_stop_with_valid_grid_roles() -> None:
    """The /8 grid must not put 256 tab stops in the reader's way.

    A tabbable cell per block is the obvious implementation and the wrong one: it
    puts 256 stops between a keyboard user and the next section, and a
    ``role="grid"`` whose children are ``role="note"`` is not a structure a screen
    reader can announce as a grid. Both were true of the first attempt here.

    The fix is the standard roving-tabindex pattern, so this asserts its two
    observable properties: proper row and gridcell roles, and exactly one cell
    reachable by Tab. Arrow-key movement is what makes the other 255 reachable.
    """
    _, page = _pages()
    assert page.count('role="grid"') == 1
    assert page.count('class="ipv4-grid-row"') == 16
    assert page.count('role="gridcell"') == 256

    tabbable = re.findall(r'class="ip-grid-cell[^"]*"[^>]*tabindex="0"', page)
    assert len(tabbable) == 1, f"expected one tabbable cell, found {len(tabbable)}"

    # Every cell still names its own block, so nothing is lost by not being a stop.
    assert page.count("0.0.0/8:") >= 256 or page.count(".0.0.0/8") >= 256
    for key in ("ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"):
        assert key in page, f"grid is missing {key} handling"


def test_both_is_honoured_as_a_selection_not_only_as_a_panel_value() -> None:
    """Selecting "Both families" must not hide every family-specific panel.

    The first implementation read ``both`` only as a panel value — a panel tagged
    ``both`` was shown under any selection — but never as a *selection*, so the
    default "Both families" filter matched only panels literally tagged ``both``
    and silently hid the /8 grid and the network table. The page rendered a
    correct-looking but empty address-space section.

    This asserts the predicate admits a ``both`` selection, and that the panels
    which regressed still declare a family so they are covered by it.
    """
    _, page = _pages()
    assert "selected === 'both'" in page, "filter no longer honours a 'both' selection"

    families = set(re.findall(r'data-family="([^"]+)"', page))
    assert "v4" in families and "v6" in families

    options = set(re.findall(r'<option value="([^"]+)"', page))
    assert {"both", "v4", "v6"} <= options, f"family control lost an option: {options}"

    # Anything a filter can hide must declare both axes, or a tier switch orphans it.
    for match in re.finditer(r'<[^>]*data-family="[^"]*"[^>]*>', page):
        assert "data-tier=" in match.group(0), f"family panel missing tier: {match.group(0)[:90]}"


def test_scroll_spy_does_not_rely_on_an_intersection_band() -> None:
    """Short sections must still be able to highlight their own nav link.

    A ``rootMargin`` band only fires for sections tall enough to cross it, so
    every short section handed its highlight to the next one down — four of eight
    links pointed at the wrong section. The fold-line approach has no minimum
    section height.
    """
    _, page = _pages()
    assert "IntersectionObserver" not in page, "band-based scroll-spy reintroduced"
    assert "getBoundingClientRect" in page and "FOLD" in page


def test_no_dead_disclosure_styling_or_handlers() -> None:
    """Don't ship styling and a click handler for a control that never renders.

    ``.disclosure`` carried CSS and a keyboard-reachable handler while zero
    disclosures were emitted, which reads as a missing feature rather than an
    absent one.
    """
    console, analysis = _pages()
    for page in (console, analysis):
        assert ".disclosure{" not in page
        assert 'class="disclosure"' not in page
        assert ".detail{" not in page


def _visible(attrs: dict[str, str], tier: str, family: str) -> bool:
    """Mirror of the client-side filter predicate, for exhaustive coverage checks."""

    def matches(value: str, selected: str) -> bool:
        return selected == "both" or value == "both" or value == selected

    if "tier" in attrs and not matches(attrs["tier"], tier):
        return False
    if "family" in attrs and not matches(attrs["family"], family):
        return False
    return not ("only-family" in attrs and attrs["only-family"] != family)


def test_every_filter_combination_leaves_every_section_explained() -> None:
    """No filter combination may leave a heading standing over nothing.

    Choosing IPv6 hid the two IPv4-only sections and showed nothing in their place,
    because the placeholders were keyed to the tier axis alone. Checking the four
    combinations that shipped is not enough — this walks all six and requires each
    section to retain at least one visible element, so a future panel cannot open a
    new hole silently.
    """
    _, page = _pages()
    sections = re.findall(
        r'<section id="([^"]+)" class="analysis-section".*?(?=<section id="|</main>)',
        page,
        re.DOTALL,
    )
    assert len(sections) >= 8, f"expected the full analysis surface, found {sections}"

    holes: list[str] = []
    for section_id in sections:
        body = re.search(
            rf'<section id="{section_id}" class="analysis-section".*?(?=<section id="|</main>)',
            page,
            re.DOTALL,
        )
        assert body is not None
        children = re.findall(r"<(?:div|p|section|table|figure)\b[^>]*>", body.group(0))
        for tier in ("primary", "noncommercial"):
            for family in ("both", "v4", "v6"):
                shown = 0
                for child in children:
                    attrs = {
                        key: value
                        for key, value in re.findall(
                            r'data-(tier|family|only-family)="([^"]*)"', child
                        )
                    }
                    if _visible(attrs, tier, family):
                        shown += 1
                if shown == 0:
                    holes.append(f"{section_id} is empty at tier={tier} family={family}")
    assert not holes, "sections with no visible content:\n  " + "\n  ".join(holes)


def test_copy_click_is_always_acknowledged() -> None:
    """A click must never be swallowed by a clipboard promise that does not settle.

    ``navigator.clipboard.writeText`` can remain permanently unsettled in a
    sandboxed or unfocused document, so awaiting it was the only path to feedback
    and the button sat inert. A timer-backed fallback selects the command instead,
    which always works.
    """
    console, _ = _pages()
    assert console.count('class="sr-only copy-status"') == console.count('class="copy"')
    assert "selectNodeContents" in console, "clipboard fallback removed"
    assert "'Selected'" in console
    # aria-label masks button text from screen readers, so the status node is required.
    assert 'role="status"' in console


def test_console_leads_with_data_before_command() -> None:
    """The console must open with the corpus, not with the install command.

    A firewall operator arriving at xfeeds should see the value of the feed
    before being asked to run anything. Ordering by ``main`` position keeps the
    check honest against future rewrites: numbers rail, then the history chart,
    then the address lookup, then the downloads, and only then the deploy
    section that carries the platform tabs and the copy command. The about
    band and licensing footer sit below the fold.
    """
    console, _ = _pages()
    main = re.search(r"<main[^>]*>(.*?)</main>", console, re.DOTALL)
    assert main is not None, "console has no <main>"
    body = main.group(1)

    markers = [
        ("hero numbers", 'class="hero-numbers"'),
        ("history chart", 'class="hero-svg"'),
        ("address lookup", 'id="lookup-form"'),
        ("downloads", 'id="feeds-title"'),
        ("deploy", 'id="deploy-title"'),
    ]
    positions = {label: body.find(needle) for label, needle in markers}
    for label, position in positions.items():
        assert position >= 0, f"missing landmark: {label}"

    order = sorted(positions, key=lambda label: positions[label])
    assert order == [label for label, _ in markers], (
        "console landmarks are out of order; got " + " -> ".join(order)
    )

    # About and footer live outside <main>, but must sit below every landmark in
    # source order, since that is what governs both visual position and reading
    # order for screen readers.
    about = console.find('id="about-title"')
    footer = console.find("<footer")
    assert about > console.find("</main>") > 0
    assert footer > about


def test_console_command_no_longer_dominates_the_hero() -> None:
    """The install command must not sit inside the data-first hero.

    The old console rendered the platform terminal beside the H1, which put the
    largest thing on the page at the top and made the numbers feel like a
    caption. The reorder moves that block into its own deploy section below the
    downloads, and this asserts it stayed there.
    """
    console, _ = _pages()
    hero = re.search(r'<section class="data-hero"[^>]*>(.*?)</section>', console, re.DOTALL)
    assert hero is not None
    hero_body = hero.group(1)
    assert 'class="terminal"' not in hero_body
    assert 'class="platforms"' not in hero_body
    assert 'class="copy"' not in hero_body

    # The command still exists on the page, just further down.
    assert console.count('class="terminal"') >= 1
    assert 'id="deploy-title"' in console


def test_hero_chart_carries_the_history_it_advertises() -> None:
    """The hero chart must render actual data with legible axes, not a stub.

    A visual has to earn its position at the top of the page. This checks the
    SVG has a viewBox, y-axis grid lines with numeric labels, and an accessible
    hit target per refresh so a keyboard user can read every column. The chart
    is the reason to lead with data; a decorative sparkline would defeat the
    reorder.
    """
    console, _ = _pages()
    svg = re.search(r'<svg class="hero-svg"[^>]*>(.*?)</svg>', console, re.DOTALL)
    assert svg is not None, "hero SVG missing"
    body = svg.group(0)
    assert 'viewBox="0 0 900 260"' in body
    assert 'role="img"' in body and "aria-label" in body

    # Y-axis: at least three labelled grid lines with numeric values.
    labels = re.findall(r'text-anchor="end">([\d,]+)</text>', body)
    assert len(labels) >= 3, f"expected multiple y-axis labels, got {labels}"

    # A hit column per run means the tooltip serves every refresh, not just a summary.
    # The check uses the manifest's own run count so a light fixture and a full
    # 40-run production history are both valid.
    expected_hits = len(_history())
    hits = re.findall(r'<rect class="hit-col"', body)
    assert len(hits) == expected_hits, (
        f"expected one hit column per history run ({expected_hits}), got {len(hits)}"
    )

    # Roving tabindex: only the first column is initially tabbable, the rest
    # respond to arrow keys. Handing every column its own tab stop would push
    # every element below the hero out of a keyboard user's reach, which is the
    # same defect the /8 address grid used to have.
    tabbable_hits = re.findall(r'<rect class="hit-col"[^>]*tabindex="0"', body)
    reachable_by_arrows = re.findall(r'<rect class="hit-col"[^>]*tabindex="-1"', body)
    assert len(tabbable_hits) == 1, f"expected one tabbable hit column, got {len(tabbable_hits)}"
    assert len(reachable_by_arrows) == len(hits) - 1, "remaining columns must sit at tabindex=-1"
    # Every column still describes its own data through data-tip.
    described = re.findall(r'<rect class="hit-col"[^>]*data-tip="[^"]+"', body)
    assert len(described) == len(hits), "some hit columns have no tip"
    # The client script must actually implement arrow-key movement.
    assert "ArrowRight" in console and "ArrowLeft" in console


def test_project_story_is_reachable_after_the_data() -> None:
    """The about band explains what xfeeds is, but only after the data has spoken.

    Putting the project story below the operational surface is deliberate: an
    operator who already knows what xfeeds is shouldn't have to scroll past
    marketing to reach the corpus. This asserts the story is present, in that
    position, and still names the things that matter contractually — the
    licence tiers and where to file a false positive — which now live in the
    shared footer rather than the about band itself.
    """
    console, _ = _pages()
    about = re.search(r'<section class="about-band"[^>]*>(.*?)</section>', console, re.DOTALL)
    assert about is not None, "about band missing"
    about_body = about.group(1)
    # The about band carries the project story and the analysis surface link.
    assert "analysis surface" in about_body.lower(), "about band missing: analysis surface"
    # Licence tiers and false-positive reporting are in the shared footer,
    # which appears on both pages. Check the full page, not just the about band.
    for phrase in ("licence tiers", "false positive"):
        assert phrase.lower() in console.lower(), f"console page missing: {phrase}"
    # And the story sits below the downloads in source order.
    assert console.find('id="about-title"') > console.find('id="feeds-title"')

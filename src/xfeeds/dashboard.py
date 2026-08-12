"""Static dashboard generation.

Produces a single self-contained HTML file served from GitHub Pages alongside the
feeds. No build step, no framework, no external requests - it reads the same
manifest.json and history.json that the pipeline already writes.
"""

import json
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

PROJECT_URL = "https://github.com/neilweitzel/xfeeds"

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xfeeds — public IP threat intelligence</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --line: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --high: #f85149; --medium: #d29922; --ok: #3fb950; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
  header {{ border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 28px; }}
  h1 {{ margin: 0 0 6px; font-size: 26px; letter-spacing: -0.01em; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: 0.08em;
       color: var(--muted); margin: 36px 0 14px; font-weight: 600; }}
  .sub {{ color: var(--muted); margin: 0; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
  .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
  .card .n {{ font-size: 30px; font-weight: 650; line-height: 1.1; }}
  .card .l {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .high {{ color: var(--high); }} .medium {{ color: var(--medium); }} .ok {{ color: var(--ok); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); }}
  th {{ color: var(--muted); font-weight: 600; font-size: 12px;
        text-transform: uppercase; letter-spacing: 0.05em; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .pill {{ display: inline-block; padding: 1px 8px; border-radius: 999px;
           font-size: 12px; border: 1px solid var(--line); }}
  .pill.ok {{ color: var(--ok); border-color: #1f6f3d; }}
  .pill.warn {{ color: var(--medium); border-color: #6b5117; }}
  .pill.bad {{ color: var(--high); border-color: #7d2b28; }}
  .pill.no {{ color: var(--muted); }}
  code {{ background: var(--panel); border: 1px solid var(--line);
          padding: 2px 6px; border-radius: 5px; font-size: 13px; }}
  pre {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
         padding: 14px; overflow-x: auto; font-size: 13px; }}
  .bar {{ display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--panel); }}
  .bar span {{ display: block; height: 100%; }}
  .note {{ color: var(--muted); font-size: 13px; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }}
  @media (max-width: 760px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
  svg text {{ fill: var(--muted); font-size: 10px; }}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>xfeeds</h1>
  <p class="sub">Corroborated public IP threat intelligence, rebuilt every 6 hours ·
     <a href="{project}">source</a></p>
  <p class="sub" style="margin-top:6px">Last run: <strong>{generated_at}</strong></p>
</header>

<div class="cards">
  <div class="card"><div class="n high">{high}</div><div class="l">high confidence</div></div>
  <div class="card"><div class="n medium">{medium}</div><div class="l">medium confidence</div></div>
  <div class="card"><div class="n">{withheld_pct}%</div><div class="l">withheld (single source)</div></div>
  <div class="card"><div class="n ok">{sources_ok}/{sources_total}</div><div class="l">sources healthy</div></div>
  <div class="card"><div class="n">+{added} / −{removed}</div><div class="l">change this run</div></div>
</div>

<h2>Feed size over time</h2>
{chart_size}

<h2>Additions and removals per run</h2>
{chart_delta}

<div class="grid2">
<div>
<h2>Corroboration</h2>
<p class="note">How many <em>independent</em> source families reported each published
address. Three or more is the safe-to-block tier.</p>
{corroboration}
</div>
<div>
<h2>Downloads</h2>
<table>
<tr><th>File</th><th>Use</th></tr>
<tr><td><a href="high-confidence.txt">high-confidence.txt</a></td><td>firewall block list</td></tr>
<tr><td><a href="medium-confidence.txt">medium-confidence.txt</a></td><td>challenge / rate-limit</td></tr>
<tr><td><a href="all.csv">all.csv</a></td><td>MISP, OpenCTI, Splunk</td></tr>
<tr><td><a href="all.json">all.json</a></td><td>full provenance</td></tr>
<tr><td><a href="stix-bundle.json">stix-bundle.json</a></td><td>STIX 2.1 for TIPs</td></tr>
<tr><td><a href="nftables.conf">nftables.conf</a></td><td>nftables sets</td></tr>
<tr><td><a href="iptables.ipset">iptables.ipset</a></td><td>ipset restore</td></tr>
<tr><td><a href="manifest.json">manifest.json</a></td><td>run metadata</td></tr>
</table>
<pre>curl -sS {base}/high-confidence.txt \\
  | grep -v '^#' | sudo ipset restore -!</pre>
</div>
</div>

<h2>Sources</h2>
<table>
<tr><th>Source</th><th>Independence class</th><th class="num">Records</th>
    <th>Status</th><th>Vote</th><th>Redistributed</th></tr>
{source_rows}
</table>
<p class="note">
  <strong>Independence matters.</strong> Many public blocklists copy from each other,
  so counting files as votes manufactures false confidence. Sources that share
  upstream data share a class, and each class votes at most once.
  Sources marked <em>scoring only</em> inform confidence but their data is never
  republished here, because their licences do not permit it.
</p>

<h2>Safety filters applied this run</h2>
<table>
<tr><th>Rule</th><th class="num">Dropped</th><th>Why it exists</th></tr>
<tr><td>allowlist</td><td class="num">{f_allow}</td>
    <td>cloud, CDN, crawler and resolver ranges must never be blocked</td></tr>
<tr><td>CIDR too wide</td><td class="num">{f_wide}</td>
    <td>a single over-broad prefix can black-hole an entire ISP</td></tr>
<tr><td>non-global</td><td class="num">{f_nonglobal}</td>
    <td>private and reserved space is never publishable</td></tr>
<tr><td>licence</td><td class="num">{f_redist}</td>
    <td>evidence came only from sources we may not republish</td></tr>
<tr><td>annotation only</td><td class="num">{f_tag}</td>
    <td>Tor exits are tagged, never blocked — that is the consumer's choice</td></tr>
</table>

<h2>Licensing</h2>
<p class="note">
  xfeeds compiles publicly available feeds and is not sold. Sources whose terms
  forbid redistribution, or attach ShareAlike obligations, are either used for
  scoring only or excluded outright — Spamhaus attribution travels with the data
  as its terms require. See
  <a href="{project}/blob/main/docs/DECISIONS.md">DECISIONS.md</a> for the
  per-source reasoning.
</p>

<p class="note" style="margin-top:36px">
  Found a false positive? <a href="{project}/issues">Open an issue</a> — those are
  triaged first. To see why any address is listed, run
  <code>xfeeds explain &lt;ip&gt;</code>.
</p>
</div>
</body>
</html>
"""


def _sparkline(
    values: list[float], labels: list[str], color: str, height: int = 90, fill: bool = True
) -> str:
    """Render a minimal inline SVG line chart. No JS, no dependencies."""
    if len(values) < 2:
        return '<p class="note">Not enough history yet — charts appear after a few runs.</p>'
    width = 1040
    pad = 24
    top = max(values) or 1
    bottom = min(values)
    span = max(top - bottom, 1)
    step = (width - 2 * pad) / (len(values) - 1)

    points = [
        (pad + i * step, height - pad - ((v - bottom) / span) * (height - 2 * pad))
        for i, v in enumerate(values)
    ]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area = f"{pad},{height - pad} " + line + f" {pad + (len(values) - 1) * step:.1f},{height - pad}"
    fill_el = f'<polygon points="{area}" fill="{color}" opacity="0.13"/>' if fill else ""
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="trend">'
        f"{fill_el}"
        f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2"/>'
        f'<text x="{pad}" y="12">{labels[0]}</text>'
        f'<text x="{width - pad}" y="12" text-anchor="end">{labels[-1]}</text>'
        f'<text x="{pad}" y="{height - 6}">min {bottom:,.0f}</text>'
        f'<text x="{width - pad}" y="{height - 6}" text-anchor="end">max {top:,.0f}</text>'
        f"</svg>"
    )


def _bars(history: list[dict[str, Any]]) -> str:
    """Added versus removed per run, as opposing bars."""
    if len(history) < 2:
        return '<p class="note">Not enough history yet — charts appear after a few runs.</p>'
    recent = history[-60:]
    width, height, pad = 1040, 110, 20
    mid = height / 2
    peak = max((max(h.get("added", 0), h.get("removed", 0)) for h in recent), default=1) or 1
    slot = (width - 2 * pad) / len(recent)
    bar_w = max(2.0, slot * 0.6)
    parts = []
    for i, h in enumerate(recent):
        x = pad + i * slot
        up = (h.get("added", 0) / peak) * (mid - pad)
        down = (h.get("removed", 0) / peak) * (mid - pad)
        if up:
            parts.append(
                f'<rect x="{x:.1f}" y="{mid - up:.1f}" width="{bar_w:.1f}" '
                f'height="{up:.1f}" fill="#3fb950" opacity="0.85"/>'
            )
        if down:
            parts.append(
                f'<rect x="{x:.1f}" y="{mid:.1f}" width="{bar_w:.1f}" '
                f'height="{down:.1f}" fill="#f85149" opacity="0.85"/>'
            )
    parts.append(
        f'<line x1="{pad}" y1="{mid}" x2="{width - pad}" y2="{mid}" '
        f'stroke="#30363d" stroke-width="1"/>'
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="additions and removals">'
        + "".join(parts)
        + f'<text x="{pad}" y="12">added</text>'
        + f'<text x="{pad}" y="{height - 4}">removed</text>'
        + "</svg>"
    )


def _corroboration_table(manifest: dict[str, Any]) -> str:
    hist = manifest.get("corroboration_histogram", {})
    if not hist:
        return '<p class="note">No data.</p>'
    total = sum(hist.values()) or 1
    promoted = manifest.get("counts", {}).get("promoted", 0)
    rows = []
    for classes, count in sorted(hist.items(), key=lambda kv: int(kv[0])):
        pct = count / total * 100
        colour = "#3fb950" if int(classes) >= 3 else "#d29922"
        label = f"{classes} independent source{'s' if int(classes) != 1 else ''}"
        if int(classes) == 1:
            label += ' <span class="note">(high-precision source, promoted)</span>'
        rows.append(
            f"<tr><td>{label}</td>"
            f'<td class="num">{count:,}</td>'
            f'<td style="width:45%"><div class="bar">'
            f'<span style="width:{pct:.1f}%;background:{colour}"></span></div></td></tr>'
        )
    footnote = (
        f'<p class="note">{promoted:,} of these were promoted by a single '
        "high-precision source — Spamhaus DROP hijacked netblocks and active abuse.ch "
        "command-and-control servers do not need a second opinion. Everything else "
        "required agreement across independent sources.</p>"
        if promoted
        else ""
    )
    return (
        '<table><tr><th>Corroboration</th><th class="num">Addresses</th><th></th></tr>'
        + "".join(rows)
        + "</table>"
        + footnote
    )


def _source_rows(manifest: dict[str, Any]) -> str:
    rows = []
    status_class = {"ok": "ok", "stale": "warn", "empty": "warn", "failed": "bad"}
    for name, info in sorted(manifest.get("sources", {}).items()):
        status = info.get("status", "unknown")
        pill = status_class.get(status, "no")
        vote = (
            '<span class="pill ok">yes</span>'
            if info.get("votes")
            else '<span class="pill no">no</span>'
        )
        redist = (
            '<span class="pill ok">yes</span>'
            if info.get("redistributable")
            else '<span class="pill no">scoring only</span>'
        )
        rows.append(
            f"<tr><td>{name}</td><td>{info.get('independence_class') or '—'}</td>"
            f'<td class="num">{info.get("records", 0):,}</td>'
            f'<td><span class="pill {pill}">{status}</span></td>'
            f"<td>{vote}</td><td>{redist}</td></tr>"
        )
    return "".join(rows)


def render(
    manifest: dict[str, Any],
    history: list[dict[str, Any]],
    base_url: str = "https://neilweitzel.github.io/xfeeds",
) -> str:
    """Render the dashboard HTML."""
    counts = manifest.get("counts", {})
    published = counts.get("published", 0)
    withheld = counts.get("withheld", 0)
    total_seen = published + withheld
    withheld_pct = round(withheld / total_seen * 100) if total_seen else 0

    sources = manifest.get("sources", {})
    filters = manifest.get("filters", {})
    labels = [h["generated_at"][:10] for h in history] or ["—"]

    return _TEMPLATE.format(
        project=PROJECT_URL,
        base=base_url,
        generated_at=manifest.get("generated_at", "unknown")[:19].replace("T", " ") + " UTC",
        high=f"{counts.get('high', 0):,}",
        medium=f"{counts.get('medium', 0):,}",
        withheld_pct=withheld_pct,
        sources_ok=sum(1 for s in sources.values() if s.get("status") == "ok"),
        sources_total=len(sources),
        added=f"{manifest.get('deltas', {}).get('added', 0):,}",
        removed=f"{manifest.get('deltas', {}).get('removed', 0):,}",
        chart_size=_sparkline([h.get("high", 0) for h in history], labels, "#f85149"),
        chart_delta=_bars(history),
        corroboration=_corroboration_table(manifest),
        source_rows=_source_rows(manifest),
        f_allow=f"{filters.get('allowlisted', 0):,}",
        f_wide=f"{filters.get('too_wide', 0):,}",
        f_nonglobal=f"{filters.get('non_global', 0):,}",
        f_redist=f"{filters.get('not_redistributable', 0):,}",
        f_tag=f"{filters.get('tag_only', 0):,}",
    )


def write_dashboard(feeds_dir: Path = Path("feeds")) -> Path:
    """Render index.html next to the feeds so Pages can serve the whole directory."""
    manifest = json.loads((feeds_dir / "manifest.json").read_text(encoding="utf-8"))
    history_path = feeds_dir / "history.json"
    history = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    out = feeds_dir / "index.html"
    out.write_text(render(manifest, history), encoding="utf-8")
    logger.info("dashboard_written", path=str(out), runs_charted=len(history))
    return out

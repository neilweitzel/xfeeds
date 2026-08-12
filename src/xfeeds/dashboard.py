"""Static dashboard generation.

A single self-contained HTML file served from GitHub Pages alongside the feeds.
No framework, no build step, no external requests - it reads the manifest and
history the pipeline already writes.

The audience is someone who needs to block bad IPs and does not have a threat
intelligence platform to do it with. So the page leads with copy-paste setup for
real firewalls, and gives them a lookup box to check a specific address, rather
than leading with statistics about itself.
"""

import ipaddress
import json
from pathlib import Path
from typing import Any

import structlog

from xfeeds.models import Band, ScoredIndicator

logger = structlog.get_logger(__name__)

PROJECT_URL = "https://github.com/neilweitzel/xfeeds"
BASE_URL = "https://neilweitzel.github.io/xfeeds"

STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2129;--line:#30363d;--text:#e6edf3;
--muted:#8b949e;--high:#f85149;--med:#d29922;--ok:#3fb950;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:34px 20px 72px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:30px}
h1{margin:0 0 6px;font-size:28px;letter-spacing:-.02em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
margin:40px 0 14px;font-weight:600}
h3{font-size:15px;margin:20px 0 8px}
.sub{color:var(--muted);margin:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:15px}
.card .n{font-size:29px;font-weight:650;line-height:1.1;font-variant-numeric:tabular-nums}
.card .l{color:var(--muted);font-size:12.5px;margin-top:3px}
.high{color:var(--high)}.med{color:var(--med)}.ok{color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;
letter-spacing:.05em}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;
border:1px solid var(--line);white-space:nowrap}
.pill.ok{color:var(--ok);border-color:#1f6f3d}
.pill.warn{color:var(--med);border-color:#6b5117}
.pill.bad{color:var(--high);border-color:#7d2b28}
.pill.no{color:var(--muted)}
code{background:var(--panel);border:1px solid var(--line);padding:2px 6px;
border-radius:5px;font-size:13px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:13px;
overflow-x:auto;font-size:12.5px;margin:0;position:relative}
pre code{background:none;border:none;padding:0}
.bar{display:flex;height:9px;border-radius:5px;overflow:hidden;background:var(--panel2)}
.bar span{display:block;height:100%}
.note{color:var(--muted);font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:30px}
svg text{fill:var(--muted);font-size:10px}
.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:-1px}
.tab{padding:7px 13px;border:1px solid var(--line);border-bottom:none;
border-radius:7px 7px 0 0;background:var(--panel2);color:var(--muted);cursor:pointer;
font-size:13.5px}
.tab[aria-selected=true]{background:var(--panel);color:var(--text);
box-shadow:inset 0 2px 0 var(--accent)}
.panel{border:1px solid var(--line);border-radius:0 8px 8px 8px;padding:16px;
background:var(--panel)}
.panel pre{background:var(--panel2)}
#look{display:flex;gap:8px;flex-wrap:wrap}
#ip{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--line);
color:var(--text);padding:11px 13px;border-radius:8px;font-size:15px;
font-family:ui-monospace,monospace}
#ip:focus{outline:none;border-color:var(--accent)}
#go{background:var(--accent);color:#06121f;border:0;padding:11px 22px;border-radius:8px;
font-weight:650;cursor:pointer;font-size:14.5px}
#go:hover{filter:brightness(1.1)}
#res{margin-top:14px}
.verdict{border:1px solid var(--line);border-radius:9px;padding:15px;background:var(--panel)}
.verdict.hit-high{border-color:#7d2b28;background:#1b1113}
.verdict.hit-med{border-color:#6b5117;background:#1b1710}
.verdict.miss{border-color:#1f6f3d;background:#101a13}
.vt{font-size:17px;font-weight:650;margin-bottom:6px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:3px 12px;font-size:13.5px;margin-top:10px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
.copy{position:absolute;top:7px;right:7px;background:var(--panel2);border:1px solid var(--line);
color:var(--muted);border-radius:6px;padding:3px 9px;font-size:11.5px;cursor:pointer}
.copy:hover{color:var(--text);border-color:var(--accent)}
.stale{color:var(--med)}
@media(max-width:760px){.grid2{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
"""

SCRIPT = """
// Tabbed setup guides.
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    document.querySelectorAll('.tab').forEach(function(x){x.setAttribute('aria-selected','false')});
    document.querySelectorAll('.tabpanel').forEach(function(x){x.hidden=true});
    t.setAttribute('aria-selected','true');
    document.getElementById(t.dataset.panel).hidden=false;
  });
});

// Copy buttons on every code block.
document.querySelectorAll('pre').forEach(function(pre){
  var b=document.createElement('button');
  b.className='copy'; b.textContent='copy';
  b.addEventListener('click', function(){
    navigator.clipboard.writeText(pre.querySelector('code').innerText);
    b.textContent='copied'; setTimeout(function(){b.textContent='copy'},1400);
  });
  pre.appendChild(b);
});

// IP lookup. Loads a compact index once, on first use, so the page stays fast.
var IDX=null, LOADING=false;
function ipToInt(s){
  var p=s.split('.'); if(p.length!==4) return null;
  var n=0;
  for(var i=0;i<4;i++){
    var o=Number(p[i]);
    if(!Number.isInteger(o)||o<0||o>255||p[i]==='') return null;
    n=n*256+o;
  }
  return n;
}
function render(html){document.getElementById('res').innerHTML=html;}
function esc(s){return String(s).replace(/[&<>]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}

function lookup(){
  var q=document.getElementById('ip').value.trim();
  if(!q){render('');return;}
  var n=ipToInt(q);
  if(n===null){
    render('<div class="verdict"><div class="vt">Not a valid IPv4 address</div>'+
      '<div class="note">Enter something like 45.33.32.156.</div></div>');
    return;
  }
  if(!IDX){
    if(LOADING) return;
    LOADING=true;
    render('<div class="verdict"><div class="vt">Loading index…</div></div>');
    fetch('lookup.json').then(function(r){return r.json();}).then(function(d){
      IDX=d; LOADING=false; lookup();
    }).catch(function(){
      LOADING=false;
      render('<div class="verdict"><div class="vt">Could not load the index</div>'+
        '<div class="note">Try <code>curl -s '+
        'https://neilweitzel.github.io/xfeeds/high-confidence.txt | grep '+esc(q)+
        '</code></div></div>');
    });
    return;
  }
  var hit=null;
  for(var i=0;i<IDX.r.length;i++){
    var e=IDX.r[i];
    if(n>=e[0] && n<=e[1]){hit=e;break;}
  }
  if(!hit){
    render('<div class="verdict miss"><div class="vt">'+esc(q)+
      ' is not in the feed</div><div class="note">It was either never reported, '+
      'reported by only one independent source (so it was withheld), or removed '+
      'by a safety filter such as the allowlist.</div></div>');
    return;
  }
  var band=hit[3], cls=hit[4], score=hit[2], label=hit[5], srcs=hit[6];
  var css = band==='high' ? 'hit-high' : 'hit-med';
  var head = band==='high'
    ? esc(q)+' is listed — high confidence'
    : esc(q)+' is listed — medium confidence';
  // Be precise about WHY it qualified. "1 independent source" next to
  // "corroborated" reads like a contradiction; promotion is a different route.
  var advice;
  if(band==='high' && cls===1){
    advice='Safe to block. Reported by a high-precision source — a Spamhaus DROP '+
      'hijacked netblock or an active abuse.ch command-and-control server. Those '+
      'do not need a second opinion.';
  } else if(band==='high'){
    advice='Safe to block. Corroborated by '+cls+' independent sources.';
  } else {
    advice='Reported by '+cls+' independent source'+(cls===1?'':'s')+'. Consider '+
      'challenging or rate-limiting rather than blocking outright.';
  }
  render('<div class="verdict '+css+'"><div class="vt">'+head+'</div>'+
    '<div class="note">'+advice+'</div>'+
    '<dl class="kv">'+
    '<dt>Matched entry</dt><dd><code>'+esc(label)+'</code></dd>'+
    '<dt>Score</dt><dd>'+score+' / 100</dd>'+
    '<dt>Independent sources</dt><dd>'+cls+(cls===1?' (promoted)':'')+'</dd>'+
    '<dt>Reported by</dt><dd>'+esc(srcs)+'</dd>'+
    '</dl>'+
    '<div class="note" style="margin-top:11px">Think this is wrong? '+
    '<a href="'+PROJECT+'/issues/new?title=False+positive:+'+encodeURIComponent(q)+
    '">Report it as a false positive</a> — those are triaged first.</div></div>');
}
document.getElementById('go').addEventListener('click',lookup);
document.getElementById('ip').addEventListener('keydown',function(e){
  if(e.key==='Enter') lookup();
});
"""


def _sparkline(values: list[float], labels: list[str], colour: str, height: int = 92) -> str:
    if len(values) < 2:
        return (
            '<p class="note">Charts appear once a few runs have accumulated — '
            "the feed refreshes every 6 hours.</p>"
        )
    width, pad = 1020, 24
    top, bottom = max(values), min(values)
    span = max(top - bottom, 1)
    step = (width - 2 * pad) / (len(values) - 1)
    pts = [
        (pad + i * step, height - pad - ((v - bottom) / span) * (height - 2 * pad))
        for i, v in enumerate(values)
    ]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pad},{height - pad} {line} {pad + (len(values) - 1) * step:.1f},{height - pad}"
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="feed size over time">'
        f'<polygon points="{area}" fill="{colour}" opacity="0.13"/>'
        f'<polyline points="{line}" fill="none" stroke="{colour}" stroke-width="2"/>'
        f'<text x="{pad}" y="12">{labels[0]}</text>'
        f'<text x="{width - pad}" y="12" text-anchor="end">{labels[-1]}</text>'
        f'<text x="{pad}" y="{height - 5}">low {bottom:,.0f}</text>'
        f'<text x="{width - pad}" y="{height - 5}" text-anchor="end">high {top:,.0f}</text>'
        f"</svg>"
    )


def _bars(history: list[dict[str, Any]]) -> str:
    if len(history) < 2:
        return (
            '<p class="note">Charts appear once a few runs have accumulated — '
            "the feed refreshes every 6 hours.</p>"
        )
    recent = history[-60:]
    width, height, pad = 1020, 108, 20
    mid = height / 2
    peak = max((max(h.get("added", 0), h.get("removed", 0)) for h in recent), default=1) or 1
    slot = (width - 2 * pad) / len(recent)
    bw = max(2.0, slot * 0.62)
    parts = []
    for i, h in enumerate(recent):
        x = pad + i * slot
        up = (h.get("added", 0) / peak) * (mid - pad)
        dn = (h.get("removed", 0) / peak) * (mid - pad)
        if up:
            parts.append(
                f'<rect x="{x:.1f}" y="{mid - up:.1f}" width="{bw:.1f}" '
                f'height="{up:.1f}" fill="#3fb950" opacity="0.85"/>'
            )
        if dn:
            parts.append(
                f'<rect x="{x:.1f}" y="{mid:.1f}" width="{bw:.1f}" '
                f'height="{dn:.1f}" fill="#f85149" opacity="0.85"/>'
            )
    parts.append(f'<line x1="{pad}" y1="{mid}" x2="{width - pad}" y2="{mid}" stroke="#30363d"/>')
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="additions and removals per run">'
        + "".join(parts)
        + f'<text x="{pad}" y="12">added</text>'
        + f'<text x="{pad}" y="{height - 4}">removed</text></svg>'
    )


def _corroboration(manifest: dict[str, Any]) -> str:
    hist = manifest.get("corroboration_histogram", {})
    if not hist:
        return '<p class="note">No data.</p>'
    total = sum(hist.values()) or 1
    promoted = manifest.get("counts", {}).get("promoted", 0)
    rows = []
    for classes, count in sorted(hist.items(), key=lambda kv: int(kv[0])):
        pct = count / total * 100
        colour = "#3fb950" if int(classes) >= 3 else "#d29922"
        label = f"{classes} source{'s' if int(classes) != 1 else ''}"
        if int(classes) == 1:
            label += ' <span class="note">— promoted, high precision</span>'
        rows.append(
            f'<tr><td>{label}</td><td class="num">{count:,}</td>'
            f'<td style="width:42%"><div class="bar">'
            f'<span style="width:{pct:.1f}%;background:{colour}"></span></div></td></tr>'
        )
    foot = (
        f'<p class="note">{promoted:,} were promoted by a single high-precision source — '
        "Spamhaus DROP hijacked netblocks and active abuse.ch command-and-control servers "
        "do not need a second opinion. Everything else required agreement across "
        "independent sources.</p>"
        if promoted
        else ""
    )
    return (
        '<table><tr><th>Independent sources</th><th class="num">Addresses</th><th></th></tr>'
        + "".join(rows)
        + "</table>"
        + foot
    )


def _sources(manifest: dict[str, Any]) -> str:
    pills = {"ok": "ok", "stale": "warn", "empty": "warn", "skipped": "no", "failed": "bad"}
    rows = []
    for name, info in sorted(manifest.get("sources", {}).items()):
        status = info.get("status", "unknown")
        note = ""
        if status == "stale":
            note = '<div class="note stale">upstream has not updated recently</div>'
        elif status == "skipped":
            note = '<div class="note">needs an API key</div>'
        elif status == "failed":
            note = f'<div class="note">{info.get("error", "")[:80]}</div>'
        rows.append(
            f"<tr><td>{name}{note}</td><td>{info.get('independence_class') or '—'}</td>"
            f'<td class="num">{info.get("records", 0):,}</td>'
            f'<td><span class="pill {pills.get(status, "no")}">{status}</span></td>'
            + (
                '<td><span class="pill ok">yes</span></td>'
                if info.get("votes")
                else '<td><span class="pill no">no</span></td>'
            )
            + (
                '<td><span class="pill ok">yes</span></td>'
                if info.get("redistributable")
                else '<td><span class="pill no">scoring only</span></td>'
            )
            + "</tr>"
        )
    return "".join(rows)


def build_lookup_index(records: list[ScoredIndicator]) -> dict[str, Any]:
    """Compact index powering the in-page lookup.

    Ranges are stored as integer [start, end] pairs so a CIDR match works the
    same as a single address. Roughly 300 KB for 4,000 entries, fetched only when
    somebody actually uses the box.
    """
    rows = []
    for r in sorted(records, key=lambda r: r.sort_key()):
        item = r.ip_or_cidr
        if item.version != 4:
            continue
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            lo = int(item.network_address)
            hi = int(item.broadcast_address)
        else:
            lo = hi = int(item)
        rows.append(
            [
                lo,
                hi,
                round(r.score),
                r.band.value,
                len(r.independence_classes),
                str(item),
                ", ".join(r.sources),
            ]
        )
    return {"v": 1, "r": rows}


def render(
    manifest: dict[str, Any], history: list[dict[str, Any]], base_url: str = BASE_URL
) -> str:
    counts = manifest.get("counts", {})
    published = counts.get("published", 0)
    withheld = counts.get("withheld", 0)
    seen = published + withheld
    pct = round(withheld / seen * 100) if seen else 0
    sources = manifest.get("sources", {})
    filters = manifest.get("filters", {})
    labels = [h["generated_at"][:10] for h in history] or ["—"]
    ok = sum(1 for s in sources.values() if s.get("status") == "ok")
    configured = sum(1 for s in sources.values() if s.get("status") != "skipped")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>xfeeds — free, corroborated IP block lists</title>
<meta name="description" content="A free, automatically updated list of known-bad
IP addresses, compiled from public threat intelligence and corroborated across
independent sources.">
<style>{STYLE}</style></head><body><div class="wrap">

<header>
<h1>xfeeds</h1>
<p class="sub">A free list of known-bad IP addresses you can drop straight into a
firewall. Compiled from public threat intelligence, rebuilt every 6 hours, and
filtered so only addresses that <strong>independent sources agree on</strong> get
published.</p>
<p class="sub" style="margin-top:8px">Updated {manifest.get("generated_at", "")[:16].replace("T", " ")} UTC
· <a href="{PROJECT_URL}">source and docs</a></p>
</header>

<div class="cards">
<div class="card"><div class="n high">{counts.get("high", 0):,}</div>
  <div class="l">safe to block</div></div>
<div class="card"><div class="n med">{counts.get("medium", 0):,}</div>
  <div class="l">worth challenging</div></div>
<div class="card"><div class="n">{pct}%</div>
  <div class="l">rejected as uncorroborated</div></div>
<div class="card"><div class="n ok">{ok}/{configured}</div>
  <div class="l">sources healthy</div></div>
<div class="card"><div class="n">+{manifest.get("deltas", {}).get("added", 0):,} /
  &minus;{manifest.get("deltas", {}).get("removed", 0):,}</div>
  <div class="l">changed this run</div></div>
</div>

<h2>Check an address</h2>
<div id="look">
  <input id="ip" type="text" placeholder="e.g. 45.33.32.156" spellcheck="false"
         autocomplete="off" aria-label="IP address to check">
  <button id="go">Check</button>
</div>
<div id="res"></div>
<p class="note" style="margin-top:10px">Runs entirely in your browser. Nothing is
sent anywhere, and no query is logged.</p>

<h2>Set it up</h2>
<div class="tabs" role="tablist">
  <button class="tab" role="tab" aria-selected="true" data-panel="p-lin">Linux</button>
  <button class="tab" role="tab" aria-selected="false" data-panel="p-nft">nftables</button>
  <button class="tab" role="tab" aria-selected="false" data-panel="p-pf">pfSense / OPNsense</button>
  <button class="tab" role="tab" aria-selected="false" data-panel="p-mt">MikroTik</button>
  <button class="tab" role="tab" aria-selected="false" data-panel="p-cf">Cloudflare</button>
  <button class="tab" role="tab" aria-selected="false" data-panel="p-tip">SIEM / TIP</button>
</div>

<div class="panel">
<div class="tabpanel" id="p-lin">
<h3>iptables with ipset</h3>
<p class="note">Loads the list into an ipset and drops matching traffic. Re-run the
first command from cron every 6 hours to stay current.</p>
<pre><code>curl -sS {base_url}/iptables.ipset | sudo ipset restore -!
sudo iptables -I INPUT -m set --match-set xfeeds src -j DROP</code></pre>
<h3>Keep it updated</h3>
<pre><code># /etc/cron.d/xfeeds
17 */6 * * * root curl -sS {base_url}/iptables.ipset | ipset restore -!</code></pre>
</div>

<div class="tabpanel" id="p-nft" hidden>
<h3>nftables</h3>
<pre><code>curl -sSO {base_url}/nftables.conf
sudo nft -f nftables.conf</code></pre>
<p class="note">Then reference the set in your ruleset:</p>
<pre><code>nft add rule inet filter input ip saddr @blocklist4 drop</code></pre>
</div>

<div class="tabpanel" id="p-pf" hidden>
<h3>pfSense or OPNsense</h3>
<p class="note">Both can fetch a URL table on a schedule — no scripting needed.</p>
<pre><code>Firewall &rarr; Aliases &rarr; Add
  Type: URL Table (IPs)
  URL:  {base_url}/high-confidence.txt
  Update frequency: 1 day

Then Firewall &rarr; Rules &rarr; WAN &rarr; Add
  Action: Block
  Source: the alias you just created</code></pre>
</div>

<div class="tabpanel" id="p-mt" hidden>
<h3>MikroTik RouterOS</h3>
<pre><code>/tool fetch url="{base_url}/high-confidence.txt" dst-path=xfeeds.txt
/import file-name=xfeeds.txt</code></pre>
<p class="note">Or use an address list with a scheduled script. Note that RouterOS
does not skip <code>#</code> comment lines automatically — strip them first.</p>
</div>

<div class="tabpanel" id="p-cf" hidden>
<h3>Cloudflare</h3>
<p class="note">Create an IP Access Rule list from the feed. The free plan caps
custom lists, so the high-confidence tier is the right one to use.</p>
<pre><code>curl -sS {base_url}/high-confidence.txt | grep -v '^#' &gt; xfeeds.txt
# Then: Cloudflare dashboard &rarr; Manage Account &rarr; Configurations
#       &rarr; Lists &rarr; Create new list &rarr; upload xfeeds.txt</code></pre>
</div>

<div class="tabpanel" id="p-tip" hidden>
<h3>MISP</h3>
<pre><code>Sync Actions &rarr; Feeds &rarr; Add Feed
  Input Source: Network
  Format: MISP
  URL: {base_url}/misp-manifest.json</code></pre>
<h3>OpenCTI, Elastic and other STIX consumers</h3>
<pre><code>{base_url}/stix-bundle.json</code></pre>
<h3>Splunk, Sentinel, or a spreadsheet</h3>
<pre><code>{base_url}/all.csv</code></pre>
</div>
</div>

<h2>All downloads</h2>
<table>
<tr><th>File</th><th>What it is</th><th class="num">Entries</th></tr>
<tr><td><a href="high-confidence.txt">high-confidence.txt</a></td>
    <td>Safe to block. Corroborated across independent sources.</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="medium-confidence.txt">medium-confidence.txt</a></td>
    <td>Two independent sources. Challenge or rate-limit rather than drop.</td>
    <td class="num">{counts.get("medium", 0):,}</td></tr>
<tr><td><a href="all.csv">all.csv</a></td>
    <td>Both tiers with scores, sources and dates.</td>
    <td class="num">{published:,}</td></tr>
<tr><td><a href="all.json">all.json</a></td><td>Full provenance per address.</td>
    <td class="num">{published:,}</td></tr>
<tr><td><a href="stix-bundle.json">stix-bundle.json</a></td><td>STIX 2.1 bundle.</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="misp-manifest.json">misp-manifest.json</a></td><td>MISP feed.</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="nftables.conf">nftables.conf</a></td><td>nftables sets.</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="iptables.ipset">iptables.ipset</a></td><td>ipset restore format.</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="manifest.json">manifest.json</a></td>
    <td>Run metadata, per-source status and licences.</td><td class="num">—</td></tr>
<tr><td><a href="history.json">history.json</a></td><td>Per-run history.</td>
    <td class="num">{len(history)}</td></tr>
</table>

<h2>Safe-to-block list over time</h2>
{_sparkline([h.get("high", 0) for h in history], labels, "#f85149")}

<h2>Added and removed each run</h2>
{_bars(history)}

<div class="grid2">
<div>
<h2>How much agreement</h2>
<p class="note">How many <em>independent</em> source families reported each
published address.</p>
{_corroboration(manifest)}
</div>
<div>
<h2>What got filtered out</h2>
<table>
<tr><th>Rule</th><th class="num">Dropped</th></tr>
<tr><td>On the allowlist<div class="note">cloud, CDN, crawlers, public
    resolvers</div></td><td class="num">{filters.get("allowlisted", 0):,}</td></tr>
<tr><td>Prefix too wide<div class="note">one bad /8 can black-hole an
    ISP</div></td><td class="num">{filters.get("too_wide", 0):,}</td></tr>
<tr><td>Private or reserved</td>
    <td class="num">{filters.get("non_global", 0):,}</td></tr>
<tr><td>Licence<div class="note">evidence came only from sources we may not
    republish</div></td><td class="num">{filters.get("not_redistributable", 0):,}</td></tr>
<tr><td>Tor exits<div class="note">tagged, never blocked — that is your
    call</div></td><td class="num">{filters.get("tag_only", 0):,}</td></tr>
</table>
</div>
</div>

<h2>Where the data comes from</h2>
<table>
<tr><th>Source</th><th>Independence class</th><th class="num">Records</th>
    <th>Status</th><th>Votes</th><th>Republished</th></tr>
{_sources(manifest)}
</table>
<p class="note"><strong>Why "independence class" matters.</strong> Many public
blocklists copy from each other, so counting files as votes manufactures false
confidence. Sources that share upstream data share a class, and each class votes
at most once. Sources marked <em>scoring only</em> help decide what is malicious,
but their data is never republished here because their licences do not allow it.</p>

<h2>Licensing</h2>
<p class="note">xfeeds compiles publicly available feeds and is not sold. Feeds
whose terms forbid redistribution, or attach ShareAlike obligations, are either
used for scoring only or excluded outright. Spamhaus attribution travels with the
data as its terms require, and every published file names its contributing
sources. Full per-source reasoning is in
<a href="{PROJECT_URL}/blob/main/docs/DECISIONS.md">DECISIONS.md</a>.</p>

<h2>False positives</h2>
<p class="note">No block list is perfect. If an address here is legitimate,
<a href="{PROJECT_URL}/issues">open an issue</a> — those are triaged ahead of
everything else, and confirmed mistakes are added to a permanent allowlist so
they cannot come back.</p>

<p class="note" style="margin-top:34px;border-top:1px solid var(--line);padding-top:18px">
Provided as-is with no warranty. Test against your own traffic before blocking in
production.</p>

</div>
<script>var PROJECT={json.dumps(PROJECT_URL)};{SCRIPT}</script>
</body></html>
"""


def write_dashboard(feeds_dir: Path = Path("feeds")) -> Path:
    """Render index.html and the lookup index next to the feeds."""
    manifest = json.loads((feeds_dir / "manifest.json").read_text(encoding="utf-8"))
    hpath = feeds_dir / "history.json"
    history = json.loads(hpath.read_text(encoding="utf-8")) if hpath.exists() else []

    published = json.loads((feeds_dir / "all.json").read_text(encoding="utf-8"))
    records = [ScoredIndicator.model_validate(e) for e in published.get("indicators", [])]
    blockable = [r for r in records if r.band is not Band.WITHHELD]
    (feeds_dir / "lookup.json").write_text(
        json.dumps(build_lookup_index(blockable), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    out = feeds_dir / "index.html"
    out.write_text(render(manifest, history), encoding="utf-8")
    logger.info("dashboard_written", path=str(out), runs_charted=len(history))
    return out

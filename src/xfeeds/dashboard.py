"""Static dashboard generation.

A single self-contained HTML file served from GitHub Pages alongside the feeds.
No framework, no build step, no external requests - it reads the manifest and
history the pipeline already writes.

The audience is someone who needs to block bad IPs and does not have a threat
intelligence platform to do it with. So the page leads with copy-paste setup for
real firewalls, and gives them a lookup box to check a specific address, rather
than leading with statistics about itself.
"""

import html
import ipaddress
import json
import math
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


.chart{border:1px solid var(--line);border-radius:10px;padding:14px 15px 10px;margin:20px 0;
background:var(--panel)}
.chead{display:flex;justify-content:space-between;align-items:baseline;gap:12px;
margin-bottom:10px;font-weight:600;font-size:14px}
.chead .note{font-weight:400}
.spectrum,.tl{width:100%;height:auto;display:block;overflow:visible}
.spectrum .bars rect{fill:#58a6ff}
.spectrum .bars rect:hover{fill:#79c0ff}
.spectrum text.ax{fill:var(--muted);font-size:11px;text-anchor:middle}
.tl .a-high{fill:#3fb95055;stroke:#3fb950;stroke-width:1.5}
.tl .a-med{fill:#d2992233;stroke:#d29922;stroke-width:1.2}
.tl .hit{fill:transparent}
.tl .hit:hover{fill:#ffffff18}
.k{display:inline-block;width:9px;height:9px;border-radius:2px;margin:0 4px 0 9px}
.k-high{background:#3fb950}
.k-med{background:#d29922}
.note.warn{color:#d29922}
/* Prefix-width bars. Sized relative to the largest cell rather than to an axis:
   the number beside each bar is the fact, the bar only ranks them at a glance. */
.pbar{height:9px;border-radius:5px;background:#58a6ff;min-width:2px}
td:has(>.pbar){width:34%;padding-right:14px}
.runs{margin:8px 0 0;padding-left:18px;font-size:13px;color:var(--muted);
  line-height:1.85}
.runs code{font-size:12px}
@media (max-width:640px){
/* SVG text scales with the viewBox, so on a phone the axis labels render at about
   four pixels whatever size they are set to. Hide them and let the HTML hint line
   above the chart carry the range, where it is real text at a real size. */
.spectrum text.ax,.spectrum text.rsvl{display:none}
.axhint{flex-direction:column;gap:1px;margin-bottom:8px}
.axhint .axarrow{font-size:12px}
}
.spectrum .rsv{fill:#ffffff07;stroke:var(--line);stroke-width:1;stroke-dasharray:3 3}
.spectrum text.rsvl{fill:var(--muted);font-size:10px;text-anchor:middle;opacity:.75}
.tl .yax{stroke:var(--line);stroke-width:1;stroke-dasharray:2 3}
.tl text.ylab{fill:var(--muted);font-size:10px}
.tscroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
.tscroll table{min-width:520px}
.axhint{display:flex;justify-content:space-between;align-items:baseline;
font-size:11px;color:var(--muted);margin:-4px 0 6px;letter-spacing:.02em}
.axhint .axarrow{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text);
opacity:.75}
.spectrum text.ax{fill:var(--muted);font-size:11px;text-anchor:middle;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.spectrum text.ax.end{fill:var(--text);opacity:.85}
.spectrum .axline{stroke:var(--line);stroke-width:1}
"""

SCRIPT = r"""
// Tabbed setup guides.
// Tabs are scoped to their own group; the page has more than one set.
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    var group = t.closest('.tabgroup') || document;
    group.querySelectorAll('.tab').forEach(function(x){x.setAttribute('aria-selected','false')});
    group.querySelectorAll('.tabpanel').forEach(function(x){x.hidden=true});
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
// IPv6 to BigInt. 128 bits does not fit a JS number, so the v6 index carries its
// bounds as decimal strings and every comparison on this path uses BigInt.
function ip6ToBig(s){
  s=s.trim().replace(/^\[/,'').replace(/\]$/,'');
  var slash=s.indexOf('/');
  if(slash>-1) s=s.slice(0,slash);   // accept a pasted prefix, match its base
  if(s.indexOf(':')<0) return null;
  if((s.match(/::/g)||[]).length>1) return null;
  // IPv4-mapped form such as ::ffff:192.0.2.1 - the trailing dotted quad stands
  // in for the final two 16-bit groups.
  var tail=null;
  if(s.indexOf('.')>-1){
    var cut=s.lastIndexOf(':')+1;
    var v4=ipToInt(s.slice(cut));
    if(v4===null) return null;
    tail=[Math.floor(v4/65536),v4%65536];
    s=s.slice(0,cut)+'0:0';
  }
  function grp(part){
    if(part==='') return [];
    var out=part.split(':');
    for(var i=0;i<out.length;i++){
      if(!/^[0-9a-fA-F]{1,4}$/.test(out[i])) return null;
      out[i]=parseInt(out[i],16);
    }
    return out;
  }
  var halves=s.split('::');
  if(halves.length>2) return null;
  var head=grp(halves[0]); if(head===null) return null;
  var rest=halves.length===2?grp(halves[1]):[]; if(rest===null) return null;
  var total=head.length+rest.length;
  var all;
  if(halves.length===2){
    if(total>7) return null;                       // :: must cover >=1 group
    all=head.concat(new Array(8-total).fill(0)).concat(rest);
  } else {
    if(total!==8) return null;
    all=head;
  }
  if(tail){ all[6]=tail[0]; all[7]=tail[1]; }
  var n=0n;
  for(var j=0;j<8;j++){ n=(n<<16n)+BigInt(all[j]); }
  return n;
}
function render(html){document.getElementById('res').innerHTML=html;}
function esc(s){return String(s).replace(/[&<>]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}

function lookup(){
  var q=document.getElementById('ip').value.trim();
  if(!q){render('');return;}
  var n=ipToInt(q), n6=null;
  if(n===null){ n6=ip6ToBig(q); }
  if(n===null && n6===null){
    render('<div class="verdict"><div class="vt">Not a valid IP address</div>'+
      '<div class="note">Enter something like 45.33.32.156 or '+
      '2001:678:254::1.</div></div>');
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
  if(n6!==null){
    // v6 bounds arrive as decimal strings; compare as BigInt so a 128-bit
    // range is not silently truncated to 53 bits of precision.
    var r6=IDX.r6||[];
    for(var k=0;k<r6.length;k++){
      var f=r6[k];
      if(n6>=BigInt(f[0]) && n6<=BigInt(f[1])){hit=f;break;}
    }
  } else {
    for(var i=0;i<IDX.r.length;i++){
      var e=IDX.r[i];
      if(n>=e[0] && n<=e[1]){hit=e;break;}
    }
  }
  if(!hit){
    render('<div class="verdict miss"><div class="vt">'+esc(q)+
      ' is not in the feed</div><div class="note">It was either never reported, '+
      'reported by only one independent source (so it was withheld), or removed '+
      'by a safety filter such as the allowlist.</div></div>');
    return;
  }
  var band=hit[3], cls=hit[4], score=hit[2], label=hit[5], srcs=hit[6];
  var rst=hit[7]||0;  // classes that corroborated under a non-redistributable licence
  var ref=hit[8]||'';  // upstream listing ticket, where the source publishes one
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
  } else if(band==='high' && rst>0){
    // Some sources are licensed for our own use but not for republication, so we
    // can count their agreement without naming them.
    advice='Safe to block. Corroborated by '+(cls+rst)+' independent sources, '+
      (rst===1?'one of which is':rst+' of which are')+' licensed for our own use '+
      'but not for republication, so '+(rst===1?'it is':'they are')+' not named here.';
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
    '<dt>Independent sources</dt><dd>'+(cls+rst)+(cls===1&&rst===0?' (promoted)':'')+
      (rst>0?' <span class="note">('+rst+' unnamed)</span>':'')+'</dd>'+
    '<dt>Reported by</dt><dd>'+esc(srcs)+'</dd>'+
    (ref?'<dt>Upstream listing</dt><dd><code>'+esc(ref)+'</code> — '+
      '<a href="https://check.spamhaus.org/" rel="noopener">look up the reason '+
      'for this listing</a></dd>':'')+
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

    IPv6 lives in a parallel ``r6`` array with its bounds as decimal **strings**.
    A 128-bit bound cannot survive JSON's number type - it exceeds
    ``Number.MAX_SAFE_INTEGER`` and would silently lose precision - so the client
    parses those with ``BigInt``. Keeping them in a separate array lets the IPv4
    path, which is 98% of lookups, stay on plain numbers.

    Previously v6 records were skipped entirely, so the box reported prefixes the
    feed was actively blocking as not listed.
    """
    rows: list[list[Any]] = []
    rows6: list[list[Any]] = []
    for r in sorted(records, key=lambda r: r.sort_key()):
        item = r.ip_or_cidr
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            lo = int(item.network_address)
            hi = int(item.broadcast_address)
        else:
            lo = hi = int(item)
        common = [
            round(r.score),
            r.band.value,
            len(r.independence_classes),
            str(item),
            ", ".join(r.sources),
            r.restricted_corroboration,
            r.source_reference or "",
        ]
        if item.version == 4:
            rows.append([lo, hi, *common])
        else:
            rows6.append([str(lo), str(hi), *common])
    return {"v": 2, "r": rows, "r6": rows6}


def _ipv6_panel(insights: dict[str, Any]) -> str:
    """What IPv6 coverage exists, how wide it reaches, and what cannot be shown.

    Deliberately not a parallel set of the IPv4 charts. The v6 corpus has no
    variance in score, band, source or category, so each of those charts would be a
    single bar - the appearance of analysis with none of the substance. What is
    shown instead is structural: prefix width, the address space it reaches, and
    which /12 of global unicast space the listings sit in.

    The wide prefixes are defended here rather than in the README. General IPv6
    practice treats a /64 as one actor and a /32 as an entire ISP that should almost
    never be blocked wholesale. Half of these entries are /32 or wider, and without
    the reason an analyst reads the feed as recklessly aggregated.
    """
    fam = (insights or {}).get("families", {}).get("v6")
    if not fam or not fam.get("entries"):
        return ""
    entries = int(fam["entries"])
    sites = int(fam.get("sites_48_total", 0))
    allocations = int(fam.get("distinct_allocations_32", 0))
    classes = int(fam.get("independence_classes", 0))
    sources = fam.get("sources") or []
    blast_by_prefix = fam.get("blast_radius_64_by_prefix", {})
    total_blast = int(fam.get("blast_radius_64_total", 0)) or 1

    prefix_rows = sorted(
        ((str(row["key"]), int(row["count"])) for row in fam.get("prefix_lengths", [])),
        key=lambda kv: int(kv[0].lstrip("/")),
    )
    widest = min((int(k.lstrip("/")) for k, _ in prefix_rows), default=0)
    bars = []
    for key, count in prefix_rows:
        blast = int(blast_by_prefix.get(key, 0))
        share = 100.0 * blast / total_blast
        # The bar encodes reach, not entry count. Encoding entries would put the
        # longest bar against /48 - the rows with the least reach - directly
        # contradicting the two columns beside it and the point this table makes.
        width = max(0.6, share)
        # A row that is a real but tiny fraction must not print as 0.0%: that
        # reads as "none" when it means "three ten-thousandths of a percent".
        share_text = format(share, ".1f") + "%" if share >= 0.1 else "&lt;0.1%"
        bars.append(
            "<tr><td><code>"
            + esc_html(key)
            + "</code></td>"
            + '<td class="num">'
            + str(count)
            + "</td>"
            + '<td><div class="pbar" style="width:'
            + format(width, ".2f")
            + '%"></div></td>'
            + '<td class="num">'
            + format(blast, ",")
            + "</td>"
            + '<td class="num">'
            + share_text
            + "</td></tr>"
        )
    folded_cells = int(fam.get("prefix_lengths_folded_cells", 0))
    folded_entries = int(fam.get("prefix_lengths_folded_entries", 0))
    if folded_cells:
        bars.append(
            '<tr><td class="note">'
            + str(folded_cells)
            + " other widths</td>"
            + '<td class="num">'
            + str(folded_entries)
            + "</td><td></td>"
            + '<td class="num">&mdash;</td><td class="num">&mdash;</td></tr>'
        )

    blocks = "".join(
        "<tr><td><code>"
        + esc_html(str(row["key"]))
        + "</code></td>"
        + '<td class="num">'
        + str(int(row["count"]))
        + "</td></tr>"
        for row in fam.get("unicast_blocks", [])
    )
    folded_blocks = int(fam.get("unicast_blocks_folded_cells", 0))
    if folded_blocks:
        blocks += (
            '<tr><td class="note">'
            + str(folded_blocks)
            + " other block(s)</td>"
            + '<td class="num">'
            + str(int(fam.get("unicast_blocks_folded_entries", 0)))
            + "</td></tr>"
        )

    runs = fam.get("contiguous_runs") or []
    runs_html = ""
    if runs:
        items = "".join(
            "<li><code>"
            + esc_html(str(r["aggregate"]))
            + "</code> &larr; "
            + ", ".join(
                "<code>" + esc_html(str(m)) + "</code>" for r_m in [r["members"]] for m in r_m
            )
            + "</li>"
            for r in runs
        )
        runs_html = (
            "<h3>Adjacent prefixes</h3>"
            + '<p class="note">Listings that sit next to each other in address space. '
            + "Contiguous allocations under common control are a stronger signal than the "
            + "same number of unrelated listings. They are reported, not merged: merging "
            + "would diverge from what the upstream published and lose the per-entry "
            + 'listing reference.</p><ul class="runs">'
            + items
            + "</ul>"
        )

    suppressed = "".join(
        "<tr><td>"
        + esc_html(str(s["analysis"]))
        + "</td>"
        + '<td class="note">'
        + esc_html(str(s["reason"]))
        + "</td></tr>"
        for s in fam.get("suppressed", [])
    )

    concentration = ""
    if classes < 2:
        named = ", ".join(esc_html(str(s)) for s in sources) or "a single source"
        concentration = (
            '<p class="note warn">All IPv6 coverage here comes from one independence '
            + "class ("
            + named
            + "). These records are published on that source&#39;s "
            + "precision alone &mdash; the same basis as a large share of the IPv4 feed "
            + "&mdash; so the limitation is <strong>concentration, not quality</strong>: "
            + "nothing corroborates them, and nothing covers for them if that source "
            + "degrades.</p>"
        )

    return (
        "\n<h2>IPv6 coverage</h2>\n"
        + '<p class="note">'
        + format(entries, ",")
        + " prefixes across "
        + format(allocations, ",")
        + " distinct /32 allocations, reaching "
        + format(sites, ",")
        + " /48 sites. No individual addresses: every entry is a "
        + "prefix.</p>\n"
        + concentration
        + '\n<div class="grid2">\n<div>\n'
        + "<h3>How wide each entry reaches</h3>\n"
        + '<p class="note">Entry count is a poor measure for IPv6 &mdash; a /29 and a '
        + "/48 are both one line and differ by a factor of half a million. The bar and "
        + "the last two columns show reach instead, which is why the most numerous row "
        + "is not the widest bar.</p>\n"
        + '<table>\n<tr><th>Prefix</th><th class="num">Entries</th><th></th>'
        + '<th class="num">/64 subnets</th><th class="num">Reach</th></tr>\n'
        + "".join(bars)
        + "\n</table>\n"
        + '<p class="note">The widest entry is a /'
        + str(widest)
        + ". General IPv6 "
        + "practice treats a /64 as one actor and a /32 as an entire ISP that should "
        + "almost never be blocked outright. These are wider on purpose: Spamhaus DROP "
        + "lists netblocks leased or stolen outright by criminal operations, published "
        + "for firewall and backbone use, where the whole allocation is the finding. "
        + "Review the widest entries before deploying them.</p>\n"
        + "</div>\n<div>\n<h3>Where in global unicast space</h3>\n"
        + '<p class="note">Which /12 of <code>2000::/3</code> the listings fall in, '
        + "derived from the address itself. This is address-space structure, not "
        + "geography &mdash; no registration country is published anywhere on this "
        + "page.</p>\n"
        + '<table><tr><th>Block</th><th class="num">Entries</th></tr>'
        + blocks
        + "</table>\n"
        + runs_html
        + "\n</div>\n</div>\n\n"
        + "<h3>Not shown for IPv6, and why</h3>\n"
        + '<p class="note">Each of these would render a single bar. Listing them is '
        + "more useful than leaving a reader to guess whether we looked.</p>\n"
        + "<table><tr><th>Analysis</th><th>Reason</th></tr>"
        + suppressed
        + "</table>\n"
    )


def esc_html(value: str) -> str:
    """Escape text destined for the page. Source names come from config, but ASN
    descriptions come from a third-party table and are not ours to trust."""
    return html.escape(value, quote=True)


def _spectrum_svg(spectrum: dict[str, Any]) -> str:
    """The whole IPv4 space as one strip, lowest address on the left.

    Address space is the coordinate system this data actually has. Geography was a
    guess wearing a fact's clothes: the country attached to an ASN is where the
    number is registered, which for a hosting company describes its paperwork and
    not its traffic.

    Counts are log-scaled. Linear scaling makes a handful of dense /9s tower over
    everything and the rest of the internet read as empty, which is the opposite of
    the point - the interesting claim here is how much of the space is touched at
    all.
    """
    counts: list[int] = [int(c) for c in spectrum.get("counts", [])]
    if not counts:
        return ""
    width, height = 1000.0, 150.0
    peak = max(counts) or 1
    step = width / len(counts)
    scale = math.log1p(peak)
    bars = []
    for i, count in enumerate(counts):
        if not count:
            continue
        h = (math.log1p(count) / scale) * height
        bars.append(
            f'<rect x="{i * step:.2f}" y="{height - h:.2f}" width="{max(step - 0.35, 0.5):.2f}" '
            f'height="{h:.2f}"><title>{i * 256 // len(counts)}.0.0.0/8 area: '
            f"{count:,} observations</title></rect>"
        )
    # Bare octet numbers along the bottom did not read as addresses - "128" looks
    # like an arbitrary tick. Dotted quads say what the axis is without a caption,
    # and the two ends are labelled explicitly with the real first and last address
    # in the space.
    tick_octets = (32, 64, 96, 128, 160, 192, 224)
    ticks = "".join(
        f'<text x="{(octet / 256) * width:.1f}" y="{height + 16:.0f}" '
        f'class="ax{" minor" if octet % 64 else ""}">{octet}.0.0.0</text>'
        for octet in tick_octets
    )
    # End caps sit inside the plot edges and are anchored so they cannot clip.
    ends = (
        f'<text x="0" y="{height + 16:.0f}" class="ax end" text-anchor="start">0.0.0.0</text>'
        f'<text x="{width:.0f}" y="{height + 16:.0f}" class="ax end" '
        'text-anchor="end">255.255.255.255</text>'
    )
    axis_line = (
        f'<line x1="0" y1="{height + 1:.0f}" x2="{width:.0f}" '
        f'y2="{height + 1:.0f}" class="axline"/>'
    )
    # 224.0.0.0/4 is multicast and 240.0.0.0/4 is reserved, so the right-hand end is
    # legitimately empty. Shade it, or an empty tail reads as a broken chart.
    reserved_x = (224 / 256) * width
    reserved = (
        f'<rect x="{reserved_x:.1f}" y="0" width="{width - reserved_x:.1f}" '
        f'height="{height:.1f}" class="rsv"/>'
        f'<text x="{reserved_x + (width - reserved_x) / 2:.0f}" y="{height / 2:.0f}" '
        'class="rsvl">multicast / reserved</text>'
    )
    occupied = int(spectrum.get("occupied_buckets", 0))
    total = int(spectrum.get("buckets", len(counts)))
    return f"""
<div class="chart">
<div class="chead"><span>Where in the IPv4 space we see activity</span>
<span class="note">{occupied} of {total} slices touched</span></div>
<div class="axhint"><span>horizontal axis: every IPv4 address, in order</span>
<span class="axarrow">0.0.0.0 &rarr; 255.255.255.255</span></div>
<svg viewBox="-58 0 {width + 116:.0f} {height + 26:.0f}" class="spectrum" role="img"
     aria-label="Observations across the IPv4 address space from 0.0.0.0 to
255.255.255.255, log scaled">
{reserved}
<g class="bars">{"".join(bars)}</g>
{axis_line}
{ticks}
{ends}
</svg>
<p class="note">The horizontal axis is the address space itself, low to high, cut
into {total} equal slices of {int(spectrum.get("addresses_per_bucket", 0)):,} addresses
&mdash; so no bar can point at an individual address. Height is log-scaled. The gaps
are as informative as the spikes: reserved ranges, and large allocations nobody has
reported to us.</p>
</div>
"""


def _timeline_svg(history: list[dict[str, Any]]) -> str:
    """Published high and medium counts across every run we have recorded."""
    # History rows carry high/medium at the top level, not under "counts".
    points = [
        (
            int(h.get("high", 0)),
            int(h.get("medium", 0)),
            str(h.get("generated_at", ""))[:16].replace("T", " "),
        )
        for h in history
    ]
    points = [p for p in points if p[0] or p[1]]
    if len(points) < 2:
        return ""
    width, height = 1000.0, 130.0
    peak = max(h + m for h, m, _ in points) or 1
    step = width / max(len(points) - 1, 1)

    def path(values: list[int], stacked: list[int] | None = None) -> str:
        top = []
        for i, v in enumerate(values):
            base = stacked[i] if stacked else 0
            y = height - ((v + base) / peak) * height
            top.append(f"{i * step:.2f},{y:.2f}")
        bottom = []
        for i in range(len(values) - 1, -1, -1):
            base = stacked[i] if stacked else 0
            y = height - (base / peak) * height
            bottom.append(f"{i * step:.2f},{y:.2f}")
        return "M" + " L".join(top + bottom) + " Z"

    highs = [h for h, _, _ in points]
    mediums = [m for _, m, _ in points]
    dots = "".join(
        f'<circle cx="{i * step:.2f}" cy="{height - ((h + m) / peak) * height:.2f}" r="9" '
        f'class="hit"><title>{label}: {h:,} high, {m:,} medium</title></circle>'
        for i, (h, m, label) in enumerate(points)
    )
    return f"""
<div class="chart">
<div class="chead"><span>Published addresses over time</span>
<span class="note">{len(points)} runs &middot; {points[0][2]} to {points[-1][2]}</span></div>
<svg viewBox="0 0 {width:.0f} {height:.0f}" class="tl" role="img"
     aria-label="Published high and medium confidence counts over time">
<path d="{path(mediums, highs)}" class="a-med"/>
<path d="{path(highs)}" class="a-high"/>
<line x1="0" y1="1" x2="{width:.0f}" y2="1" class="yax"/>
<text x="4" y="12" class="ylab">{peak:,} published</text>
{dots}
</svg>
<p class="note"><span class="k k-high"></span>high confidence
<span class="k k-med"></span>medium. Hover any point for the run. Steps rather than
a smooth curve are expected: this refreshes every six hours, and a source dropping
out or returning moves the whole line.</p>
</div>
"""


def _per_million(row: dict[str, Any]) -> str:
    value = row.get("per_million_announced")
    if value is None:
        return "&mdash;"
    return f"{float(value):,.1f}"


def _asn_windows(windows: dict[str, Any]) -> str:
    """Top networks over three windows, with the caveats attached rather than filed.

    Tabs instead of the three side-by-side columns in the sketch: each row carries
    five numbers that only mean something together, and three of those tables abreast
    would have to drop the normalised column - which is the one that stops this being
    a list of the largest hosting providers.
    """
    if not windows.get("available"):
        return ""
    span = int(windows.get("history_span_days", 0))
    tabs = [
        ("last_30_days", "30 days", 30),
        ("last_60_days", "60 days", 60),
        ("all_time", "All time", 0),
    ]

    buttons = []
    panels = []
    for index, (key, label, size) in enumerate(tabs):
        rows = windows.get(key) or []
        selected = "true" if index == 0 else "false"
        buttons.append(
            f'<button class="tab" role="tab" aria-selected="{selected}" '
            f'data-panel="w-{key}">{label}</button>'
        )
        partial = ""
        if size and span < size:
            partial = (
                f'<p class="note warn">Only {span} days of history so far, so this is '
                f"the same as all-time. It will diverge once there is more than {size} "
                "days of record.</p>"
            )
        body = "".join(
            "<tr>"
            f'<td><a href="https://bgp.tools/as/{r["asn"]}">AS{r["asn"]}</a></td>'
            f"<td>{esc_html(str(r['name'])[:38])}</td>"
            f'<td class="num">{int(r["days_active"])}</td>'
            f'<td class="num">{int(r["address_days"]):,}</td>'
            f'<td class="num">{_per_million(r)}</td>'
            f'<td class="num">{int(r["announced_addresses"]):,}</td>'
            "</tr>"
            for r in rows
        )
        panels.append(
            f'<div class="tabpanel" id="w-{key}"{"" if index == 0 else " hidden"}>{partial}'
            '<div class="tscroll">'
            '<table><tr><th>ASN</th><th>Network</th><th class="num">Days seen</th>'
            '<th class="num">Address-days</th><th class="num">Per million</th>'
            '<th class="num">Announced</th></tr>'
            f"{body}</table></div></div>"
        )

    return f"""
<h2>Networks that keep coming back</h2>
<p class="note">Sorted by <strong>days seen</strong>, not by volume. Individual
addresses churn out within about a week, so a big one-day number is an incident and
a network present on eight separate days is a standing pattern. <strong>Per
million</strong> divides by the size of the network: without it a ranking like this
just rediscovers which hosting providers are biggest, which needs no threat feed to
work out.</p>
<div class="tabgroup">
<div class="tabs" role="tablist">{"".join(buttons)}</div>
<div class="panel">{"".join(panels)}</div>
</div>
<p class="note">Dates come from the upstream feed where it publishes them &mdash;
bruteforceblocker carries about a month and ipthreat about ten days, which is why
these windows have depth the project itself does not yet have. Days before we
started running are covered by those two feeds alone and are thinner than recent
days.</p>
"""


def _insights_section(insights: dict[str, Any]) -> str:
    """Aggregate view over every source, including those we may not republish.

    This is the only place a restricted source appears by name against a number.
    Counts are derived facts, not an extract, and no address appears here - see
    insights.py for why that line matters and how it is enforced.
    """
    if not insights:
        return ""
    corpus = insights.get("corpus", {})
    networks = insights.get("networks", {})
    if not networks.get("available"):
        return ""

    top_asns = networks.get("top_asns", [])[:12]
    suppressed = networks.get("suppressed", {})

    asn_rows = "".join(
        "<tr>"
        f'<td><a href="https://bgp.tools/as/{r["asn"]}">AS{r["asn"]}</a></td>'
        f"<td>{esc_html(str(r['name'])[:44])}</td>"
        f'<td class="num">{int(r["addresses"]):,}</td>'
        f'<td class="num">{int(r["sources_reporting"])}</td>'
        "</tr>"
        for r in top_asns
    )

    contributors = insights.get("sources", [])
    scoring_only = [s for s in contributors if not s.get("republished_noncommercial_tier")]
    scoring_rows = "".join(
        "<tr>"
        f"<td>{esc_html(str(s['source']))}</td>"
        f"<td>{esc_html(str(s.get('credit') or ''))[:70]}</td>"
        f'<td class="num">{int(s["addresses_reported"]):,}</td>'
        f'<td class="num">{int(s["reported_only_by_this_source"]):,}</td>'
        "</tr>"
        for s in sorted(scoring_only, key=lambda s: -int(s["addresses_reported"]))
    )

    return f"""
<h2>What the whole corpus looks like</h2>
<p class="note">The feeds above contain only what we are licensed to republish.
These figures cover <strong>everything we look at</strong> —
{int(corpus.get("addresses_observed", 0)):,} addresses from
{int(corpus.get("sources_contributing", 0))} sources across
{int(networks.get("distinct_asns_seen", 0)):,} networks — including sources whose licences
forbid us republishing their addresses. A count is a derived fact, not an extract,
so those sources can finally show their work here.</p>
<p class="note"><strong>No individual address appears in this section</strong>, and
named ASNs or countries with fewer than {int(suppressed.get("threshold", 5))} addresses are
folded into an unnamed bucket ({int(suppressed.get("asns_below_threshold", 0)):,} networks) so
no cell can identify a single address. That is a deliberate limit, not an
oversight: a &ldquo;top offending addresses&rdquo; list would be the data itself
wearing a hat.</p>

<h3>Networks with the most listed addresses in this run</h3>
<div class="tscroll">
<table>
<tr><th>ASN</th><th>Network</th>
    <th class="num">Addresses</th><th class="num">Sources</th></tr>
{asn_rows}
</table>
</div>
<p class="note">The <em>Sources</em> column is the interesting one. A network
reported by nine or ten independent sources is not having a bad week — that is a
sustained pattern, and worth a look at the whole network rather than one address.</p>

<h3>Sources credited here that appear in no feed file</h3>
<div class="tscroll">
<table>
<tr><th>Source</th><th>Credit</th><th class="num">Addresses seen</th>
    <th class="num">Only source</th></tr>
{scoring_rows}
</table>
</div>
<p class="note">Their licences do not let us republish their addresses, so none of
their data is in any download. They still shape every confidence score, and the
numbers above are the work they contributed. The <em>Only source</em> column counts
addresses nobody else reported — evidence we would simply not have without them.</p>
<p class="note">Network attribution in this section uses
<a href="https://iptoasn.com/">IPtoASN</a> by Frank Denis (Public Domain, PDDL v1.0).
It contributes no threat data; it only turns an address into an AS number and a
network name.</p>
"""


def render(
    manifest: dict[str, Any],
    history: list[dict[str, Any]],
    base_url: str = BASE_URL,
    nc_counts: dict[str, int] | None = None,
    insights: dict[str, Any] | None = None,
) -> str:
    spectrum = (insights or {}).get("spectrum", {})
    asn_win = (insights or {}).get("asn_windows", {})
    counts = manifest.get("counts", {})
    nc = nc_counts or {}
    nc_published = nc.get("published", 0)
    nc_high = nc.get("high", 0)
    nc_medium = nc.get("medium", 0)
    published = counts.get("published", 0)
    # Per-family counts come from the manifest rather than being recomputed, and the
    # downloads table uses them instead of the combined high count. Reporting the
    # combined figure against iptables.ipset was how that file's published entry
    # count came to be wrong by every IPv6 record in the feed.
    families = manifest.get("families", {})
    fam4 = families.get("v4", {})
    fam6 = families.get("v6", {})
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
<p class="sub" style="margin-top:8px">Updated {
        manifest.get("generated_at", "")[:16].replace("T", " ")
    } UTC
· <a href="{PROJECT_URL}">source and docs</a></p>
</header>

{_spectrum_svg(spectrum)}
{_timeline_svg(history)}
{_asn_windows(asn_win)}
{_ipv6_panel(insights or {})}

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
<div class="tabgroup">
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
<h3>IPv6</h3>
<p class="note">An ipset holds one address family, so IPv6 needs its own set and its
own rule. Skip this if you are single-stack IPv4.</p>
<pre><code>curl -sS {base_url}/iptables6.ipset | sudo ipset restore -!
sudo ip6tables -I INPUT -m set --match-set xfeeds6 src -j DROP</code></pre>
<h3>Keep it updated</h3>
<pre><code># /etc/cron.d/xfeeds
17 */6 * * * root curl -sS {base_url}/iptables.ipset | ipset restore -!
17 */6 * * * root curl -sS {base_url}/iptables6.ipset | ipset restore -!</code></pre>
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
</div>

<h2>All downloads</h2>
<p class="note">The combined files carry both address families. If your firewall or
tooling is single-stack, take the matching <code>-v4</code> or <code>-v6</code> file
instead &mdash; a v4-only parser will choke on an IPv6 line.</p>
<table>
<tr><th>File</th><th>What it is</th><th>Family</th><th class="num">Entries</th></tr>
<tr><td><a href="high-confidence.txt">high-confidence.txt</a></td>
    <td>Safe to block. Corroborated across independent sources.</td>
    <td>both</td>
    <td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="high-confidence-v4.txt">high-confidence-v4.txt</a></td>
    <td>Safe to block, IPv4 only.</td><td>IPv4</td>
    <td class="num">{fam4.get("high", 0):,}</td></tr>
<tr><td><a href="high-confidence-v6.txt">high-confidence-v6.txt</a></td>
    <td>Safe to block, IPv6 only.</td><td>IPv6</td>
    <td class="num">{fam6.get("high", 0):,}</td></tr>
<tr><td><a href="medium-confidence.txt">medium-confidence.txt</a></td>
    <td>Two independent sources. Challenge or rate-limit rather than drop.</td>
    <td>both</td>
    <td class="num">{counts.get("medium", 0):,}</td></tr>
<tr><td><a href="medium-confidence-v4.txt">medium-confidence-v4.txt</a></td>
    <td>Challenge or rate-limit, IPv4 only.</td><td>IPv4</td>
    <td class="num">{fam4.get("medium", 0):,}</td></tr>
<tr><td><a href="medium-confidence-v6.txt">medium-confidence-v6.txt</a></td>
    <td>Challenge or rate-limit, IPv6 only.</td><td>IPv6</td>
    <td class="num">{fam6.get("medium", 0):,}</td></tr>
<tr><td><a href="all.csv">all.csv</a></td>
    <td>Both tiers with scores, sources and dates.</td><td>both</td>
    <td class="num">{published:,}</td></tr>
<tr><td><a href="all.json">all.json</a></td><td>Full provenance per address.</td>
    <td>both</td><td class="num">{published:,}</td></tr>
<tr><td><a href="stix-bundle.json">stix-bundle.json</a></td><td>STIX 2.1 bundle.</td>
    <td>both</td><td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="misp-manifest.json">misp-manifest.json</a></td><td>MISP feed.</td>
    <td>both</td><td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="nftables.conf">nftables.conf</a></td>
    <td>nftables sets &mdash; <code>blocklist4</code> and <code>blocklist6</code>.</td>
    <td>both</td><td class="num">{counts.get("high", 0):,}</td></tr>
<tr><td><a href="iptables.ipset">iptables.ipset</a></td>
    <td>ipset restore format, set <code>xfeeds</code>.</td><td>IPv4</td>
    <td class="num">{fam4.get("high", 0):,}</td></tr>
<tr><td><a href="iptables6.ipset">iptables6.ipset</a></td>
    <td>ipset restore format, set <code>xfeeds6</code>. An ipset holds one family.</td>
    <td>IPv6</td><td class="num">{fam6.get("high", 0):,}</td></tr>
<tr><td><a href="manifest.json">manifest.json</a></td>
    <td>Run metadata, per-source status and licences.</td><td>&mdash;</td>
    <td class="num">&mdash;</td></tr>
<tr><td><a href="history.json">history.json</a></td><td>Per-run history.</td>
    <td>&mdash;</td><td class="num">{len(history)}</td></tr>
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
<div class="tscroll">
<table>
<tr><th>Source</th><th>Independence class</th><th class="num">Records</th>
    <th>Status</th><th>Votes</th><th>Republished</th></tr>
{_sources(manifest)}
</table>
</div>
<p class="note"><strong>Why "independence class" matters.</strong> Many public
blocklists copy from each other, so counting files as votes manufactures false
confidence. Sources that share upstream data share a class, and each class votes
at most once. Sources marked <em>scoring only</em> help decide what is malicious,
but their data is never republished here because their licences do not allow it.</p>

{_insights_section(insights or {})}

<h2>Two tiers, and which one you want</h2>
<p class="note">Everything above is the <strong>primary feed</strong>. Use it for
anything, including commercial work. No source in it restricts commercial use.</p>
<p class="note">Some good public feeds allow redistribution but forbid commercial
use. We cannot put those in a file that anyone might use at work, so they are
republished separately in
<a href="noncommercial/">the non-commercial tier</a> under CC BY-NC-SA 4.0. It is
larger — <strong>{nc_published:,}</strong> addresses versus {published:,} — because it can
include the Turris Sentinel router-sensor data and StopForumSpam's toxic ranges in
full rather than just counting them as corroboration.</p>
<p class="note"><strong>Home lab, personal server, school, charity, or research?</strong>
Take the non-commercial tier — it sees more. <strong>At a company, or building
anything anyone pays for?</strong> Take the primary feed. That is not a nag; the
licences genuinely differ, and
<a href="noncommercial/LICENSE.txt">LICENSE.txt</a> in that directory spells it
out.</p>
<table>
<tr><th>File</th><th>What it is</th><th class="num">Entries</th></tr>
<tr><td><a href="noncommercial/high-confidence.txt">noncommercial/high-confidence.txt</a></td>
    <td>Safe to block. Non-commercial use only.</td>
    <td class="num">{nc_high:,}</td></tr>
<tr><td><a href="noncommercial/medium-confidence.txt">noncommercial/medium-confidence.txt</a></td>
    <td>Two independent sources. Non-commercial use only.</td>
    <td class="num">{nc_medium:,}</td></tr>
<tr><td><a href="noncommercial/all.json">noncommercial/all.json</a></td>
    <td>Full provenance. Non-commercial use only.</td>
    <td class="num">{nc_published:,}</td></tr>
</table>

<h2>Licensing and credit</h2>
<p class="note">xfeeds compiles publicly available feeds and is not sold. Where a
source forbids redistribution outright it is used for scoring only, or excluded.
Where it permits redistribution but forbids commercial use, it goes in the
non-commercial tier. Every published file names its contributing sources and
carries their terms. Full per-source reasoning, including the sources we rejected
and why, is in
<a href="{PROJECT_URL}/blob/main/docs/DECISIONS.md">DECISIONS.md</a>.</p>
<p class="note">Spamhaus attribution travels with the data as their terms require.
Threat data also provided by
<a href="https://ipthreat.net">IPThreat at https://ipthreat.net</a>, and by the
<a href="https://view.sentinel.turris.cz/">Turris Sentinel</a> project at CZ.NIC
(CC BY-NC-SA 4.0, non-commercial tier only).</p>

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

    # The non-commercial tier has its own manifest. Read it so the page can state
    # honestly how much more that tier sees, rather than describing it vaguely.
    nc_manifest_path = feeds_dir / "noncommercial" / "manifest.json"
    nc_counts: dict[str, int] = {}
    if nc_manifest_path.exists():
        nc_manifest = json.loads(nc_manifest_path.read_text(encoding="utf-8"))
        nc_counts = {k: int(v) for k, v in nc_manifest.get("counts", {}).items()}

    out = feeds_dir / "index.html"
    insights_path = feeds_dir / "insights.json"
    insights: dict[str, Any] = {}
    if insights_path.exists():
        insights = json.loads(insights_path.read_text(encoding="utf-8"))

    out.write_text(
        render(manifest, history, nc_counts=nc_counts, insights=insights), encoding="utf-8"
    )
    logger.info("dashboard_written", path=str(out), runs_charted=len(history))
    return out

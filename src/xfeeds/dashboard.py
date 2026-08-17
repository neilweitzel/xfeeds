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
DOCS_URL = f"{PROJECT_URL}/blob/main/docs/DASHBOARD.md"
DECISIONS_URL = f"{PROJECT_URL}/blob/main/docs/DECISIONS.md"

STYLE = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2129;--line:#30363d;--text:#e6edf3;
--muted:#8b949e;--high:#f85149;--med:#d29922;--ok:#3fb950;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.65 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:34px 20px 72px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:24px}
/* Sticky nav rather than collapsing panels. The page is long because the data is
   worth showing; the fix for length is wayfinding, not concealment. */
nav.toc{position:sticky;top:0;z-index:20;display:flex;gap:2px;flex-wrap:wrap;
background:#0d1117f2;backdrop-filter:blur(8px);border-bottom:1px solid var(--line);
margin:0 -20px 26px;padding:9px 20px}
nav.toc a{color:var(--muted);font-size:12.5px;padding:5px 10px;border-radius:6px;
white-space:nowrap}
nav.toc a:hover{color:var(--text);background:var(--panel);text-decoration:none}
h2[id],section[id]{scroll-margin-top:64px}
h1{margin:0 0 6px;font-size:28px;letter-spacing:-.02em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
margin:40px 0 14px;font-weight:600}
h3{font-size:15px;margin:20px 0 8px}
/* Analysis panels sit under one "Threat landscape" h2, so their own titles are a
   level down and their internal subheadings a level below that. */
h3.ptitle{font-size:17px;margin:32px 0 10px;letter-spacing:-.01em}
h4{font-size:14px;margin:18px 0 7px;color:var(--text)}
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
/* Tooltips carry the one-sentence "why this metric is built this way" that used to
   sit on the page as a paragraph. Hover alone would strand touch and keyboard
   users, so .hint carries tabindex and the :focus rule below does the real work;
   aria-label repeats the text for screen readers. Anything longer than two
   sentences belongs in docs/DASHBOARD.md, not here. */
.hint{position:relative;border-bottom:1px dotted var(--muted);cursor:help;
outline:none}
.hint>.tip{position:absolute;left:0;bottom:calc(100% + 7px);z-index:30;
display:none;width:max-content;max-width:280px;padding:8px 11px;
background:var(--panel2);border:1px solid var(--line);border-radius:7px;
color:var(--text);font-size:12.5px;font-weight:400;line-height:1.5;
text-transform:none;letter-spacing:normal;
box-shadow:0 6px 18px #0009}
.hint:hover>.tip,.hint:focus>.tip,.hint:focus-visible>.tip{display:block}
.hint:focus{border-bottom-color:var(--accent)}
th .hint{color:var(--muted)}
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
.tl .c-add{fill:#3fb950;opacity:.85}
.tl .c-rem{fill:#f85149;opacity:.85}
.tl .cax{stroke:var(--line);stroke-width:1}
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
        f'<p class="note">{promoted:,} '
        + _hint(
            "promoted by a single high-precision source",
            "Spamhaus DROP hijacked netblocks and active abuse.ch "
            "command-and-control servers do not need a second opinion. Everything "
            "else required agreement across independent classes.",
        )
        + ".</p>"
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
            "<h4>"
            + _hint(
                "Adjacent prefixes",
                "Contiguous allocations under common control are a stronger signal "
                "than the same number of unrelated listings. They are reported, not "
                "merged: merging would diverge from what the upstream published.",
            )
            + "</h4>"
            + '<p class="note">Listings that sit next to each other in address '
            + 'space.</p><ul class="runs">'
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
            '<p class="note warn">All IPv6 coverage comes from one independence class ('
            + named
            + "), so the limitation is "
            + _hint(
                "concentration, not quality",
                "These records rest on that source's precision alone, the same basis "
                "as a large share of the IPv4 feed. Nothing corroborates them, and "
                "nothing covers for them if that source degrades.",
            )
            + ".</p>"
        )

    return (
        '\n<h3 class="ptitle">IPv6 coverage</h3>\n'
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
        + "<h4>How wide each entry reaches</h4>\n"
        + '<table>\n<tr><th>Prefix</th><th class="num">Entries</th><th></th>'
        + f'<th class="num">/64 subnets</th><th class="num">{_REACH_TH}</th></tr>\n'
        + "".join(bars)
        + "\n</table>\n"
        + '<p class="note warn">Widest entry is a /'
        + str(widest)
        + ". "
        + _hint(
            "Wide on purpose, not recklessly aggregated",
            "General IPv6 practice treats a /64 as one actor and a /32 as an entire "
            "ISP that should almost never be blocked outright. Spamhaus DROP lists "
            "netblocks leased or stolen outright by criminal operations, published "
            "for firewall and backbone use, where the whole allocation is the "
            "finding.",
        )
        + " &mdash; review the widest entries before deploying them.</p>\n"
        + "</div>\n<div>\n<h4>Where in global unicast space</h4>\n"
        + '<p class="note">Which /12 of <code>2000::/3</code> the listings fall in. '
        + _hint(
            "Address-space structure, not geography",
            "No registration country is published anywhere on this page: an ASN's "
            "registration location does not establish where its traffic originates.",
        )
        + ".</p>\n"
        + '<table><tr><th>Block</th><th class="num">Entries</th></tr>'
        + blocks
        + "</table>\n"
        + runs_html
        + "\n</div>\n</div>\n\n"
        + "<h4>Not shown for IPv6, and why</h4>\n"
        + '<p class="note">Each would render a single bar. '
        + _hint(
            "Listed rather than silently omitted",
            "Saying which analyses were considered and rejected is more useful "
            "than leaving a reader to guess whether we looked at all.",
        )
        + ".</p>\n"
        + "<table><tr><th>Analysis</th><th>Reason</th></tr>"
        + suppressed
        + "</table>\n"
    )


def esc_html(value: str) -> str:
    """Escape text destined for the page. Source names come from config, but ASN
    descriptions come from a third-party table and are not ours to trust."""
    return html.escape(value, quote=True)


def _hint(label: str, tip: str) -> str:
    """A metric label carrying its own one-sentence rationale.

    These explanations used to sit on the page as paragraphs, which is most of why
    it read as verbose. They are not decoration though: a ranking normalised per
    million of announced space means nothing if you do not know why it is
    normalised, and an analyst who does not know why IPv6 entries are /32 wide
    reads the feed as recklessly aggregated. So the reasoning moves onto the label
    it explains rather than being deleted, and the long form lives in
    docs/DASHBOARD.md.

    ``tabindex`` is what makes this work outside a mouse: the CSS shows the tip on
    :focus as well as :hover, so touch and keyboard both reach it, and aria-label
    repeats it for screen readers. Plain text in, escaped here - do not pass HTML
    entities.
    """
    return (
        f'<span class="hint" tabindex="0" role="note" aria-label="{esc_html(tip)}">'
        f'{label}<span class="tip">{esc_html(tip)}</span></span>'
    )


# Terms whose meaning is not self-evident, hinted where the reader meets them.
#
# These live in the note directly above or below their table, never inside a `th`.
# A `.tscroll` wrapper is `overflow:auto`, which clips any absolutely positioned
# descendant that escapes its box - so a tip anchored to a table header computed as
# visible and then painted nowhere at all, for mouse and keyboard alike. Tables
# without a scroll wrapper may hint inline safely; test_dashboard.py enforces the
# distinction rather than trusting this comment.
_DAYS_SEEN_HINT = _hint(
    "Days seen",
    "Individual addresses churn out of most upstream feeds within about a week, so "
    "a large one-day count is an incident while a network seen on eight separate "
    "days is a standing pattern.",
)
_PER_MILLION_HINT = _hint(
    "Per million",
    "Divided by the size of the network's announced address space. Without that, a "
    "ranking like this just rediscovers which hosting providers are biggest.",
)
_CLASS_HINT = _hint(
    "Independence class",
    "Many public blocklists copy or aggregate each other, so counting files as "
    "votes manufactures false confidence. Sources sharing upstream data share a "
    "class, and each class votes at most once.",
)
_REDIST_HINT = _hint(
    "scoring only",
    "Sources marked scoring only help decide what is malicious, but their licences "
    "do not let us republish their addresses, so none of their data appears in any "
    "download.",
)
_SOURCES_HINT = _hint(
    "the Sources column",
    "A network reported by nine or ten independent sources is not having a bad "
    "week. That is a sustained pattern, worth examining at network level rather "
    "than address by address.",
)
_ONLY_SOURCE_HINT = _hint(
    "Only source",
    "Addresses nobody else reported - evidence the feed would simply not have "
    "without this source, even though its data never ships.",
)
_REACH_TH = _hint(
    "Reach",
    "Entry count is a poor measure for IPv6: a /29 and a /48 are both one line and "
    "differ by a factor of half a million. Reach counts covered /64 networks "
    "instead, which is why the most numerous row is not the widest bar.",
)


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
<h3 class="ptitle">Where in the IPv4 space we see activity</h3>
<div class="chart">
<div class="chead"><span>One bar per /9 slice, log-scaled</span>
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
<p class="note">{total} equal slices of
{int(spectrum.get("addresses_per_bucket", 0)):,} addresses, so
{
        _hint(
            "no bar points at an individual address",
            "The slicing is deliberate. A per-address chart would be the restricted "
            "data itself in a thin disguise, so occupancy is only ever shown at "
            "slice resolution.",
        )
    }.
{
        _hint(
            "Gaps are as informative as spikes",
            "A gap is either a reserved range or a large allocation nobody has "
            "reported to us. Height is log-scaled, because linear scaling flattens "
            "everything except the two or three busiest slices.",
        )
    }.</p>
</div>
"""


def _history_panel(history: list[dict[str, Any]]) -> str:
    """Feed size and per-run churn in one chart, on one shared time axis.

    Previously this was three separate charts in two disconnected places on the
    page: this stacked area, a high-confidence sparkline that was a strict subset
    of it, and an added/removed bar chart far below. Churn is only meaningful
    against the total it changes, so the bars belong on the same x axis as the
    line they move - reading them 800 pixels apart asked the reader to hold two
    unaligned axes in their head, and the sparkline said nothing this does not.
    """
    # History rows carry high/medium/added/removed at the top level, not under
    # "counts".
    points = [
        (
            int(h.get("high", 0)),
            int(h.get("medium", 0)),
            int(h.get("added", 0)),
            int(h.get("removed", 0)),
            str(h.get("generated_at", ""))[:16].replace("T", " "),
        )
        for h in history
    ]
    points = [p for p in points if p[0] or p[1]]
    if len(points) < 2:
        return (
            '<p class="note">Charts appear once a few runs have accumulated &mdash; '
            "the feed refreshes every 6 hours.</p>"
        )

    width, height = 1000.0, 130.0
    # The churn strip hangs below the area chart and shares its x mapping, so a
    # spike in the bars sits directly under the step it caused in the line.
    gap, churn_h = 16.0, 56.0
    churn_top = height + gap
    churn_mid = churn_top + churn_h / 2
    total_h = churn_top + churn_h

    peak = max(h + m for h, m, _, _, _ in points) or 1
    step = width / max(len(points) - 1, 1)
    churn_peak = max((max(a, r) for _, _, a, r, _ in points), default=1) or 1

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

    highs = [h for h, _, _, _, _ in points]
    mediums = [m for _, m, _, _, _ in points]

    # Bars are clamped inside the plot box so the churn strip shares its exact left
    # and right edges with the area chart above it. Centring the first and last bar
    # on their data point would push them past the axis and break that alignment,
    # which is the whole reason the two views share one axis.
    bw = max(1.5, step * 0.5)
    bars = []
    for i, (_, _, added, removed, _) in enumerate(points):
        x = min(max(i * step - bw / 2, 0.0), width - bw)
        up = (added / churn_peak) * (churn_h / 2)
        dn = (removed / churn_peak) * (churn_h / 2)
        if up:
            bars.append(
                f'<rect x="{x:.2f}" y="{churn_mid - up:.2f}" width="{bw:.2f}" '
                f'height="{up:.2f}" class="c-add"/>'
            )
        if dn:
            bars.append(
                f'<rect x="{x:.2f}" y="{churn_mid:.2f}" width="{bw:.2f}" '
                f'height="{dn:.2f}" class="c-rem"/>'
            )

    # One hover target per run spanning both regions, so a single hover reports
    # the size and the churn together rather than needing two separate hovers.
    hits = "".join(
        f'<rect x="{min(max(i * step - step / 2, 0.0), width - step):.2f}" y="0" '
        f'width="{step:.2f}" '
        f'height="{total_h:.0f}" class="hit">'
        f"<title>{label}: {h:,} high, {m:,} medium &#183; "
        f"+{a:,} / &#8722;{r:,} this run</title></rect>"
        for i, (h, m, a, r, label) in enumerate(points)
    )

    return f"""
<div class="chart">
<div class="chead"><span>Feed size and churn per run</span>
<span class="note">{len(points)} runs &middot; {points[0][4]} to {points[-1][4]}</span></div>
<svg viewBox="0 0 {width:.0f} {total_h:.0f}" class="tl" role="img"
     aria-label="Published high and medium confidence counts over time, with
     addresses added and removed each run">
<path d="{path(mediums, highs)}" class="a-med"/>
<path d="{path(highs)}" class="a-high"/>
<line x1="0" y1="1" x2="{width:.0f}" y2="1" class="yax"/>
<text x="4" y="12" class="ylab">{peak:,} published</text>
{"".join(bars)}
<line x1="0" y1="{churn_mid:.2f}" x2="{width:.0f}" y2="{churn_mid:.2f}" class="cax"/>
{hits}
</svg>
<p class="note"><span class="k k-high"></span>high confidence
<span class="k k-med"></span>medium, with additions above and removals below the
centre line, on the same time axis. Bars scale to &plusmn;{churn_peak:,}, the largest
single-run change. Hover any run for its figures.</p>
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
                f'<p class="note warn">Only {span} days of history, so this matches '
                f"all-time until the record passes {size} days.</p>"
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
            "<table><tr><th>ASN</th><th>Network</th>"
            '<th class="num">Days seen</th>'
            '<th class="num">Address-days</th>'
            '<th class="num">Per million</th>'
            '<th class="num">Announced</th></tr>'
            f"{body}</table></div></div>"
        )

    return f"""
<h3 class="ptitle">Networks that keep coming back</h3>
<p class="note">Ranked by {_DAYS_SEEN_HINT}, not volume, so a standing pattern
outranks a one-day incident. {_PER_MILLION_HINT} normalises for network size.
<a href="{DOCS_URL}">Reading this panel</a>.</p>
<div class="tabgroup">
<div class="tabs" role="tablist">{"".join(buttons)}</div>
<div class="panel">{"".join(panels)}</div>
</div>
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
<h3 class="ptitle">What the whole corpus looks like</h3>
<p class="note">{int(corpus.get("addresses_observed", 0)):,} addresses from
{int(corpus.get("sources_contributing", 0))} sources across
{int(networks.get("distinct_asns_seen", 0)):,} networks &mdash; everything the pipeline
looks at, not only what it may republish, because {
        _hint(
            "a count is a derived fact, not an extract",
            "That is why restricted sources can be credited with figures here even "
            "though their addresses never appear in any feed file.",
        )
    }.</p>
<p class="note"><strong>No individual address appears in this section.</strong> ASNs
under {int(suppressed.get("threshold", 5))} addresses fold into an unnamed bucket
({int(suppressed.get("asns_below_threshold", 0)):,} networks). There is no
top-offending-addresses list, by design.</p>

<h4>Networks with the most listed addresses in this run</h4>
<div class="tscroll">
<table>
<tr><th>ASN</th><th>Network</th>
    <th class="num">Addresses</th><th class="num">Sources</th></tr>
{asn_rows}
</table>
</div>
<p class="note">{_SOURCES_HINT} is the one to read first.</p>

<h4>Sources credited here that appear in no feed file</h4>
<p class="note">Their licences forbid republishing their addresses, so none of their
data ships. They still shape every confidence score.</p>
<div class="tscroll">
<table>
<tr><th>Source</th><th>Credit</th><th class="num">Addresses seen</th>
    <th class="num">Only source</th></tr>
{scoring_rows}
</table>
</div>
<p class="note">{_ONLY_SOURCE_HINT} counts what nobody else reported.</p>
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
firewall. Rebuilt every 6 hours from public threat intelligence, and filtered so only
addresses that <strong>independent sources agree on</strong> get published.</p>
<p class="sub" style="margin-top:8px">Updated {
        manifest.get("generated_at", "")[:16].replace("T", " ")
    } UTC
· <a href="{PROJECT_URL}">source</a>
· <a href="{DOCS_URL}">how to read this page</a></p>
</header>

<nav class="toc" aria-label="Sections">
<a href="#lookup">Check an address</a>
<a href="#downloads">Downloads</a>
<a href="#setup">Set it up</a>
<a href="#health">Feed health</a>
<a href="#sources">Sources</a>
<a href="#analysis">Threat landscape</a>
<a href="#licensing">Licensing</a>
</nav>

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

<h2 id="lookup">Check an address</h2>
<div id="look">
  <input id="ip" type="text" placeholder="e.g. 45.33.32.156" spellcheck="false"
         autocomplete="off" aria-label="IP address to check">
  <button id="go">Check</button>
</div>
<div id="res"></div>
<p class="note" style="margin-top:10px">Runs entirely in your browser. Nothing is
sent anywhere, and no query is logged.</p>

<h2 id="downloads">Downloads</h2>
<p class="note">Combined files carry both address families. Single-stack tooling
wants the matching <code>-v4</code> or <code>-v6</code> file instead &mdash; a v4-only
parser will choke on an IPv6 line.</p>
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

<h2 id="setup">Set it up</h2>
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

<h2 id="health">Feed health</h2>
{_history_panel(history)}
<p class="note">{ok} of {configured} sources returned data this run. {
        _hint(
            "A stalled refresh alerts automatically",
            "A heartbeat compares the committed manifest against the one published "
            "to Pages and alerts after four missed refreshes, so a stalled pipeline "
            "is not left for a reader to notice.",
        )
    } &mdash; <a href="#sources">per-source status</a> below.</p>

<h2 id="sources">Sources and provenance</h2>
<h3>Where the data comes from</h3>
<div class="tscroll">
<table>
<tr><th>Source</th><th>Independence class</th><th class="num">Records</th>
    <th>Status</th><th>Votes</th><th>Republished</th></tr>
{_sources(manifest)}
</table>
</div>
<p class="note">{_CLASS_HINT} groups sources that share upstream data, and a source
marked {_REDIST_HINT} never appears in a download. Per-source admit and reject
reasoning is in <a href="{DECISIONS_URL}">DECISIONS.md</a>.</p>

<div class="grid2">
<div>
<h3>How much agreement</h3>
<p class="note">Independent source families &mdash; not files &mdash; reporting each
published address.</p>
{_corroboration(manifest)}
</div>
<div>
<h3>What got filtered out</h3>
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

<h2 id="analysis">Threat landscape</h2>
<p class="note">Aggregate structure of the whole corpus, including sources whose
data is never republished. <a href="{DOCS_URL}">Reader's guide to these panels</a>.</p>
{_spectrum_svg(spectrum)}
{_asn_windows(asn_win)}
{_ipv6_panel(insights or {})}
{_insights_section(insights or {})}

<h2 id="licensing">Tiers and licensing</h2>
<p class="note">Everything above is the <strong>primary feed</strong>:
{published:,} addresses, no commercial restriction. The
<a href="noncommercial/">non-commercial tier</a> holds
<strong>{nc_published:,}</strong> under CC BY-NC-SA 4.0 and {
        _hint(
            "sees more",
            "It can carry share-alike material in full rather than only counting it "
            "as corroboration, so it covers addresses the primary feed must "
            "withhold.",
        )
    }.</p>
<p class="note">At a company, or building anything anyone pays for: primary. Home
lab, school, charity, or research: non-commercial. Terms in
<a href="noncommercial/LICENSE.txt">LICENSE.txt</a>.</p>
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

<h3>Credit</h3>
<p class="note">xfeeds compiles publicly available feeds and is not sold. Every
published file names its contributing sources and carries their terms.</p>
<p class="note">Spamhaus attribution travels with the data as their terms require.
Threat data also provided by
<a href="https://ipthreat.net">IPThreat at https://ipthreat.net</a>, and by the
<a href="https://view.sentinel.turris.cz/">Turris Sentinel</a> project at CZ.NIC
(CC BY-NC-SA 4.0, non-commercial tier only).</p>

<h2>False positives</h2>
<p class="note">No block list is perfect. If an address here is legitimate,
<a href="{PROJECT_URL}/issues">open an issue</a> &mdash; those are triaged first, and
confirmed mistakes go on a permanent allowlist so they cannot come back.</p>

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

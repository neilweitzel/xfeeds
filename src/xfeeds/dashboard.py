"""Self-contained Direction A dashboard generation.

The public dashboard is intentionally a pair of static documents rather than an
application: firewall operators can copy a command without waiting on a service,
while analysts get a deeper surface that is generated solely from committed feed
artifacts. Keeping all assets inline makes both pages deployable from any static
host without another operational dependency.
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
ORCID_URL = "https://orcid.org/0009-0007-2546-2331"
CONCEPT_DOI = "10.5281/zenodo.22045733"
CONCEPT_DOI_URL = f"https://doi.org/{CONCEPT_DOI}"

STYLE = '\n:root{--bg:#0C0C0D;--surface:#16161A;--surface2:#1D1D22;--line:#26262C;--line2:#34343B;--text:#EDEDEF;--muted:#9B9BA3;--faint:#6A6A72;--orange:#FF6A3D;--orange-d:#B84828;--high:#E5484D;--medium:#E0A82E;--ok:#B6D67A;--mono:ui-monospace,SFMono-Regular,Menlo,"Cascadia Mono",Consolas,monospace;--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;--s1:.25rem;--s2:.5rem;--s3:.75rem;--s4:1rem;--s5:1.25rem;--s6:1.5rem;--s8:2rem;--s10:2.5rem;--s12:3rem;--s16:4rem;--s20:5rem;--r:8px}\n*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:84px}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:16px;line-height:1.5}.mono,.file,code,.num,time,.stat b,.entry-count,.source-name,.asn{font-family:var(--mono);font-variant-numeric:tabular-nums lining-nums}a{color:var(--orange);text-decoration-thickness:1px;text-underline-offset:3px}a:hover{color:#FF8F6E}button,input{font:inherit;color:inherit}button{cursor:pointer}button:focus-visible,a:focus-visible,input:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--orange);outline-offset:3px}.skip,.sr-only{position:absolute;left:-999px;top:0}.skip{background:var(--orange);color:#160904;padding:10px 14px;z-index:100;font-weight:700}.skip:focus{left:10px;top:10px}.shell{max-width:1280px;margin:0 auto;padding:0 var(--s8)}.status-strip{border-bottom:1px solid var(--line);background:#111115}.status-inner{max-width:1280px;margin:auto;min-height:54px;padding:0 var(--s8);display:flex;align-items:center;gap:var(--s3);font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden}.status-inner strong{color:var(--text);font-weight:600}.pulse{color:var(--ok);font-size:18px;line-height:0}.divider{color:var(--faint)}.stale-link{color:#EABF4E}.brandbar{height:74px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--text);font-weight:700;letter-spacing:-.02em}.brand:hover{color:var(--text)}.brand-mark{width:26px;height:26px;color:var(--orange)}.brand-meta{font-size:12px;color:var(--muted);font-family:var(--mono);letter-spacing:.03em}.topnav{display:flex;align-items:center;gap:20px;font-size:14px}.topnav a{color:var(--muted);text-decoration:none}.topnav a:hover{color:var(--text)}.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:650}.console-hero{padding:clamp(34px,5vw,68px) 0 34px;display:grid;grid-template-columns:5.2fr 6.8fr;gap:clamp(32px,3.4vw,48px);border-bottom:1px solid var(--line)}.console-hero>*,.lookup-grid>*{min-width:0}h1,h2,h3,p{margin:0}h1{font-size:clamp(32px,2.85vw,42px);line-height:1.03;letter-spacing:-.045em;font-weight:700;margin:13px 0 18px;max-width:none}h2{font-size:22px;letter-spacing:-.025em;line-height:1.15}h3{font-size:16px;letter-spacing:-.01em}.lede{color:var(--muted);max-width:32ch}.stat-rail{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;margin-top:28px}.stat{min-width:0;padding:0 10px;border-left:1px solid var(--line)}.stat:first-child{padding-left:0;border-left:0}.stat b{font-size:21px;display:block;line-height:1.1;letter-spacing:-.05em}.stat span{display:block;color:var(--muted);font-size:12px;line-height:1.3;margin-top:5px}.command-wrap{align-self:start}.platforms{display:flex;overflow-x:auto;scrollbar-width:none;border-bottom:1px solid var(--line)}.platforms::-webkit-scrollbar{display:none}.platform{border:0;background:transparent;color:var(--muted);padding:10px 13px 11px;white-space:nowrap;font-size:13px;border-bottom:2px solid transparent}.platform[aria-selected=true]{color:var(--text);border-bottom-color:var(--orange)}.terminal{position:relative;background:var(--surface);border:1px solid var(--line2);border-radius:var(--r);padding:25px 84px 18px 24px}.terminal::before{content:\'● ● ●\';color:#6A5353;letter-spacing:4px;font-size:10px;position:absolute;top:10px;left:15px}.terminal code{display:block;font-size:15px;line-height:1.75;white-space:pre-wrap;overflow-wrap:anywhere;color:#F4F0E7}.prompt{color:var(--orange);user-select:none}.copy{position:absolute;right:13px;top:14px;min-height:42px;border:1px solid var(--orange);background:var(--orange);color:#24110A;border-radius:6px;padding:0 14px;font-size:13px;font-weight:750}.copy:hover{background:#FF8F6E}.command-note{margin-top:12px;color:var(--muted);font-size:13px}.command-note code{color:var(--text);font-size:12px}.availability{margin-top:25px;display:flex;gap:12px;align-items:center;color:var(--muted);font-size:12px}.availability span{white-space:nowrap}.run-strip{height:34px;display:flex;gap:3px;align-items:end;flex:1}.run-tick{display:block;flex:1;min-width:2px;padding:0;border:0;background:#707079;border-radius:1px 1px 0 0}.run-tick.partial{box-shadow:inset 0 2px 0 #D48E35}.run-tick.severe{box-shadow:inset 0 2px 0 #EABF4E,inset 0 0 0 1px #EABF4E}.run-tick:hover,.run-tick:focus-visible{background:var(--orange);outline:none}.section{padding:36px 0;border-bottom:1px solid var(--line)}.section-head{display:flex;justify-content:space-between;gap:20px;align-items:baseline;margin-bottom:17px}.section-sub{font-size:13px;color:var(--muted);margin-top:5px}.lookup-grid{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:44px;align-items:start}.lookup-form{display:flex;gap:9px;margin-top:18px}.lookup-form input{min-width:0;flex:1;height:48px;padding:0 14px;border:1px solid var(--line2);border-radius:6px;background:var(--surface);font-family:var(--mono);font-size:15px}.lookup-form input::placeholder{color:var(--faint)}.action{height:48px;border:0;border-radius:6px;background:var(--orange);color:#23100A;padding:0 17px;font-weight:750}.action:hover{background:#FF8F6E}.privacy{display:block;margin-top:9px;color:var(--muted);font-size:12px}.verdict{border:1px solid var(--line2);border-radius:var(--r);background:var(--surface);padding:18px}.verdict-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.verdict-label{font-family:var(--mono);font-size:12px;letter-spacing:.09em;text-transform:uppercase}.tag{font-size:11px;font-family:var(--mono);border:1px solid currentColor;border-radius:999px;padding:3px 7px;white-space:nowrap}.tag.high{color:var(--high)}.tag.medium{color:var(--medium)}.tag.clear{color:var(--ok)}.verdict-address{font-family:var(--mono);font-size:22px;line-height:1.15;margin:12px 0 7px;overflow-wrap:anywhere}.verdict p{font-size:13px;color:var(--muted)}.verdict dl{display:grid;grid-template-columns:110px 1fr;gap:5px 12px;margin:15px 0 0;font-size:12px}.verdict dt{color:var(--faint)}.verdict dd{margin:0;font-family:var(--mono);overflow-wrap:anywhere}.feed-groups{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:32px}.feed-group+.feed-group{border-left:1px solid var(--line);padding-left:32px}.feed-group h3{font-family:var(--mono);font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:11px}.feed-row{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:12px;align-items:center;padding:10px 0;border-top:1px solid var(--line)}.file{font-size:13px;overflow-wrap:anywhere}.family{font:11px var(--mono);color:var(--muted);border:1px solid var(--line2);border-radius:99px;padding:2px 6px}.entry-count{font-size:12px;color:var(--muted);text-align:right;white-space:nowrap}.feeds-foot{margin-top:18px;font-size:12px;color:var(--muted)}.callout-link{margin-top:16px;border-top:1px solid var(--line);padding-top:16px;display:flex;justify-content:space-between;gap:22px;align-items:center;font-size:14px}.callout-link b{font-family:var(--mono);font-weight:600;color:var(--text)}footer{color:var(--muted);font-size:12px}footer.shell{padding-top:var(--s10);padding-bottom:var(--s12)}.foot-grid{display:grid;grid-template-columns:1fr 1fr;gap:28px}.foot-grid p+p{margin-top:9px}.footer-note{margin-top:20px;border-top:1px solid var(--line);padding-top:14px;color:var(--faint)}\n/* analysis */.analysis-shell{display:grid;grid-template-columns:202px minmax(0,1fr);gap:50px;padding-top:34px}.analysis-nav{position:sticky;top:20px;align-self:start}.back{display:inline-flex;gap:7px;align-items:center;font-size:13px;text-decoration:none;color:var(--muted);margin-bottom:30px}.analysis-nav .nav-label{font:11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-bottom:8px}.analysis-nav a{display:block;border-left:1px solid var(--line);padding:7px 0 7px 12px;color:var(--muted);font-size:13px;text-decoration:none}.analysis-nav a.active,.analysis-nav a:hover{border-color:var(--orange);color:var(--text)}.analysis-main{min-width:0;padding-bottom:54px}.analysis-heading{padding-bottom:35px;border-bottom:1px solid var(--line)}.analysis-heading h1{max-width:17ch;margin-bottom:14px}.analysis-heading .lede{max-width:58ch}.analysis-section{padding:45px 0;border-bottom:1px solid var(--line)}.analysis-section h2{font-size:26px}.wide-chart{margin-top:25px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:18px}.chart-top{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:9px}.chart-top strong{font-size:14px}.chart-top span{color:var(--muted);font:12px var(--mono)}.history-wrap{position:relative}.history-svg{width:100%;height:auto;overflow:visible}.history-svg .grid{stroke:#38383F;stroke-dasharray:3 5}.history-svg text{fill:#9B9BA3;font:11px var(--mono)}.history-svg .high-line{stroke:#FF6A3D;fill:none;stroke-width:2.2}.history-svg .medium-line{stroke:#9898A1;fill:none;stroke-width:1.5}.history-svg .area{fill:#FF6A3D;opacity:.1}.history-svg .add{stroke:#D8DDAD;stroke-width:3}.history-svg .remove{stroke:#D7846F;stroke-width:3}.history-svg .hit{fill:transparent;cursor:pointer}.history-svg .hit:focus{outline:none;fill:#ffffff10}.chart-tooltip{min-height:28px;margin-top:8px;color:var(--muted);font:12px var(--mono)}.chart-tooltip strong{color:var(--text)}.rank-grid{display:grid;grid-template-columns:1fr 1fr;gap:42px;margin-top:28px}.rank-grid>section{min-width:0;overflow:hidden}.rank-title{display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:10px}.rank-title h3{font-size:15px}.rank-title span{min-width:0;font:12px var(--mono);color:var(--muted);text-align:right}.rank-row{padding:9px 0;border-top:1px solid var(--line)}.rank-line{display:flex;justify-content:space-between;gap:14px;font-size:13px}.rank-line b{font-family:var(--mono);font-weight:500;white-space:nowrap}.rank-line span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.track{height:4px;background:#29292F;margin-top:7px}.fill{height:100%;background:var(--orange)}.fill.dim{background:#85858F}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:25px}.spectrum-wrap{margin-top:24px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:18px}.spectrum{width:100%;height:auto;overflow:visible}.spectrum text{fill:#9B9BA3;font:11px var(--mono)}.spectrum .rsv{fill:#2A2928;stroke:#5A514A;stroke-dasharray:4 4}.spectrum .bar{fill:#FF6A3D}.spectrum .bar.low{opacity:.3}.spectrum .bar.mid{opacity:.6}.spectrum .bar.high{opacity:1}.spectrum .leader{stroke:#FFB094;stroke-width:1}.chart-annotation{display:none}.note{color:var(--muted);font-size:13px;margin-top:12px}.source-table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);margin-top:20px}.source-table{border-collapse:collapse;width:100%;min-width:710px;font-size:13px}.source-table th,.source-table td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.source-table tr:last-child td{border:0}.source-table th{font:11px var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:#141418}.source-table .num{text-align:right}.status-ok{color:var(--ok)}.status-stale{color:#EABF4E}.status-text{font:12px var(--mono)}.license-row{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:22px}.tier{border-top:1px solid var(--line);padding-top:14px}.tier h3{font:13px var(--mono);letter-spacing:.08em;text-transform:uppercase}.tier p{font-size:13px;color:var(--muted);margin-top:7px}.mini-list{margin:12px 0 0;padding-left:18px;color:var(--muted);font-size:13px}.mini-list li+li{margin-top:5px}\n@media(max-width:820px){.shell{padding:0 var(--s5)}.status-inner{padding:0 var(--s5)}.status-inner .optional{display:none}.console-hero{grid-template-columns:1fr;gap:30px}.lookup-grid{grid-template-columns:1fr}.feed-groups{grid-template-columns:1fr;gap:20px}.feed-group+.feed-group{border-left:0;border-top:1px solid var(--line);padding-left:0;padding-top:20px}.analysis-shell{display:block;padding-top:22px}.analysis-nav{position:sticky;top:0;z-index:4;background:var(--bg);padding:10px 0 12px;border-bottom:1px solid var(--line);margin-bottom:28px;display:flex;gap:14px;overflow-x:auto}.analysis-nav .back,.analysis-nav .nav-label{display:none}.analysis-nav a{display:inline-block;border-left:0;border-bottom:1px solid var(--line);padding:5px 0;white-space:nowrap}.analysis-nav a.active{border-bottom-color:var(--orange)}.rank-grid,.two-col,.license-row{grid-template-columns:1fr;gap:28px}.foot-grid{grid-template-columns:1fr}.availability{align-items:flex-start}.run-strip{min-width:120px}.analysis-section{padding:36px 0}}\n@media(max-width:520px){.brandbar{height:62px}.brand-meta{display:none}.topnav{gap:13px;font-size:12px}.console-hero{padding-top:32px}h1{font-size:36px}.stat-rail{grid-template-columns:repeat(2,minmax(0,1fr));margin-top:23px}.stat{padding:0 12px 16px}.stat:nth-child(odd){border-left:0;padding-left:0}.terminal{padding:25px 16px 18px}.terminal code{font-size:12px;line-height:1.7;padding-top:20px}.copy{right:10px;top:10px}.lookup-form{flex-direction:column}.lookup-form input,.action{width:100%}.verdict{margin-top:4px}.section{padding:30px 0}.section-head{display:block}.section-head h2{font-size:21px}.callout-link{display:block}.callout-link a{display:block;margin-top:8px}.feed-row{grid-template-columns:minmax(0,1fr) auto}.entry-count{grid-column:2}.family{grid-column:2;grid-row:1}.availability span{display:none}.availability .run-strip{display:flex}.analysis-heading h1{font-size:34px}.analysis-section h2{font-size:23px}.rank-title span{display:none}.wide-chart,.spectrum-wrap{margin-left:-4px;margin-right:-4px;padding:13px}.spectrum .annotation{display:none}.chart-annotation{display:block;margin:6px 0 9px;color:var(--muted);font-size:12px;line-height:1.4}.chart-annotation strong{color:var(--text)}.chart-top{display:block}.chart-top span{display:block;margin-top:4px}.verdict dl{grid-template-columns:96px 1fr}.status-inner{font-size:12px}.status-inner .cadence{display:none}}\n@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}\n\n\n/* Direction A additions kept inline so both published surfaces stay portable. */\n.hint{position:relative;border-bottom:1px dotted var(--muted);cursor:help;outline:none}\n.hint>.tip{display:none;position:absolute;z-index:20;left:0;bottom:calc(100% + 7px);width:max-content;max-width:300px;padding:8px 10px;border:1px solid var(--line2);border-radius:6px;background:var(--surface2);color:var(--text);font:12px/1.45 var(--sans);letter-spacing:normal;text-transform:none;box-shadow:0 8px 22px #0009}\n.hint:hover>.tip,.hint:focus>.tip,.hint:focus-visible>.tip{display:block}\n.filter-bar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin-top:22px;padding:14px 16px;border:1px solid var(--line2);border-radius:var(--r);background:var(--surface)}\n.filter-bar label{display:grid;gap:4px;color:var(--muted);font:11px var(--mono);letter-spacing:.08em;text-transform:uppercase}\n.filter-bar select{min-width:150px;border:1px solid var(--line2);border-radius:5px;background:var(--bg);padding:7px 9px;color:var(--text);font:13px var(--mono)}\n.filter-status{color:var(--muted);font-size:12px;margin-left:auto}.filter-status b{color:var(--text);font-family:var(--mono)}\n.funnel{display:grid;gap:8px;margin-top:22px}.funnel-step{display:grid;grid-template-columns:minmax(116px,150px) minmax(0,1fr) minmax(78px,100px);gap:12px;align-items:center;font-size:13px}.funnel-bar{height:28px;display:flex;align-items:center;padding:0 10px;background:var(--surface2);border-left:3px solid var(--orange);font-family:var(--mono);font-variant-numeric:tabular-nums}.funnel-step.minus .funnel-bar{border-color:var(--medium);color:var(--muted)}.funnel-step.final .funnel-bar{border-color:var(--ok);color:var(--text)}.funnel-step strong{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}.funnel-rule{color:var(--muted);font-size:12px}\n.ipv4-grid{display:grid;gap:3px;margin-top:15px}.ipv4-grid-row{display:grid;grid-template-columns:repeat(16,minmax(0,1fr));gap:3px}.ip-grid-cell{position:relative;aspect-ratio:1;border:1px solid #3b332f;background:rgba(255,106,61,var(--level));padding:0;color:transparent;font:9px var(--mono)}.ip-grid-cell.edge{color:var(--muted);font-size:9px}.ip-grid-cell.reserved{background:#2a2928;border-style:dashed;border-color:#5a514a}.ip-grid-cell:focus-visible,.ip-grid-cell:hover{outline:2px solid var(--orange);z-index:1}.ip-grid-cell .tip{display:none;position:absolute;z-index:22;left:0;top:calc(100% + 5px);width:210px;padding:7px;background:var(--surface2);border:1px solid var(--line2);border-radius:5px;color:var(--text);font:12px/1.35 var(--sans);text-align:left}.ip-grid-cell:hover .tip,.ip-grid-cell:focus .tip{display:block}.grid-legend{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font:12px var(--mono);margin-top:10px}.grid-key{display:flex;gap:6px;align-items:center}.grid-key i{width:12px;height:12px;background:rgba(255,106,61,.72);border:1px solid #4a312a}.grid-key i.reserved{background:#2a2928;border-style:dashed;border-color:#5a514a}.wide-prefix{margin-top:24px;padding:15px;border-left:3px solid var(--medium);background:var(--surface);color:var(--muted);font-size:13px}.wide-prefix strong{color:var(--text)}\n.prefix-table,.network-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}.prefix-table th,.prefix-table td,.network-table th,.network-table td{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left}.prefix-table th,.network-table th{font:11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.prefix-table .num,.network-table .num{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums}.network-table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);margin-top:16px}.network-table{min-width:590px;margin:0}.empty-filter{padding:16px;border:1px dashed var(--line2);color:var(--muted);font-size:13px;margin-top:18px}.table-scroll{overflow-x:auto;margin-top:12px}\n@media print{html,body{background:#fff!important;color:#000!important;font-size:12pt}.status-strip,.brandbar,.analysis-nav,.skip,.platforms,.copy,.lookup-form,.filter-bar,.action{display:none!important}a{color:#000!important;text-decoration:underline}.shell{max-width:none;padding:0}.console-hero,.lookup-grid,.feed-groups,.analysis-shell,.rank-grid,.two-col,.license-row{display:block}.console-hero,.section,.analysis-section,.wide-chart,.spectrum-wrap,.feed-group,.source-table-wrap,table,svg{break-inside:avoid;page-break-inside:avoid}.platform-panel[hidden],.tabpanel[hidden]{display:block!important}.platform-panel{margin-top:12px}.terminal,.verdict,.wide-chart,.spectrum-wrap,.filter-bar{background:#fff!important;border-color:#555!important}.terminal code{color:#000!important}.analysis-shell{padding-top:0}.analysis-main{padding:0}.analysis-heading{padding-top:0}.hint>.tip{display:none!important}.ipv4-grid-row{display:grid!important}.ip-grid-cell{border-color:#777!important;background:#ddd!important}.ip-grid-cell.reserved{background:#eee!important}.footer-note{color:#333!important}footer.shell{padding-top:16px;padding-bottom:0}}\n'

STYLE += """
/* Data-first console hero. Numbers rail sits at hero size above a 40-run history
   chart, so the value of the corpus is the first thing an operator sees. */
.data-hero{padding:clamp(38px,5vw,72px) 0 32px;border-bottom:1px solid var(--line)}
.data-hero .eyebrow{margin-bottom:12px}
.data-hero h1{font-size:clamp(30px,3.2vw,44px);line-height:1.02;letter-spacing:-.045em;font-weight:700;margin:6px 0 22px;max-width:22ch}
.hero-numbers{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;margin-bottom:34px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.hero-num{padding:22px 20px;border-left:1px solid var(--line);min-width:0}.hero-num:first-child{border-left:0;padding-left:0}
.hero-num b{display:block;font-family:var(--mono);font-variant-numeric:tabular-nums lining-nums;font-size:clamp(30px,4vw,52px);letter-spacing:-.05em;line-height:1;color:var(--text)}
.hero-num .hero-num-label{display:block;font:11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-top:9px}
.hero-num .hero-num-detail{display:block;color:var(--muted);font-size:12px;margin-top:5px}
.hero-num.accent b{color:var(--orange)}
.hero-chart-wrap{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:20px 22px 16px}
.hero-chart-head{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between;margin-bottom:10px}
.hero-chart-head h2{font-size:16px;letter-spacing:-.01em}.hero-chart-head .hero-chart-legend{display:flex;flex-wrap:wrap;gap:16px;color:var(--muted);font:12px var(--mono)}
.hero-chart-legend i{display:inline-block;width:11px;height:11px;margin-right:6px;vertical-align:-1px;border-radius:2px}
.hero-chart-legend .lg-high{background:var(--orange)}.hero-chart-legend .lg-medium{background:#7f7f88}.hero-chart-legend .lg-adds{background:var(--ok)}.hero-chart-legend .lg-removes{background:#D7846F}
.hero-svg{width:100%;height:auto;overflow:visible;display:block}
.hero-svg .axis text{fill:#9B9BA3;font:11px var(--mono)}.hero-svg .grid-line{stroke:#26262C}
.hero-svg .area-high{fill:var(--orange);opacity:.14}.hero-svg .area-med{fill:#7f7f88;opacity:.10}
.hero-svg .line-high{fill:none;stroke:var(--orange);stroke-width:2.4;stroke-linejoin:round}
.hero-svg .line-med{fill:none;stroke:#B0B0B8;stroke-width:1.8;stroke-linejoin:round;stroke-dasharray:5 4}
.hero-svg .flow-add{stroke:var(--ok);stroke-width:0}.hero-svg .flow-remove{stroke:#D7846F;stroke-width:0}
.hero-svg .hit-col{fill:transparent;cursor:pointer}.hero-svg .hit-col:hover,.hero-svg .hit-col:focus-visible{fill:#ffffff10;outline:none}
.hero-chart-tip{display:flex;flex-wrap:wrap;gap:6px 16px;min-height:22px;margin-top:10px;color:var(--muted);font:12px var(--mono)}
.hero-chart-tip strong{color:var(--text)}
.hero-runs-strip{display:flex;gap:3px;align-items:end;height:24px;margin-top:6px}
.hero-runs-strip .run-tick{flex:1;min-width:3px;border-radius:1px 1px 0 0}
.hero-runs-label{display:flex;justify-content:space-between;align-items:baseline;margin-top:14px;color:var(--muted);font:12px var(--mono)}
.hero-runs-label strong{color:var(--text);font-weight:600}
.hero-runs-label .run-key{display:flex;gap:12px;align-items:center}
.hero-runs-label .run-key i{display:inline-block;width:10px;height:10px;border-radius:1px;vertical-align:-1px;margin-right:4px}
.hero-runs-label .run-key .k-ok{background:#707079}
.hero-runs-label .run-key .k-partial{background:#707079;box-shadow:inset 0 2px 0 #D48E35}
.hero-runs-label .run-key .k-severe{background:#707079;box-shadow:inset 0 2px 0 #EABF4E,inset 0 0 0 1px #EABF4E}
.hero-followups{display:flex;flex-wrap:wrap;justify-content:space-between;gap:14px;margin-top:16px;font-size:13px;color:var(--muted)}
.hero-followups a{color:var(--orange);text-decoration:none;border-bottom:1px dotted currentColor}
.deploy-band{border-top:1px solid var(--line)}
.deploy-band .section-head h2{font-size:20px}
.deploy-band .command-wrap{margin-top:16px}
.about-band{background:#0F0F13;border-top:1px solid var(--line)}
.about-band .about-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:44px;padding:46px 0 30px}
.about-band .about-grid h2{font-size:22px;letter-spacing:-.02em}
.about-band .about-grid p{margin-top:12px;color:var(--muted);max-width:52ch}
.about-band .about-grid .mono{font-size:.92em;letter-spacing:-0.01em}
.nowrap{white-space:nowrap}
.about-band .about-grid p+p{margin-top:12px}
.about-band .about-grid strong{color:var(--text)}
@media(max-width:820px){.hero-numbers{grid-template-columns:repeat(2,minmax(0,1fr))}.hero-num{padding:18px 14px;border-left:0;border-top:1px solid var(--line)}.hero-num:nth-child(-n+2){border-top:0}.hero-num:nth-child(odd){padding-left:0}.hero-num:nth-child(even){border-left:1px solid var(--line)}.about-band .about-grid{grid-template-columns:1fr;padding:32px 0 22px;gap:22px}}
@media(max-width:520px){.hero-num b{font-size:34px}.hero-chart-wrap{padding:15px}.hero-chart-head{gap:8px}.hero-chart-head .hero-chart-legend{gap:10px;font-size:11px}}
@media print{.data-hero{padding:0 0 20px}.hero-chart-wrap{background:#fff!important;border-color:#777!important}.hero-svg .area-high,.hero-svg .area-med{opacity:.25!important}.about-band{background:#fff!important}}
.funnel,.ip-grid-cell,.history-svg,.chart-tooltip,.asn-persistence,.corroboration,.class-overlap,.ipv6-coverage{font-variant-numeric:tabular-nums lining-nums}
.asn-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0 10px}.asn-tab{border:1px solid var(--line2);border-radius:999px;background:transparent;color:var(--muted);padding:6px 10px;font:12px var(--mono)}.asn-tab[aria-selected=true]{border-color:var(--orange);background:#2d1913;color:var(--text)}.asn-window-panel{margin-top:0}.asn-window-panel .network-table-wrap{margin-top:12px}.network-table-wrap+.note{margin-top:10px}.corroboration-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-top:14px}.corroboration-cell{padding:10px;border:1px solid var(--line2);border-radius:6px;background:var(--bg)}.corroboration-cell b{display:block;font:600 19px var(--mono);letter-spacing:-.04em}.corroboration-cell span{display:block;color:var(--muted);font-size:11px;line-height:1.25;margin-top:4px}.evidence-table{margin-top:12px}.evidence-table h3{margin-bottom:2px}
@media(max-width:520px){.corroboration-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.asn-tabs{gap:5px}.asn-tab{padding:5px 8px}}
"""

CONSOLE_SCRIPT = r"""
(function () {
  const tabs = Array.from(document.querySelectorAll('.platform'));
  const panels = Array.from(document.querySelectorAll('.platform-panel'));
  function choose(tab) {
    tabs.forEach(function (item) { item.setAttribute('aria-selected', item === tab ? 'true' : 'false'); });
    panels.forEach(function (panel) { panel.hidden = panel.id !== tab.getAttribute('aria-controls'); });
  }
  tabs.forEach(function (tab, index) {
    tab.addEventListener('click', function () { choose(tab); });
    tab.addEventListener('keydown', function (event) {
      if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
        (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      tabs[next].focus(); choose(tabs[next]);
    });
  });
  document.querySelectorAll('.copy').forEach(function (button) {
    const status = button.parentNode.querySelector('.copy-status');
    let pending = null;
    // The button carries an aria-label, which masks its own text from screen
    // readers, so the visible label and the announcement are updated separately.
    function report(message) {
      if (pending === null) return;
      clearTimeout(pending); pending = null;
      button.textContent = message;
      if (status) status.textContent = message;
      setTimeout(function () { button.textContent = 'Copy'; if (status) status.textContent = ''; }, 2200);
    }
    button.addEventListener('click', function () {
      const code = document.querySelector('#' + button.dataset.copy + ' code');
      if (code === null) return;
      const text = code.innerText.replace(/^\$ /gm, '');
      pending = setTimeout(function () {
        // Sandboxed and unfocused documents can leave writeText permanently
        // unsettled, which used to leave the click with no acknowledgement at
        // all. Selecting the command is a fallback that always works.
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges(); selection.addRange(range);
        report('Selected');
      }, 500);
      try {
        navigator.clipboard.writeText(text).then(
          function () { report('Copied'); },
          function () { report('Press Ctrl+C'); }
        );
      } catch (error) { report('Press Ctrl+C'); }
    });
  });

  // Hero history chart tooltips. Each column has a data-tip; a single delegated
  // listener on the SVG updates one live-region paragraph, so a screen reader
  // hears the same run summary a sighted reader sees on hover.
  const heroTip = document.getElementById('hero-chart-tip');
  const heroSvg = document.querySelector('.hero-svg');
  if (heroSvg) {
    // Roving tabindex over the run columns. Without this the chart added one tab
    // stop per refresh (40 today), which pushed everything after it out of reach.
    const cols = Array.from(heroSvg.querySelectorAll('.hit-col'));
    heroSvg.addEventListener('keydown', function (event) {
      const current = cols.indexOf(document.activeElement);
      if (current < 0) return;
      const moves = {ArrowRight: current + 1, ArrowLeft: current - 1, Home: 0, End: cols.length - 1};
      if (!(event.key in moves)) return;
      const next = Math.max(0, Math.min(cols.length - 1, moves[event.key]));
      event.preventDefault();
      cols.forEach(function (col) { col.tabIndex = -1; });
      cols[next].tabIndex = 0;
      cols[next].focus();
    });
  }
  if (heroTip && heroSvg) {
    const defaultTip = heroTip.innerHTML;
    function showTip(target) { heroTip.innerHTML = '<strong>' + target.dataset.tip.split('  ')[0] + '</strong> ' + target.dataset.tip.split('  ').slice(1).join(' '); }
    heroSvg.addEventListener('mouseover', function (event) { if (event.target.classList.contains('hit-col')) showTip(event.target); });
    heroSvg.addEventListener('focusin', function (event) { if (event.target.classList.contains('hit-col')) showTip(event.target); });
    heroSvg.addEventListener('mouseleave', function () { heroTip.innerHTML = defaultTip; });
    heroSvg.addEventListener('focusout', function () { heroTip.innerHTML = defaultTip; });
  }

  let index = null;
  let loading = false;
  const form = document.getElementById('lookup-form');
  const input = document.getElementById('ip');
  const output = document.getElementById('verdict');
  function escapeHtml(value) { return String(value).replace(/[&<>]/g, function (char) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;'}[char];
  }); }
  function ipToInt(value) {
    const parts = value.split('.'); if (parts.length !== 4) return null;
    let number = 0;
    for (let i = 0; i < 4; i += 1) {
      const octet = Number(parts[i]);
      if (!Number.isInteger(octet) || octet < 0 || octet > 255 || parts[i] === '') return null;
      number = number * 256 + octet;
    }
    return number;
  }
  function ip6ToBig(value) {
    let address = value.trim().replace(/^\[/, '').replace(/\]$/, '');
    const slash = address.indexOf('/'); if (slash > -1) address = address.slice(0, slash);
    if (address.indexOf(':') < 0 || (address.match(/::/g) || []).length > 1) return null;
    let tail = null;
    if (address.indexOf('.') > -1) {
      const cut = address.lastIndexOf(':') + 1; const v4 = ipToInt(address.slice(cut));
      if (v4 === null) return null;
      tail = [Math.floor(v4 / 65536), v4 % 65536]; address = address.slice(0, cut) + '0:0';
    }
    function groups(part) {
      if (part === '') return [];
      const result = part.split(':');
      for (let i = 0; i < result.length; i += 1) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(result[i])) return null;
        result[i] = parseInt(result[i], 16);
      }
      return result;
    }
    const halves = address.split('::'); const head = groups(halves[0]);
    const rest = halves.length === 2 ? groups(halves[1]) : [];
    if (head === null || rest === null || halves.length > 2) return null;
    let all;
    if (halves.length === 2) {
      if (head.length + rest.length > 7) return null;
      all = head.concat(new Array(8 - head.length - rest.length).fill(0)).concat(rest);
    } else { if (head.length !== 8) return null; all = head; }
    if (tail) { all[6] = tail[0]; all[7] = tail[1]; }
    let number = 0n;
    for (let i = 0; i < 8; i += 1) number = (number << 16n) + BigInt(all[i]);
    return number;
  }
  function renderVerdict(value) { output.innerHTML = value; }
  function lookup() {
    const query = input.value.trim(); if (!query) { input.focus(); return; }
    let number = ipToInt(query); let number6 = null; if (number === null) number6 = ip6ToBig(query);
    if (number === null && number6 === null) {
      renderVerdict('<div class="verdict-label">Lookup</div><div class="verdict-address">Not a valid IP address</div><p>Enter an IPv4 or IPv6 address or prefix.</p>'); return;
    }
    if (!index) {
      if (loading) return; loading = true;
      renderVerdict('<div class="verdict-label">Lookup</div><div class="verdict-address">Loading index…</div>');
      fetch('lookup.json').then(function (response) { return response.json(); }).then(function (data) {
        index = data; loading = false; lookup();
      }).catch(function () { loading = false; renderVerdict('<div class="verdict-label">Lookup</div><div class="verdict-address">Could not load the index</div><p>Try again after the feed files finish loading.</p>'); });
      return;
    }
    let hit = null;
    if (number6 !== null) {
      const ranges6 = index.r6 || [];
      for (let i = 0; i < ranges6.length; i += 1) if (number6 >= BigInt(ranges6[i][0]) && number6 <= BigInt(ranges6[i][1])) { hit = ranges6[i]; break; }
    } else {
      for (let i = 0; i < index.r.length; i += 1) if (number >= index.r[i][0] && number <= index.r[i][1]) { hit = index.r[i]; break; }
    }
    if (!hit) {
      renderVerdict('<div class="verdict-top"><span class="verdict-label">Lookup</span><span class="tag clear">not listed</span></div><div class="verdict-address">' + escapeHtml(query) + '</div><p>Not in this feed. It may be unreported, uncorroborated, filtered, or no longer current.</p>'); return;
    }
    const band = hit[3]; const css = band === 'high' ? 'high' : 'medium';
    const action = band === 'high' ? 'Safe to block.' : 'Challenge or rate-limit rather than drop outright.';
    renderVerdict('<div class="verdict-top"><span class="verdict-label">Lookup</span><span class="tag ' + css + '">listed · ' + band + '</span></div><div class="verdict-address">' + escapeHtml(query) + '</div><p>Matched <span class="mono">' + escapeHtml(hit[5]) + '</span>. ' + action + '</p><dl><dt>Score</dt><dd>' + hit[2] + ' / 100</dd><dt>Evidence</dt><dd>' + hit[4] + ' class' + (hit[4] === 1 ? '' : 'es') + '</dd><dt>Source</dt><dd>' + escapeHtml(hit[6]) + '</dd></dl>');
  }
  form.addEventListener('submit', function (event) { event.preventDefault(); lookup(); });
}());
"""

ANALYSIS_SCRIPT = r"""
(function () {
  const tier = document.getElementById('tier-filter');
  const family = document.getElementById('family-filter');
  const status = document.getElementById('filter-status');
  // 'both' is meaningful on either side: a panel marked 'both' belongs to every
  // selection, and selecting 'both' admits every panel. Reading it only as a panel
  // value is what hid the /8 grid under the default filter.
  function matches(value, selected) { return selected === 'both' || value === 'both' || value === selected; }
  function apply() {
    // One pass per element, ANDing every axis it declares. Separate per-axis loops
    // each reassigned `hidden`, so whichever axis ran last silently overrode the rest.
    document.querySelectorAll('[data-tier],[data-family],[data-only-family]').forEach(function (item) {
      let show = true;
      if (item.dataset.tier !== undefined) show = show && matches(item.dataset.tier, tier.value);
      if (item.dataset.family !== undefined) show = show && matches(item.dataset.family, family.value);
      if (item.dataset.onlyFamily !== undefined) show = show && item.dataset.onlyFamily === family.value;
      item.hidden = !show;
    });
    status.innerHTML = '<b>' + (tier.value === 'primary' ? 'Primary tier' : 'Non-commercial tier') + '</b> · ' + (family.value === 'both' ? 'IPv4 + IPv6' : family.value.toUpperCase());
  }
  tier.addEventListener('change', apply); family.addEventListener('change', apply); apply();
  const tip = document.getElementById('history-tip');
  document.querySelectorAll('.history-svg .hit').forEach(function (item) {
    function show() { tip.textContent = item.dataset.tip; }
    item.addEventListener('focus', show); item.addEventListener('mouseenter', show); item.addEventListener('click', show);
  });
  // Roving tabindex over the /8 grid. Without it the 256 cells would be 256 tab
  // stops between the reader and the next section, which is why only the focused
  // cell is tabbable and the arrow keys do the moving.
  const grid = document.querySelector('.ipv4-grid');
  if (grid) {
    const cells = Array.from(grid.querySelectorAll('.ip-grid-cell'));
    const COLUMNS = 16;
    function focusCell(index) {
      if (index < 0 || index >= cells.length) return;
      cells.forEach(function (cell) { cell.tabIndex = -1; });
      cells[index].tabIndex = 0;
      cells[index].focus();
    }
    grid.addEventListener('keydown', function (event) {
      const current = cells.indexOf(document.activeElement);
      if (current < 0) return;
      const moves = {
        ArrowRight: current + 1,
        ArrowLeft: current - 1,
        ArrowDown: current + COLUMNS,
        ArrowUp: current - COLUMNS,
        Home: Math.floor(current / COLUMNS) * COLUMNS,
        End: Math.floor(current / COLUMNS) * COLUMNS + COLUMNS - 1
      };
      if (!(event.key in moves)) return;
      event.preventDefault();
      focusCell(moves[event.key]);
    });
  }
  const asnTabs = Array.from(document.querySelectorAll('.asn-tab'));
  const asnPanels = Array.from(document.querySelectorAll('.asn-window-panel'));
  function chooseAsnWindow(tab) {
    asnTabs.forEach(function (item) { item.setAttribute('aria-selected', item === tab ? 'true' : 'false'); });
    asnPanels.forEach(function (panel) { panel.hidden = panel.id !== tab.getAttribute('aria-controls'); });
  }
  asnTabs.forEach(function (tab, index) {
    tab.addEventListener('click', function () { chooseAsnWindow(tab); });
    tab.addEventListener('keydown', function (event) {
      if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? asnTabs.length - 1 :
        (index + (event.key === 'ArrowRight' ? 1 : -1) + asnTabs.length) % asnTabs.length;
      asnTabs[next].focus(); chooseAsnWindow(asnTabs[next]);
    });
  });
  // Scroll-spy by "last heading above the fold line" rather than by intersection
  // band. A band only highlights sections tall enough to cross it, so short or
  // filtered-down sections used to hand their highlight to the next one down.
  const links = Array.from(document.querySelectorAll('[data-nav]'));
  const spied = links
    .map(function (link) { return {link: link, section: document.getElementById(link.dataset.nav)}; })
    .filter(function (pair) { return pair.section !== null; });
  if (spied.length) {
    const FOLD = 96;  // matches scroll-padding-top, so an anchored heading counts as arrived
    let queued = false;
    function markActive() {
      queued = false;
      let current = spied[0];
      spied.forEach(function (pair) {
        if (pair.section.getBoundingClientRect().top <= FOLD) current = pair;
      });
      // At the very bottom the last section may be too short to reach the fold line.
      if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 2) {
        current = spied[spied.length - 1];
      }
      spied.forEach(function (pair) { pair.link.classList.toggle('active', pair === current); });
    }
    function schedule() { if (!queued) { queued = true; requestAnimationFrame(markActive); } }
    window.addEventListener('scroll', schedule, {passive: true});
    window.addEventListener('resize', schedule, {passive: true});
    // Filter changes resize sections, which moves every fold-line answer.
    tier.addEventListener('change', schedule); family.addEventListener('change', schedule);
    markActive();
  }
}());
"""


def esc_html(value: str) -> str:
    """Escape generated text because source metadata is not controlled by the page."""
    return html.escape(value, quote=True)


def _hint(label: str, tip: str) -> str:
    """Keep short rationale reachable by keyboard without relying on browser tooltips."""
    return (
        f'<span class="hint" tabindex="0" role="note" aria-label="{esc_html(tip)}">'
        f'{esc_html(label)}<span class="tip">{esc_html(tip)}</span></span>'
    )


def _int(data: dict[str, Any], key: str) -> int:
    """Make partially written reporting artifacts degrade to zero rather than fail publication."""
    return int(data.get(key, 0))


def _generated_time(manifest: dict[str, Any]) -> tuple[str, str]:
    raw = str(manifest.get("generated_at", ""))
    time = raw[11:16] if len(raw) >= 16 else "unknown"
    machine = raw.replace("+00:00", "Z") if raw else ""
    return time, machine


def _status(manifest: dict[str, Any]) -> tuple[int, int, list[tuple[str, str]]]:
    sources = manifest.get("sources", {})
    if not isinstance(sources, dict):
        return 0, 0, []
    entries = sorted((str(name), info) for name, info in sources.items() if isinstance(info, dict))
    bad = [
        (name, str(info.get("status", "unknown")))
        for name, info in entries
        if info.get("status") != "ok"
    ]
    return len(entries) - len(bad), len(entries), bad


def _brand() -> str:
    return """<a class="brand" href="index.html" aria-label="xfeeds home"><svg class="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M4 8h9v7h7v9h8" stroke="currentColor" stroke-width="3" stroke-linecap="square"/><path d="M23 5v5m-2.5-2.5h5" stroke="currentColor" stroke-width="2"/><rect x="3" y="21" width="5" height="5" fill="currentColor"/></svg><span>xfeeds</span><span class="brand-meta">public threat intelligence</span></a>"""


def _status_strip(manifest: dict[str, Any]) -> str:
    ok, total, bad = _status(manifest)
    clock, machine = _generated_time(manifest)
    issue = ""
    if bad:
        names = ", ".join(name for name, _ in bad)
        issue = f'<span class="divider optional">·</span><a class="stale-link optional" href="analysis.html#sources">{len(bad)} needs review: {esc_html(names)}</a>'
    return f"""<div class="status-strip"><div class="status-inner"><span class="pulse" aria-hidden="true">●</span><strong>Feed live</strong><span class="divider">·</span><span>rebuilt <time datetime="{esc_html(machine)}">{esc_html(clock)} UTC</time></span><span class="divider cadence">·</span><span class="cadence">every 6 hours</span><span class="divider optional">·</span><span class="optional"><strong>{ok}/{total}</strong> sources OK</span>{issue}</div></div>"""


def _availability(history: list[dict[str, Any]]) -> str:
    """Compact per-run availability strip; kept as an inline sparkline in the hero chart."""
    points = history[-40:]
    if not points:
        return '<div class="hero-runs-strip" aria-label="No run history yet"></div>'
    peak = max((_int(item, "published") for item in points), default=1) or 1
    ticks: list[str] = []
    for number, item in enumerate(points, start=1):
        published = _int(item, "published")
        source_ok = _int(item, "sources_ok")
        source_total = _int(item, "sources_total")
        missing = max(source_total - source_ok, 0)
        state = "severe" if missing >= 2 else "partial" if missing else ""
        height = 6 + round(18 * published / peak)
        label = (
            f"Run {number}: {published:,} published, {source_ok} of {source_total} sources healthy"
        )
        ticks.append(
            f'<button class="run-tick {state}" style="height:{height}px" aria-label="{esc_html(label)}" tabindex="-1"></button>'
        )
    return (
        '<div class="hero-runs-label">'
        "<strong>Source health per run</strong>"
        '<span class="run-key">'
        '<span><i class="k-ok"></i>All sources OK</span>'
        '<span><i class="k-partial"></i>1 missing</span>'
        '<span><i class="k-severe"></i>2+ missing</span>'
        "</span>"
        "</div>"
        '<div class="hero-runs-strip" role="img" aria-label="Availability across the last 40 refreshes">'
        + "".join(ticks)
        + "</div>"
    )


def _hero_history_chart(history: list[dict[str, Any]]) -> str:
    """Render the console's headline history chart.

    A firewall operator arriving at xfeeds should read the value of the corpus
    before reading anything else, and "how large and how stable is this feed" is
    the specific question the chart answers. High/medium curves show growth and
    steadiness; the add/remove bars underneath show that the feed is churning,
    not just accumulating, which is the actual signal of an active source of
    intelligence.
    """
    runs = history[-40:]
    if len(runs) < 2:
        return '<div class="hero-chart-wrap"><p class="section-sub">Not enough run history yet to draw a trend.</p></div>'

    high_values = [_int(item, "high") for item in runs]
    medium_values = [_int(item, "medium") for item in runs]
    add_values = [_int(item, "added") for item in runs]
    remove_values = [_int(item, "removed") for item in runs]
    published_values = [_int(item, "published") for item in runs]

    width, height = 900, 260
    pad_l, pad_r, pad_t, pad_b = 46, 14, 12, 36
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    flow_h = 46
    top_h = plot_h - flow_h - 8

    y_max = max(max(high_values), max(medium_values), 1)
    # Round the axis to a clean interval so the reader can read counts directly.
    step = 1000 if y_max <= 5000 else 2000 if y_max <= 12000 else 5000
    y_top = ((y_max + step) // step) * step

    def x(index: int) -> float:
        return pad_l + (plot_w * index / (len(runs) - 1))

    def y_count(value: int) -> float:
        return pad_t + top_h - (top_h * value / y_top)

    flow_max = max(max(add_values), max(remove_values), 1)
    flow_top = pad_t + top_h + 8

    def y_flow(value: int) -> float:
        # Flows are drawn from the midline of the flow band so adds and removes are visually paired.
        midline = flow_top + flow_h / 2
        return midline - (flow_h / 2) * value / flow_max

    def path(values: list[int]) -> str:
        points = [f"{x(i):.1f},{y_count(v):.1f}" for i, v in enumerate(values)]
        return "M " + " L ".join(points)

    def area(values: list[int]) -> str:
        base = pad_t + top_h
        parts = [f"M {x(0):.1f},{base:.1f}"]
        parts += [f"L {x(i):.1f},{y_count(v):.1f}" for i, v in enumerate(values)]
        parts.append(f"L {x(len(values) - 1):.1f},{base:.1f} Z")
        return " ".join(parts)

    # Y-axis gridlines and labels every `step`.
    grid = []
    labels = []
    tick_value = 0
    while tick_value <= y_top:
        y_pos = y_count(tick_value)
        grid.append(
            f'<line class="grid-line" x1="{pad_l}" x2="{width - pad_r}" y1="{y_pos:.1f}" y2="{y_pos:.1f}"/>'
        )
        labels.append(
            f'<text x="{pad_l - 8}" y="{y_pos + 3:.1f}" text-anchor="end">{tick_value:,}</text>'
        )
        tick_value += step

    # Time axis: label first, middle, last runs so the reader knows the span.
    def short_ts(ts: str) -> str:
        return ts[5:10] if len(ts) >= 10 else ts

    time_ticks = []
    for index in (0, len(runs) // 2, len(runs) - 1):
        ts = short_ts(str(runs[index].get("generated_at", "")))
        time_ticks.append(
            f'<text x="{x(index):.1f}" y="{pad_t + plot_h + 20}" text-anchor="middle">{esc_html(ts)}</text>'
        )

    # Adds above the midline, removes below it; each column is one refresh.
    band_center = flow_top + flow_h / 2
    bar_w = max(2.0, plot_w / (len(runs) * 1.5))
    bars: list[str] = []
    for index, (added, removed) in enumerate(zip(add_values, remove_values)):
        cx = x(index) - bar_w / 2
        if added:
            bars.append(
                f'<rect class="flow-add" x="{cx:.1f}" y="{y_flow(added):.1f}" width="{bar_w:.1f}" height="{band_center - y_flow(added):.1f}" fill="var(--ok)" opacity="0.9"/>'
            )
        if removed:
            top = band_center
            h = (band_center - y_flow(removed)) or 0.1
            bars.append(
                f'<rect class="flow-remove" x="{cx:.1f}" y="{top:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="#D7846F" opacity="0.9"/>'
            )

    # Hit rectangles carry per-run tooltips through a single event handler.
    hits: list[str] = []
    col_w = plot_w / (len(runs) - 1)
    for index, item in enumerate(runs):
        cx = x(index) - col_w / 2
        cw = col_w
        if index == 0:
            cx = pad_l
            cw = col_w / 2
        elif index == len(runs) - 1:
            cw = col_w / 2
        ts = str(item.get("generated_at", ""))
        summary = (
            f"{short_ts(ts)}  "
            f"published {published_values[index]:,} "
            f"({high_values[index]:,} high · {medium_values[index]:,} medium) "
            f"+{add_values[index]:,} added · -{remove_values[index]:,} removed · "
            f"{_int(item, 'sources_ok')}/{_int(item, 'sources_total')} sources"
        )
        # Only the first cell is initially tabbable; JS handles the roving pattern.
        tabindex = "0" if index == 0 else "-1"
        hits.append(
            f'<rect class="hit-col" x="{cx:.1f}" y="{pad_t}" width="{cw:.1f}" height="{plot_h}" '
            f'tabindex="{tabindex}" role="button" aria-label="{esc_html(summary)}" '
            f'data-tip="{esc_html(summary)}"/>'
        )

    zero_line = (
        f'<line class="grid-line" x1="{pad_l}" x2="{width - pad_r}" '
        f'y1="{band_center:.1f}" y2="{band_center:.1f}"/>'
    )
    default_tip = f"<strong>Last {len(runs)} refreshes.</strong> Hover or focus a column for that refresh's numbers."
    return (
        '<div class="hero-chart-wrap">'
        '<div class="hero-chart-head">'
        f"<h2>Corpus growth and turnover · last {len(runs)} refreshes</h2>"
        '<div class="hero-chart-legend">'
        '<span><i class="lg-high"></i>Safe to block</span>'
        '<span><i class="lg-medium"></i>Worth challenging</span>'
        '<span><i class="lg-adds"></i>Added</span>'
        '<span><i class="lg-removes"></i>Removed</span>'
        "</div>"
        "</div>"
        f'<svg class="hero-svg" viewBox="0 0 {width} {height}" role="img" '
        'aria-label="Feed size, additions, and removals across the last refreshes">'
        f'<g class="axis">{"".join(grid)}{"".join(labels)}{zero_line}{"".join(time_ticks)}</g>'
        f'<path class="area-med" d="{area(medium_values)}"/>'
        f'<path class="area-high" d="{area(high_values)}"/>'
        f'<path class="line-med" d="{path(medium_values)}"/>'
        f'<path class="line-high" d="{path(high_values)}"/>'
        f"{''.join(bars)}"
        f"{''.join(hits)}"
        "</svg>"
        f'<p class="hero-chart-tip" id="hero-chart-tip" aria-live="polite">{default_tip}</p>'
        f"{_availability(history)}"
        "</div>"
    )


def _platforms(base_url: str) -> str:
    guides = [
        (
            "linux",
            "Linux",
            f"$ curl -sS {base_url}/iptables.ipset | sudo ipset restore -!\n$ sudo iptables -I INPUT -m set --match-set xfeeds src -j DROP",
            "Loads the IPv4 high-confidence feed, then drops matches. Add the first line to cron every six hours.",
        ),
        (
            "nft",
            "nftables",
            f"$ curl -sS -o xfeeds.nft {base_url}/nftables.conf\n$ sudo nft -f xfeeds.nft",
            "Creates IPv4 and IPv6 sets. Reference @blocklist4 or @blocklist6 in your ruleset.",
        ),
        (
            "pf",
            "pfSense / OPNsense",
            f"Firewall → Aliases → Add\n  Type: URL Table (IPs)\n  URL: {base_url}/high-confidence.txt\n  Update frequency: 1 day",
            "Create a WAN block rule using this alias. The combined list contains both families.",
        ),
        (
            "mikro",
            "MikroTik",
            f'/tool fetch url="{base_url}/high-confidence.txt" dst-path=xfeeds.txt\n/import file-name=xfeeds.txt',
            "Use an address list with a scheduled script. Strip # comments before importing.",
        ),
        (
            "cloudflare",
            "Cloudflare",
            f"curl -sS {base_url}/high-confidence.txt | grep -v '^#' > xfeeds.txt\n# Account → Configurations → Lists → upload xfeeds.txt",
            "Use the high-confidence tier to stay within custom-list limits.",
        ),
        (
            "siem",
            "SIEM / TIP",
            f"MISP: {base_url}/misp-manifest.json\nSTIX: {base_url}/stix-bundle.json\nCSV:  {base_url}/all.csv",
            "Direct URLs for MISP, STIX 2.1, OpenCTI, Elastic, Splunk, Sentinel, and spreadsheet consumers.",
        ),
    ]
    buttons = "".join(
        f'<button class="platform" role="tab" id="tab-{key}" aria-controls="{key}" aria-selected="{"true" if index == 0 else "false"}" type="button">{label}</button>'
        for index, (key, label, _, _) in enumerate(guides)
    )
    panels = "".join(
        f'<section class="platform-panel" id="{key}" role="tabpanel"{"" if index == 0 else " hidden"}><div class="terminal"><button class="copy" type="button" data-copy="{key}" aria-label="Copy {esc_html(label)} setup">Copy</button><span class="sr-only copy-status" role="status" aria-live="polite"></span><code>{esc_html(command)}</code></div><p class="command-note">{esc_html(note)}</p></section>'
        for index, (key, label, command, note) in enumerate(guides)
    )
    return f'<div class="command-wrap"><div class="platforms" role="tablist" aria-label="Deployment platforms">{buttons}</div>{panels}</div>'


def _feed_row(filename: str, family: str, count: int | None) -> str:
    value = "—" if count is None else f"{count:,}"
    return f'<div class="feed-row"><a class="file" href="{filename}">{filename}</a><span class="family">{family}</span><span class="entry-count">{value}</span></div>'


def _downloads(manifest: dict[str, Any], history: list[dict[str, Any]]) -> str:
    counts = manifest.get("counts", {})
    families = manifest.get("families", {})
    family4 = families.get("v4", {}) if isinstance(families, dict) else {}
    family6 = families.get("v6", {}) if isinstance(families, dict) else {}
    high = _int(counts, "high")
    medium = _int(counts, "medium")
    published = _int(counts, "published")
    block = "".join(
        (
            _feed_row("high-confidence.txt", "both", high),
            _feed_row("high-confidence-v4.txt", "v4", _int(family4, "high")),
            _feed_row("high-confidence-v6.txt", "v6", _int(family6, "high")),
            _feed_row("medium-confidence.txt", "both", medium),
            _feed_row("medium-confidence-v4.txt", "v4", _int(family4, "medium")),
            _feed_row("medium-confidence-v6.txt", "v6", _int(family6, "medium")),
        )
    )
    structured = "".join(
        (
            _feed_row("all.csv", "both", published),
            _feed_row("all.json", "both", published),
            _feed_row("stix-bundle.json", "both", high),
            _feed_row("misp-manifest.json", "both", high),
            _feed_row("nftables.conf", "both", high),
            _feed_row("iptables.ipset", "v4", _int(family4, "high")),
            _feed_row("iptables6.ipset", "v6", _int(family6, "high")),
        )
    )
    metadata = "".join(
        (
            _feed_row("manifest.json", "run data", None),
            _feed_row("history.json", f"{len(history)} runs", None),
            _feed_row("lookup.json", "lazy index", None),
        )
    )
    return f"""<section class="section" aria-labelledby="feeds-title"><div class="section-head"><div><div class="eyebrow">Downloads</div><h2 id="feeds-title">Download a feed format.</h2></div><span class="section-sub">Primary / commercial-safe tier</span></div><div class="feed-groups"><section class="feed-group"><h3>Block lists</h3>{block}</section><section class="feed-group"><h3>Structured formats</h3>{structured}</section><section class="feed-group"><h3>Metadata</h3>{metadata}</section></div><p class="feeds-foot">Non-commercial equivalents retain these filenames under <a href="noncommercial/high-confidence.txt">/noncommercial/</a>.</p><div class="callout-link"><span>Studying the corpus? <b>{high:,} high-confidence entries</b></span><a href="analysis.html">Open analysis →</a></div></section>"""


def _footer() -> str:
    return f"""<footer class="shell"><div class="foot-grid"><div><p><strong>Two licence tiers.</strong> The primary tier is for any use, including commercial work. The <a href="noncommercial/">non-commercial tier</a> is CC BY-NC-SA 4.0 and can carry more share-alike material.</p><p>Spamhaus attribution travels with the data. Threat data is also provided by <a href="https://ipthreat.net">IPThreat at ipthreat.net</a> and the Turris Sentinel project at CZ.NIC (CC BY-NC-SA 4.0, non-commercial tier only).</p></div><div><p>Network attribution in analysis: <a href="https://iptoasn.com/">IPtoASN by Frank Denis</a> (Public Domain, PDDL v1.0). It maps networks; it contributes no threat data.</p><p>Think an address is wrong? <a href="{PROJECT_URL}/issues">Report a false positive</a>. Confirmed mistakes are permanently allowlisted.</p></div></div><p class="footer-note">Provided as-is with no warranty. Test against your own traffic before blocking in production. Maintained by <a href="{ORCID_URL}" class="nowrap">Neil Weitzel (ORCID)</a>. Cite via <a href="{CONCEPT_DOI_URL}" class="nowrap">DOI {CONCEPT_DOI}</a>.</p></footer>"""


def _hero(manifest: dict[str, Any], history: list[dict[str, Any]]) -> str:
    """Data-first hero: the numbers rail sits above a real chart of the last 40 refreshes.

    Operators arriving at the page shouldn't have to scroll past a marketing block to
    see the corpus they came for. Four counts read at a glance; the chart underneath
    shows growth and turnover, so the value of the feed is legible before anything else.
    """
    counts = manifest.get("counts", {})
    high = _int(counts, "high")
    medium = _int(counts, "medium")
    published = _int(counts, "published")
    withheld = _int(counts, "withheld")
    rejected = round(100 * withheld / (published + withheld)) if published + withheld else 0
    families = manifest.get("families", {}) if isinstance(manifest.get("families"), dict) else {}
    v4_published = _int(
        families.get("v4", {}) if isinstance(families.get("v4"), dict) else {}, "published"
    )
    v6_published = _int(
        families.get("v6", {}) if isinstance(families.get("v6"), dict) else {}, "published"
    )
    numbers = (
        '<div class="hero-numbers" role="list" aria-label="Feed at a glance">'
        f'<div class="hero-num accent" role="listitem"><b>{high:,}</b>'
        '<span class="hero-num-label">Safe to block</span>'
        '<span class="hero-num-detail">High-confidence, corroborated evidence</span></div>'
        f'<div class="hero-num" role="listitem"><b>{medium:,}</b>'
        '<span class="hero-num-label">Worth challenging</span>'
        '<span class="hero-num-detail">Rate-limit, tarpit, or elevate for review</span></div>'
        f'<div class="hero-num" role="listitem"><b>{published:,}</b>'
        '<span class="hero-num-label">Published today</span>'
        f'<span class="hero-num-detail">{v4_published:,} IPv4 · {v6_published:,} IPv6</span></div>'
        f'<div class="hero-num" role="listitem"><b>{rejected}%</b>'
        '<span class="hero-num-label">Rejected before publish</span>'
        f'<span class="hero-num-detail">{withheld:,} observations held back this run</span></div>'
        "</div>"
    )
    return (
        '<section class="data-hero" aria-labelledby="console-title">'
        '<div class="eyebrow">Operator console · primary tier</div>'
        '<h1 id="console-title">Corroborated threat intelligence, refreshed every six hours.</h1>'
        f"{numbers}"
        f"{_hero_history_chart(history)}"
        '<p class="hero-followups">'
        "<span>Look up a specific address below, download a feed, or review deployment examples. "
        'Full aggregate evidence in <a href="analysis.html">analysis</a>.</span>'
        "</p>"
        "</section>"
    )


def _lookup_section() -> str:
    return (
        '<section class="section" aria-labelledby="lookup-title">'
        '<div class="lookup-grid">'
        '<div><div class="eyebrow">Local check</div>'
        '<h2 id="lookup-title">Check an address</h2>'
        '<p class="section-sub">Does it appear in this feed right now?</p>'
        '<form class="lookup-form" id="lookup-form">'
        '<label class="sr-only" for="ip">IP address or prefix</label>'
        '<input id="ip" name="ip" type="text" placeholder="Try 1.10.16.7 or 2001:db8::7" '
        'autocomplete="off" spellcheck="false">'
        '<button class="action" type="submit">Check address</button></form>'
        '<small class="privacy">Runs entirely in your browser. The production page loads '
        "<code>lookup.json</code> only when you check; no query is logged.</small></div>"
        '<div class="verdict" id="verdict" aria-live="polite">'
        '<div class="verdict-label">Local lookup</div>'
        '<div class="verdict-address">Ready when you are</div>'
        "<p>Enter an address to compare it with the current published feed.</p>"
        "</div></div></section>"
    )


def _deploy_section(base_url: str) -> str:
    return (
        '<section class="section deploy-band" aria-labelledby="deploy-title">'
        '<div class="section-head">'
        '<div><div class="eyebrow">Deploy</div>'
        '<h2 id="deploy-title">Deployment examples</h2>'
        '<p class="section-sub">Reference commands for common environments. Use the feed format above and '
        "schedule refreshes on the same six-hour cadence.</p></div>"
        "</div>"
        f"{_platforms(base_url)}"
        "</section>"
    )


def _about_section(manifest: dict[str, Any]) -> str:
    sources = manifest.get("sources", {})
    source_count = len(sources) if isinstance(sources, dict) else 0
    # active_voting_classes ships as either the list of class names or the count,
    # depending on manifest version; accept both so a schema tweak upstream doesn't
    # break the render.
    voting = manifest.get("active_voting_classes")
    classes = len(voting) if isinstance(voting, list) else _int(manifest, "active_voting_classes")
    return (
        '<section class="about-band" aria-labelledby="about-title">'
        '<div class="shell about-grid">'
        '<div><div class="eyebrow">About the project</div>'
        '<h2 id="about-title">What xfeeds is, and why it exists.</h2>'
        "<p><strong>xfeeds is a public, corroborated malicious-IP feed.</strong> Every published "
        "record is backed by at least one high-precision source or by two independent classes of "
        "evidence — not by the number of source files that happen to repeat it. Widely-scoped "
        "prefixes and known cloud, CDN, and resolver space are held back rather than published "
        "as blocks.</p>"
        f"<p>The corpus draws on <strong>{source_count} sources across {classes} independent "
        "evidence classes</strong>, refreshed every six hours.</p>"
        "</div>"
        '<div><div class="eyebrow">Why it matters</div>'
        "<h2>An open, auditable alternative to opaque blocklists.</h2>"
        "<p>Commercial blocklists rarely publish the evidence behind a record. xfeeds does: the "
        '<a href="analysis.html">analysis surface</a> shows the publication funnel, the '
        "corroboration histogram, per-source health, and the IPv4 address-space distribution, "
        "so a security team can decide for themselves what to trust.</p>"
        "<p>Everything is generated from committed artifacts, hosted on GitHub Pages, and "
        "reproducible from source.</p>"
        "</div>"
        '<div><div class="eyebrow">Cite and follow</div>'
        "<h2>Citeable research output.</h2>"
        "<p>Each release is archived on Zenodo with a persistent DOI, so xfeeds can be "
        "cited in papers, reports, and other tools. Cite the concept DOI "
        f'<a href="{CONCEPT_DOI_URL}" class="nowrap"><span class="mono">{CONCEPT_DOI}</span></a> — '
        "it always resolves to the newest published version.</p>"
        f'<p>Maintained by <a href="{ORCID_URL}">Neil Weitzel</a>, ORCID '
        f'<a href="{ORCID_URL}" class="nowrap"><span class="mono">0009-0007-2546-2331</span></a>. '
        "Machine-readable citation metadata is in "
        f'<a href="{PROJECT_URL}/blob/main/CITATION.cff">CITATION.cff</a>, and archival policy is in '
        f'<a href="{PROJECT_URL}/blob/main/docs/CITABILITY.md">docs/CITABILITY.md</a>.</p>'
        "</div></div></section>"
    )


def render_console(
    manifest: dict[str, Any], history: list[dict[str, Any]], base_url: str = BASE_URL
) -> str:
    """Data first, then the files that represent it, then how to deploy, then the story."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="description" content="Corroborated threat intelligence feeds — published, refreshed every six hours, with the evidence behind every record.">'
        f"<title>xfeeds · Operator Console</title><style>{STYLE}</style></head>"
        '<body><a class="skip" href="#main">Skip to content</a>'
        f"{_status_strip(manifest)}"
        f'<header class="shell brandbar">{_brand()}'
        '<nav class="topnav" aria-label="Primary"><a href="analysis.html">Analysis</a>'
        f'<a href="{PROJECT_URL}">Source</a></nav></header>'
        '<main id="main" class="shell">'
        f"{_hero(manifest, history)}"
        f"{_lookup_section()}"
        f"{_downloads(manifest, history)}"
        f"{_deploy_section(base_url)}"
        "</main>"
        f"{_about_section(manifest)}"
        f"{_footer()}"
        f"<script>{CONSOLE_SCRIPT}</script>"
        "</body></html>"
    )


def _history_chart(history: list[dict[str, Any]]) -> str:
    points = history[-40:]
    if len(points) < 2:
        return '<p class="note">Charts appear once a few runs have accumulated — the feed refreshes every 6 hours.</p>'
    values = [
        (
            _int(point, "high"),
            _int(point, "medium"),
            _int(point, "added"),
            _int(point, "removed"),
            str(point.get("generated_at", ""))[:16].replace("T", " "),
        )
        for point in points
    ]
    width, height = 1000, 180
    peak = max((high + medium for high, medium, _, _, _ in values), default=1) or 1
    change = max((max(added, removed) for _, _, added, removed, _ in values), default=1) or 1
    step = width / (len(values) - 1)
    line = " ".join(
        f"{i * step:.1f},{height - 40 - ((high + medium) / peak) * 115:.1f}"
        for i, (high, medium, _, _, _) in enumerate(values)
    )
    high_line = " ".join(
        f"{i * step:.1f},{height - 40 - (high / peak) * 115:.1f}"
        for i, (high, _, _, _, _) in enumerate(values)
    )
    bars: list[str] = []
    hits: list[str] = []
    for i, (high, medium, added, removed, label) in enumerate(values):
        x = i * step
        bars.append(
            f'<line x1="{x:.1f}" y1="155" x2="{x:.1f}" y2="{155 - added / change * 25:.1f}" class="add"/><line x1="{x:.1f}" y1="155" x2="{x:.1f}" y2="{155 + removed / change * 25:.1f}" class="remove"/>'
        )
        tip = f"{label}: {high:,} high, {medium:,} medium; +{added:,} / −{removed:,} this run"
        left = max(x - step / 2, 0)
        hits.append(
            f'<rect class="hit" tabindex="0" role="note" aria-label="{esc_html(tip)}" data-tip="{esc_html(tip)}" x="{left:.1f}" y="0" width="{step:.1f}" height="180"/>'
        )
    return f'<div class="wide-chart" data-tier="primary" data-family="both"><div class="chart-top"><strong>Feed size and change per run</strong><span>{len(values)} recorded runs</span></div><div class="history-wrap"><svg class="history-svg" viewBox="0 0 1000 180" role="img" aria-label="Published high and medium confidence counts across recorded runs"><line class="grid" x1="0" y1="25" x2="1000" y2="25"/><line class="grid" x1="0" y1="140" x2="1000" y2="140"/><polyline class="medium-line" points="{line}"/><polyline class="high-line" points="{high_line}"/>{"".join(bars)}{"".join(hits)}</svg><div id="history-tip" class="chart-tooltip">Focus a run for exact counts.</div></div></div>'


def _funnel(manifest: dict[str, Any], insights: dict[str, Any]) -> str:
    counts = manifest.get("counts", {})
    filters = manifest.get("filters", {})
    observed = _int(insights.get("corpus", {}), "addresses_observed")
    restricted = _int(filters, "not_redistributable")
    allowlisted = _int(filters, "allowlisted")
    tagged = _int(filters, "tag_only")
    withheld = _int(counts, "withheld")
    published = _int(counts, "published")
    high = _int(counts, "high")
    medium = _int(counts, "medium")
    peak = max(observed, 1)
    rows = [
        ("observed", observed, "Observed across public sources", "start"),
        (
            "licence-restricted evidence only",
            restricted,
            "Licence permits scoring, not redistribution",
            "minus",
        ),
        ("allowlisted", allowlisted, "Known cloud, CDN, crawler, and resolver space", "minus"),
        (
            "tagged only (Tor exits)",
            tagged,
            "Visible for context; never automatically blocked",
            "minus",
        ),
        (
            "withheld as uncorroborated",
            withheld,
            "Did not reach the publication confidence threshold",
            "minus",
        ),
        ("published", published, f"{high:,} high + {medium:,} medium", "final"),
    ]
    rendered = "".join(
        f'<div class="funnel-step {kind}"><strong>{value:,}</strong><div class="funnel-bar" style="width:{max(9, round(value / peak * 100))}%">{esc_html(label)}</div><span class="funnel-rule">{esc_html(rule)}</span></div>'
        for label, value, rule, kind in rows
    )
    return f'<div class="funnel" data-tier="primary" data-family="both">{rendered}</div>'


def _corroboration_panel(manifest: dict[str, Any], insights: dict[str, Any]) -> str:
    counts = manifest.get("counts", {})
    histogram = manifest.get("corroboration_histogram", {})
    if not isinstance(histogram, dict):
        histogram = {}
    distribution = sorted(
        ((int(classes), int(records)) for classes, records in histogram.items()),
        key=lambda row: row[0],
    )
    published = _int(counts, "published")
    high = _int(counts, "high")
    promoted = _int(counts, "promoted")
    capped = _int(counts, "benign_scanners_capped")
    cells = (
        "".join(
            f'<div class="corroboration-cell"><b>{records:,}</b><span>{classes} '
            f"independent {'class' if classes == 1 else 'classes'}</span></div>"
            for classes, records in distribution
        )
        or '<p class="note">Corroboration distribution is unavailable for this run.</p>'
    )
    agreement = insights.get("agreement", {})
    agreement_counts = (
        agreement.get("by_independent_class_count", {}) if isinstance(agreement, dict) else {}
    )
    single_class_seen = (
        int(agreement_counts.get("1", 0)) if isinstance(agreement_counts, dict) else 0
    )
    promoted_share = round(promoted / published * 100) if published else 0
    high_share = round(promoted / high * 100) if high else 0
    promotion_reason = _hint(
        "Why some records are promoted without a second class",
        "Spamhaus DROP hijacked netblocks and active abuse.ch command-and-control "
        "servers are high-precision findings that do not need a second opinion. "
        "Everything else requires agreement across independent classes.",
    )
    return (
        '<div class="wide-chart corroboration" data-tier="primary" data-family="both">'
        '<div class="chart-top"><strong>Corroboration across independent classes</strong>'
        f"<span>{published:,} published records</span></div>"
        '<p class="note">Each published record is counted by the independent classes that '
        "backed it, not by the number of source files that might repeat the same evidence.</p>"
        f'<div class="corroboration-grid" aria-label="Published records by independent '
        f'class corroboration">{cells}</div>'
        f'<p class="note">{promoted:,} records ({promoted_share}% of published records; '
        f"{high_share}% of the high tier) were admitted on a single high-precision source. "
        f"{promotion_reason}</p>"
        f'<p class="note">{capped:,} indicators had benign-scanner evidence and were capped '
        "from high to medium rather than deleted, preserving the consumer's policy choice. "
        "GreyNoise is reported only in this aggregate; it is never named against an "
        "individual record.</p>"
        + (
            f'<p class="note">Before publication controls, {single_class_seen:,} observed '
            "candidates had evidence from exactly one independent class.</p>"
            if single_class_seen
            else ""
        )
        + "</div>"
    )


def _ipv4_grid(insights: dict[str, Any]) -> str:
    """The IPv4 space as a 16x16 grid of /8 blocks.

    Replaces a strip of 512 identical pickets whose only affordance was hovering a
    ``<title>``. A grid is legible at a glance because position carries meaning:
    the reader can find 45.0.0.0/8 by counting rows rather than by probing pixels.

    Accessibility is the reason this is a real ARIA grid rather than 256 tabbable
    spans. A tab stop per cell would put 256 of them between the reader and the
    next section, and ``role="grid"`` whose children are ``role="note"`` is not a
    valid structure for a screen reader to announce. So the grid follows the
    standard roving-tabindex pattern: exactly one cell is tabbable, arrow keys move
    focus within the grid, and rows and cells carry their proper roles. Each cell
    still names its own block and count, so nothing is lost.
    """
    spectrum = insights.get("spectrum", {})
    raw = [int(value) for value in spectrum.get("counts", [])]
    counts = [sum(raw[index : index + 2]) for index in range(0, min(len(raw), 512), 2)]
    counts += [0] * (256 - len(counts))
    peak = max(counts) or 1
    rows: list[str] = []
    for row_index in range(16):
        cells: list[str] = []
        for column in range(16):
            octet = row_index * 16 + column
            count = counts[octet]
            reserved = octet >= 224
            level = 0.07 if not count else 0.2 + 0.8 * math.log1p(count) / math.log1p(peak)
            label = f"{octet}.0.0.0/8: {count:,} observations" + (
                "; multicast or reserved range" if reserved else ""
            )
            edge = " edge" if octet % 16 == 0 or octet >= 240 else ""
            state = " reserved" if reserved else ""
            visible = str(octet) if edge else ""
            # Only the first cell is reachable by Tab; the rest are driven by the
            # arrow-key handler, which is what keeps the grid to one tab stop.
            tabindex = "0" if octet == 0 else "-1"
            cells.append(
                f'<span class="ip-grid-cell{edge}{state}" style="--level:{level:.3f}" '
                f'role="gridcell" tabindex="{tabindex}" aria-label="{esc_html(label)}">'
                f'{visible}<span class="tip" aria-hidden="true">{esc_html(label)}</span>'
                "</span>"
            )
        rows.append(f'<div role="row" class="ipv4-grid-row">{"".join(cells)}</div>')
    occupied = sum(1 for count in counts if count)
    busiest = max(range(256), key=lambda octet: counts[octet])
    summary = (
        f"IPv4 /8 observation grid. {occupied} of 256 blocks observed. "
        f"Busiest is {busiest}.0.0.0/8 with {counts[busiest]:,} observations. "
        "Use the arrow keys to move between blocks."
    )
    return (
        '<div class="spectrum-wrap" data-tier="primary" data-family="v4">'
        '<div class="chart-top"><strong>One cell per IPv4 /8, log-scaled</strong>'
        f"<span>{occupied} /8 blocks observed</span></div>"
        f'<div class="ipv4-grid" role="grid" aria-label="{esc_html(summary)}">'
        f"{''.join(rows)}</div>"
        '<div class="grid-legend">'
        "<span>0.0.0.0/8 at upper left &rarr; 255.0.0.0/8 at lower right</span>"
        '<span class="grid-key"><i></i>observed <i class="reserved"></i>'
        "multicast / reserved</span></div>"
        '<p class="note">Two /9 buckets are folded into each /8. Counts are '
        "logarithmically shaded so sparse activity remains visible without revealing "
        "individual addresses.</p></div>"
    )


def _prefix_table(insights: dict[str, Any]) -> str:
    family = insights.get("families", {}).get("v6", {})
    rows = sorted(
        (
            (str(row.get("key", "")), int(row.get("count", 0)))
            for row in family.get("prefix_lengths", [])
        ),
        key=lambda row: int(row[0].lstrip("/") or "0"),
    )
    body = (
        "".join(
            f'<tr><td><code>{esc_html(prefix)}</code></td><td class="num">{count:,}</td></tr>'
            for prefix, count in rows
        )
        or '<tr><td colspan="2">No IPv6 prefixes in this run.</td></tr>'
    )
    widest = min((int(prefix.lstrip("/")) for prefix, _ in rows), default=0)
    return f'<div data-tier="primary" data-family="v6"><div class="wide-prefix"><strong>Wide on purpose.</strong> General IPv6 practice treats a /64 as one actor and a /32 as an entire ISP that should almost never be blocked outright. These wider entries are Spamhaus DROP netblocks leased or stolen outright by criminal operations, published for firewall and backbone use, where the whole allocation is the finding. The widest entry in this run is /{widest}; <strong>review the widest entries</strong> before deploying them.</div><table class="prefix-table"><tr><th>Prefix width</th><th class="num">Entries</th></tr>{body}</table></div>'


def _family_coverage_panel(insights: dict[str, Any]) -> str:
    coverage = insights.get("family_coverage", {})
    if not isinstance(coverage, dict):
        return ""
    sources = coverage.get("sources_reporting_ipv6", [])
    if not isinstance(sources, list):
        return ""
    rows = sorted(
        (row for row in sources if isinstance(row, dict)),
        key=lambda row: (-int(row.get("ipv6_observations", 0)), str(row.get("source", ""))),
    )
    body = "".join(
        f'<tr><td class="source-name">{esc_html(str(row.get("source", "unknown")))}</td>'
        f"<td>{esc_html(str(row.get('independence_class', '—')))}</td>"
        f'<td class="num">{int(row.get("ipv6_observations", 0)):,}</td>'
        f"<td>{'republished' if bool(row.get('redistributable')) else 'scoring only'}</td></tr>"
        for row in rows
    )
    if not body:
        return ""
    note = str(coverage.get("note", ""))
    return (
        '<div class="wide-chart ipv6-coverage" data-tier="primary" data-family="v6">'
        '<div class="chart-top"><strong>Which sources report IPv6</strong>'
        f"<span>{len(rows)} sources</span></div>"
        f'<p class="note">{esc_html(note)}</p>'
        '<div class="table-scroll"><table class="prefix-table"><tr><th>Source</th><th>Independence class</th>'
        '<th class="num">IPv6 observations</th><th>Publication</th></tr>'
        f"{body}</table></div></div>"
    )


def _asn_persistence(insights: dict[str, Any]) -> str:
    windows = insights.get("asn_windows", {})
    if not isinstance(windows, dict) or not bool(windows.get("available")):
        return ""
    span = int(windows.get("history_span_days", 0))
    window_definitions = (
        ("last_30_days", "Last 30 days", 30),
        ("last_60_days", "Last 60 days", 60),
        ("all_time", "All recorded history", None),
    )
    tabs: list[str] = []
    panels: list[str] = []
    for index, (key, label, requested_days) in enumerate(window_definitions):
        tab_id = f"asn-tab-{key}"
        panel_id = f"asn-window-{key}"
        selected = "true" if index == 0 else "false"
        tabs.append(
            f'<button class="asn-tab" id="{tab_id}" type="button" role="tab" '
            f'aria-selected="{selected}" aria-controls="{panel_id}">{label}</button>'
        )
        raw_rows = windows.get(key, [])
        rows = sorted(
            (row for row in raw_rows if isinstance(row, dict))
            if isinstance(raw_rows, list)
            else [],
            key=lambda row: (
                -int(row.get("days_active", 0)),
                -int(row.get("address_days", 0)),
                int(row.get("asn", 0)),
            ),
        )
        body = (
            "".join(
                f'<tr><td class="asn">AS{int(row.get("asn", 0))}</td>'
                f"<td>{esc_html(str(row.get('name', 'Unknown')))}</td>"
                f'<td class="num">{int(row.get("days_active", 0)):,}</td>'
                f'<td class="num">{int(row.get("address_days", 0)):,}</td>'
                f'<td class="num">{_per_million(row.get("per_million_announced"))}</td>'
                f'<td class="num">{int(row.get("announced_addresses", 0)):,}</td></tr>'
                for row in rows
            )
            or '<tr><td colspan="6">No ASN persistence data is available for this window.</td></tr>'
        )
        warning = (
            f'<p class="note">Only {span} days of history, so this matches all-time until '
            f"the record passes {requested_days} days.</p>"
            if requested_days is not None and span < requested_days
            else ""
        )
        panels.append(
            f'<div class="asn-window-panel" id="{panel_id}" role="tabpanel" '
            f'aria-labelledby="{tab_id}"{" hidden" if index else ""}>{warning}'
            '<div class="network-table-wrap"><table class="network-table"><tr><th>ASN</th>'
            '<th>Network</th><th class="num">Days seen</th><th class="num">Address-days</th>'
            '<th class="num">Per million</th><th class="num">Announced</th></tr>'
            f"{body}</table></div></div>"
        )
    caveat = str(windows.get("caveat", ""))
    dated_sources = windows.get("dated_history_sources", [])
    source_list = (
        ", ".join(sorted(str(source) for source in dated_sources))
        if isinstance(dated_sources, list)
        else ""
    )
    per_million_hint = _hint(
        "Per million",
        "Address-days per million announced addresses normalise for network size, so this is "
        "not merely a list of the largest hosting providers.",
    )
    return (
        '<div class="wide-chart asn-persistence" data-tier="primary" data-family="v4">'
        '<div class="chart-top"><strong>Persistence, not provider size</strong>'
        f"<span>{span} days recorded</span></div>"
        '<p class="note">Ranked by days seen, then address-days. '
        f"{per_million_hint} "
        "uses announced address space; a missing denominator is shown as an em dash.</p>"
        f'<div class="asn-tabs" role="tablist" aria-label="ASN persistence window">'
        f"{''.join(tabs)}</div>{''.join(panels)}"
        f'<p class="note">{esc_html(caveat)}'
        + (
            f" Dated upstream history: {esc_html(source_list)}. Its earlier left edge is "
            "thinner than recent project-run history, so it is not a trend line."
            if source_list
            else ""
        )
        + "</p></div>"
    )


def _per_million(value: Any) -> str:
    return "&mdash;" if value is None else f"{float(value):,.1f}"


def _network_table(insights: dict[str, Any]) -> str:
    networks = insights.get("networks", {})
    rows = networks.get("top_asns", [])[:25]
    body = "".join(
        f'<tr><td class="asn">AS{int(row.get("asn", 0))}</td><td>{esc_html(str(row.get("name", "Unknown")))}</td><td class="num">{int(row.get("addresses", 0)):,}</td><td class="num">{int(row.get("sources_reporting", 0))}</td></tr>'
        for row in rows
    )
    if not body:
        body = '<tr><td colspan="4">Network enrichment is unavailable for this run.</td></tr>'
    return f'<div data-tier="primary" data-family="v4"><h3 class="evidence-table">Current-run volume (context only)</h3><p class="note">Raw address count is retained as context, but it favours the largest providers; use persistence above for the comparable ranking.</p><div class="network-table-wrap"><table class="network-table"><tr><th>ASN</th><th>Network</th><th class="num">Addresses</th><th class="num">Sources</th></tr>{body}</table></div></div>'


def _class_overlap_panel(insights: dict[str, Any]) -> str:
    overlap = insights.get("class_overlap", [])
    if not isinstance(overlap, list):
        return ""
    rows = sorted(
        (row for row in overlap if isinstance(row, dict)),
        key=lambda row: (
            -float(row.get("jaccard", 0)),
            str(row.get("a", "")),
            str(row.get("b", "")),
        ),
    )[:8]
    body = "".join(
        f"<tr><td>{esc_html(str(row.get('a', 'unknown')))}</td>"
        f"<td>{esc_html(str(row.get('b', 'unknown')))}</td>"
        f'<td class="num">{float(row.get("jaccard", 0)):.1%}</td>'
        f'<td class="num">{int(row.get("shared_addresses", 0)):,}</td></tr>'
        for row in rows
    )
    if not body:
        return ""
    return (
        '<div class="wide-chart class-overlap" data-tier="primary" data-family="both">'
        '<div class="chart-top"><strong>Highest class overlap</strong>'
        f"<span>{len(rows)} highest pairs</span></div>"
        '<p class="note">Jaccard similarity measures shared observations over the combined '
        "observations of a pair. These low overlaps support treating the classes as "
        "independent, while the scorer still counts at most one vote per class.</p>"
        '<div class="table-scroll"><table class="prefix-table"><tr><th>Class A</th><th>Class B</th>'
        '<th class="num">Jaccard</th><th class="num">Shared observations</th></tr>'
        f"{body}</table></div></div>"
    )


def _source_rows(manifest: dict[str, Any]) -> str:
    sources = manifest.get("sources", {})
    if not isinstance(sources, dict):
        return ""
    rows: list[str] = []
    for name, info in sorted(sources.items()):
        if not isinstance(info, dict):
            continue
        status = str(info.get("status", "unknown"))
        status_class = "status-ok" if status == "ok" else "status-stale"
        republished = "yes" if bool(info.get("redistributable")) else "scoring only"
        rows.append(
            f'<tr><td class="source-name">{esc_html(str(name))}</td><td>{esc_html(str(info.get("independence_class") or "—"))}</td><td class="num">{int(info.get("records", 0)):,}</td><td class="status-text {status_class}">{esc_html(status)}</td><td>{republished}</td></tr>'
        )
    return "".join(rows)


def _analysis_footer(manifest: dict[str, Any], nc_manifest: dict[str, Any]) -> str:
    primary = _int(manifest.get("counts", {}), "published")
    noncommercial = _int(nc_manifest.get("counts", {}), "published")
    return f"""<section id="licensing" class="analysis-section"><div class="eyebrow">Terms and provenance</div><h2>Licensing is a publication control, not a footnote.</h2><div class="license-row"><div class="tier" data-tier="primary" data-family="both"><h3>Primary tier</h3><p>{primary:,} addresses suitable for commercial and non-commercial use. Restricted sources may contribute only to scoring and are never republished.</p></div><div class="tier" data-tier="noncommercial" data-family="both"><h3>Non-commercial tier</h3><p>{noncommercial:,} addresses under CC BY-NC-SA 4.0. It can retain share-alike material that the primary tier must withhold.</p></div></div></section>"""


def render_analysis(
    manifest: dict[str, Any],
    history: list[dict[str, Any]],
    insights: dict[str, Any],
    nc_manifest: dict[str, Any] | None = None,
) -> str:
    """Expose the evidence and publication trade-offs without making the operator page dense."""
    nc = nc_manifest or {}
    corpus = insights.get("corpus", {})
    networks = insights.get("networks", {})
    _, _, bad = _status(manifest)
    status_detail = (
        ", ".join(f"{name} ({state})" for name, state in bad) if bad else "No source needs review."
    )
    nav = "".join(
        f'<a href="#{key}" data-nav="{key}">{label}</a>'
        for key, label in (
            ("health", "Health"),
            ("method", "Method"),
            ("spectrum", "IPv4 spectrum"),
            ("networks", "Networks"),
            ("ipv6", "IPv6"),
            ("corpus", "Corpus"),
            ("sources", "Sources"),
            ("licensing", "Licensing"),
        )
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Aggregate analysis and publication method for xfeeds"><title>xfeeds · Analysis</title><style>{STYLE}</style></head><body><a class="skip" href="#main">Skip to content</a>{_status_strip(manifest)}<header class="shell brandbar">{_brand()}<nav class="topnav" aria-label="Primary"><a href="index.html">Console</a><a href="{PROJECT_URL}">Source</a></nav></header><div class="shell analysis-shell"><aside class="analysis-nav" aria-label="Analysis sections"><a class="back" href="index.html">← Operator console</a><div class="nav-label">Analysis</div>{nav}</aside><main id="main" class="analysis-main"><header class="analysis-heading"><div class="eyebrow">Evidence surface</div><h1>How the feed gets smaller before it gets useful.</h1><p class="lede">Aggregate analysis of the pipeline, its sources, and the deliberately conservative choices that keep a blocklist from becoming an outage.</p><div class="filter-bar" aria-label="Analysis filters"><label>Tier<select id="tier-filter"><option value="primary">Primary</option><option value="noncommercial">Non-commercial</option></select></label><label>Address family<select id="family-filter"><option value="both">Both families</option><option value="v4">IPv4</option><option value="v6">IPv6</option></select></label><span id="filter-status" class="filter-status"></span></div></header><section id="health" class="analysis-section"><div class="eyebrow">Run health</div><h2>Every refresh leaves a trace.</h2>{_history_chart(history)}<p class="note">{esc_html(status_detail)} A stalled source degrades a run rather than stopping publication; its status remains visible in the source table.</p><div class="empty-filter" data-tier="noncommercial" data-family="both">Refresh history is recorded per publication run. The chart shows the primary run; the non-commercial tier is rebuilt on the same cadence but counted separately.</div></section><section id="method" class="analysis-section"><div class="eyebrow">Publication method</div><h2>The funnel is the product.</h2><p class="note">The feed publishes corroborated evidence, not every address a source observed. Each subtraction is a safety or licensing rule applied before an address can become a firewall action.</p>{_funnel(manifest, insights)}{_corroboration_panel(manifest, insights)}<div class="empty-filter" data-tier="noncommercial" data-family="both">The non-commercial tier has its own licensed publication counts, but this aggregate evidence funnel is intentionally shown only for the primary corpus so restricted-source observations are never relabelled.</div></section><section id="spectrum" class="analysis-section"><div class="eyebrow">IPv4 distribution</div><h2>Where observations land in IPv4 space.</h2>{_ipv4_grid(insights)}<div class="empty-filter" data-tier="primary" data-only-family="v6">The /8 grid divides the 32-bit IPv4 space, so it has no IPv6 equivalent. IPv6 is examined by prefix rather than by address block in the <a href="#ipv6">IPv6 coverage</a> section.</div><div class="empty-filter" data-tier="noncommercial" data-family="both">The /8 observation grid is a primary-corpus aggregate. Tier selection never rewrites or invents a download path.</div></section><section id="networks" class="analysis-section"><div class="eyebrow">Network patterns</div><h2>Networks that recur across sources.</h2><p class="note" data-tier="primary" data-family="v4">{_int(networks, "distinct_asns_seen"):,} distinct ASNs were seen. Small-ASN results remain aggregated to avoid turning this section into an address disclosure channel.</p>{_asn_persistence(insights)}{_network_table(insights)}<div class="empty-filter" data-tier="primary" data-only-family="v6">Network enrichment maps IPv4 announcements to autonomous systems. The IPv6 records here are too few to attribute to networks without narrowing the aggregate further than disclosure allows.</div><div class="empty-filter" data-tier="noncommercial" data-family="both">Network enrichment is held to the primary aggregate in this surface; non-commercial selection leaves only paths that exist in the feeds.</div></section><section id="ipv6" class="analysis-section"><div class="eyebrow">IPv6 coverage</div><h2>Prefixes need different judgement than addresses.</h2>{_prefix_table(insights)}{_family_coverage_panel(insights)}<div class="empty-filter" data-tier="primary" data-only-family="v4">Only IPv6 records are analysed here. The IPv4 view of the same corpus is the <a href="#spectrum">/8 observation grid</a> and the <a href="#networks">network patterns</a> section.</div><div class="empty-filter" data-tier="noncommercial" data-family="both">IPv6 structural analysis is derived from the primary corpus and is not relabelled for the non-commercial tier.</div></section><section id="corpus" class="analysis-section"><div class="eyebrow">Disclosure control</div><h2>The corpus is visible only in aggregate.</h2><div class="two-col"><section data-tier="primary" data-family="both"><h3>What entered scoring</h3><p class="note"><strong>No individual address appears in this section.</strong> {_int(corpus, "addresses_observed"):,} addresses were observed from {_int(corpus, "sources_contributing")} sources before publication controls. There is no top-offending-addresses list.</p></section><section data-tier="primary" data-family="both"><h3>Why restricted sources appear here</h3><p class="note">A count is a derived fact, not an extract. A scoring-only source may be named against a count, but never against an address; GreyNoise and other restricted-source identities are not published per record.</p></section><section data-tier="noncommercial" data-family="both"><h3>Tier view</h3><p class="note">The non-commercial feed is licensed to retain additional share-alike material. Its filenames remain stable under <a href="noncommercial/">noncommercial/</a>.</p></section></div></section><section id="sources" class="analysis-section"><div class="eyebrow">Source health</div><h2>Independence beats source count.</h2><p class="note">{_hint("Independence class", "Sources that share upstream data contribute at most one vote, preventing copied lists from manufacturing false confidence.")} and {_hint("scoring only", "These sources can influence a confidence score, but their licences prohibit republishing their addresses.")} are explained beside the table, never inside its scrolling container.</p><div class="source-table-wrap" data-tier="primary" data-family="both"><table class="source-table"><tr><th>Source</th><th>Independence class</th><th class="num">Records</th><th>Status</th><th>Publication</th></tr>{_source_rows(manifest)}</table></div>{_class_overlap_panel(insights)}<div class="empty-filter" data-tier="noncommercial" data-family="both">The non-commercial tier uses its own manifest and preserves the same stable feed filenames. Source-level aggregate health is presented for the primary publication run.</div></section>{_analysis_footer(manifest, nc)}</main></div>{_footer()}<script>{ANALYSIS_SCRIPT}</script></body></html>"""


def render(
    manifest: dict[str, Any],
    history: list[dict[str, Any]],
    base_url: str = BASE_URL,
    nc_counts: dict[str, int] | None = None,
    insights: dict[str, Any] | None = None,
) -> str:
    """Retain the former renderer's console-shaped API for callers that only need index.html."""
    del nc_counts, insights
    return render_console(manifest, history, base_url)


def build_lookup_index(records: list[ScoredIndicator]) -> dict[str, Any]:
    """Preserve precision for IPv6 lookups because JavaScript numbers lose 128-bit bounds."""
    rows: list[list[Any]] = []
    rows6: list[list[Any]] = []
    for record in sorted(records, key=lambda item: item.sort_key()):
        item = record.ip_or_cidr
        if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            low = int(item.network_address)
            high = int(item.broadcast_address)
        else:
            low = high = int(item)
        common = [
            round(record.score),
            record.band.value,
            len(record.independence_classes),
            str(item),
            ", ".join(record.sources),
            record.restricted_corroboration,
            record.source_reference or "",
        ]
        if item.version == 4:
            rows.append([low, high, *common])
        else:
            rows6.append([str(low), str(high), *common])
    return {"v": 2, "r": rows, "r6": rows6}


def write_dashboard(feeds_dir: Path = Path("feeds")) -> tuple[Path, Path, Path]:
    """Write all public surfaces from committed artifacts so a presentation refresh needs no network."""
    manifest = json.loads((feeds_dir / "manifest.json").read_text(encoding="utf-8"))
    history_path = feeds_dir / "history.json"
    history = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    insights_path = feeds_dir / "insights.json"
    insights = (
        json.loads(insights_path.read_text(encoding="utf-8")) if insights_path.exists() else {}
    )
    nc_path = feeds_dir / "noncommercial" / "manifest.json"
    nc_manifest = json.loads(nc_path.read_text(encoding="utf-8")) if nc_path.exists() else {}
    published = json.loads((feeds_dir / "all.json").read_text(encoding="utf-8"))
    records = [ScoredIndicator.model_validate(entry) for entry in published.get("indicators", [])]
    blockable = [record for record in records if record.band is not Band.WITHHELD]
    lookup_path = feeds_dir / "lookup.json"
    lookup_path.write_text(
        json.dumps(build_lookup_index(blockable), separators=(",", ":")) + "\n", encoding="utf-8"
    )
    console_path = feeds_dir / "index.html"
    analysis_path = feeds_dir / "analysis.html"
    console_path.write_text(render_console(manifest, history), encoding="utf-8")
    analysis_path.write_text(
        render_analysis(manifest, history, insights, nc_manifest), encoding="utf-8"
    )
    logger.info(
        "dashboard_written",
        console=str(console_path),
        analysis=str(analysis_path),
        runs_charted=len(history),
    )
    return console_path, analysis_path, lookup_path

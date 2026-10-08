# Source discovery review, 2026-10-08

Review cycle for [issue #62](https://github.com/neilweitzel/xfeeds/issues/62),
run against `v1.0.1` and the live manifest generated `2026-10-08T16:27Z`. First
cycle to use the lane taxonomy and the persistent
[candidate register](SOURCE_CANDIDATES.md) (backlog items 3.2 and 3.3).

**Nothing is admitted by this document.** `sources.yaml`, `src/`, and
`.github/workflows/` are untouched. Every recommendation below still needs its
own PR, fixture, ADR, and scoring test, and a maintainer decision about which
minor release window it lands in.

## Summary

| Rank | Candidate | Lane | Recommendation |
|---|---|---|---|
| 1 | ReportedIP blacklist (CC BY 4.0) | botnet/abuse | 30-day shadow trial as a vote-only, non-admitting class, then decide admission |
| 2 | SANS ISC API `sources/attacks` | existing `dshield` class | Evaluate as a higher-volume replacement for `dshield_block` (20 /24s to ~9,200 fresh hosts) |
| 3 | SANS ISC `threatintel.txt` research-scanner labels | false-positive controls | Evaluate as a benign-scanner cap input alongside GreyNoise |
| 4 | AbuseIPDB Basic | commercial scoring-only | Run backlog 4.2 inside the 30-day free trial AbuseIPDB lists for every plan |
| 5 | Spur Anonymous feed | commercial scoring-only | Request a feed trial; the free Community plan does not include feeds |
| 6 | jacobrakai honeypot (CC0) | botnet/abuse | Register; evaluate in the same window as ReportedIP |

Everything else surveyed this cycle was rejected or deferred, with reasons, in
the lane tables below and in the register.

## Step 1: coverage gaps

From the live manifest:

- **24 configured sources reported `ok`; `feodo_tracker` is `expired`** (evidence
  age 217 days). abuse.ch's FAQ still attributes the empty datasets to the
  Emotet (2021) and Operation Endgame (2024) takedowns. No change: it remains
  fetched as a recovery signal under ADR-059.
- **6 admitting classes against 13 voting classes.** Categories with no admitting
  class: `abuse`, `botnet-c2`, `spam-source`, `telnet-attack` (unchanged since
  ADR-058).
- **IPv6 publishes from one class.** `families.v6` shows 91 published records,
  all Spamhaus DROPv6, `independence_classes: 1`. The ADR-033 open item for a
  second redistributable host-level IPv6 source is still open.
- **Clean tier is 128 records**, every one `bruteforceblocker` + `ipthreat`.
  Any permissively licensed independent source grows it directly.

## Step 3 (existing sources): upstream changes

Spot-checked on 2026-10-08 against the fetched payloads:

- Binary Defense header still reads "public use only ... may not be used for
  commercial resale or in products that are charging fees". Unchanged.
- Dataplane headers still read "free for non-commercial use ONLY" with
  redistribution prohibited. Unchanged.
- Spamhaus DROP v4 metadata still points to `spamhaus.org/drop/terms/`.
  Unchanged.
- Turris `LICENSE.txt` still CC BY-NC-SA 4.0. Unchanged.
- SANS ISC: the API page states the data is provided under CC BY-NC-SA 4.0 "if
  your lawyers ask", while `feeds_doc.html` says "Use of data permitted with
  attribution ... Do not resell the data. Other commercial uses are allowed."
  Under ADR-060 the stricter text governs, so `dshield_block` placement does not
  change. Recorded because it affects candidate 2 and 3 below.

No source needs a tier or state change from this cycle.

## Method

- Candidate payloads and current copies of every public existing source were
  fetched on 2026-10-08 between 16:30 and 17:10 UTC with a descriptive
  User-Agent.
- Host sets only: CIDR rows were excluded from Jaccard, but containment inside
  published CIDRs was counted separately.
- AbuseIPDB was not compared (keyed, and rows cannot leave private state).
- `ipsum_any` (every IPsum level) is reported as containment only, since it is
  an aggregate prior rather than an independence class.
- "Cloud share" counts addresses inside AWS, Google Cloud, DigitalOcean, and
  Oracle published ranges. Azure was not included, so it is a floor.
- "New primary if admitting" is an upper bound: candidate addresses that are
  also in at least one current admitting source but not published today. It
  ignores the allowlist and GreyNoise capping, both of which would reduce it.

## Measurements

| Candidate | Hosts | IPv6 | Max Jaccard (source) | Jaccard vs published | Novel vs every source and IPsum | Cloud share | New primary if admitting | Medium to high | New clean if CC-licensed |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|
| ReportedIP | 12,803 | 82 | 0.130 (greensnow) | 0.126 | 26.2% | 13.7% | 4,384 | 701 | 4,097 |
| SANS ISC `sources/attacks/10000` | 9,193 | 0 | 0.011 (cins) | 0.008 | 87.1% | 19.9% | 517 | 35 | n/a (NC-SA) |
| jacobrakai honeypot | 508 | 0 | 0.032 (greensnow) | 0.022 | 21.5% | 5.9% | 105 | 0 | 272 |
| HFish (yuexuan521) | 266 | 0 | 0.014 (binary_defense) | 0.006 | 17.3% | 4.1% | 95 | 27 | 72 |
| ThreatView IP high-confidence | 13,974 | 461 | 0.119 (blocklist_de) | 0.102 | 11.2% | 7.2% | 6,780 | 318 | rejected |
| Etnetera aggressive | 630 | 10 | 0.033 (tor) | 0.004 | 29.4% | **56.0%** | 246 | 0 | rejected |
| blocklist.net.ua | 221,339 | 0 | 0.053 (ipthreat) | 0.014 | 83.8% | 10.7% | 19,105 | 1,117 | rejected |
| ThreatHive | 200,662 | 0 | 0.136 (ipthreat) | 0.038 | 55.2% | 20.9% | 49,205 | 1,303 | rejected |

Every candidate clears the 0.5 Jaccard gate. Independence is not the binding
constraint this cycle; licence, aggregation, and hygiene are.

## Lane: botnet/abuse and attack sensors

### ReportedIP: recommended for a shadow trial

- **Licence:** CC BY 4.0, real `LICENSE` file in
  [`reportedip/reportedip-blacklist`](https://github.com/reportedip/reportedip-blacklist),
  credit to "ReportedIP (reportedip.com)". Commercial redistribution permitted,
  so it is the first new candidate since ipthreat that is eligible for
  `feeds/clean/`.
- **Sensor method:** first-party reports from the ReportedIP WordPress plugin,
  Linux agent, and operator honeypots. The confidence score is documented
  ([Confidence score](https://reportedip.com/docs/api/confidence-score/)):
  reports, reporter diversity, recency, severity, and a verified-honeypot bonus.
  Anti-poisoning caps: fewer than 5 effective reports caps at 49, fewer than 10
  at 74, a single repeat reporter at 60. Only scores of 75 or higher are listed.
  No third-party feed import is stated in the README, FAQ, or score docs.
- **Freshness:** `metadata.json` carries `generatedAt`; every CSV row carries
  `last_reported`. Rebuilt daily about 04:20 UTC.
- **Expiry, measured from git history:** unlike sefinek (ADR-057), addresses
  leave. 2026-10-01 to 2026-10-08: 2,135 removed, 2,611 added. Documented
  policy: after two weeks without a report the score halves every 30 days.
- **IPv6:** 82 host addresses under CC BY 4.0. Only 2 match a Blocklist.de IPv6
  host exactly (8 share a /64), so it does not close the IPv6 open item on its
  own, but it is the first redistributable, expiring, host-level IPv6 candidate
  found in three cycles.
- **Risks that justify shadow mode first:**
  - The project started 2026-02-28 and has one maintainer.
  - **Methodology changed on 2026-09-28:** the list went from 32,621 to 7,011
    addresses in one day, then rebuilt to about 12,800 by 2026-10-01 under the
    new 48-hour first-report delay. A source that changes shape this much needs
    its own observation window.
  - 98% of addresses carry CMS-login categories, so it is a WordPress-heavy
    vantage point.
  - Admitting it immediately would raise the primary feed by up to about 46%
    (4,384 records), mostly medium. The churn guard watches `high`, which would
    move about 8.6% (701 upgrades), so the guard would not catch it. That is
    exactly the kind of jump ADR-015's committed range asks to be decided
    explicitly, not discovered.
- **Incremental coverage hypothesis:** fills web-attack and CMS brute-force
  corroboration from a non-honeypot vantage point; expected overlap with
  published about 20%; expected FP risk moderate (community reports, 13.7%
  cloud). Keep it if, after 30 days, the list is stable in shape, upgrades hold
  up against allowlist and GreyNoise checks, and removal behavior continues.
- **Proposed shape:** new class `reportedip`, weight 0.7, `ttl_days: 7`,
  `vote: true`, non-admitting for the trial (ADR-035 pattern), parser for
  `blacklist-all.csv` using `last_reported` as the per-row timestamp.

### jacobrakai honeypot: register, evaluate with ReportedIP

CC0 1.0 (`LICENSE` text is a CC0 dedication even though GitHub reports
`NOASSERTION`). Single self-operated Cowrie/Heralding sensor, 508 addresses,
30-day activity window, hourly canonical feed at `jacobrakai.org/feed/`,
published research-scanner ranges excluded. Small and one vantage point:
63% of it is already in Dataplane. Worth adding only if it shares a release
window with ReportedIP; not worth a release on its own.

### Rejected this cycle

| Candidate | Gate failed | Evidence |
|---|---|---|
| HFish (yuexuan521) | Freshness and FP controls, deferred rather than rejected | MIT, 266 addresses, 24-hour rolling window. The `Updated:` header is unlabeled local time (UTC+8) and the list includes Censys and Palo Alto Xpanse scanner ranges. `anonymous99-Rise/honeypot-blocklist` is a fork of the same data and would share its class. |
| Etnetera aggressive | Licence; FP risk | No licence. 56% of addresses are in Google/AWS cloud ranges. |
| blocklist.net.ua | Licence; FP risk | "Absolutely open and accessible" is not a grant. Ban windows run up to a year and reasons are DDoS against specific Ukrainian sites. |
| ThreatHive | Aggregate | Self-described "20+ OSINT feeds and 50+ honeypots"; forbids bundling in a paid service. Would be `META_aggregate`. |
| ThreatView IP high-confidence | Licence; data quality | No licence. Contains reserved and invalid entries such as `0.0.0.2` and `1.0.0.0`. |
| ConfigServer blocklists | Licence; aggregate | Main lists are built from AbuseIPDB, IPThreat, CINS, and GreenSnow. No licence. |
| LittleJake ip-blacklist | Laundering restriction | Republishes AbuseIPDB score lists; rejected on the same principle as `borestad/blocklist-abuseipdb` (ADR-033). |
| romainmarcoux, bitwire-it, ip-db.com | Aggregate | Self-described aggregations of public lists already ingested. |
| James Brine | Licence (reason changed, verdict unchanged) | ADR-033 rejected it as a dead endpoint. The site is live again, but no licence is stated anywhere. |
| ELLIO free community list | Licence | "for homelabers, cybersecurity enthusiasts, and non-commercial individual use only". |
| Cisco Talos / Snort IP block list | Licence | Granted only "to test IP blocking functionality"; no derivative works. |
| AlienVault OTX | Licence; aggregate | EULA forbids republishing or distributing any portion of OTX. |
| Silent Push Community | Licence | "intended for evaluation, testing, and research, not Production Use". |
| myip.ms blacklist | Licence | Terms cover embedding the lookup form, not the list. |

## Lane: existing-class upgrade (SANS ISC / DShield)

`dshield_block` is 20 /24 subnets, which is why ADR-030 and the open items call
it "not worth a collector at that volume". The ISC API endpoint
`/api/sources/attacks/10000?json` returns **9,193 hosts, every one with
`lastseen` 2026-10-08**, per-IP `attacks`/`count`/`firstseen`/`lastseen`, from
the DShield sensor network. Max Jaccard 0.011, 87% novel against everything
xfeeds ingests.

It is the same publisher and the same licence (CC BY-NC-SA 4.0 per the API
page), so it stays in the `dshield` class: voting-only in the primary feed,
admitting only in `feeds/noncommercial/`. The upside is mostly in the
non-commercial tier. Before a PR: confirm the API's rate expectations (the docs
ask for a custom User-Agent and no more than hourly bulk fetches), decide
whether it replaces or augments `block.txt`, and set `ttl_days` from `lastseen`.
20% cloud share means the allowlist will matter.

## Lane: malware and C2

The ADR-033/2026-09-01 finding still holds: the free C2 ecosystem has no
redistributable source with an expiry policy, so `botnet-c2` stays
corroboration-only.

| Candidate | Verdict | Evidence |
|---|---|---|
| Feodo Tracker | Expired, keep fetching | Datasets still empty per abuse.ch FAQ. |
| URLhaus | Not evaluated further | Requires an abuse.ch Auth-Key since 2025-06-30; Community API is fair-use with commercial use possibly requiring the paid API. Same `abusech` class as ThreatFox, so it cannot add a vote. |
| montysecurity/C2-Tracker | Dead | Archived 2026-04-13 (already rejected for no licence). |
| Spamhaus Intelligence API (BCL) | Evaluation-only licence | Developer licence is free for 6 months at 5,000 queries/month but "does not cover commercial or high-volume use"; production needs a subscription. |
| Hunt.io C2 feed, ThreatView C2 | Commercial lane / no licence | See commercial lane. |

## Lane: proxy and anonymization

| Candidate | Verdict | Evidence |
|---|---|---|
| Spur Anonymous | Queued (backlog 3.1) | Community plan is $0 with 250 manual lookups and no feeds; Teams is $200/mo with 50k Context API calls. Feed tiers are sold by subscription and are not priced publicly. Feeds update daily, typically by 05:00 UTC, with IPv6 available. |
| X4BNet lists_vpn | Context lane, not a voting source | MIT. VPN and datacenter ranges derived from ASNs. Not evidence of abuse, so at most a published context tag. |
| IP2Proxy LITE PX | Context lane, scoring-only | Free with a download token. LITE pages say CC BY-SA 4.0 and commercial use with attribution, but the general terms restrict use to internal business purposes and prohibit redistribution. Read as written: no redistribution. Covers open proxies on IPv4 and IPv6. |
| IPQS, proxycheck.io | Not useful at free volume | 5,000/month and 1,000/day lookups. |
| ipapi.is VPN database, IPinfo privacy | Commercial lane | Paid; ipapi.is documents an enumeration method (buys VPN subscriptions and records exit nodes). |

## Lane: fraud infrastructure

| Candidate | Verdict | Evidence |
|---|---|---|
| Spamhaus free DNS query service (XBL/CSS) | Defer | Free for "non-commercial small organizations and individuals" at no more than 100,000 queries/day. Per-IP lookups would need a query budget design, and the data shares the `spamhaus` family. |
| Project Honey Pot http:BL | Defer | Free key, per-IP DNS, IPv4 only, key sharing forbidden. Scoring-only at best. |
| ReportedIP `fraud` and `spam` sublists | Covered by candidate 1 | 808 and 741 addresses. |

## Lane: IPv6

Still open after a third cycle. ReportedIP (82 hosts) is the only new
redistributable host-level IPv6 candidate with a removal policy; Etnetera (10)
and ThreatView (461) have no licence. Two IPv6 sources that agree on hosts
remain rare, because Blocklist.de and ReportedIP share only 2 exact IPv6 hosts.

## Lane: commercial credentialed scoring-only

Paid or authenticated access is not a disqualifier (backlog 3.2). Nothing here
is purchased by this review.

| Candidate | Access | Status |
|---|---|---|
| AbuseIPDB Basic | $25/mo or $228/yr; 100 blacklist requests/day, up to 100,000 IPs; "All plans include a free 30-Day trial" | Ready for backlog 4.2 inside the trial |
| Spur Anonymous feed | Sales-quoted subscription | Ready for backlog 3.1 once a trial is granted |
| GreyNoise paid tiers | Prices not public; Free refreshes every 8 hours, paid every 1 to 4 hours | Free tier already used for benign capping (ADR-049) |
| CrowdSec | Community blocklist only through a running Security Engine that shares signals; commercial embedding needs the Partnership Program | Register; would also produce original telemetry |
| ReportedIP API | `/check` free at 1,000/day; live `/blacklist` from the free Contributor plan if you run a honeypot | Not needed for the trial; the daily GitHub snapshot is enough |
| ELLIO Threat List MAX/ONE | 14-day trial | Register |
| Hunt.io, Team Cymru Scout, Censys, Spamhaus SIA | Paid, enterprise-priced or evaluation-only | Register; out of scope for this project's budget |

## Lane: false-positive controls

SANS ISC `threatintel.txt` is not a threat source: it is a 199,526-row dump of
every label ISC attaches to an address, most of them third-party lists
(`ciarmy`, `blocklistde*`, `forumspam`) or benign classes (`openresolver`,
`mastodon`). That makes it an aggregate as a voting source, and it is rejected
as one.

Its **research-scanner labels** are a different matter: 19,344 addresses across
35 labels (Censys, Palo Alto Xpanse, Shadowserver, Onyphe, Driftnet,
Internet-Census, LeakIX, Modat, University of Michigan, Rapid7 Sonar, Shodan,
and others). **789 currently published records carry one of those labels, and
46 of them are high band**, meaning GreyNoise did not cap them. Since GreyNoise
RIOT is not obtainable on the free tier (ADR-049), this is the closest free
complement. Used only to cap, nothing is redistributed, so the CC BY-NC-SA
versus feeds_doc question does not arise.

## Access needed from the maintainer

| Item | What is needed | Blocking |
|---|---|---|
| ReportedIP shadow trial | Nothing; public GitHub snapshot | Release-window decision only |
| DShield API upgrade | Nothing; custom User-Agent | Release-window decision only |
| ISC scanner labels | Nothing | Release-window decision only |
| AbuseIPDB 4.2 | Start the Basic trial on the existing account so the same token gets Basic limits | Account action |
| Spur 3.1 | Free Community account, then a feed trial request through Spur sales | Account action and trial terms |
| IP2Proxy LITE (optional) | Free IP2Location LITE account for a download token, stored as an Actions secret | Only if the context lane is pursued |

## Addendum: second pass

A second, independent pass on 2026-10-08 (17:00 to 17:45 UTC) used the same
fetch-and-compare method plus two additions: **containment** (share of a
candidate's hosts present in each single source) and a datacenter share
measured against X4BNet's `datacenter/ipv4.txt`, which is broader than the
four-provider cloud set above. No figure above changes. Nothing is admitted.

### Method finding: Jaccard misses subsets

Rutgers' attacker list (`report.rutgers.edu/DROP/attackers`, 1,498 hosts)
scores a maximum Jaccard of 0.077, but **93.7% of it is inside Blocklist.de**.
Containment is now measured alongside Jaccard.

> **Correction (same day, #66).** #64 wrote containment into the gate
> as a presumption of copying. That was wrong: independent sensors seeing the
> same attackers is the corroboration xfeeds exists to measure. Rutgers is
> derived because its own status page names a Blocklist.de listing as a block
> trigger, not because of the containment figure. Sblam's 72.5% containment in
> StopForumSpam is corroboration between two independent spam sensors. The
> gate now records containment and requires provenance evidence before
> assigning a shared class (ADR-064).

### New candidates

| Candidate | Hosts | Max Jaccard (source) | Max single-source containment | Novel vs all raw sources | Datacenter (X4B) | Verdict |
|---|---:|---|---|---:|---:|---|
| Carpathian (CC BY 4.0) | 1,233 | 0.035 (tor) | 26.6% (ipthreat) | 57.4% | 70.5% | Researching |
| Rutgers DROP attackers | 1,498 | 0.077 (ipsum_l5) | **93.7% (blocklist_de)** | 2.3% | 29.4% | Rejected: derived |
| Sblam | 1,239 | 0.084 (tor) | 72.5% (stopforumspam) | 24.9% | 61.7% | Ready: scoring-only (see correction) |
| myip.ms (full) | 212,320 | 0.010 (ipsum_l1) | 1.6% | 99.2% | 37.0% | Rejected (already): entries back to 2013 |

**Carpathian** publishes
[CC BY 4.0 files from its own infrastructure](https://carpathian.ai/threat-intelligence)
(IDS bans, SSH gateway permabans, web-edge error bursts), rebuilt hourly, with
`generated_at` and per-row `first_seen`/`last_seen`. It is independent and the
licence is clean-tier eligible. Three things block a PR:

- **Provenance.** 312 rows carry `sources: threat_intel`. The page says
  Carpathian buys and resells no one else's data but does not define the
  value. Ask before treating it as first-party.
- **No expiry on permabans.** 1,027 rows are `permaban`. 251 rows have a
  `last_seen` older than 90 days. A parser must use per-row `last_seen` as
  evidence time, not the file timestamp. Filtering to 30 days leaves 683 hosts.
- **Cloud-heavy vantage.** 70.5% sit in X4B datacenter ranges, consistent with
  a hosting provider being scanned from cloud VMs. That is real abuse, but
  recycled addresses are the high-FP case in the gate.

Upper bound on new primary records if it were admitting: 202 at 30 days
(257 unfiltered). IPv4 only; the nftables file declares an IPv6 set but it is
empty.

**GPF Comics DNSBL** is listed in FireHOL and ip-db.com as CC BY-SA 4.0. That
is FireHOL's licence for its own repository. GPF's site says: "No content on
this site may be copied, redistributed, and/or derived without explicit written
permission." Rejected, and recorded so an aggregator's licence label is not
mistaken for the publisher's grant again.

**Stratosphere AIP** (Aposemat IoT honeypots, CTU Prague) is a credible sensor
network, but its `Todays-Blacklists` files were last modified 2026-08-05 and
no licence is stated. Deferred.

### jacobrakai churn, measured

The canonical `https://jacobrakai.org/feed/blocklist.txt` sends
`Last-Modified`, so evidence age works without new parsing. Git history of
the hourly snapshot, daily samples 2026-09-09 to 2026-10-08: 416 to 507
hosts, 250 of the 416 starting addresses removed. The 30-day age-off is real.
Its `# Updated : …Z` header is not matched by the current `updated:` pattern
(space before the colon), so the HTTP header is what would be used. No change
to the deferred verdict: still batch with ReportedIP.

### Commercial lane additions

- **Spur.** Feeds are not in the free Community plan, so admission waits on an
  ongoing subscription. Terms are read as written under ADR-060
  (`redistribute: false`, issue/PR objection path); no permission request.
  *(Revised 2026-10-08: an earlier draft of this line proposed asking Spur for
  written authorization, which is not how this project handles licences.)*
- **IPSpamList** (NoVirusThanks): honeypots and spam traps since 2016, hourly
  regeneration, removal 15 days after last detection, and a dedicated
  `last-15-days-ipv6` feed (3,000 to 5,000 addresses). Paid yearly key and no
  named licence, so at best `redistribute: false`. It cannot close the IPv6
  open item, which needs a redistributable second source.
- **FraudGuard:** threat feeds start at the $299/month Business plan; the
  14-day trial excludes feeds.

### Existing-source terms

abuse.ch's current [Terms of Use](https://abuse.ch/terms-of-use/) limit
authenticated use to "not-for-profit purposes" and prohibit derivative works
without consent. ThreatFox is already `redistribute: false` and xfeeds is a
not-for-profit project, so no state change. Recorded as a watch item: if xfeeds
were ever offered commercially, ThreatFox's scoring role would need a Spamhaus
subscription.

### Correction: Sblam is a scoring-only candidate

Sblam collects from spam submitted to its own web-form classifier, so its
overlap with StopForumSpam is two independent sensors agreeing. Measured
2026-10-08: 1,239 hosts, 898 also in StopForumSpam, 309 (24.9%) seen by no
configured source, 15.4% Tor exits (already tagged and capped). It publishes
the list for blocking use and states that the service "can be used freely,
even on commercial websites"; it states no licence for redistribution. Read as
written, that is use without redistribution: `redistribute: false`, class
`sblam`, category `spam-source`.

What it adds: `spam-source` has two voting classes today (StopForumSpam and
DataPlane `smtpgreet`) and no admitting class. Sblam becomes a third
independent vote. Its 309 unique addresses cannot publish alone, which is
correct, but they enter the observed corpus and the aggregates, and any of them
becomes publishable the day a redistributable source corroborates it. Freshness
comes from `Last-Modified` (its `# Generated` line has no timezone). The list
covers the previous month, rebuilt daily, so `ttl_days` should be no more than
30.

### Correction: trial-only access is not a source

A source reachable only through a time-limited trial or evaluation licence
cannot contribute to the long-term dataset, so it is not a candidate. ELLIO
MAX/ONE (14 days) and the Spamhaus Intelligence API developer licence
(6 months, evaluation) move to rejected as trial-only. Spur and AbuseIPDB
Basic are evaluated as ongoing subscriptions. ReportedIP is unaffected: it is
a free, ongoing CC BY 4.0 dataset, and the "30-day shadow" above was an
internal observation period, not a vendor trial.

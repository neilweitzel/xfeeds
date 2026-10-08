# Source register

The single record of every source xfeeds runs, is evaluating, plans to evaluate,
or has rejected (backlog item 3.3). Read it before any source work, so nothing
already settled is re-surveyed and nothing deferred is forgotten.

- **Production** sources are documented with how they are used and what they
  contribute. From the v1.1.0 window on, contribution is measured on every run
  in `insights.json` → `class_contribution` and the analysis page panel
  "What each class contributes" ([ADR-064](DECISIONS.md), PR #65). The figures
  below are the 2026-10-08 16:27 UTC production snapshot.
- **Candidate statuses:** `new` · `researching` · `ready` (passes every gate,
  awaiting a release window) · `deferred` · `rejected`.
- **Lanes:** `c2` · `abuse` (attack sensors and abuse reports) · `spam` ·
  `proxy` (proxy/anonymization) · `fraud` · `ipv6` · `commercial`
  (credentialed scoring-only) · `fp` (false-positive controls) · `context`
  (tags, never votes) · `existing` (upgrade to a configured class).
- Full evidence lives in the linked review, ADR, or research document. Rows stay
  short.

Last full review: [2026-10-08](source-discovery-2026-10.md). Next scheduled
review: 2027-01-08.

## Rules this register applies

1. **Overlap is corroboration, not a defect.** Independent sensors that see the
   same attackers are what the score is built on. Independence classes stop
   copies from voting twice; overlap and containment are measured and reported,
   and a candidate shares an existing class only when it is shown to be derived
   from it (the publisher says so, or the sets are near-identical, as ET
   compromised-ips is to bruteforceblocker at Jaccard 0.953).
2. **Ongoing access only.** A source reachable only through a time-limited trial
   or evaluation licence is not a candidate: it cannot contribute to the
   long-term dataset. Paid sources are evaluated on an ongoing subscription,
   with any purchase a separate maintainer decision.
3. **Scoring-only is a full role.** A source whose terms allow use but not
   redistribution is evaluated as `redistribute: false`: it votes, raises
   confidence, and appears in aggregates, but never admits a record and never
   appears in a feed file.
4. **Licences are read as written** (ADR-060). We interpret each source's terms
   as best we can and act on that reading; we do not ask publishers for
   permission or clarification. Every feed header carries an issue/PR path, and
   any objection or correction is reviewed. Mistakes are possible and are fixed
   when reported.
5. A `rejected` entry reopens only when its stated reason changes.

## In production

Counts: **observed** is addresses in this run's observations, carried evidence
included. **Only this source** means seen by no other configured source.
**Named on published** is published primary records listing the source, which
only redistributable sources can be; restricted classes are never named per
record. Across the feed, 7,488 of 9,564 published records carry at least one
restricted corroboration.

### Admitting classes (can put a record into the primary feed)

| Source | Class | How it is used | Tiers | Weight / TTL | Observed | Only this source | Named on published (high) |
|---|---|---|---|---|---:|---:|---:|
| Spamhaus DROP v4 | `spamhaus` | Solo-promotes on its own: documented investigator verification (ADR-015) | primary, NC, clean | 1.0 / 30d | 1,671 | 1,668 | 1,671 (1,671) |
| Spamhaus DROP v6 | `spamhaus` | Same; the only IPv6 class publishing today | primary, NC, clean | 1.0 / 30d | 91 | 91 | 91 (91) |
| Blocklist.de all | `blocklist_de` | Largest independent attack-sensor vote | primary, NC | 0.8 / 10d | 29,920 | 16,206 | 6,608 (5,956) |
| Blocklist.de strongips | `blocklist_de` | Same class; adds a 30-day repeat-offender view | primary, NC | 0.8 / 30d | 385 | 4 | 181 (181) |
| ipthreat | `ipthreat` | Community reports at score ≥15 (ADR-050); clean-tier grant | primary, NC, clean | 0.8 / 10d | 7,477 | 1,542 | 5,386 (5,252) |
| CINS Army | `cins` | Sentinel IPS sensor vote | primary, NC | 0.8 / 10d | 20,108 | 6,702 | 2,146 (1,014) |
| Binary Defense | `binary_defense` | Artillery honeypot vote | primary, NC | 0.6 / 10d | 2,985 | 391 | 1,684 (718) |
| bruteforceblocker | `bruteforceblocker` | SSH brute-force vote | primary, NC | 0.6 / 10d | 656 | 1 | 379 (329) |
| ET compromised-ips | `bruteforceblocker` | Class-pinned mirror; carries the BSD grant that lets the class into the clean tier (ADR-051) | primary, NC, clean | 0.6 / 14d | 635 | 5 | 366 (316) |

### Voting-only classes (raise confidence, never admit)

| Source | Class | Why voting-only | Weight / TTL | Observed | Only this source |
|---|---|---|---|---:|---:|
| AbuseIPDB blacklist | `abuseipdb` | Terms restrict republishing (ADR-012). Free tier: 10,000 rows at confidence 100 | 0.9 / 10d | 23,427 | 1,423 |
| ThreatFox | `abusech` | Fair-use, not-for-profit terms; the only live C2 vote | 1.0 / 7d | 666 | 647 |
| Turris Sentinel greylist | `turris` | CC BY-NC-SA: admits in the non-commercial tier only; repeat-sighting window (ADR-061) | 0.7 / 7d | 31,577 | 6,396 |
| DataPlane (6 signals) | `dataplane` | Redistribution prohibited (ADR-048). proto41 and telnetlogin are almost entirely unique | 0.7 / 7d | 118k (all six) | 86k (all six) |
| StopForumSpam | `stopforumspam` | No-derivatives custom CC terms (ADR-050) | 0.5 / 14d | 54,302 | 52,759 |
| GreenSnow | `greensnow` | "Reproduction or republication strictly prohibited" | 0.6 / 10d | 6,908 | 1,963 |
| DShield block list | `dshield` | CC BY-NC-SA: admits in the non-commercial tier only; 20 /24s | 0.5 / 3d | 22 | 19 |

### Admitted in v1.1.0 (burn-in)

| Source | Class | How it is used | Tiers | Weight / TTL | PR |
|---|---|---|---|---|---|
| ReportedIP | `reportedip` | Admitting community-report vote (web, CMS, brute force); IPv6 hosts; clean-tier grant | primary, NC, clean | 0.7 / 7d | ADR-067 |
| jacobrakai honeypot | `jacobrakai` | Admitting honeypot vote; first admitting class for `telnet-attack`; clean-tier grant | primary, NC, clean | 0.6 / 7d | ADR-066 |
| Sblam | `sblam` | Scoring-only third vote for `spam-source`; never admits, never republished | none (scoring only) | 0.5 / 7d | ADR-065 |

### Non-voting roles

| Source | Role | Effect this run |
|---|---|---|
| GreyNoise (free Business tier) | Caps benign scanners from high to medium; aggregate reporting only (ADR-049) | 1,094 records capped |
| Tor exit list | `tor-exit` tag, hard-capped below high (ADR-013) | 1,232 exits tagged |
| IPsum levels | Bounded prior at level ≥5; never a vote (ADR-011) | named on 5,452 published records |
| Allowlists (Cloudflare, Google, GitHub, bots) | Applied last; a failed fetch aborts the run | 5,430 removed in the 2026-10-08 scratch run |

### Configured but not contributing

| Source | State | Revisit when |
|---|---|---|
| Feodo Tracker | Expired (ADR-059), fetched as a recovery signal | Payload timestamp moves; then a reactivation review |
| SSLBL | Disabled, deprecated upstream | Never |
| Spamhaus ASN-DROP | Disabled annotation | ASN context work |
| FireHOL level1 | Disabled aggregate (ADR-011) | Never as a vote |
| sefinek | Disabled: no expiry, measured (ADR-057) | Upstream documents expiry |
| Data-Shield (duggytuxy) | Disabled aggregate (ADR-048) | Never as a vote |

## Candidates

| Candidate | Lane | Status | Access | Last reviewed | Next step | Evidence |
|---|---|---|---|---|---|---|
| Spur Anonymous feed | proxy, ipv6, commercial | researching | Ongoing paid subscription (feeds are not in the free plan) | 2026-10-08 | Blocked only on a subscription. Terms read as written: `redistribute: false`, daily feed, conservative weight (backlog 3.1) | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| SANS ISC API `sources/attacks` | existing | ready | Free, ongoing | 2026-10-08 | Augment `dshield` class from 20 /24s to ~9,200 fresh hosts; keep the ISC "not a blocklist" caveat in its notes | [2026-10](source-discovery-2026-10.md) |
| SANS ISC research-scanner labels | fp | ready | Free, ongoing | 2026-10-08 | Cap input alongside GreyNoise: 789 published records carry one, 46 high | [2026-10](source-discovery-2026-10.md) |
| Carpathian | abuse | ready | Free, ongoing, CC BY 4.0 | 2026-10-08 | Admit in v1.1.0. Read as written: no third-party data, so `threat_intel` rows are first-party; per-row `last_seen` bounds stale permabans | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| IPSpamList (NoVirusThanks) | abuse, ipv6, commercial | new | Ongoing yearly subscription | 2026-10-08 | Paid yearly key, no named licence: scoring-only if subscribed. Honeypots since 2016, 15-day expiry, IPv6 feed | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| Original xfeeds honeypot | abuse, ipv6 | new | Self-operated | 2026-10-08 | ADR-033 growth direction 2: a class nobody else has. Not yet scoped | [ADR-033](DECISIONS.md) |
| Blocklist.de or CINS dated variants | existing | new | Free | 2026-10-08 | Open item: per-row dates would make recency decay real | [DECISIONS open items](DECISIONS.md) |
| `threatview_CS_c2.rules` | c2 | researching | Free | 2026-08-14 | Provenance check still open (ADR-050) | [ADR-050](DECISIONS.md) |
| VoIPBL | abuse | new | Free | 2026-08-13 | 97,480 netblocks of VoIP attackers, no licence stated: evaluate scoring-only and netblock width | [licence research](licence-research-2026-08.md) |
| Interserver / MailBaby bad IPs | abuse, spam | new | Free | 2026-08-13 | Live 48-hour, one-week, and full windows; no licence. Measure, then decide scoring-only | [licence research](licence-research-2026-08.md) |
| Team Cymru fullbogons | fp | new | Free | 2026-08-13 | Hygiene or allowlist input, never a vote | [licence research](licence-research-2026-08.md) |
| HFish (yuexuan521) | abuse | deferred | Free, MIT | 2026-10-08 | Timestamp gains a timezone and scanner ranges are filtered | [2026-10](source-discovery-2026-10.md) |
| X4BNet lists_vpn | context | deferred | Free, MIT | 2026-10-08 | Context tag only, never a vote | [2026-10](source-discovery-2026-10.md) |
| IP2Proxy LITE PX | context | deferred | Free account token | 2026-10-08 | Tag-only; terms prohibit redistribution | [2026-10](source-discovery-2026-10.md) |
| Spamhaus free DNS query service (XBL/CSS) | fraud | deferred | Free, ongoing, query-based | 2026-10-08 | Needs a per-IP query budget; `spamhaus` family question | [2026-10](source-discovery-2026-10.md) |
| Project Honey Pot http:BL | fraud | deferred | Free key, query-based | 2026-10-08 | Needs a per-IP query budget | [2026-10](source-discovery-2026-10.md) |
| CrowdSec community blocklist | abuse | deferred | Free with a running engine | 2026-10-08 | Requires a Security Engine sharing signals; pairs naturally with the xfeeds honeypot | [2026-10](source-discovery-2026-10.md) |
| FraudGuard threat feeds | commercial | deferred | Ongoing paid ($299/mo Business) | 2026-10-08 | Budget decision | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| Stratosphere AIP | abuse | deferred | Free | 2026-10-08 | Files stale since 2026-08-05; no licence stated | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| DigitalSide Threat-Intel | c2 | new | Free, MIT | 2026-10-08 | Endpoint reset the connection; retry and measure | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |

## Rejected

| Candidate | Lane | Last reviewed | Reason | Revisit when |
|---|---|---|---|---|
| AbuseIPDB Basic expansion | commercial | 2026-10-08 | Not paying; AbuseIPDB stays in production on the free tier | Purchase decision changes |
| ELLIO Threat List MAX/ONE | commercial | 2026-10-08 | Trial-only access (14 days) | Ongoing plan considered |
| Spamhaus Intelligence API developer licence | c2, commercial | 2026-10-08 | Evaluation-only licence, 6 months | Commercial subscription approved |
| Silent Push Community | commercial | 2026-10-08 | Not for production use | Terms change |
| ELLIO free community list | abuse | 2026-10-08 | Non-commercial individual use only | Terms change |
| Rutgers DROP attackers | abuse | 2026-10-08 | Publisher names a Blocklist.de listing as an input trigger (93.7% inside it); no licence | Never as a separate class |
| GPF Comics DNSBL | spam | 2026-10-08 | Site forbids copying or redistribution without written permission; FireHOL's CC BY-SA label is FireHOL's, not GPF's | Written permission |
| BotScout | spam | 2026-10-08 | No licence; endpoint returned 16 bytes | Licence and a list endpoint |
| MuteBefehl ICS honeypot | abuse | 2026-10-08 | Stale since 2026-08-02; mixes in bans already reported to AbuseIPDB | Updates resume |
| Etnetera aggressive IPs | abuse | 2026-10-08 | No licence; 56% cloud | Licence published |
| blocklist.net.ua | abuse | 2026-10-08 | No licence; year-long bans; site-specific DDoS reports | Licence published |
| ThreatHive | abuse | 2026-10-08 | Aggregate of 20+ OSINT feeds | Never as a vote |
| ThreatView IP high-confidence | abuse, ipv6 | 2026-10-08 | Terms forbid republishing or derivatives; reserved/invalid entries | Terms change and data cleaned |
| ConfigServer blocklists | abuse | 2026-10-08 | Built from AbuseIPDB, IPThreat, CINS, GreenSnow | Never as a vote |
| LittleJake ip-blacklist | abuse | 2026-10-08 | Republishes AbuseIPDB | Never |
| romainmarcoux, bitwire-it, ip-db.com | abuse | 2026-10-08 | Aggregates | Never as votes |
| James Brine | abuse | 2026-10-08 | No licence (endpoint live again) | Licence published |
| myip.ms blacklist | abuse | 2026-10-08 | No list licence; entries back to 2013 | Licence and expiry |
| Cisco Talos / Snort IP block list | abuse | 2026-10-08 | Test-only licence | Terms change |
| AlienVault OTX | abuse | 2026-10-08 | EULA forbids redistribution; aggregate | Terms change |
| SANS ISC `threatintel.txt` as a vote | abuse | 2026-10-08 | Label dump of third-party lists (see fp lane) | Never as a vote |
| URLhaus | c2 | 2026-10-08 | Same `abusech` class as ThreatFox | Class model changes |
| montysecurity/C2-Tracker | c2 | 2026-10-08 | Archived; no licence | Never |
| HoneyDB | abuse | 2026-09-01 | No redistribution or embedding, even scoring-only | Commercial licence bought |
| Viriback Tracker | c2 | 2026-09-01 | No licence; all-time list | Licence and expiry |
| TweetFeed | c2 | 2026-09-01 | CC0, but "someone tweeted it" with no verification | Verification step added |
| criminalip C2 daily sample | c2 | 2026-09-01 | 50-address shop-window sample, bespoke licence | Never |
| ET `emerging-botcc.rules` | c2 | 2026-09-01 | Same 5 addresses as Feodo | Never |
| borestad/blocklist-abuseipdb | abuse | 2026-08-12 | Republishes AbuseIPDB | Never |
| Ultimate.Hosts.Blacklist | abuse | 2026-08-12 | Mega-aggregate | Never as a vote |
| C2IntelFeeds (drb-ra) | c2 | 2026-10-08 | `NOASSERTION`, no grant (still, 2026-10-08) | Licence published |
| botvrij.eu | c2 | 2026-08-13 | 4 addresses, stale since 2026-02-03 | Volume returns |
| CriticalPathSecurity feeds | abuse | 2026-08-13 | MIT repo re-aggregating restricted upstreams | Never as a vote |
| Maltrail trails | c2 | 2026-08-13 | Aggregate trails crediting third parties | Never as a vote |
| CIRCL open data | abuse | 2026-08-13 | CC BY 4.0 but no IP blocklist published | An IP list appears |
| Blocklist Project | abuse | 2026-08-13 | Domain lists, not IPs | Never |
| OpenPhish community | fraud | 2026-08-13 | Personal use only; URLs, not IPs | Never |
| Project Honey Pot directory, CleanTalk, 3CORESec, CyberCure, Rescure, Charles Haley, NoThink, Mirai tracker | various | 2026-08-13 | Dead, HTML-only, or no parseable list | Endpoint returns |
| SSLBL | c2 | 2026-08-15 | Deprecated upstream; capability moved to paid feeds | Never |

# Source candidate register

Persistent state for every source candidate the discovery process has
considered (backlog item 3.3). Read this before surveying, so a review does not
re-evaluate settled candidates or lose track of deferred ones.

- **Statuses:** `new` · `researching` · `shadow` (vote-only private trial) ·
  `burn-in` · `accepted` · `rejected` · `deferred`
- **Lanes:** `c2` (malware/C2) · `abuse` (botnet/abuse and attack sensors) ·
  `proxy` (proxy/anonymization) · `fraud` · `ipv6` · `commercial`
  (credentialed scoring-only) · `fp` (false-positive controls) · `existing`
  (upgrade to a configured class)
- A `rejected` entry is re-opened only when its stated reason changes. Put the
  condition in **Revisit when**.
- Full evidence lives in the linked review or ADR. Keep rows short.

Last full review: [2026-10-08](source-discovery-2026-10.md). Next scheduled
review: 2027-01-08.

## Active and deferred

| Candidate | Lane | Status | Last reviewed | Revisit | Revisit when / next step | Evidence |
|---|---|---|---|---|---|---|
| ReportedIP blacklist | abuse, ipv6 | researching | 2026-10-08 | next minor window | Shadow trial: vote-only, non-admitting, 30 days, then decide admission | [2026-10](source-discovery-2026-10.md) |
| SANS ISC API `sources/attacks` | existing | researching | 2026-10-08 | next minor window | Replace or augment `dshield_block`; confirm rate expectations | [2026-10](source-discovery-2026-10.md) |
| SANS ISC research-scanner labels | fp | researching | 2026-10-08 | next minor window | Cap input alongside GreyNoise | [2026-10](source-discovery-2026-10.md) |
| AbuseIPDB Basic | commercial | new | 2026-10-08 | on access | Backlog 4.2 inside the 30-day trial | [backlog 4.2](POST_BURN_IN_BACKLOG.md) |
| Spur Anonymous feed | commercial, proxy | new | 2026-10-08 | on access | Backlog 3.1 once a feed trial is granted | [backlog 3.1](POST_BURN_IN_BACKLOG.md) |
| jacobrakai honeypot | abuse | deferred | 2026-10-08 | with ReportedIP | Batch with ReportedIP; too small for its own release | [2026-10](source-discovery-2026-10.md) |
| HFish (yuexuan521) | abuse | deferred | 2026-10-08 | 2027-01-08 | Timestamp gains a timezone and scanner ranges are filtered | [2026-10](source-discovery-2026-10.md) |
| X4BNet lists_vpn | proxy | deferred | 2026-10-08 | context-tag work | Only as a published context tag, never a vote | [2026-10](source-discovery-2026-10.md) |
| IP2Proxy LITE PX | proxy | deferred | 2026-10-08 | context-tag work | Scoring/tag-only; needs a free download token | [2026-10](source-discovery-2026-10.md) |
| Spamhaus free DNS query service | fraud | deferred | 2026-10-08 | 2027-01-08 | Per-IP query budget designed; family question for `spamhaus` | [2026-10](source-discovery-2026-10.md) |
| Project Honey Pot http:BL | fraud | deferred | 2026-10-08 | 2027-01-08 | Per-IP query budget designed | [2026-10](source-discovery-2026-10.md) |
| CrowdSec community blocklist | commercial | deferred | 2026-10-08 | if a sensor is run | Requires running a Security Engine that shares signals | [2026-10](source-discovery-2026-10.md) |
| ELLIO Threat List MAX/ONE | commercial | deferred | 2026-10-08 | on budget | 14-day trial available; free list is non-commercial individual only | [2026-10](source-discovery-2026-10.md) |
| Carpathian threat-intel blocklist | abuse | researching | 2026-10-08 | on operator reply | CC BY 4.0, own infrastructure. Needs `threat_intel` provenance and `permaban` expiry confirmed; parser must filter on per-row `last_seen` | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| IPSpamList (NoVirusThanks) | commercial, ipv6 | new | 2026-10-08 | on budget | Paid yearly key; own honeypots since 2016, 15-day expiry, `last-15-days-ipv6` feed. Licence unnamed: get terms before any trial | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| FraudGuard threat feeds | commercial | deferred | 2026-10-08 | on budget | Feeds only from Business ($299/mo); trials exclude feeds | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| Stratosphere AIP blacklists | abuse | deferred | 2026-10-08 | 2027-01-08 | Files last modified 2026-08-05 (stale); no licence found. Revisit if updates resume and a licence is stated | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| DigitalSide Threat-Intel | c2 | new | 2026-10-08 | 2027-01-08 | MIT; malware-analysis lab. Endpoint reset the connection on 2026-10-08, so not measured | [2026-10 addendum](source-discovery-2026-10.md#addendum-second-pass) |
| `threatview_CS_c2.rules` | c2 | researching | 2026-08-14 | 2027-01-08 | Provenance check still open from ADR-050 | [ADR-050](DECISIONS.md) |
| sefinek Malicious-IP-Addresses | abuse, ipv6 | rejected | 2026-09-01 | on change | Upstream documents an expiry policy (ADR-057) | [ADR-057](DECISIONS.md) |
| Feodo Tracker | c2 | accepted, expired | 2026-10-08 | each review | Payload timestamp moves; then run the reactivation review | [ADR-059](DECISIONS.md) |

## Rejected

| Candidate | Lane | Last reviewed | Reason | Revisit when |
|---|---|---|---|---|
| Rutgers DROP attackers | abuse | 2026-10-08 | 93.7% contained in Blocklist.de, which its page names as a trigger; no licence | Never as a separate class |
| Sblam blacklist | abuse | 2026-10-08 | No licence for the list; 72.5% contained in StopForumSpam | Licence published |
| GPF Comics DNSBL | abuse | 2026-10-08 | Site copyright forbids redistribution without written permission. The CC BY-SA label seen in FireHOL and ip-db.com is FireHOL's, not the publisher's | Written permission |
| BotScout | abuse | 2026-10-08 | No licence; public endpoint returned 16 bytes | Licence and a list endpoint |
| MuteBefehl ICS honeypot | abuse | 2026-10-08 | Last update 2026-08-02; `high.txt` mixes in fail2ban bans already reported to AbuseIPDB | Updates resume |
| Etnetera aggressive IPs | abuse | 2026-10-08 | No licence; 56% cloud | Licence published |
| blocklist.net.ua | abuse | 2026-10-08 | No licence; year-long bans; site-specific DDoS reports | Licence published |
| ThreatHive | abuse | 2026-10-08 | Aggregate of 20+ OSINT feeds | Never as a voting source |
| ThreatView IP high-confidence | abuse, ipv6 | 2026-10-08 | No licence; reserved/invalid entries | Licence published and data cleaned |
| ConfigServer blocklists | abuse | 2026-10-08 | Aggregate of AbuseIPDB/IPThreat/CINS/GreenSnow; no licence | Never as a voting source |
| LittleJake ip-blacklist | abuse | 2026-10-08 | Republishes AbuseIPDB | Never |
| romainmarcoux, bitwire-it, ip-db.com | abuse | 2026-10-08 | Aggregates | Never as voting sources |
| James Brine | abuse | 2026-10-08 | No licence (endpoint now live) | Licence published |
| ELLIO free community list | abuse | 2026-10-08 | Non-commercial individual use only | Terms change |
| Cisco Talos / Snort IP block list | abuse | 2026-10-08 | Test-only licence | Terms change |
| AlienVault OTX | abuse | 2026-10-08 | EULA forbids redistribution; aggregate | Terms change |
| Silent Push Community | commercial | 2026-10-08 | Not for production use | Terms change |
| myip.ms blacklist | abuse | 2026-10-08 | No licence for the list | Licence published |
| SANS ISC `threatintel.txt` as a voting source | abuse | 2026-10-08 | Aggregate label dump | Never as a voting source (see fp lane) |
| URLhaus | c2 | 2026-10-08 | Shares `abusech` class with ThreatFox; cannot add a vote | Class model changes |
| Spamhaus Intelligence API developer licence | c2, commercial | 2026-10-08 | Evaluation only, not production | Commercial subscription approved |
| montysecurity/C2-Tracker | c2 | 2026-10-08 | Archived 2026-04-13; no licence | Never |
| HoneyDB | abuse | 2026-09-01 | No redistribution or embedding | Commercial licence bought |
| Viriback, TweetFeed, criminalip C2 sample, ET botcc | c2 | 2026-09-01 | See DECISIONS open items | Per open items |
| ADR-033 set (borestad, Ultimate.Hosts, C2IntelFeeds, botvrij, and others) | various | 2026-08-12 | See ADR-033 | Per ADR-033 |
| SSLBL | c2 | 2026-08-15 | Deprecated upstream; capability moved to paid feeds | Never |

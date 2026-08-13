# Licence & redistribution research: public IP threat-intelligence feeds

Research session date: **2026-08-13 (UTC)**. Every value below comes from a page fetched during this session. Where a page could not be reached or the terms are silent, the cell reads `n.a.` Nothing here is filled in from general knowledge.

Context for the assessment: the project republishes a combined IP list publicly on GitHub Pages, does not sell anything, but downstream consumers may be commercial. So "non-commercial only" licences are treated as **PERMITTED WITH CONDITIONS (NC)** at best, and as a practical blocker for a public aggregate whose downstream use cannot be controlled.

---

## Table 1 — Existing sources

| Source | Licence | Redistribution | Attribution required | Entries | Actively maintained | Terms URL |
|---|---|---|---|---|---|---|
| Binary Defense Artillery Threat Intelligence Banlist | Custom terms in file header; no formal licence, no LICENSE file in the [Artillery repo](https://github.com/BinaryDefense/artillery) | **PERMITTED WITH CONDITIONS** — no redistribution ban; ban is on *commercial resale / charging fees*. "Public use only" | Not stated | 3,544 IPs (3,555 lines incl. 11 comment lines), fetched from [banlist.txt](https://binarydefense.com/banlist.txt) | Yes — live file served 2026-08-13 | [binarydefense.com/banlist.txt](https://binarydefense.com/banlist.txt) (header block) |
| CINS Army List (cinsscore.com) | No formal licence; permissive statement only ([cinsscore.com](https://cinsscore.com/)) | **PERMITTED WITH CONDITIONS** — "use in any way you see fit"; conditions are effectively none, but nothing is written about republication specifically | Not stated | 15,000 IPs, capped by design ([ci-badguys.txt](http://cinsscore.com/list/ci-badguys.txt), [cinsscore.com](https://cinsscore.com/)) | Yes — file served 2026-08-13 | [cinsscore.com](https://cinsscore.com/) |
| StopForumSpam (toxic_ip_cidr.txt) | Custom terms + unspecified "Creative Commons License" ([stopforumspam.com/legal](https://www.stopforumspam.com/legal)) | **PERMITTED WITH CONDITIONS** — non-commercial only, no charging for software using the data; CC version/flavour unspecified | Not stated | 60 CIDR entries ([toxic_ip_cidr.txt](https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt)) | Yes — served 2026-08-13 ([downloads page](https://www.stopforumspam.com/downloads)) | [stopforumspam.com/legal](https://www.stopforumspam.com/legal) |
| AbuseIPDB blacklist API | Proprietary ToS ([abuseipdb.com/legal](https://www.abuseipdb.com/legal)) | **PROHIBITED** — express ban on republishing/reselling site content and on reproducing/copying the API "and associated data" | n.a. (moot) | n.a. — API key required, not fetched | Yes | [abuseipdb.com/legal](https://www.abuseipdb.com/legal) |
| abuse.ch — Feodo Tracker | **CC0** per platform ToS on the blocklist page ([feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/)) | **PERMITTED** (CC0, commercial and non-commercial) — but see caveat: datasets are currently **empty** and platform-wide [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/) impose auth + fair-use limits | No | 0 — "Our Feodo Tracker datasets are currently empty" ([feodotracker.abuse.ch](https://feodotracker.abuse.ch/)) | Site live 2026-08-13, but data empty | [feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/) and [abuse.ch/terms-of-use](https://abuse.ch/terms-of-use/) |
| abuse.ch — ThreatFox | Fair-use ToS, no CC0 statement found ([threatfox.abuse.ch/faq](https://threatfox.abuse.ch/faq/), [abuse.ch/terms-of-use](https://abuse.ch/terms-of-use/)) | **UNCLEAR / effectively restricted** — auth key mandatory, not-for-profit fair use, commercial use may require paid Spamhaus subscription; no explicit redistribution grant | n.a. | n.a. — Auth-Key required for every export ([threatfox.abuse.ch/export](https://threatfox.abuse.ch/export/)) | Yes | [abuse.ch/terms-of-use](https://abuse.ch/terms-of-use/) |
| Spamhaus DROP | Custom free-use terms ([spamhaus.org DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)) | **PERMITTED WITH CONDITIONS** — free for any use including commercial; credit to Spamhaus Project required when used in a product; date and © text must remain with the file/data | **Yes** — "credit must be given to Spamhaus Project, and the date and © text should remain with the file and data" | 1,688 CIDR records ([drop_v4.json](https://www.spamhaus.org/drop/drop_v4.json)) | Yes — re-evaluated daily per [DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | [spamhaus.org/blocklists/do-not-route-or-peer](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| Blocklist.de | **No licence stated.** [Terms/Privacy page](https://www.blocklist.de/en/terms.html) covers reporting accounts and data retention only; no reuse/redistribution clause | **UNCLEAR** — export page says only "These files are as they are, and to be used at your own risk"; site is "a free and voluntary service", nothing about republication | Not stated | 31,459 IPs in all.txt (site reports 31,465) ([lists.blocklist.de/lists/all.txt](https://lists.blocklist.de/lists/all.txt), [export page](https://www.blocklist.de/en/export.html)) | Yes — regenerated every 30 min | [blocklist.de/en/terms.html](https://www.blocklist.de/en/terms.html) and [blocklist.de/en/export.html](https://www.blocklist.de/en/export.html) |
| GreenSnow | Custom terms — all-rights-reserved ([greensnow.co](https://greensnow.co/)) | **PROHIBITED** — "Reproduction or republication strictly prohibited." | n.a. (moot) | 3,583 per site counter; 3,587 lines in the file ([greensnow.co](https://greensnow.co/), [blocklist.greensnow.co/greensnow.txt](https://blocklist.greensnow.co/greensnow.txt)) | Yes — "Last update : 3:10 13/08/2026" | [greensnow.co](https://greensnow.co/) |
| bruteforceblocker (danger.rulez.sk) | **No licence stated** — [project page](http://danger.rulez.sk/index.php/bruteforceblocker/) describes the tool and links the list; no terms of use anywhere on the page | **UNCLEAR** | Not stated | 553 IPs — file header says "Result contains 553 entries" ([blist.php](https://danger.rulez.sk/projects/bruteforceblocker/blist.php)) | Yes — Last-Modified 2026-08-13 01:20 GMT in file header | [danger.rulez.sk/index.php/bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) |
| Tor Project exit list | **No licence found on the data endpoint.** [torbulkexitlist](https://check.torproject.org/torbulkexitlist) is a bare IP list with no header; [Tor Metrics About](https://metrics.torproject.org/about.html) states data policy but no reuse licence; the canonical LICENSE file at gitlab.torproject.org returned HTTP 403 in this session | **UNCLEAR** — no licence text retrievable in this session (Tor's software is BSD-licensed, but I could not fetch that file, so I am not asserting it) | Not stated on the endpoint | 1,337 IPs ([torbulkexitlist](https://check.torproject.org/torbulkexitlist)) | Yes — served 2026-08-13 | [check.torproject.org/torbulkexitlist](https://check.torproject.org/torbulkexitlist) |
| IPsum (stamparm) | **The Unlicense** (public domain) ([LICENSE](https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE), badge in [README](https://raw.githubusercontent.com/stamparm/ipsum/master/README.md)) | **PERMITTED** — unconditional | No | 129,253 entries ([ipsum.txt](https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt)) | Yes — README "Wall of Shame (2026-08-13)" | [github.com/stamparm/ipsum/LICENSE](https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE) |
| Turris Sentinel greylist | **CC BY-NC-SA 4.0** — confirmed ([LICENSE.txt](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt)) | **PERMITTED WITH CONDITIONS** — attribution + share-alike + **non-commercial only** | **Yes** — CC BY-NC-SA attribution; no exact string specified beyond naming "Turris Sentinel Greylist" / CZ.NIC | 9,530 CSV rows ([greylist-latest.csv](https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv)) | Yes — file dated 12-Aug-2026 22:07 ([directory index](https://view.sentinel.turris.cz/greylist-data/)) | [view.sentinel.turris.cz/greylist-data/LICENSE.txt](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt) |

### Verbatim licence quotes — existing sources where redistribution is PERMITTED or PERMITTED WITH CONDITIONS

**Binary Defense Artillery Banlist** — [https://binarydefense.com/banlist.txt](https://binarydefense.com/banlist.txt), file header:

> \# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
> \# https://www.binarydefense.com
> \#
> \# Note that this is for public use only.
> \# The ATIF feed may not be used for commercial resale or in products that are charging fees for such services.
> \# Use of these feeds for commerical (having others pay for a service) use is strictly prohibited.

**CINS Army List** — [https://cinsscore.com/](https://cinsscore.com/):

> The CINS Army list is here and at Emerging Threats as part of their Open Source Community. The link below is provided as a simple text file, with which you can parse and use in any way you see fit. We assume Network Administrators will use the IP addresses from this file in their firewall blacklists and possibly in custom IDS and IPS signatures.

> CINS Army is a way for our company to give back to the community by sharing valuable threat intelligence harvested from our CINS system.

**StopForumSpam** — [https://www.stopforumspam.com/legal](https://www.stopforumspam.com/legal), "API/data usage":

> Your use of this data and supporting software is non-commercial.
> You will not charge money for any software that utilizes the data.
> API queries are limited to 20,000 per day.
> Anything else is covered under a Creative Commons License
> Any of the above terms way be waived, at the discretion, of the copyright holder (this website).

**abuse.ch Feodo Tracker** — [https://feodotracker.abuse.ch/blocklist/](https://feodotracker.abuse.ch/blocklist/), "Terms of Services (ToS)":

> By using the website of Feodo Tracker, or any of the services / datasets referenced above, you agree that:
> All datasets offered by Feodo Tracker can be used for both, commercial and non-commercial purpose without any limitations ( CC0 )
> Any data offered by Feodo Tracker is served as it is on best effort
> abuse.ch can not be held liable for any false positive or damage caused by the use of the website or the datasets offered above

Caveat from the same platform's umbrella terms — [https://abuse.ch/terms-of-use/](https://abuse.ch/terms-of-use/):

> Authenticated Users may access the Platforms for not-for-profit purposes, subject to usage limitations imposed by abuse.ch and/or Spamhaus.

> Use of the Platforms by companies, networks, or individuals with commercial or for- profit needs may require a paid subscription, which will be managed by Spamhaus, and will be subject to separate terms and conditions.

**Spamhaus DROP** — [https://www.spamhaus.org/blocklists/do-not-route-or-peer/](https://www.spamhaus.org/blocklists/do-not-route-or-peer/):

> Spamhaus believes that due to the vital nature of the DROP list data, it should be available at no cost, regardless of size or business type, to protect internet users. We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data.

> The DROP list contains IP ranges which are so dangerous to internet users that Spamhaus provides it to anyone who wants to use it, free of charge.

> Please DO NOT auto-fetch the DROP list more than once per hour!

**IPsum** — [https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE](https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE):

> This is free and unencumbered software released into the public domain.
> Anyone is free to copy, modify, publish, use, compile, sell, or
> distribute this software, either in source code form or as a compiled
> binary, for any purpose, commercial or non-commercial, and by any
> means.

**Turris Sentinel greylist** — [https://view.sentinel.turris.cz/greylist-data/LICENSE.txt](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt):

> Turris Sentinel Greylist[1] is licensed under a Creative Commons
> Attribution-NonCommercial-ShareAlike 4.0 International License[2].

> For commercial offerings, please contact us directly via e-mail info@turris.cz

---

## Table 2 — Candidate new sources

| Source | Licence | Redistribution | Attribution required | Entries | Actively maintained | Terms URL |
|---|---|---|---|---|---|---|
| Botvrij.eu OSINT feeds | Custom terms in FAQ ([botvrij.eu](https://www.botvrij.eu/)) | **PERMITTED WITH CONDITIONS** — free use, but **no resale**, individually or bundled | Not stated | ip-dst list currently 4 IPs ([ioclist.ip-dst](https://www.botvrij.eu/data/ioclist.ip-dst)); also has ip-src, domain, url, hash lists ([data dir](https://www.botvrij.eu/data/)) | Stale — Last-Modified on ip-dst: **Tue, 03 Feb 2026** | [botvrij.eu](https://www.botvrij.eu/) (FAQ, "What are the terms of use?") |
| CIRCL.lu open data | **CC BY 4.0**, TLP:WHITE ([circl.lu/opendata](https://www.circl.lu/opendata/)) | **PERMITTED WITH CONDITIONS** — attribution; commercial use explicitly welcomed | **Yes** — CC BY 4.0; no exact attribution string specified | Datasets listed are CVE dumps, BGP Ranking per-ASN, honeypot stats, image datasets — **no plain IP blocklist found** on the open-data page | Page maintained; revision history ends v1.3 Oct 2017 | [circl.lu/opendata](https://www.circl.lu/opendata/) |
| Rescure / rescure.fr | n.a. — **domain gone.** `rescure.fr` does not resolve (NXDOMAIN); `rescure.me` returns HTTP 406; the URL originally at rescure.fr now serves unrelated casino spam content | n.a. | n.a. | n.a. | **No** — dead | n.a. |
| Team Cymru Bogon reference | **No licence stated.** [Bogon HTTP page](https://www.team-cymru.com/bogon-reference-http) and [Bogon Networks page](https://www.team-cymru.com/bogon-networks) give usage guidance but no licence/redistribution grant | **UNCLEAR** — "Free. Forever." and "Operated for the community, not as a product", but no reuse licence text; only a fetch-frequency request | Not stated | 3,025 IPv4 fullbogon prefixes ([fullbogons-ipv4.txt](https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)); site claims 250K+ fullbogon prefixes across v4+v6 | Yes — file header "last updated … Thu Aug 13 00:55:02 2026 GMT" | [team-cymru.com/bogon-reference-http](https://www.team-cymru.com/bogon-reference-http) |
| Emerging Threats (ET) Open — compromised-ips | **BSD 3-clause** for ET-authored content (sids 2000000–2799999); GPLv2 for legacy sids ([ET ruleset LICENSE](https://rules.emergingthreats.net/open/suricata-5.0/rules/LICENSE)) | **PERMITTED WITH CONDITIONS** — BSD: redistribution allowed if copyright notice, conditions list and disclaimer are retained; no endorsement use of names | **Yes** — retain copyright notice + disclaimer | 544 IPs ([compromised-ips.txt](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)) | Yes — blockrules dir timestamp 2026-08-12 ([rules index](https://rules.emergingthreats.net/)) | [rules.emergingthreats.net/open/suricata-5.0/rules/LICENSE](https://rules.emergingthreats.net/open/suricata-5.0/rules/LICENSE) |
| Snort / Cisco Talos IP blacklist | Cisco proprietary EULA ([snort.org](https://snort.org/downloads/ip-block-list)); talosintelligence.com/documents/ip-blacklist returned HTTP 403 | **PROHIBITED** — may not transfer, sell, sublicense, monetize or provide functionality of the List to any third party | n.a. (moot) | n.a. — download gated behind acceptance | Yes | [snort.org/downloads/ip-block-list](https://snort.org/downloads/ip-block-list) |
| CyberCure.ai free feeds | n.a. — feed API dead. `api.cybercure.ai/feed/get_ips` returns Cloudflare **error 520**; [cybercure.ai](https://www.cybercure.ai/) now serves the Nucleon Cyber commercial AGTI platform page with no free-feed terms | n.a. | n.a. | n.a. | **No** — free feed endpoint not serving | [cybercure.ai](https://www.cybercure.ai/) |
| Blocklist Project (blocklistproject/Lists) | **The Unlicense** (public domain) ([LICENSE](https://raw.githubusercontent.com/blocklistproject/Lists/master/LICENSE)) | **PERMITTED** — unconditional | No | Lists are predominantly **domain/hosts-format**, not IP lists ([README](https://raw.githubusercontent.com/blocklistproject/Lists/master/README.md)) | Yes — repo pushed 2026-08-12 ([GitHub API](https://api.github.com/repos/blocklistproject/Lists)) | [github.com/blocklistproject/Lists/LICENSE](https://raw.githubusercontent.com/blocklistproject/Lists/master/LICENSE) |
| Charles Haley SSH lists | n.a. — **host does not resolve.** `charles.the-haleys.org` NXDOMAIN in this session | n.a. | n.a. | n.a. | **No** | n.a. |
| VoIPBL | **No licence stated.** [voipbl.org](https://voipbl.org/) has a "NO WARRANTY" section (GPL-style warranty text) but no grant-of-rights or redistribution clause | **UNCLEAR** — "This service is offered completely free"; no reuse terms | Not stated | 97,480 netblocks — file header "# TOTAL NETBLOCK: 97480" ([voipbl.org/update](https://voipbl.org/update/)) | Yes — served 2026-08-13 | [voipbl.org](https://voipbl.org/) |
| NoThink honeypot blocklists | n.a. | **n.a. — discontinued.** Site states honeypot data is no longer published | n.a. | n.a. | **No** | [nothink.org](https://www.nothink.org/) |
| Mirai tracker (mirai.security.gives) | n.a. — host resolves but returns Cloudflare **error 525** for both `/` and `/data/ip_list.txt` | n.a. | n.a. | n.a. | **No** — not serving | n.a. |
| Feodo Tracker IP blocklist (as separate feed) | **CC0** ([feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/)) | **PERMITTED** — same CC0 ToS as the main entry above | No | 0 — datasets currently empty | Site live, data empty | [feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/) |
| montysecurity C2-Tracker | **No licence** — no LICENSE file (HTTP 404 at repo root path); GitHub API reports `license: None` | **UNCLEAR — and moot.** README: project **archived**, `data/` text files removed | n.a. | 0 — data files deleted ([README](https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/README.md)) | **No** — archived; last push 2026-04-13 ([GitHub API](https://api.github.com/repos/montysecurity/C2-Tracker)) | [github.com/montysecurity/C2-Tracker](https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/README.md) |
| ThreatFox export lists | Fair-use ToS; no CC0 statement located ([threatfox.abuse.ch/faq](https://threatfox.abuse.ch/faq/)) | **UNCLEAR / restricted** — Auth-Key required for every export; not-for-profit fair use; commercial may require paid subscription | n.a. | n.a. — gated | Yes | [threatfox.abuse.ch/export](https://threatfox.abuse.ch/export/) |
| James Brine (jamesbrine.com.au) | **No licence found.** Page is behind Cloudflare interstitial; the HTML retrieved shows a "Threat Feed Endpoint - Updated Daily" section and links to PulseDive / OTX / MISP feeds, but no terms text | **UNCLEAR** — also `/csv` returned HTTP 403 (Cloudflare challenge) | Not stated | n.a. — could not fetch | Page claims "Updated Daily"; could not independently verify a data timestamp | [jamesbrine.com.au](https://jamesbrine.com.au/) |
| Interserver IP list | **No licence stated.** Page (now branded MailBaby) lists a "Bad IPs" feed at `/ip` with 1-week / 48-hour / full windows; no terms of use | **UNCLEAR** | Not stated | n.a. — counts not published on the page | Page live 2026-08-13; described as "Live" | [sigs.interserver.net](https://sigs.interserver.net/) |
| CriticalPathSecurity Public-Intelligence-Feeds | **MIT** ([LICENSE](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/LICENSE)) | **PERMITTED WITH CONDITIONS (MIT)** — *but* the repo is a re-aggregation of upstream feeds whose own terms govern; its [README](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/README.md) lists Binary Defense, AlienVault, ET, ThreatFox, SANS as sources | Yes — MIT copyright notice | n.a. — individual `.intel` files I probed returned 404; README timestamp shows a build at "Thu Aug 13 01:03:34 UTC 2026" | Yes — repo pushed 2026-08-13 ([GitHub API](https://api.github.com/repos/CriticalPathSecurity/Public-Intelligence-Feeds)) | [github.com/CriticalPathSecurity/Public-Intelligence-Feeds/LICENSE](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/LICENSE) |
| Duggy Tuxy — Data-Shield IPv4 Blocklist | **GNU GPLv3** ([README](https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/README.md); GitHub API reports `GPL-3.0`) | **PERMITTED WITH CONDITIONS** — GPLv3 copyleft: source/licence must accompany redistribution; commercial use allowed | **Yes** — GPLv3 notice/copyright | 76,548 entries ([prod_data-shield_ipv4_blocklist.txt](https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/prod_data-shield_ipv4_blocklist.txt)) | Yes — repo pushed 2026-08-13; README says refreshed every 6 hours | [github.com/duggytuxy/Data-Shield_IPv4_Blocklist](https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/README.md) |
| Romain Marcoux — malicious-ip | **MIT** ([LICENSE](https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/LICENSE)) | **PERMITTED WITH CONDITIONS (MIT)** — copyright + permission notice must be retained | **Yes** — MIT notice | 40,000 in `full-40k.txt`; README reports 533,796 malicious IPs across the project ([README](https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/README.md)) | Yes — README "Last update: 2026-08-13 02:12 CEST"; updated hourly | [github.com/romainmarcoux/malicious-ip/LICENSE](https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/LICENSE) |
| ipthreat.net | **Creative Commons Attribution (BY), described with share-alike wording** ([ipthreat.net/license](https://ipthreat.net/license)) | **PERMITTED WITH CONDITIONS** — commercial reuse allowed; must relicense derived data under same CC licence; must credit with a live link; must use monthly public data dumps rather than reading the site | **Yes** — exact suggested text: `Data sourced from IPThreat located at https://ipthreat.net` plus `<a href="https://ipthreat.net">Data provided by IPThreat at https://ipthreat.net</a>` | n.a. — [/lists](https://ipthreat.net/lists) says "Please login to view lists urls" | Yes — pages rendered 2026-08-13 | [ipthreat.net/license](https://ipthreat.net/license) |
| GreyNoise free / community | Proprietary EULA ([greynoise.io/terms](https://www.greynoise.io/terms)) | **PROHIBITED** — Free Customers may not distribute or publish the Platform to third parties; use limited to internal business or non-commercial purposes | n.a. (moot) | n.a. — Community API is a per-IP lookup, not a bulk list; 50 lookups/week for free-tier business email ([GreyNoise docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api)) | Yes | [greynoise.io/terms](https://www.greynoise.io/terms) |
| ELLIO community feed | **Custom: non-commercial / personal use only** (vendor statements) | **PROHIBITED for our use case** — non-commercial personal use only, so a public aggregate with possible commercial downstream consumption does not fit | n.a. | Vendor material cites ~25,000 entities and ~220k IPs at different dates; I could not verify — `cdn.ellio.tech/community-feed` now returns an HTML page, not a feed, and `ellio.tech/community-feed` is HTTP 404 | Product line is live ([ellio.tech](https://ellio.tech/)), but the community feed URL no longer serves plain data | [blog.ellio.tech (community blocklist)](https://blog.ellio.tech/ellio-blocklist-for-check-point-ngfw-3-million-unwanted-connections-blocked-in-45-days/) |
| AlienVault OTX / LevelBlue | Proprietary EULA ([levelblue.com OTX EULA](https://www.levelblue.com/legal/otx-eula-terms)) | **PROHIBITED** — may not republish, distribute, or make OTX available to third parties; free for non-commercial use only | n.a. (moot) | n.a. — API key required | Yes | [levelblue.com/legal/otx-eula-terms](https://www.levelblue.com/legal/otx-eula-terms) |
| Maltrail (stamparm) trails | **MIT** ([LICENSE](https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE); README §License) | **PERMITTED WITH CONDITIONS (MIT)** — retain copyright + permission notice. Note: individual trail files credit third-party upstreams ([README source list](https://raw.githubusercontent.com/stamparm/maltrail/master/README.md)) | **Yes** — MIT notice | Per-file; e.g. `trails/static/malware/zeus.txt` has 2,263 entries; trails are a mix of IPs, domains and URLs | Yes — repo pushed 2026-08-12 ([GitHub API](https://api.github.com/repos/stamparm/maltrail)) | [github.com/stamparm/maltrail/LICENSE](https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE) |
| Tweetfeed.live | **CC0 1.0 Universal** ([LICENSE](https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/LICENSE); GitHub API reports `CC0-1.0`) | **PERMITTED** — unconditional | No | Rolling; site publishes URLs, domains, **IPs**, SHA256 and MD5 in daily CSVs ([tweetfeed.live](https://tweetfeed.live/)) | Yes — repo pushed 2026-08-13 ([GitHub API](https://api.github.com/repos/0xDanielLopez/TweetFeed)) | [github.com/0xDanielLopez/TweetFeed/LICENSE](https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/LICENSE) |
| OpenPhish community feed | Proprietary ToS ([openphish.com/terms.html](https://openphish.com/terms.html)) | **PROHIBITED** — personal use only; may not distribute or make available to any third party without written permission | n.a. (moot) | n.a. — and it is a **phishing URL** feed, not an IP feed | Yes | [openphish.com/terms.html](https://openphish.com/terms.html) |
| FireHOL blocklist-ipsets (individual lists) | **No repo-level licence** — no LICENSE file (HTTP 404); [README](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/README.md) explicitly defers to each upstream source | **UNCLEAR by design** — per-source; must be evaluated list by list | Per-source | Per-source; README documents each ipset's size (e.g. `iblocklist_webexploit` 15,382 unique IPs) | Yes — repo pushed 2026-08-12 ([GitHub API](https://api.github.com/repos/firehol/blocklist-ipsets)) | [github.com/firehol/blocklist-ipsets README](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/README.md) |

### Verbatim licence quotes — candidate sources where redistribution is PERMITTED or PERMITTED WITH CONDITIONS

**Botvrij.eu** — [https://www.botvrij.eu/](https://www.botvrij.eu/), FAQ:

> What are the terms of use?
> You can use this data the way you prefer but all use of the data is at your own risk . You cannot resell the data, neither as an individual package or as part of a larger package.

> It is free!
> The data is free (obviously, the source of the data is also free). Use the data at your own risk. This project only makes the data easy accessible. It is up to you to decide where and how you want to use it.

**CIRCL.lu** — [https://www.circl.lu/opendata/](https://www.circl.lu/opendata/):

> TLP:WHITE information may be distributed without restrictions. The document and the Open Data mentioned are licensed under an international CC-BY 4.0 .

> CIRCL advocates data sharing and knows that sharing Open Data can lead to new research, analyses, software or services that could improve security on the long-term. We also hope that the data shared can be used for any usage including commercial or non-commercial security services within Luxembourg and abroad.

> “Open data and content can be freely used, modified, and shared by anyone for any purpose” as defined by opendefinition.org .

**Emerging Threats Open** — [https://rules.emergingthreats.net/open/suricata-5.0/rules/LICENSE](https://rules.emergingthreats.net/open/suricata-5.0/rules/LICENSE):

> \#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License
> \#  Copyright (c) 2003-2026, Emerging Threats
> \#  All rights reserved.
> \#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
> \#  following conditions are met:
> \#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
> \#    disclaimer.
> \#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
> \#    following disclaimer in the documentation and/or other materials provided with the distribution.
> \#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
> \#    from this software without specific prior written permission.

**Blocklist Project** — [https://raw.githubusercontent.com/blocklistproject/Lists/master/LICENSE](https://raw.githubusercontent.com/blocklistproject/Lists/master/LICENSE):

> This is free and unencumbered software released into the public domain.
> Anyone is free to copy, modify, publish, use, compile, sell, or
> distribute this software, either in source code form or as a compiled
> binary, for any purpose, commercial or non-commercial, and by any
> means.

**Critical Path Security Public-Intelligence-Feeds** — [https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/LICENSE](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/LICENSE):

> MIT License
> Copyright (c) 2021 Critical Path Security
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

**Duggy Tuxy Data-Shield** — [https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/README.md](https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/main/README.md):

> **Open Source & Community Driven** Accessible to anyone—from hobbyists to enterprise admins. The project is proudly distributed under the [GNU GPLv3 license](/LICENSE), fostering a transparent and collaborative security ecosystem.

> "This project is open-source software licensed under the **[GNU GPLv3 License](/LICENSE)**."

**Romain Marcoux malicious-ip** — [https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/LICENSE](https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/LICENSE):

> MIT License
> Copyright (c) 2025 Romain MARCOUX
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

**ipthreat.net** — [https://ipthreat.net/license](https://ipthreat.net/license):

> IPThreat breaks this trend by being 100% free and releasing all of it's data under a creative-commons by attribution license .

> You are free to re-use, re-mix the data from this website, even commercially, provided that:
> You must release any transformed, re-mixed or derived data under the same creative-commons license. This does not prohibit you from using the data commercially.
> You must give appropriate credit back to IPThreat if you redistribute the data in any form (commercially or not, internally or public).

> For raw data:
> Provide a short attribution statement in your readme file or data file, something like 'Data sourced from IPThreat located at https://ipthreat.net'.
> Provide in your readme or data file a direct link back to the home page at https://ipthreat.net.
> If your dataset is hosted on a website, please put a link to the home page at https://ipthreat.net on the website as well.

> Please don't scrape the IPThreat website. Instead, use the public data dumps that are provided monthly .

**Maltrail** — [https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE](https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE):

> The MIT License (MIT)
> Copyright (c) 2014-2026 Maltrail developers (https://github.com/stamparm/maltrail/)
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

**TweetFeed** — [https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/LICENSE](https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/LICENSE):

> Creative Commons Legal Code
> CC0 1.0 Universal

Operational caveat from the publisher — [https://tweetfeed.live/](https://tweetfeed.live/):

> Please consider making your own analysis before taking any action related to the IOCs. The confidence of the shared IOCs is not always 100% so it is strongly recommended NOT adding them to a blocklist directly.

### Verbatim prohibition quotes (for the decision log)

**AbuseIPDB** — [https://www.abuseipdb.com/legal](https://www.abuseipdb.com/legal):

> Scraping, reproducing, republishing, selling, reselling, duplicating, or trading the Website or its content;

> No Resale of The Website or Data.
> You agree not to reproduce, duplicate, copy, sell, resell or exploit any portion of the Website (including the API and associated data), use of the Website, or access to the Website without express permission by AbuseIPDB.

**GreenSnow** — [https://greensnow.co/](https://greensnow.co/) (footer):

> Copyright © 2013-2026 GreenSnow.co. All rights reserved.
> Reproduction or republication strictly prohibited.

**Snort / Cisco Talos IP block list** — [https://snort.org/downloads/ip-block-list](https://snort.org/downloads/ip-block-list):

> Limited License : Cisco hereby grants You a limited, non-exclusive, non-transferable, non-sub-licensable right to download and use the List to test IP blocking functionality.

> Limits on Usage . You may not: transfer, sell, sublicense, monetize or provide the functionality of the List to any third party, except as authorized by Cisco;

**GreyNoise** — [https://www.greynoise.io/terms](https://www.greynoise.io/terms):

> For Free Customers, GreyNoise hereby grants you a non-exclusive, non-transferable revocable license to access and use the relevant portions of the Platform available for unpaid GreyNoise Products, subject to your complete compliance with this EULA. In every case (Free Customers and Paid Customers), such use is limited to your internal business purposes or noncommercial purposes such as academic research, if applicable.

> (1) rent, lease, lend, sell, license, sublicense, assign, distribute, publish, transfer, or otherwise make available the Platform to any third party except for Authorized Users;

**AlienVault OTX / LevelBlue** — [https://www.levelblue.com/legal/otx-eula-terms](https://www.levelblue.com/legal/otx-eula-terms):

> OTX is free to end users for non-commercial use.

> (v) attempt to copy, modify, duplicate, create derivative works from, frame, mirror, republish, download, display, transmit, or distribute all or any portion of OTX or OTX Endpoint Security software in any form or media or by any means;

> (vi) license, sell, rent, lease, transfer, assign, distribute, display, disclose, or otherwise commercially exploit OTX or OTX Endpoint Security software , or otherwise make it available to any third party (e.g., as a service bureau);

**OpenPhish** — [https://openphish.com/terms.html](https://openphish.com/terms.html):

> The Services are provided solely for your personal use. You agree not to use any part of the Services for any commercial purposes without the prior written consent of OpenPhish.

> Except as expressly permitted by OpenPhish in writing, you agree not to license, sell, rent, lease, transfer, assign, distribute, display, disclose, create derivative works or otherwise make all or any portion of the information obtained through the Services available to any third party.

---

## Where our understanding appears WRONG, or terms are genuinely ambiguous

**1. Binary Defense banlist — our understanding is WRONG (or at least over-inferred).**
We believed it is "free for non-commercial use" and implicitly non-redistributable. The actual header text at [binarydefense.com/banlist.txt](https://binarydefense.com/banlist.txt) says something narrower: "this is for public use only", and the prohibition is specifically "may not be used for **commercial resale** or in products that are charging fees" — with the parenthetical gloss "(having others pay for a service)". There is **no redistribution restriction stated at all**. Republishing the IPs for free, publicly, is arguably exactly "public use". The residual risk is only that a downstream consumer could fold our aggregate into a paid product — which is their breach vector, not ours, though a cautious reading might argue we would be facilitating it. Note also: the [Artillery repo](https://github.com/BinaryDefense/artillery) has **no LICENSE file** and the code was last pushed 2022-01-06, so the header text is the only governing statement.

**2. Feodo Tracker — licence is right, but the data is gone.** The CC0 statement at [feodotracker.abuse.ch/blocklist](https://feodotracker.abuse.ch/blocklist/) is unambiguous and remains the single best licence of any source here. But the site banner says "Empty datasets | Our Feodo Tracker datasets are currently empty." Also, the platform-level [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/) now impose authentication and not-for-profit fair-use limits that sit uneasily beside the per-dataset CC0 grant. Two documents, two different postures. If we cite CC0 in our decision log we should also record that abuse.ch has layered a fair-use ToS on top since the Spamhaus partnership.

**3. ThreatFox is materially different from Feodo Tracker.** Both are abuse.ch, but I found **no CC0 statement** on the ThreatFox side. The [ThreatFox FAQ](https://threatfox.abuse.ch/faq/) instead answers "Can I use data from ThreatFox commercially?" with "may require a paid subscription", and every export now requires an Auth-Key ([export page](https://threatfox.abuse.ch/export/)). Treating ThreatFox as CC0 by analogy with Feodo would be an error.

**4. CINS — our understanding is essentially right but weaker than "free licence".** There is no licence. What exists is a sentence of intent: "parse and use in any way you see fit" ([cinsscore.com](https://cinsscore.com/)). That covers *use*, and does not say anything about *republication*. It is permissive in tone and probably safe in practice, but it is not a licence grant, and a formal reviewer would call it UNCLEAR-leaning-permitted. Worth an email to cins@sentinelips.com to get it in writing.

**5. StopForumSpam is ambiguous on its face.** The [legal page](https://www.stopforumspam.com/legal) says "Anything else is covered under a Creative Commons License" — without naming which CC licence, which version, or which elements. Combined with the flat statement "Your use of this data and supporting software is non-commercial", the data effectively behaves like CC BY-NC of unknown version. For a feed whose downstream consumers may be commercial, this is a genuine blocker, not a technicality. Also note the page itself declares "This is a draft policy, and while it reflects our longstanding practice, it remains a draft and not official policy."

**6. Blocklist.de has no terms at all covering reuse.** The page called "Terms/Privacy" ([blocklist.de/en/terms.html](https://www.blocklist.de/en/terms.html)) is entirely about report submission, log handling and data retention, in German. The [export page](https://www.blocklist.de/en/export.html) offers only "These files are as they are, and to be used at your own risk." There is no grant and no prohibition. Genuinely UNCLEAR.

**7. GreenSnow is a clear PROHIBITED and should be dropped.** The site footer states "Reproduction or republication strictly prohibited" ([greensnow.co](https://greensnow.co/)). That is directly aimed at what our project does. If we currently republish GreenSnow IPs, that is a live compliance problem, not a theoretical one.

**8. Tor exit list — I could not confirm a licence.** The endpoint ([torbulkexitlist](https://check.torproject.org/torbulkexitlist)) is a bare list with no header, no licence, no copyright. [Tor Metrics' About page](https://metrics.torproject.org/about.html) explains their data-collection philosophy but grants nothing. The canonical LICENSE in Tor's GitLab returned HTTP 403 in this session, so I am deliberately not asserting "3-clause BSD" from memory. Recorded as UNCLEAR pending a successful fetch of the actual licence file.

**9. Team Cymru bogons — free, community-run, but no licence text exists.** Both pages I fetched ([Bogon HTTP](https://www.team-cymru.com/bogon-reference-http), [Bogon Networks](https://www.team-cymru.com/bogon-networks)) say "Free. Forever.", "No registration required", "Operated for the community, not as a product" — but give no reuse or redistribution grant. Also worth noting: bogons are derived from IANA/RIR allocation state, i.e. largely factual data, which weakens any copyright claim. Still formally UNCLEAR.

**10. Four candidate sources are effectively dead and should be removed from the shortlist.** `charles.the-haleys.org` does not resolve (NXDOMAIN). `rescure.fr` does not resolve, and `rescure.me` returns HTTP 406 — the rescure.fr name now serves unrelated casino spam content. `mirai.security.gives` returns Cloudflare error 525 on both the root and the data path. CyberCure's feed API returns Cloudflare error 520, and [cybercure.ai](https://www.cybercure.ai/) is now a Nucleon Cyber commercial platform page with no free-feed terms. Add to that [montysecurity/C2-Tracker](https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/README.md), which is archived with its `data/` text files removed, and [Botvrij](https://www.botvrij.eu/), whose ip-dst list carries a Last-Modified of 2026-02-03 and currently contains 4 IPs.

**11. CriticalPathSecurity's MIT licence does not launder its upstreams.** The repo is MIT ([LICENSE](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/LICENSE)), but its own [README](https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/README.md) enumerates its sources as Binary Defense, AlienVault, ET, ThreatFox and SANS — including AlienVault, whose EULA prohibits redistribution. Consuming CPS instead of the upstream does not cure the upstream restriction. Same structural issue applies to FireHOL (which says so explicitly), IPsum (built from 30+ upstream lists), and Maltrail.

**12. IPsum's Unlicense is a licence over the *aggregation*, not over the upstream sources.** [IPsum's README](https://raw.githubusercontent.com/stamparm/ipsum/master/README.md) states it is "based on 30+ different publicly available lists", and links to Maltrail's source set. The Unlicense is genuine and unconditional for the repo, and it is probably the single cleanest re-use path we have — but the same laundering caveat as item 11 technically applies. Practically, the fact that IPsum has published under public domain since inception without objection is meaningful evidence.

**13. Duggy Tuxy's GPLv3 is a copyleft trap for a *data* feed.** GPLv3 is written for software. Applying it to a list of IPs raises the awkward question of whether our combined output becomes a derivative work that must itself be GPLv3. That would be a licence-compatibility conflict with, say, CC BY-NC-SA (Turris) in the same aggregate. Worth deciding deliberately rather than by default.

**14. ipthreat.net's licence text is internally inconsistent.** It says the data is released "under a creative-commons by attribution license", then immediately says "The creative commons by sa license can be used as a guide" and requires derived data to be released "under the same creative-commons license" ([ipthreat.net/license](https://ipthreat.net/license)). BY and BY-SA are different licences with different obligations. Practically we should assume BY-SA (the stricter reading) and comply with the share-alike. Their attribution requirements are unusually prescriptive — a live, non-`nofollow`, non-shortened HTML link — so if we include IPThreat, the exact string and link must go in both our README and the data file header.

**15. ELLIO's community feed URL no longer serves data.** All vendor documentation points at `https://cdn.ellio.tech/community-feed`, but in this session that URL returned an HTML application page rather than a feed, and `ellio.tech/community-feed` is HTTP 404. Separately, every vendor statement I found describes it as "non-commercial individual use only", which rules it out for us regardless.

**16. Blocklist Project and OpenPhish are not IP feeds.** [Blocklist Project](https://raw.githubusercontent.com/blocklistproject/Lists/master/README.md) publishes domain/hosts-format lists; its Unlicense is excellent but the content type is wrong for us. [OpenPhish](https://openphish.com/terms.html) is phishing URLs and is prohibited anyway. CIRCL's [open data page](https://www.circl.lu/opendata/) likewise lists CVE dumps, per-ASN BGP rankings and image datasets — I found no plain IP blocklist there, so its excellent CC BY 4.0 licence does not currently buy us an IP feed.

### Shortlist of clean permissive candidates found

Ranked by licence quality for our specific use case (public republication, uncontrolled downstream commercial use):

1. **TweetFeed** — CC0 1.0, contains IPs, updated 2026-08-13. No conditions at all.
2. **IPsum** — The Unlicense, 129,253 IPs, updated 2026-08-13. Already in use; licence is stronger than we may have recorded.
3. **Spamhaus DROP** — free for any use, commercial included; only needs a credit line and retention of the date/© text. 1,688 CIDRs.
4. **Emerging Threats compromised-ips** — BSD 3-clause; needs the copyright notice and disclaimer carried through. 544 IPs.
5. **Romain Marcoux malicious-ip** — MIT, 40k–533k IPs, hourly updates.
6. **Maltrail trails** — MIT, but mixed IP/domain content and upstream-attribution caveats.
7. **ipthreat.net** — CC BY(-SA), commercial reuse explicitly allowed, but heavy attribution obligations and list URLs are login-gated.
8. **Duggy Tuxy** — GPLv3; permitted but copyleft-awkward for a data aggregate.

Sources to **drop or exclude**: GreenSnow (republication prohibited), AbuseIPDB (republication prohibited), Snort/Talos (prohibited), AlienVault OTX (prohibited), OpenPhish (prohibited, and not IPs), GreyNoise (prohibited for free tier), ELLIO (non-commercial + URL dead), Rescure / Charles Haley / Mirai tracker / CyberCure / C2-Tracker (dead or archived).

Sources needing a written clarification email before continued use: **CINS**, **Blocklist.de**, **bruteforceblocker**, **Team Cymru**, **Tor Project**, **VoIPBL**, **Interserver/MailBaby**, **James Brine**.

# Architecture Decision Record

Decisions are locked unless superseded. Each records what was chosen, what was rejected, and why — so the reasoning survives even when the choice is revisited.

Guiding constraint for every decision below: **current but not bleeding-edge.** Prefer the newest thing that is boring, has universal wheel/tooling coverage, and can be swapped out without rewriting the project. All probe data cited here was measured against live endpoints on **2026-08-11**.

---

## Runtime and tooling

### ADR-001 — Python 3.13 as the target runtime

**Decision.** Target 3.13. Floor at 3.11. CI matrix: 3.11, 3.12, 3.13, and 3.14 (allowed to fail).

3.14 shipped 2025-10-07 and 3.13 is supported until 2029-10-31 ([endoflife.date](https://endoflife.date/python)). Running one release behind the newest gives complete binary-wheel coverage across every dependency and keeps four more years of security support — while the 3.14 matrix leg means the upgrade is a one-line change, not a migration.

Free-threaded builds (`3.13t`/`3.14t`) are explicitly out of scope. The workload is network-bound over ~12 sources; the GIL is not the bottleneck, and free-threaded wheel coverage is still uneven.

### ADR-002 — uv for packaging, pinned to an exact version

**Decision.** `uv` with `pyproject.toml` + committed `uv.lock`. Pin the exact uv version in CI. Export a `requirements.txt` on release.

uv passed Poetry in downloads during 2026 (~75M vs ~66M monthly) and resolves a lockfile in seconds rather than tens of seconds ([nomadlab](https://insights.nomadlab.cc/blog/2026/05/uv-vs-poetry-vs-pip-vs-pdm-python-package-manager-2026)). The lock-in question matters more than the speed: uv stores dependencies in **standard** `[project]` metadata, so pip, Poetry, and PDM can all consume the same `pyproject.toml`. The only uv-specific artifact is `uv.lock`. If uv were abandoned tomorrow, recovery is `uv pip compile` once and delete a file.

uv is still pre-1.0 (0.12.x), so CI pins an exact version rather than tracking latest. The exported `requirements.txt` guarantees anyone can build the project with nothing but stock pip.

### ADR-003 — Dependency set, deliberately small

Every dependency is a thing that can break a scheduled job at 3am. The list is short on purpose.

| Need | Choice | Why this, not that |
|---|---|---|
| HTTP | `httpx` (sync client) | HTTP/2, real timeout semantics, first-class test mocking. Used synchronously — 12 sources do not need an event loop. Slow-moving (0.28.1) but that is API stability, not abandonment. |
| Validation | `pydantic` v2 | De-facto standard, and `model_json_schema()` gives consumers a published schema for `all.json` for free. |
| Retries | `tenacity` | `httpx` only retries connect errors at transport level; 429/5xx need policy. |
| CLI | `typer` | Built on click, stable, generates `--help` from type hints. |
| Logging | `structlog` → JSON | Machine-readable run logs that a SIEM can ingest directly. |
| Config | `pyyaml` | `sources.yaml` is the operator interface. Boring is correct. |
| STIX | `stix2` (OASIS) | Official OASIS library, actively released (3.0.2, Feb 2026). |
| Lint + format | `ruff` | Replaces black, isort, flake8, pyupgrade with one binary. |
| Types | `mypy --strict` | Astral's `ty` is not ready to be a gate. Revisit in 2027. |
| Tests | `pytest` + `pytest-httpx` | Recorded fixtures per source. **No unit test touches the network.** |

**Explicitly rejected:** `netaddr` — stdlib `ipaddress` covers every operation needed (parsing, containment, supernet collapse, integer sort) and ships with Python. `orjson` — stdlib `json` is irrelevant overhead at ~50k records. `pandas`/`polars` — this is a set-operations problem, not a dataframe problem. A database — state round-trips through `feeds/all.json`, which keeps the repo self-contained and every state change reviewable in a diff.

### ADR-004 — Distribute via GitHub Pages, mirror on raw

**Decision.** Canonical feed URLs are GitHub Pages (`https://neilweitzel.github.io/xfeeds/...`). `raw.githubusercontent.com` stays as a documented mirror.

`raw.githubusercontent.com` is capped at roughly **5,000 requests/hour/IP**, and exceeding it blocks the IP from all GitHub HTTPS for 30 minutes ([GitHub community](https://github.com/orgs/community/discussions/160828)). GitHub tightened unauthenticated limits further in May 2025 ([GitHub Changelog](https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/)), and raw does not honour a token at all. A threat feed is pulled by many hosts behind shared NAT — exactly the traffic shape that trips this. Pages is CDN-backed and carries no such per-IP cap.

---

## Interoperability

### ADR-005 — Publish plain text, CSV, JSON, STIX 2.1, and a MISP manifest

Five formats, each earning its place:

- **Plain text** — the universal substrate: `ipset`, nftables, pfSense, OPNsense, MikroTik, nginx, HAProxy, Cloudflare lists.
- **CSV** — MISP CSV feeds and OpenCTI CSV mappers both consume it, as do Splunk lookups and Sentinel watchlists.
- **JSON** — full provenance, with a pydantic-generated JSON Schema published beside it.
- **STIX 2.1 bundle** — OpenCTI ingests STIX natively via `ImportFileStix`; there is no `.txt` ingestion path in OpenCTI ([OpenCTI docs](https://docs.opencti.io/latest/usage/import-files/)). STIX is the price of admission to serious TIPs.
- **MISP feed manifest** — MISP consumes MISP-format, CSV, or freetext ([MISP](https://www.misp-project.org/feeds/)); the native manifest is the best experience.

### ADR-006 — Serve STIX over HTTPS; do not build a TAXII server

TAXII is the natural pairing with STIX, but `taxii2-client` has not shipped since **2021**, and a TAXII *server* requires a live application — impossible from a static repo and contrary to the zero-cost constraint. Static STIX bundles over HTTPS are ingestible by OpenCTI, MISP, and Elastic today. If TAXII demand ever appears, it is a thin service layered over the same artifacts.

---

## Sources

The single most important finding of this research: **most public IP feeds are not independent of each other.** Naive corroboration scoring across them produces confident-looking garbage. Measured pairwise overlaps, 2026-08-11:

| | blocklist_de | cins | et_comp | ipsum3 | greensnow | bfblocker | binarydef | tor |
|---|---|---|---|---|---|---|---|---|
| **blocklist_de** (28,605) | — | 0.8% | 0.5% | 21.0% | 3.5% | 0.6% | 1.1% | 0.2% |
| **cins** (15,000) | 1.6% | — | 0.1% | 26.0% | 0.6% | 0.1% | 4.2% | 0.0% |
| **et_comp** (539) | 27.3% | 1.7% | — | 44.5% | 1.9% | **98.5%** | 7.1% | 0.0% |
| **ipsum3** (17,078) | 35.2% | 22.9% | 1.4% | — | 6.6% | 1.4% | 12.3% | 1.6% |
| **greensnow** (3,595) | 28.2% | 2.4% | 0.3% | 31.5% | — | 0.3% | 3.7% | 1.3% |
| **bfblocker** (549) | 29.3% | 1.6% | **96.7%** | 44.1% | 2.0% | — | 7.3% | 0.0% |
| **binarydef** (3,300) | 9.5% | 18.9% | 1.2% | **63.8%** | 4.0% | 1.2% | — | 1.9% |

Read as: percentage of the row source's IPs that also appear in the column source.

### ADR-010 — Independence classes, one vote each

**Decision.** Every source declares an `independence_class`. The scorer counts **at most one vote per class**, and confidence is a function of distinct classes, not distinct files.

Without this rule, adding a mirror or an aggregator silently inflates every score. With it, adding one is harmless. This is the mechanism that makes the source list safe to grow.

### ADR-011 — Aggregators corroborate, they never vote

**IPsum** is disabled as a voting source. It aggregates 30+ public lists — including most of ours — so 35.2% of Blocklist.de and 63.8% of Binary Defense reappear inside it. Its levels are strictly nested (verified: L8 ⊂ L5 ⊂ L3) and the level number *is* the upstream corroboration count. It is consumed as a bounded prior at level ≥5 and nothing more.

**FireHOL level1** is disabled outright. Its own header declares it composed of `dshield feodo fullbogons spamhaus_drop` — every one already a direct source. Worse, it spans **611,224,833 addresses**, including `224.0.0.0/3` (536,870,912 addresses of multicast and reserved space) and 615 routable blocks wider than /22. It is built for a different threat model than a published block feed.

**Emerging Threats compromised-ips** is disabled as a duplicate: **Jaccard 0.953** against bruteforceblocker (531 of 539 IPs identical). It is a mirror, not a second opinion. Retained in `sources.yaml` pinned to bruteforceblocker's class so it can never double-vote if someone re-enables it.

### ADR-012 — Licensing gates redistribution, not just attribution

Republishing other people's data is the whole product, so licence terms are a hard constraint enforced in code via a `redistribute` flag — checked in the emitters, not merely documented.

- **DShield/SANS is excluded.** Its feed header declares **CC BY-NC-SA 2.5**. NonCommercial breaks the promise that anyone can use xfeeds output, and ShareAlike would attach viral terms to every file containing it. It contributes only 20 /24 blocks — not worth compromising the licence of the entire project.
- **AbuseIPDB defaults to `redistribute: false`.** It is a strong scoring signal, but their terms restrict republishing the blacklist verbatim. It informs confidence; its rows are not emitted until the terms are confirmed in writing.
- **Spamhaus requires attribution and rate discipline.** Credit must be given and "the date and copy text should remain with the file and data"; automated fetches must be **at least one hour apart** ([Spamhaus FAQ](https://check.spamhaus.org/faqs/do-not-route-or-peer-drop/)). The 6-hour cron complies comfortably; the header is preserved verbatim in output.
- **CINS Army has no formal licence** — the site says only that the list is shared for others to "parse and use in any way you see fit" ([CINSscore](https://cinsscore.com/#list)). Permissive in intent, not in writing. Flagged `license_risk: medium`, attributed prominently, droppable on request.

Every published artifact carries per-source attribution, and `feeds/manifest.json` exposes each contributing source's licence so downstream users can filter on their own compliance needs.

### ADR-013 — Tor exits are tagged, never blocked

1,367 exit nodes, and other feeds are visibly contaminated by them: IPsum L3 lists 265, Binary Defense 64, Blocklist.de 49, GreenSnow 48. Blocking Tor is a policy choice belonging to the consumer, not a threat assertion. Exits are tagged `tor-exit` and hard-capped below the high-confidence threshold, so a consumer who *wants* to block Tor filters on the tag.

### ADR-014 — Always authenticate to abuse.ch

abuse.ch made authentication **mandatory as of 2025-06-30** across its platforms ([abuse.ch](https://abuse.ch/blog/community-first/)), and it now operates under Spamhaus. Static `/downloads/` paths still answer unauthenticated — verified — but that is an accident of deployment, not a contract. The free Auth-Key from `auth.abuse.ch` is sent on every abuse.ch request.

Note that Feodo Tracker currently carries **5 IPs** and a last-updated header of 2026-03-04. It stays wired up because its precision is near-perfect, but the pipeline raises a staleness warning when a source's last-updated header exceeds 30 days, so a dead upstream is never mistaken for a quiet internet.

### ADR-015 — Locked source list

| Source | Class | Votes | Redistribute | Volume |
|---|---|---|---|---|
| Spamhaus DROP v4/v6 | `spamhaus` | ✅ 1.0 | ✅ (attribution) | 1,687 + 92 CIDRs |
| Feodo Tracker | `abusech` | ✅ 1.0 | ✅ | 5 IPs |
| SSLBL | `abusech` | ✅ 1.0 | ✅ | 0 currently |
| ThreatFox | `abusech` | ✅ 1.0 | ✅ | key required |
| Blocklist.de | `blocklist_de` | ✅ 0.8 | ✅ | 28,605 |
| CINS Army | `cins` | ✅ 0.8 | ⚠️ no formal licence | 15,000 |
| AbuseIPDB | `abuseipdb` | ✅ 0.9 | ❌ scoring only | 10,000 |
| GreenSnow | `greensnow` | ✅ 0.6 | ✅ | 3,595 |
| Binary Defense | `binary_defense` | ✅ 0.6 | ⚠️ non-commercial | 3,300 |
| bruteforceblocker | `bruteforceblocker` | ✅ 0.6 | ✅ | 549 |
| IPsum L3–L8 | `META_aggregate` | ❌ prior only | ❌ | 17,078 → 31 |
| Spamhaus ASN-DROP | `spamhaus` | ❌ annotation | ❌ | 426 ASNs |
| Tor exits | `tor` | ❌ tag only | ✅ as tag | 1,367 |
| FireHOL level1 | `META_aggregate` | ❌ disabled | ❌ | — |
| ET compromised-ips | `bruteforceblocker` | ❌ disabled | ❌ | — |
| DShield | `dshield` | ❌ disabled | ❌ licence | — |

**Nine voting classes are defined; seven are active on a fresh clone.** `abuseipdb` and the ThreatFox member of `abusech` ship disabled until their free API keys are in repo secrets. The pipeline must therefore be correct with seven classes and gain accuracy — not change behaviour — when the remaining two are enabled. `xfeeds validate` prints the active class count so this is never ambiguous.

Every class is a distinct sensor network, reporter community, or research team.

---

## Scoring

### ADR-020 — Independence-weighted confidence, calibrated to measured data

```
raw = Σ over distinct independence classes:
        max(weight × recency_factor × severity for sources in that class)

recency_factor = max(0.2, 1 − days_since_last_seen / ttl_days)

score = 100 × (1 − exp(−raw))        # saturating, so no single class reaches 90
```

Exponential saturation means one loud source can never alone produce a "block this" verdict — corroboration across independent classes is the only path to the top band. Two exceptions bypass it, both justified by source precision rather than agreement: Spamhaus DROP membership and an active abuse.ch C2 listing each promote directly.

**Thresholds, calibrated against measured corroboration:**

| Distinct classes | IPs | Band |
|---|---|---|
| 1 | 42,034 (77.5%) | withheld |
| 2 | 10,294 (19.0%) | medium |
| 3 | 1,656 (3.1%) | high |
| 4 | 214 (0.4%) | high |
| 5+ | 43 (0.1%) | high |

Measured across the seven currently-active classes, so these are floor figures — enabling AbuseIPDB and ThreatFox moves IPs up, never down.

Total unique across non-Tor voting sources: **54,241**. At ≥2 classes: **12,207**. At ≥3: **1,913**.

So the expected high-confidence feed is roughly **2,000–4,000 entries** once Spamhaus and abuse.ch promotions are included — the same order of magnitude as the original 2,973-entry 2022 list, which is a satisfying result. Anyone expecting a 50,000-entry feed is expecting a feed that should not be blocked on.

### ADR-021 — The 77% is the point

Withholding single-source IPs discards more than three quarters of the raw input. That is the product working. Republishing the union of public blocklists is a solved, worthless problem — the value xfeeds adds is the independence-aware filter that says which entries are actually corroborated.

---

---

## Licensing, revisited after building it (ADR-030)

Verifying licences against the live feeds — rather than their documentation pages
— changed the source list materially. **Most "free" public IP feeds do not permit
redistribution.** Since republishing is the entire product, this is the binding
constraint on the project, not an afterthought.

What the payloads actually say:

| Source | Finding | Outcome |
|---|---|---|
| **dataplane.org** | "Redistribution of the sshpwauth report in whole or in part without the express permission of Dataplane.org is expressly prohibited" | **Not ingested at all.** A compiled feed is arguably redistribution "in part"; this project will not test that argument. |
| **Turris Sentinel** | CC BY-NC-SA 4.0 ([LICENSE.txt](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt)) | **Excluded.** ~9,700 IPs from a genuinely independent router sensor network, but ShareAlike would attach viral terms to any derived output. |
| **DShield / SANS** | CC BY-NC-SA 2.5, declared in the feed header | **Excluded**, same reasoning. |
| **StopForumSpam** | Non-commercial use only | **Scoring only.** Corroborates, never republished. |
| **Binary Defense** | "may not be used for commercial resale" | **Scoring only.** |
| **AbuseIPDB** | terms restrict republishing the blacklist | **Scoring only.** |
| **Spamhaus DROP** | free for all, attribution required, fetch ≥1h apart | **Redistributed** with attribution carried into every output header. |
| **CINS Army** | no formal licence; "parse and use in any way you see fit" | **Redistributed**, flagged `license_risk: medium`, droppable on request. |

The `redistribute` flag is enforced in `filters.py` and tested, not merely
documented. A record whose only evidence comes from non-redistributable sources
is dropped from every published artifact regardless of how confident we are about
it. Feed headers list redistributed sources as contributors and name
corroboration-only sources separately, so a header can never imply that data we
may not publish is present in the file.

**ShareAlike is treated as more dangerous than NonCommercial.** xfeeds is not
sold, so NC terms are satisfiable for our own use — we simply do not pass that
data on. ShareAlike cannot be contained that way: it would attach obligations to
output that other people rely on being freely usable.

## What the first real run produced (ADR-031)

Measured on 2026-08-12 against live sources, 8 active voting classes and no API
keys configured:

| Metric | Value |
|---|---|
| Unique indicators observed | 53,479 |
| Published | 3,763 |
| — high confidence | 1,907 |
| — medium confidence | 1,856 |
| Withheld (single source) | 49,716 (93%) |
| Promoted by a high-precision source | 1,780 |
| Dropped by allowlist | 4,139 |
| Dropped by CIDR width cap | 8 |
| Dropped for licensing | 51 |

The high-confidence tier landed at 1,907 — the same order of magnitude as the
original 2,973-entry 2022 dataset, and within the 2,000–4,000 range ADR-020
predicted before any of this was built.

Note that the withheld share is 93% rather than the 77% estimated earlier. The
estimate was computed over seven sources; the live run ingests more, and the
additional volume is overwhelmingly single-source. That is the filter doing its
job: republishing the union of public blocklists is a solved and worthless
problem, and 93% of the raw input does not meet the bar.

Corroboration distribution among published records: 1 class 1,779 (all
promoted), 2 classes 1,857, 3 classes 119, 4 classes 8.

## ThreatFox enabled (ADR-032)

The abuse.ch Auth-Key is configured, activating ThreatFox as a live source and
bringing the `abusech` class back to life — Feodo Tracker has thinned to 5
entries and its header is frozen 42 days back, so the class was effectively
dormant.

Effect on the published feed: high confidence **1,907 → 2,389**, from 1,026
ThreatFox records covering 664 unique addresses over a 7-day window (the maximum
the API accepts).

**Compromised hosts do not get the precision promotion.** ThreatFox flags
`is_compromised` on roughly a third of its IP IOCs. Those are legitimate servers
somebody hacked and is now using for command-and-control — a victim, not
purpose-built attacker infrastructure. Blocking one can take out a real business
that is itself under attack. They vote normally, but unlike other abuse.ch
records they cannot reach the safe-to-block tier unaided; they need corroboration
like any ordinary source. Tagged `compromised-host` in the output so consumers
can see which is which.

Two related robustness fixes came out of enabling this:

- **A missing API key now reports `skipped`, not `failed`.** Keyed sources are
  expected to be unconfigured on a fresh clone, and treating that as a broken
  upstream made the dashboard misreport health.
- **Allowlist sources fall back to their last cached copy on a transient
  failure.** A live run aborted because `api.github.com` returned a 403. The
  hard-fail was correct in principle — never publish from a partial allowlist —
  but an out-of-date list of GitHub ranges still protects those ranges, whereas
  aborting every run over a transient 403 is the worse outcome. Threat feeds
  deliberately do **not** get this fallback: silently serving stale threat data
  is exactly what the staleness warning exists to catch.

## Source expansion review, 2026-08-12 (ADR-033)

Probed a further 20 candidate feeds looking for additional independent classes.
**None were added.** Recording why, so the same ground is not re-covered:

| Candidate | Volume | Verdict |
|---|---|---|
| `borestad/blocklist-abuseipdb` | 112,780 | **Rejected on principle.** A third-party republication of AbuseIPDB data. AbuseIPDB's terms restrict redistributing their blacklist; consuming someone else's copy would launder a restriction we have already chosen to respect. Volume is not a reason to do that. |
| Ultimate.Hosts.Blacklist | 148,838 | Mega-aggregate of dozens of lists including several we already ingest. Would be a `META_aggregate`, not a new class — exactly the double-counting ADR-011 exists to prevent. |
| C2IntelFeeds | 243 | GitHub reports `NOASSERTION` — no explicit licence grant. Good data, no permission to republish. |
| montysecurity/C2-Tracker | — | No licence file. |
| dataplane.org | — | Redistribution expressly prohibited (ADR-030). |
| Turris Sentinel | ~9,700 | CC BY-NC-SA 4.0 (ADR-030). **Superseded by ADR-035**: now enabled as a scoring-only source. |
| ELLIO community | — | Now requires authentication; the open CDN endpoint is retired. |
| botvrij.eu | 4 | Too small to matter. |
| blocklist.de strongips | 346 | Same operator as `blocklist_de` — shares its class, adds nothing. |
| Project Honeypot, interserver, CleanTalk, 3CORESec, TweetFeed, CyberCure, James Brine | — | Dead endpoints, HTML-only, or no parseable IP list. |

The conclusion is uncomfortable but real: **the set of IP feeds that are both
independent and freely redistributable is small, and xfeeds already has most of
it.** Growth comes from three directions, none of which is "add more public lists":

1. Keyed free sources with usable terms — ThreatFox (done), AbuseIPDB (pending).
2. Original telemetry — the Phase 3 honeypot would be a class nobody else has.
3. Better use of what we have — enrichment, ASN clustering, confidence tuning.

Padding the list with aggregates would inflate the headline count while making the
independence model *less* accurate. That trade is not worth making.

## Dashboard rebuilt around the reader (ADR-034)

The first dashboard reported on the project. The rewrite serves the person who
needs to block bad IPs and has no threat intelligence platform to do it with:

- **In-page IP lookup.** Paste an address, get a verdict, the score, how many
  independent sources reported it, and a pre-filled false-positive link. Backed by
  a compact `lookup.json` of integer ranges (~300 KB, ~3,600 entries) fetched only
  on first use, so a CIDR match works the same as a single address. Runs entirely
  client-side — no query leaves the browser, which matters because the addresses
  people check are often their own.
- **Copy-paste setup for real platforms** — iptables/ipset, nftables,
  pfSense/OPNsense, MikroTik, Cloudflare, MISP/OpenCTI — in tabs, with a cron line
  for staying current. This is the difference between a dataset and a tool for the
  stated audience.
- Copy buttons on every command, per-source failure reasons surfaced inline, and
  entry counts against every download so the tiers are self-explanatory.

## Restricted sources may upgrade a band, never admit a record (ADR-035)

**Status:** accepted (2026-08-12)

The `vote` / `redistribute` split already lets a source corroborate without its
rows being emitted. Reviewed under that lens, the Turris Sentinel greylist —
excluded outright in ADR-030 for being CC BY-NC-SA — becomes usable for scoring.

Why it is worth the trouble, measured rather than assumed:

- 9,529–9,719 addresses from the CZ.NIC Turris consumer-router sensor network: a
  different vantage point from the server-side honeypots that dominate our set.
- Overlap with our published feed is **7.7%** (548 exact, 203 inside a published
  CIDR). It is not a reshuffle of data we already have.
- It corroborates **477 of 1,837** medium-confidence records.

**The licensing reasoning.** NonCommercial is satisfied; we do not sell. ShareAlike
attaches when you *Share* Adapted Material, and vote-only use shares nothing. The
CC 4.0 database provision makes a database Adapted Material when it contains "all
or a substantial portion of the database contents"; a numeric confidence
adjustment contains none of it.

**The gap that reasoning leaves.** A vote can still change *whether* a record is
published, because one class is withheld and two is medium. If a Turris vote
lifted a record from withheld to medium, our decision to publish that address
would have been caused by a list we may not republish, and the feed would disclose
greylist membership one address at a time.

**Decision.** Restricted classes are excluded from the count that admits a record
and may only upgrade one that already qualifies: medium → high, never withheld →
medium. Three containments, all enforced in code and tested:

1. `_band()` counts only redistributable classes toward the publication threshold.
2. Restricted source names and classes are stripped from published records,
   replaced by a `restricted_corroboration` count. Publishing `turris` against an
   address would disclose the very membership the licence protects.
3. `filters.py` continues to drop any record with no redistributable source.

Measured on a live run with identical inputs, the rule behaves exactly as intended:
enabling Turris moved **high 1,903 → 2,398 (+495)** while leaving the total
published count **unchanged at 3,721**. Upgrades only, no admissions. That
invariant is the test worth keeping.

Rejected: full voting rights (larger recall gain, but the publish decision becomes
attributable to a restricted list) and precision-only use (no confidence gain).

## Binary Defense is not redistributable either (ADR-036)

**Status:** accepted (2026-08-12)

Found during the ADR-035 review. `binary_defense` was configured with
`license: "Free for non-commercial use"`, `license_risk: medium`, and no
`redistribute` flag — so it defaulted to **true**. `stopforumspam_toxic` carries
materially the same non-commercial term and was correctly set to `false`, with the
reasoning that we cannot impose a non-commercial restriction on downstream
consumers of a public feed.

Two sources, the same term, opposite treatment. The permissive one was wrong.

`redistribute: false`. This costs real coverage — published records fall from
3,721 to **3,019 (−702)** because records whose only corroboration came from
Binary Defense no longer reach two redistributable classes. It is still the right
call: those are precisely the records we had no clear licence to publish. Binary
Defense keeps voting and can still upgrade a band under ADR-035.

Reversible in one line if the terms are ever confirmed as permitting
redistribution, which is now tracked as an open item.

## A source that misses a run keeps voting, decayed (ADR-037)

**Status:** accepted (2026-08-12)

`recency_factor()` was **inert in production**. Scoring only ever saw records
collected in the current run, so `last_seen` was always today and the factor was
always 1.00. Verified against the live feed: 4,240 of 4,240 published records had
`last_seen == today`. The decay curve was computed, tested, and never applied, and
the per-source `ttl_days` values were close to decorative.

The consequence was not wrong output but brittle output. A source having a bad
fetch day took its whole independence class with it and silently demoted every
record that depended on it. The churn guard catches this when a large source fails
(losing Spamhaus is 40% of the feed, over the 25% limit) but not a smaller one —
GreenSnow is 21% and would pass while quietly demoting records.

**Decision.** State now persists per-source sighting dates, and
`carried_observations()` re-casts a vote from any source that missed the current
run, at the decayed weight `recency_factor` produces, until that source's
`ttl_days` expires. Bounded, so nothing accumulates.

Two limits keep it honest:

- Only indicators reported by *some* source in the current run are eligible.
  Nothing is resurrected; the feed still contains only addresses somebody reports
  today.
- Carried observations cannot promote. Promotion asserts that a source's word alone
  is enough, which requires it to be saying so now rather than up to 30 days ago.

On a cold CI cache the sighting map cannot be rebuilt from `feeds/all.json`, so no
votes are carried on the first run afterwards. That under-reports confidence rather
than over-reporting it, which is the correct direction to fail.

## No independent retention window; 90 days would be harmful (ADR-038)

**Status:** accepted (2026-08-12)

Asked how long an address should live on the list, with 90 days proposed.

Publication is already source-driven and stays that way: an address leaves the feed
on the next run after its last source stops reporting it. Effective retention for
publication is zero days. `ttl_days` governs vote decay (ADR-037) and state
accounting, not membership.

The measurement literature is consistent and points away from long windows:

- 86.4% of blocklisted IPs are short-lived offenders, averaging about one week of
  presence ([A Decade of Mal-Activity Reporting, AsiaCCS 2019](https://internetmaliciousactivity.github.io/submission/asiaccs2019_accepted_paper.pdf)).
- Blocklisted addresses are removed within ~9 days on average; **dynamically
  allocated addresses within ~3 days**. Reused addresses can sit in lists for up to
  **44 days** and affect as many as **78 legitimate users**; ~60% of blocklists
  contain at least one NATed address ([Quantifying the Impact of Blocklisting in the Age of Address Reuse, IMC 2020](https://www.isi.edu/people-mirkovic/wp-content/uploads/sites/52/2023/10/imc2020.pdf)).

A 90-day window would hold entries roughly 10× longer than the median offender
stays active, squarely inside the range where ISP reassignment turns an entry into
a false positive against a residential customer. For a feed whose audience will
drop traffic on it without a review step, that is the wrong direction.

The counter-argument is real but does not change the decision: the most recurrent
offenders have a ~5.5 week report cycle, so aggressive delisting does lose repeat
infrastructure. That argues for *remembering* history, not for *publishing* stale
entries — which `first_seen` retention already provides.

Per-source TTLs stay short and differentiated: 7d abuse.ch C2 and Turris, 10d
brute-force sensors, 30d Spamhaus DROP (hijacked netblocks are a slow structural
signal), 2d Tor.


## Binary Defense: we were wrong, and it is redistributable (ADR-039)

**Status:** accepted (2026-08-13). Supersedes ADR-036.

ADR-036 set `binary_defense` to `redistribute: false` on the basis of a
`license` field reading "Free for non-commercial use per Artillery/Banlist terms".
Nobody had read the actual feed. The header says:

> Note that this is for public use only.
> The ATIF feed may not be used for commercial resale or in products that are
> charging fees for such services.
> Use of these feeds for commerical (having others pay for a service) use is
> strictly prohibited.

That prohibits **resale**, not redistribution, and explicitly frames the feed as
being *for public use*. The [Artillery repository](https://github.com/BinaryDefense/artillery)
carries no LICENSE file that says otherwise. A free public republication is the
paradigm case of public use.

Restored to `redistribute: true`, recovering the 702 records ADR-036 cost, and
`license` now quotes the terms instead of paraphrasing them.

**The lesson is the reusable part.** ADR-036 reasoned from a summary field that a
previous change had written, not from the source. Licence conclusions must quote
the upstream text verbatim, and `sources.yaml` now does for every restricted
source.

## Two sources we should not have been republishing (ADR-040)

**Status:** accepted (2026-08-13)

The same verbatim-quote review that cleared Binary Defense found two live problems
in the other direction.

**GreenSnow.** The site footer states, verbatim:

> Copyright © 2013-2026 GreenSnow.co. All rights reserved. Reproduction or
> republication strictly prohibited.

We were republishing it in every feed file. It is now `redistribute: false` and
also `noncommercial_compatible: false` — the prohibition is on republication of
any kind, so no tier can carry it. It still votes and can upgrade a band under
ADR-035.

**ThreatFox.** ADR-030 recorded "abuse.ch Feodo/ThreatFox" as one licence. They
are not. Feodo Tracker's blocklist page says its datasets "can be used for both,
commercial and non-commercial purpose without any limitations (CC0)". ThreatFox
carries no such grant; it falls under the
[abuse.ch platform terms](https://abuse.ch/terms-of-use/), which state:

> You may not: copy, adapt, alter, translate, modify or make derivative works
> based on the Platforms and/or any other of our or Spamhaus' intellectual
> property, without the express consent of abuse.ch and/or Spamhaus

and route commercial use to a paid Spamhaus subscription. The
[export page](https://threatfox.abuse.ch/export/) carries no CC0 notice. Now
`redistribute: false`, which also means it can no longer promote a record on its
own, since ADR-035 made promotion conditional on being publishable.

Between them these cost more than Binary Defense returned. That is the correct
trade: the alternative was continuing to republish data against an explicit
prohibition, which is exactly the outcome this project was told to avoid.

## A second, non-commercial tier (ADR-041)

**Status:** accepted (2026-08-13)

The brief asked for as much public data as possible. The blocker had been treated
as binary: either a source can go in the feed or it can only vote. There is a
third option we had not taken.

CC BY-NC-SA permits redistribution. What it forbids is commercial use. We cannot
put that data in the primary feed because a public file is downloaded by companies
too, and we cannot bind them. But we *can* republish it under the same licence in
a separate, clearly marked tier — which is precisely what the licence is for.

`feeds/noncommercial/` is built by a second scoring pass in which
`redistribute_noncommercial` sources count as fully publishable. It is licensed
CC BY-NC-SA 4.0, carries its own `LICENSE.txt`, and every file leads with a banner
naming the restriction and pointing commercial users back to the primary feed.

Measured on a live run: **5,281 published versus 4,204** in the primary feed, a
gain of 1,077 addresses, because Turris Sentinel and StopForumSpam can be
published in full instead of only counted as corroboration.

**One constraint is not obvious and is enforced in code.** `noncommercial_compatible`
exists because CC BY-SA and CC BY-NC-SA are mutually incompatible in one file. A
ShareAlike licence forbids applying "additional or different terms" to an
adaptation, and NonCommercial is an additional term. So ipthreat.net data, which
carries a ShareAlike obligation without a NonCommercial one, **may not be mixed
into the non-commercial tier** — and is excluded from it by
`noncommercial_sources()`, with a test asserting it never appears there.

Rejected: a third tier to carry ShareAlike-plus-NonCommercial separately. The
audience is people without a threat intelligence platform; two clearly explained
tiers is already at the limit of what a public feed should ask of a reader.

## ipthreat.net added: a rare commercially-reusable feed (ADR-042)

**Status:** accepted (2026-08-13)

3,266 addresses at threat level 30 or above, from ipthreat.net's own community and
honeypot reporting.

- **Independent.** 5.4% overlap with our published feed — a genuinely new class,
  not a reshuffle.
- **Fresh.** The site describes monthly dumps, but
  `lists.ipthreat.net/file/ipthreat-lists/threat/threat-30.txt` reported a
  `last-modified` within the hour, and every row carries its own threat level and
  timestamp.
- **Commercially reusable**, which is rare here. The
  [licence](https://ipthreat.net/license) says: "You are free to re-use, re-mix
  the data from this website, even commercially".

Two implementation notes worth recording:

- **The number is a threat level, not a day count.** `threat-14.txt` has *more*
  entries (6,092) than `threat-30.txt` (3,266) because it includes everything
  scoring 14 or above. We take the level-30 list.
- **Use the `.txt`, not the `.gz`.** The gzipped variant is served as
  `content-type: application/gzip` rather than as a content-encoding, so httpx
  does not transparently decompress it and the parser silently produced zero
  records. The first measurement run showed ipthreat adding exactly nothing, which
  is what caught it.

Effect: published 3,114 → **4,204**, high confidence 2,321 → **2,642**.

Attribution is required and specific — "Data sourced from IPThreat located at
https://ipthreat.net", with a plain, non-nofollow link where the data appears on a
website. Both the feed headers and the dashboard now carry it.


## Credit the sources that grant us nothing (ADR-043)

**Status:** accepted (2026-08-13)

Three sources we republish state no licence at all: Blocklist.de, bruteforceblocker
and the Tor exit list. In the published headers they appeared as a bare name with
no credit line, because the header fell back to the `license` field and they had
nothing to put there.

That is backwards. A source that has granted us nothing in writing is the one that
most deserves a visible, correct credit — it is the only thing we are actually
giving back, and it costs nothing.

Added a `credit` field, set for every source we republish, rendered ahead of the
licence summary. Headers now name the project and the people behind it:
bruteforceblocker credits Daniel Gerzo at danger.rulez.sk, IPsum credits Miroslav
Štampar, the Tor exit list credits the Tor Project. The licence text still appears
beneath, including the plain admission "No licence stated" where that is the truth.

## Aggregate statistics as a first-class artifact (ADR-044)

**Status:** accepted (2026-08-13)

The question raised was whether the project could pivot to publishing only
roll-up analytics — top ASNs, maps, counts — on the theory that a statistic is a
new work rather than a redistribution.

**The legal half of that is right.** "AS9009 has 18,942 listed addresses" is a
derived fact. It is not an extract of anybody's list, and nobody can block anything
with it. Publishing aggregates computed over sources we may not republish is
sound, and it is what commercial threat reports have always done.

**The product half is wrong, so this is an addition and not a pivot.** The stated
goal is to help people who need to block bad addresses and lack the tooling. A map
blocks nothing. Removing the lists to keep the charts would abandon the only part
that has utility, in exchange for a licensing benefit we can get without giving
anything up.

Two arguments were explicitly not relied on:

- *"Someone could dig through the files but that is not the main intent."* Intent
  does not cure distribution. If restricted data is in a published file we are
  redistributing it, whatever the intent; and if it is not in a file, the intent
  argument is unnecessary.
- *"Anyone could abuse any software."* True and irrelevant. Third-party misuse of
  what we publish is their problem. What *we* distribute is ours.

**What was built.** `feeds/insights.json` and a dashboard section computed over
**every** observation from **every** source, restricted ones included. It is the
one place GreenSnow, ThreatFox and AbuseIPDB appear by name against a number, with
a column counting addresses only they reported — evidence we would not otherwise
have. Alongside: top ASNs with a count of how many independent sources reported
each, a country map, and pairwise overlap between independence classes.

Two rules make the distinction defensible rather than convenient, and both are
enforced in code with tests rather than left to discipline:

1. **No address is ever emitted.** Not as a top-offenders list, not as an example.
   `test_insights_never_emit_an_address` asserts it. This is why there is no "worst
   IPs" table despite it being the obvious thing to build: at that point the
   statistic is the data wearing a hat.
2. **Cells below 5 addresses are suppressed** into an unnamed bucket. A named ASN
   holding one listed address is very nearly that address. Standard statistical
   disclosure control, and it costs nothing at the granularity anyone reads —
   3,920 tiny networks fold away and the top of the table is unchanged.

ASN and country mapping comes from [iptoasn.com](https://iptoasn.com/), Public
Domain under PDDL v1.0, rebuilt hourly. The licence was a selection criterion: an
enrichment dataset with redistribution conditions would attach its own obligations
to every statistic we publish. Country centroids for the map come from
world-countries-centroids by Gavin Rehkemper under MIT, with the notice retained in
`centroids.py`.

The first run immediately produced something the feeds alone did not show: M247
(AS9009) carries 18,942 listed addresses and is reported by **10 of 10** independent
classes. That is not a bad week, it is a standing pattern, and it is the sort of
finding that argues for a conversation about the network rather than a whack-a-mole
against addresses.


## Open items

- [ ] Confirm AbuseIPDB redistribution terms in writing; flip `redistribute` if permitted.
- [x] Decide whether a separately-licensed NC-SA feed variant is worth shipping — done, shipped (ADR-041). DShield remains unattractive on volume, not licence: `block.txt` is only the top 20 /24 subnets.
- [ ] Free-tier GreyNoise API keys require a business email address; a personal-domain account may be limited to unauthenticated lookups (~10/day). Confirm what tier is actually obtainable before wiring GreyNoise enrichment in Phase 2b.
- [ ] Blocklist.de, bruteforceblocker and the Tor exit list state **no licence at all**. We publish them, and now credit them properly (ADR-043), but a credit is not a grant. Still need an explicit statement from each maintainer; this remains the weakest position in the set.
- [ ] Google Cloud (AS396982) appears in the top networks with 6,865 addresses. Expected for a large cloud, but worth checking that the allowlist covers Google's published service ranges rather than only the ones we happened to add.
- [ ] ipthreat.net's licence contradicts itself, naming "creative-commons by attribution" while saying "the creative commons by sa license can be used as a guide" and requiring derived data under the same licence. We read it conservatively as ShareAlike. Worth asking them to clarify, since a plain CC BY reading would let it into the non-commercial tier too.
- [ ] ELLIO community feed now 404s and dataplane.org still prohibits redistribution; neither is actionable.
- [ ] Feodo Tracker has been stale for 43 days and its IP blocklist is nearly empty. It is our only CC0 promoting source now that ThreatFox cannot promote. If it stays dead, the abuse.ch promotion path is effectively gone and should be removed rather than left looking active.
- [x] Confirm whether Binary Defense's terms permit redistribution — done, they do (ADR-039).
- [ ] Re-check DShield: independent and PGP-signed, but `block.txt` is only the top 20 /24 subnets, so it is not worth a collector at that volume.

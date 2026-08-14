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
- **AbuseIPDB defaults to `redistribute: false`.** It is a strong scoring signal, but their terms restrict republishing the blacklist verbatim. It informs confidence; its rows are not emitted until the terms are confirmed in writing. **Updated 2026-08-14:** the free-tier key is now configured and the source is enabled, which changes nothing about redistribution — `redistribute` stays `false`, and `test_record_sourced_only_from_non_redistributable_is_never_published` is what enforces it. Having the key is not permission to republish.
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

**Eleven voting classes are defined.** `abuseipdb` and the ThreatFox member of `abusech` are keyed; both are enabled in `sources.yaml` and both skip cleanly when their key is absent, so the pipeline must still be correct on a clone with no secrets and gain accuracy — not change behaviour — when the keys are present. `xfeeds validate` prints the active class count so this is never ambiguous. `ABUSEIPDB_API_KEY` was configured on 2026-08-14.

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

Measured before the keyed sources were configured, so these are floor figures — AbuseIPDB and ThreatFox move IPs up, never down. Not re-measured here: the distribution is re-derived every run and published in `feeds/manifest.json`, which is the number to trust.

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

1. Keyed free sources with usable terms — ThreatFox (done), AbuseIPDB (done 2026-08-14, scoring only).
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


## Address space instead of geography; persistence instead of volume (ADR-045)

**Status:** accepted (2026-08-13). Supersedes the map added in ADR-044.

The map was removed. Two reasons, and the second is the real one.

It looked wrong: centroid dots on an unlabelled equirectangular projection, with a
legitimately empty right-hand side that read as a rendering bug. That was fixable.

**What was not fixable is that the underlying number was misleading.** The country
in an IP-to-ASN table is where the AS *number is registered*. For a hosting company
that describes where its paperwork lives, not where any traffic came from. M247 is
registered in Romania and operates worldwide; a chart headed "listed addresses by
country" would have put 19,000 addresses on Romania and been the most confidently
wrong thing on the page. Country has been dropped from `insights.json` entirely
rather than kept with a caveat, because a caveat under a coloured map does not
survive a screenshot.

**What replaced it.** Address space is the coordinate system this data actually
has, so the hero visual is the whole IPv4 range as one strip, 512 slices of
8.4 million addresses each, log-scaled. It answers a question the feed files cannot:
how much of the internet do we see activity in at all. The answer today is 402 of
512 slices, which is a more interesting claim than any country ranking. Log rather
than linear because a handful of dense slices would otherwise flatten everything
else to nothing, and the breadth is the point. Multicast and reserved space
(224.0.0.0/4 and up) is shaded and labelled, since an empty tail otherwise reads as
a broken chart.

Beneath it, published counts across every recorded run.

**The ASN table was rebuilt around persistence rather than volume.** Ranked by
`days_active` first, because ADR-038 established that individual addresses churn out
inside about a week: a large one-day number is an incident, and a network present on
nine separate days is a standing pattern. Volume alone was also actively misleading
— the first version's top rows were Google Cloud, Microsoft, Alibaba and
DigitalOcean, which is a ranking of who is biggest, not who is worst.

So every row now carries `per_million_announced`: address-days divided by the
address space the ASN actually announces, computed from the iptoasn ranges. That is
the column that separates signal from size. On the first run it moved DigitalOcean
(716/M over 3.1M announced) and Tencent (641/M over 2.1M) above ChinaNet
(18/M over 99M) — ChinaNet is simply enormous, while the other two are
disproportionately hostile for their size. The cut-off for computing a rate is 256
addresses, a /24: an earlier 1024 excluded every /24, which is exactly where a
small, almost entirely hostile network appears.

**Real 30- and 60-day windows on day two.** The project has 13 runs over 17 hours,
so windows over its own history would have been three identical columns pretending
to be three measurements. Two sources publish dated history of their own —
bruteforceblocker about a month, ipthreat about ten days — and both were being
thrown away: `bruteforceblocker` parsed the address and discarded the "Last
Reported" column, and ipthreat was read by the generic `plain_text` parser which
never saw its per-row timestamp. Both now preserve it, giving 11 days of genuine
dated history immediately.

Crucially that date is carried in a **new field**, `source_last_reported`, and not
in `last_seen`. Putting a 31-day-old upstream date into `last_seen` would feed it
straight through `recency_factor` (ADR-037) and silently restate every score in the
feed. History and insights consume the new field; scoring does not see it. Whether
scoring *should* is a genuine question, but it is a scoring change and belongs in
its own decision with its own churn measurement.

`feeds/asn-history.json` accumulates distinct addresses per ASN per day, retained 90
days, merged with `max` rather than summed — the same dated list is re-read every six
hours, and addition would inflate one fact four times a day. Windows shorter than the
available history are labelled as incomplete on the page rather than quietly implying
depth that is not there.

**Deviation from the sketch.** The sketch had 30/60/all-time as three side-by-side
columns. Each row carries five numbers that only mean anything together, and three
of those tables abreast would have had to drop the normalised column — the one that
stops this being a list of large hosting providers. Tabs instead, reusing the
existing pattern, which also required scoping the tab script to its group since the
page now has two independent sets.


## Map remnants removed (ADR-046)

**Status:** accepted (2026-08-13)

ADR-045 removed the map. It did not remove everything that existed to serve it,
which was reported as "there are still mentions of the Map on the application".

Two leftovers, and the second matters more than the first:

- The credit paragraph still thanked world-countries-centroids for "map positions",
  crediting a dataset whose module had been deleted in the same change. Corrected to
  credit only IPtoASN, which is still used.
- **The top-ASN table still had a Country column**, and `insights.json` still carried
  `country` on every row. That is the registration country - the precise number
  ADR-045 removed the map *for*. Deleting the map while keeping the same figure in a
  table would have kept the wrong claim on the page in smaller type. Both removed,
  with a test asserting it cannot reappear.

The lesson repeats one from ADR-039: a change is not finished when the offending
thing stops rendering. The supporting data, credits and columns are part of it, and a
grep for the feature name is a cheap last step that would have caught both of these.

Also renamed that table to "Networks with the most listed addresses in this run", so
it is clearly a current-run view rather than competing with the historical windows at
the top of the page.


## The spectrum axis says what it is (ADR-047)

**Status:** accepted (2026-08-13)

Feedback on the spectrum chart: the visual works, but the axis did not read as an
address range. That was fair. The ticks were bare octet numbers - `0`, `32`, `64` -
which look like an arbitrary scale. Nothing on the chart said "these are IP
addresses" except a caption below it, which is the wrong place to explain an axis.

Three changes, no new data:

- **Ticks are dotted quads.** `32.0.0.0`, `64.0.0.0`, and so on, in a monospace face
  so they read as addresses rather than decimals.
- **Both ends are labelled with the real bounds**, `0.0.0.0` and
  `255.255.255.255`, at slightly higher contrast than the intermediate ticks. The
  viewBox was widened by 58 units either side to make room; insetting the plot
  instead would have misaligned the bars from the axis describing them.
- **A hint line above the chart** states "horizontal axis: every IPv4 address, in
  order" beside the range.

**The mobile case needed a different answer.** SVG text scales with the viewBox, so
at 390px the axis labels render around four pixels regardless of the font size set on
them - an earlier attempt to bump them to 15 units achieved nothing. Below 640px the
in-SVG labels are hidden entirely and the HTML hint line carries the range, where it
is real text at a real size. Losing the intermediate ticks on a phone costs little;
the claim that matters there is "this is the whole address space", not which /8 a
particular spike sits in.


## Licence re-audit, 2026-08-14 (ADR-048)

**Status:** accepted (2026-08-14)

Every source was re-read against its live terms page, and the question asked was
not "is this allowed" but "are we taking everything this licence actually gives
us". Three sources were being under-used and two findings are uncomfortable.

### DataPlane.org re-admitted as a scoring source

The old note said redistribution is prohibited "in whole or in part", so the
source was not ingested at all. That conflated *may not republish* with *may not
read*. The header ([sshpwauth.txt](https://dataplane.org/sshpwauth.txt)) says both
things, and only one of them binds us:

> The sshpwauth report is free for non-commercial use ONLY. ... Redistribution of the sshpwauth report in whole or in part without the express permission of Dataplane.org is expressly prohibited.

This project is free and sells nothing, so the use grant applies. Redistribution
is refused completely — `redistribute: false` **and**
`noncommercial_compatible: false`, so unlike GreenSnow and AbuseIPDB it is barred
from the non-commercial tier too. It is the only source with that combination, and
there is a test asserting it.

It needed a new parser: the report is five pipe-delimited columns behind a 74-line
header, and `plain_text` read zero records from it while reporting success. The
per-row `lastseen` column also gives seven days of real dated history, which
previously only two sources provided.

### DShield re-admitted to the non-commercial tier

ADR-012 excluded DShield because CC BY-NC-SA "breaks the promise that anyone can
use xfeeds output". That was correct for the primary feed and became wrong the day
ADR-041 shipped a non-commercial tier. The ISC API page
([isc.sans.edu/api](https://isc.sans.edu/api/)) is explicit:

> It is ok to use this data for commercial purposes, for example to protect your own company's network. But again: do not resell ... the data is provided using a Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0) License.

That is the same posture as Turris, so it gets the same treatment:
`redistribute: false`, `redistribute_noncommercial: true`. Weight is held at 0.5
and TTL at 3 days because this feed publishes the top 20 **/24 subnets**, not
addresses — one vote here covers 256 hosts, and it must never be the reason a /24
is published.

Note for whoever wires up more DShield data: `isc.sans.edu/api/threatlist/dshield?json`
returned an empty array on 2026-08-14. `feeds.dshield.org/block.txt` is the live path.

### Measured effect

Controlled A/B on 2026-08-14, same run, same missing API keys on both sides:

| Config | Published | High | Medium |
|---|---|---|---|
| Baseline | 3,518 | 2,376 | 1,142 |
| + DataPlane + DShield | 3,518 | **2,751** | 767 |
| + sefinek only | 4,318 | 2,580 | 1,738 |

DataPlane and DShield admitted **nothing new** and upgraded 375 records from
medium to high. That is exactly what an independent corroborating source should
do, and it is the strongest argument yet for the vote/redistribute split.

### sefinek added to the config but left disabled

[sefinek/Malicious-IP-Addresses](https://github.com/sefinek/Malicious-IP-Addresses)
is MIT — one of only two cleanly redistributable feeds the 2026-08-14 sweep found —
and it is the least-correlated list we have measured: 2.7% of our published feed,
2.2% against duggytuxy, 1.4% against Blocklist.de, 0.0% against ET compromised-ips.

It is disabled anyway, on measured behaviour rather than licence. Its README says
"Entries are added continuously and are generally not removed", so it never expires
anything and our TTL can never age one out. In the table above it admitted 800 new
records, but the gain was mostly new **medium**-band material (+596 medium against
+204 high). Admitting 596 records on the word of a list that never retracts is the
false-positive vector this project exists to avoid. Revisit with a churn measurement,
and consider capping it to upgrade-only under ADR-035.

### duggytuxy rejected on measurement, not on its README

[Data-Shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) claims
original telemetry "fed by global probes". Measurement disagrees: it contains
**90.7% of everything we currently publish**, 96% of ET compromised-ips, and 95% of
it sits inside ThreatHive, which is a confirmed re-aggregator. A source that
already contains nine tenths of our corroborated output is not an independent
vote — it is our own feed echoed back. Recorded in `sources.yaml` under
`META_aggregate` so this is not re-litigated. Its GPLv3 licence would also collide
with ipthreat's ShareAlike requirement.

### Uncomfortable finding: Spamhaus grants us no licence

This one is unresolved and it matters more than everything above. The friendly
wording we have relied on is on the blocklist page
([DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)):

> We do ask, when used in a product, credit must be given to Spamhaus Project, and the date and © text should remain with the file and data.

But the Terms of Use that the data file itself points at
([Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)) say:

> 3.1 The content of the DROP List is protected by copyright and database right. Nothing in these Terms shall be construed as granting an assignment or licence of any intellectual property rights in the DROP Lists.

> 3.3 We reserve the right in our absolute discretion to revoke your right to use the DROP Lists for any reason

There is no prohibition on redistribution anywhere, and Spamhaus plainly intends
DROP to be spread widely and used freely. But there is no grant either, and they
assert both copyright and database right. Spamhaus is our largest auto-promoting
source, so demoting it to scoring-only would gut the high-confidence band — which
is a reason to get an answer, not a reason to assume one. **Action: email Spamhaus
for written confirmation.** Nothing changed in this ADR pending that reply.

Also noted: §3.2 bars use of the Spamhaus name in "marketing, promotional or any
other commercial materials". Our attribution is required by their own page and is
not marketing, so the credit line stays.

### Smaller corrections from the same pass

- **SSLBL's IP list is not empty, it is retired.** The file says "ATTENTION: This
  list has been deprecated on 2025-01-03" ([sslipblacklist.txt](https://sslbl.abuse.ch/blacklist/sslipblacklist.txt)).
  It stays disabled, now for the right reason.
- **Feodo Tracker is 5 entries and 163 days stale**, and it is our only CC0
  promoting source. The staleness warning is firing correctly every run. If it is
  still dead in a month, remove the promotion path rather than leave it looking
  active.
- **bruteforceblocker moved**: `blist.txt` now 404s, `blist.php` is live. We were
  already on `blist.php`.
- **Spamhaus is deprecating its text feeds** in favour of JSON. We already parse
  `drop_v4.json`, `drop_v6.json` and `asndrop.json`, so no action — but
  `asndrop.txt` is already a stub, and the `/blocklists/asn-do-not-route-or-peer/`
  page now 404s.
- **ET compromised-ips stays disabled**, now with a measured reason: 96% of it is
  already inside duggytuxy and it is class-pinned to bruteforceblocker anyway, so
  it cannot add a vote.
- **AbuseIPDB compliance verified end to end.** After enabling it, `grep` across
  every file under `feeds/` returns zero occurrences of any AbuseIPDB-sourced row
  or the source name. The manifest declares it as a non-redistributable
  contributor, which is the intended transparency.
- **`mirai.security.gives` is now a parked gambling site.** No references remain in
  this repo; do not restore it from an old branch.
- Fixed a duplicated `notes:` key on `turris_greylist` in `sources.yaml`, where the
  first block was silently discarded by the YAML parser.


## GreyNoise caps benign scanners, and RIOT is not obtainable (ADR-049)

**Status:** accepted (2026-08-14)

### The measurement that justifies this

A free-tier GreyNoise key was obtained and pointed at 500 addresses from our own
published feed. The result:

| GreyNoise classification | Count | Share |
|---|---:|---:|
| malicious | 266 | 53% |
| benign | **85** | **17%** |
| suspicious | 77 | 15% |
| unknown | 63 | 13% |

**17% of what we publish is scanning activity GreyNoise considers benign** — the
sample includes Hurricane Electric ranges tagged as SNMP and F5 BIG-IP crawlers,
which is research scanning, not attack traffic. For a project whose stated first
principle is that a false positive drops somebody's real traffic, that number is
the single largest quality problem measured so far.

### Cap, do not delete

Benign-classified records are demoted **HIGH -> MEDIUM**, not removed. This is
ADR-013's reasoning applied to a second case: blocking a known research scanner is
a policy choice belonging to the consumer, and MEDIUM is already documented as
"challenge or rate-limit rather than a hard block". A consumer who *does* want to
block Censys can still act on the medium tier.

### The licensing constraint is tighter than for any other source

GreyNoise's EULA forbids free customers from distributing or publishing the
Platform to third parties. So this integration may only ever **remove** confidence:

- **No tag is written onto a capped record.** A `greynoise-benign` tag would
  disclose their dataset one address at a time, which is redistribution with extra
  steps. There is a test asserting the record is not annotated.
- **Only an aggregate count reaches the manifest** (`benign_scanners_capped`), on
  the same reasoning ADR-044 used for the insights layer: a count is a statistic
  derived from data, not an extract of it.

That makes GreyNoise the first source here that influences the output while being
invisible in it even as a name.

### RIOT is not available, and will not be on a free key

This is worth recording so nobody re-attempts it. RIOT was renamed **Business
Service Intelligence** and folded into `/v3/ip/:ip`; the v2 `/v2/riot/:ip` endpoint
now returns HTTP 410. The dataset itself is a separately licensed **add-on** that,
per [GreyNoise plans](https://www.greynoise.io/plans), "attach[es] to any paid
platform tier". Our key confirms it directly: every response lists
`business_service_intelligence` in `request_metadata.restricted_fields`, and the
field is `found: null` even for Googlebot and Bingbot, which are unambiguous
business-service entries.

So the Phase 2b "GreyNoise RIOT suppression" item cannot be completed as written.
What replaced it is better targeted anyway: RIOT identifies benign *business
infrastructure* (CDNs, public DNS, NTP), which the allowlist already covers from
authoritative first-party sources. `internet_scanner_intelligence.classification`
identifies benign *scanners*, which nothing else here covers at all.

Other free-tier limits observed on 2026-08-14: a 10-day lookback window, 37
restricted fields including `cve`, `scan_ports` and `first_seen`, and HTTP 206 as
the normal response when some addresses fall outside the window. Undocumented
request quota — which is precisely why the integration is built to survive a 429.

### Never load-bearing

No key, a connection error, a 401/403/429, or a malformed body all degrade to
"cap nothing" and the run completes normally. A feed that failed to build because
an enrichment API was down would be a worse outcome than one that is 17% noisier.
`quick=true` is used because it carries both fields we read while returning 80 KB
per 500 addresses instead of 5.5 MB, and one request per run covers the whole
published feed against a documented 10,000-address batch cap.

### Local reproducibility (`scripts/seed-cache.py`)

Separate but from the same session: local runs could not include the keyed sources
because the environment's egress proxy is traversable by `curl` but fails the
pipeline's own TLS handshake, so a local run reported a smaller feed than
production and could not be used to validate output. Rather than teach the
collector about proxies, `scripts/seed-cache.py` writes a body fetched by any means
into `.cache/`, where `fetch_source` serves it exactly as a fresh fetch. Verified:
seeding ThreatFox reproduced production's 1,112 records precisely.


## Using more of each licence, 2026-08-14 (ADR-050)

**Status:** accepted (2026-08-14)

A sweep of every publisher's full file listing, asking not "is this source allowed"
but "are we reading everything this licence already lets us read". Four publishers
turned out to be fully consumed already — Spamhaus, CINS, Binary Defense, and SSLBL
which is dead. Four were not.

### ipthreat: we were misreading the filename and discarding 96% of the feed

`threat-N.txt` is a **minimum score**, not a number of days. Verified: `threat-0`
has a minimum row score of 0 and `threat-30` a minimum of 30, and the files get
*smaller* as N rises, which a day-window cannot do. The source was named
`ipthreat_30d` and documented as a 30-day window. It was really a score≥30 slice
holding 2,327 of 57,806 rows.

Now fetches `threat-0.txt` and applies the floor through the new `min_score` config,
so the threshold is a reviewable number instead of a digit buried in a URL.

`min_score` is **15**, and the anchor is this project's own published expectation
rather than taste. ADR-015 predicted a high-confidence feed of 2,000–4,000 entries:

| min_score | ipthreat rows | published | high |
|---:|---:|---:|---:|
| 30 (old effective) | 2,281 | 3,522 | 3,187 |
| **15 (chosen)** | **4,787** | **4,268** | **3,838** |
| 5 | 9,329 | 5,258 | 4,605 |
| 1 | 22,330 | 7,650 | 6,108 |

15 roughly doubles coverage and stays inside the committed range; 5 and 1 leave it,
and 1 would move the high band by +118%. Scores below 15 are 91% of the corpus and
are dominated by single low-confidence observations. Band assignment counts
**classes, not weights**, so a score-1 row admits a record exactly as hard as a
score-100 one — which is why this is a floor and not a weight adjustment, and why
lowering it later is a policy change needing its own churn measurement.

### StopForumSpam: a compliance downgrade and a 912× volume increase, together

We were publishing StopForumSpam in the non-commercial tier. Re-reading
[their licence](https://www.stopforumspam.com/license), that is not defensible. The
page grants "To Share — to copy, distribute and transmit the work" and then, under
**No Derivative Works**, says:

> You may not alter, transform, or build upon this work, nor use any manual or
> automated tools or system to mirror, copy, scan, duplicate, backup, distribute,
> scrap or spider any of the data on this website

Those clauses contradict each other, and "build upon this work" describes an
aggregated feed precisely. Under AGENTS.md we bias toward publishing less, so it is
now **scoring only in both tiers**.

Because nothing is republished, volume became free. We were reading
`toxic_ip_cidr.txt` — 60 CIDRs. We now read `listed_ip_30_ipv46.gz` — **54,710**
addresses last seen within 30 days, same site-wide licence, one fetch. Their
downloads page defines the window as a last-seen recency window, which is the
semantics we want anyway.

Two operational limits, both real and both encoded: the `listed_*` files are capped
at **2 downloads per IP per day** (hence `min_interval_seconds: 43200`, so four
scheduled runs make two real fetches), and the site answers bursts with
`429 error code: 1015` from Cloudflare, counting `HEAD` requests. Never fan out
across their files in parallel.

Their NonCommercial clause is also narrower than most — "You may use this work on
commercial sites however you cannot resell any information gathered from this site"
— but that does not rescue redistribution, because No Derivative Works is the
binding clause.

### DataPlane: one report of nineteen

DataPlane publishes 19 signal reports; 17 carry addresses; we read one. Added
`telnetlogin` (89,312), `proto41` (55,772), `sshclient` (19,446), `smtpgreet`
(9,508) and `vncrfb` (5,384) alongside `sshpwauth` (9,768).

All are **class-pinned to `dataplane`**, so together they remain exactly one vote.
They are one sensor network reporting different protocols; treating them as
independent would manufacture corroboration out of a single operator's telemetry,
which is the specific failure independence classes exist to prevent. What they buy
is coverage — far more addresses receive that single vote. There is a test asserting
the pinning, because a copied YAML block with a fresh class is an easy mistake.

`proto41` has **six columns, not five**: it inserts `firstseen` before `lastseen`.
The parser now reads the timestamp from the end of the row, which handles both
layouts.

### Blocklist.de: `strongips` is small and genuinely additive

348 addresses, of which **104 are not in `all.txt`** — and that is structural, not
fetch skew: both files share a `Last-Modified` minute. `all.txt` is "the last 48
hours"; `strongips` is "older then 2 month and have more then 5.000 attacks". Aged,
high-conviction attackers that have gone quiet for two days fall out of one and stay
in the other. Class-pinned to `blocklist_de`.

The 15 undocumented files under `lists.blocklist.de/lists/` were checked and add
**zero** addresses beyond `all.txt` — they are port-numbered and daemon-named
aliases. Do not add them.

### Deliberately not taken

- **Feodo's `ipblocklist_aggressive.txt`** (7,607 vs 5) is nominally 1,521×, but the
  publisher says "I strongly recommend you to not use the aggressive version... it
  definitely will cause false positives", it is an all-time list of recycled
  addresses, and the whole tracker has not updated since 2026-03-04.
- **Turris archive**, 2,404 daily snapshots back to 2020; a 30-day union measures
  75,454 unique addresses against 9,488 in one snapshot (8×). Same licence, no new
  endpoint. Left for a separate change because backfilling history interacts with
  state and ageing, and deserves its own measurement.
- **ThreatFox bulk export** still serves without an Auth-Key at the legacy paths,
  but the docs are now login-gated and the files point at the ThreatFox ToS rather
  than CC0. Anonymous availability is not a licence.
- **Emerging Threats' 14,935** is almost entirely re-badged data we already ingest
  from the original publishers. The only genuinely new ET dataset is
  `threatview_CS_c2.rules` (752 Cobalt Strike C2), whose third-party provenance
  inside ET's directory needs its own licence check first.

## A third tier: clean provenance (ADR-051)

**Status:** accepted (2026-08-14)

The primary feed's own header says `Licence: see individual source terms below`.
That is honest and it is also the problem. A practitioner's blocker is rarely "is
this allowed" in the abstract — it is being asked by their own legal or procurement
review to name the licence for every input, and not being able to, because several
of our publishers distribute freely and openly while never having granted anything.
**Absence of a prohibition is not a grant.**

`feeds/clean/` contains only sources that pass a stricter test than `redistribute`.
The new `explicit_grant` flag means: the publisher has issued a **written, named**
licence affirmatively permitting redistribution, commercial use included. CC0,
Unlicense, MIT, BSD, CC BY / BY-SA qualify. "Publishes it freely and says nothing"
does not.

Built by the same mechanism as ADR-041's non-commercial tier — a source-name set
plus its own scoring, filtering and emit pass — so bands and provenance are computed
for that membership rather than inherited.

`clean/LICENSE.txt` is the actual deliverable: it enumerates, per contributing
source, the licence name, the URL of its text, and the required credit line, then
states the obligations that travel with the data. That file is what goes to a legal
review.

### Two errors this tier caught in its own first draft

Worth recording, because both looked correct in the config and were only visible in
the output:

1. **Tor was in it.** `explicit_grant` had been set from the Tor Project's CC0
   declaration on `metrics.torproject.org`, while the source's own `license` field
   still read "No licence stated on the endpoint". The bulk exit list is served from
   `check.torproject.org` with no licence text, and Tor's canonical LICENSE was
   unreachable on two separate days. Inferring a grant across hosts is exactly the
   reasoning this tier exists to refuse. Removed; it is tag-only and cast no vote
   anyway.
2. **`et_compromised` had no licence fields at all**, so the generated LICENSE.txt
   rendered `Licence: n.a.` to the reader — in the one file whose entire purpose is
   naming licences. Now carries the BSD 3-clause name, URL and copyright line.

`test_every_clean_tier_source_can_actually_name_its_licence` now fails the build if
a granted source has no licence name or URL, or if its licence text contains "no
licence", "not stated", "unclear", "n.a." or "see terms".

### Emerging Threats re-enabled, for a reason that did not exist before

`et_compromised` was disabled as a duplicate — Jaccard 0.953 against
bruteforceblocker, a mirror rather than a second opinion. It stays class-pinned, so
it still adds **no vote to the primary feed**. But bruteforceblocker publishes no
licence at all while this file is BSD 3-clause, so in the clean tier it becomes the
sole member of its class and supplies the third citable-licence class the tier needs
to corroborate anything. Costs nothing, unlocks the tier.

### The tier is small, and that is the finding

Measured on a full local run: **primary 4,270 published / 3,840 high;
non-commercial 6,036 / 5,312; clean 23 / 23.**

Twenty-three entries. Three voting classes (`ipthreat`, `bruteforceblocker` via ET,
`abusech` via Feodo), of which Feodo contributes 5 frozen addresses, so in practice
it is two — and a two-class requirement over two classes admits only their exact
overlap. This is not a bug in the tier; it is a measurement of the public threat
intelligence commons, and it agrees with the conclusion already recorded in ADR-033
that the set of feeds which are both independent and freely redistributable is
small.

The lever that would change it is **sefinek** (MIT, 217k addresses, the
least-correlated list we have measured). Enabling it takes the clean tier from 23 to
223. It stays disabled: it also takes the primary feed from 4,270 to 5,192 published
and 3,840 to 4,325 high — outside ADR-015's committed range — on a source whose
README says entries "are generally not removed", so nothing can ever age out. Buying
a 10× bigger clean tier by degrading the primary feed is the wrong trade. The right
fix is more permissively-licensed independent sources, and the tier grows
automatically the moment one is added.


## Open items

- [ ] **Email Spamhaus** for written confirmation that redistributing DROP inside a public aggregate is permitted. Their Terms of Use §3.1 grant no IP licence while the blocklist page invites free use with credit; we currently publish on the second reading. Highest-value open question in this document (ADR-048).
- [ ] Confirm AbuseIPDB redistribution terms in writing; flip `redistribute` if permitted. Key is now configured and the source is live as a scoring input (ADR-048).
- [ ] Measure sefinek churn across several runs, then decide between enabling it upgrade-only or leaving it out (ADR-048/ADR-051). It is now the single biggest lever on the clean tier: enabling it takes that tier from 23 to 223 entries, at the cost of pushing the primary feed outside its committed range.
- [ ] Backfill the Turris archive: 2,404 daily snapshots exist back to 2020, and a 30-day union is 75,454 unique addresses against 9,488 in one snapshot. Same licence, no new endpoint, but it interacts with state and ageing so it needs its own measurement (ADR-050).
- [ ] Check the provenance of `threatview_CS_c2.rules` (752 Cobalt Strike C2). It is the only genuinely new Emerging Threats dataset, but it is third-party data inside ET's directory and its licence is not the ET BSD grant (ADR-050).
- [ ] Ask StopForumSpam to resolve the contradiction between their "To Share" grant and their No-Derivative-Works clause. Until then the source is scoring-only (ADR-050).
- [ ] Ask Dataplane.org whether they would grant redistribution permission for the non-commercial tier; their header requires express permission rather than forbidding it outright (ADR-048).
- [x] Decide whether a separately-licensed NC-SA feed variant is worth shipping — done, shipped (ADR-041). DShield remains unattractive on volume, not licence: `block.txt` is only the top 20 /24 subnets.
- [x] GreyNoise wired up (ADR-049). The obtainable free tier is "Business - Free": enterprise scanner intelligence with a 10-day window, but **not** the Business Service (RIOT) add-on, which is paid-tier only. Benign-scanner capping shipped instead, and it addresses 17% of the published feed.
- [ ] Watch `benign_scanners_capped` in the manifest across a few runs. If GreyNoise starts returning 429, the run degrades silently by design — the count dropping to 0 while the feed grows is the signal to look for.
- [ ] Blocklist.de, bruteforceblocker and the Tor exit list state **no licence at all**. We publish them, and now credit them properly (ADR-043), but a credit is not a grant. Still need an explicit statement from each maintainer; this remains the weakest position in the set.
- [ ] Google Cloud appears prominently in raw volume but drops sharply once normalised by announced size (ADR-045), which is the expected shape for a hyperscaler. Still worth confirming the allowlist covers Google's published service ranges rather than only the ones we happened to add.
- [ ] Consider whether `source_last_reported` should feed `last_seen` and therefore scoring. It would make recency decay real for the two sources that publish dates, but it restates every score and needs a churn measurement first (ADR-045).
- [ ] Only two sources publish dated history, so days before this project started running are covered by those two alone. Worth checking whether Blocklist.de or CINS expose a dated variant.
- [ ] ipthreat.net's licence contradicts itself, naming "creative-commons by attribution" while saying "the creative commons by sa license can be used as a guide" and requiring derived data under the same licence. We read it conservatively as ShareAlike. Worth asking them to clarify, since a plain CC BY reading would let it into the non-commercial tier too.
- [x] ELLIO community feed now 404s. DataPlane.org was resolved in ADR-048: redistribution is still refused, but its use grant permits ingesting it as a scoring source, which is now done.
- [ ] Feodo Tracker has been stale for 43 days and its IP blocklist is nearly empty. It is our only CC0 promoting source now that ThreatFox cannot promote. If it stays dead, the abuse.ch promotion path is effectively gone and should be removed rather than left looking active.
- [x] Confirm whether Binary Defense's terms permit redistribution — done, they do (ADR-039).
- [ ] Re-check DShield: independent and PGP-signed, but `block.txt` is only the top 20 /24 subnets, so it is not worth a collector at that volume.

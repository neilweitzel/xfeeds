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

Nine voting classes. Every one is a distinct sensor network, reporter community, or research team.

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

Total unique across non-Tor voting sources: **54,241**. At ≥2 classes: **12,207**. At ≥3: **1,913**.

So the expected high-confidence feed is roughly **2,000–4,000 entries** once Spamhaus and abuse.ch promotions are included — the same order of magnitude as the original 2,973-entry 2022 list, which is a satisfying result. Anyone expecting a 50,000-entry feed is expecting a feed that should not be blocked on.

### ADR-021 — The 77% is the point

Withholding single-source IPs discards more than three quarters of the raw input. That is the product working. Republishing the union of public blocklists is a solved, worthless problem — the value xfeeds adds is the independence-aware filter that says which entries are actually corroborated.

---

## Open items

- [ ] Confirm AbuseIPDB redistribution terms in writing; flip `redistribute` if permitted.
- [ ] Decide whether a separately-licensed NC-SA feed variant is worth shipping to reclaim DShield.
- [ ] Free-tier GreyNoise API keys require a business email address; a personal-domain account may be limited to unauthenticated lookups (~10/day). Confirm what tier is actually obtainable before wiring GreyNoise enrichment in Phase 2b.
- [ ] Evaluate ELLIO community feed and dataplane.org as additional independent classes.

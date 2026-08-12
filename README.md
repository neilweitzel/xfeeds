# xfeeds

**A self-updating, open threat intelligence feed.**

xfeeds publishes curated lists of known-bad IP addresses that anyone can pull into a firewall, WAF, reverse proxy, or SIEM. The repository itself is the distribution mechanism: feeds are plain files under `feeds/`, regenerated on a schedule by GitHub Actions and served over GitHub Pages.

What makes it different from the dozens of public blocklists it draws on: **xfeeds only publishes what independent sources agree on.** Most public feeds quietly mirror each other, so naive aggregation manufactures false confidence. xfeeds models that dependency explicitly and throws away the ~77% of candidate IPs that only one independent sensor network has ever seen.

---

## Background

xfeeds started as a one-time publication. During a ThreatX SOC "do good" day, ~5 million WAF match events were analyzed to profile the sources of nefarious HTTP traffic. The resulting IPs were validated against GreyNoise to strip benign scanner noise — GreyNoise had previously seen 71 of them and had already tagged 33 as malicious, leaving 2,901 previously-unpublished bad actors. That snapshot lives on, frozen, as `legacy/IP_List` (2,973 entries, April 2022).

That dataset is stale and there is no longer a private WAF telemetry source behind it. **Phase 2 replaces one-time human curation with an automated aggregation pipeline built on public, free-to-use intelligence.**

---

## Design principles

1. **Automate.** No manual steps. A scheduled workflow ingests, normalizes, scores, filters, and commits.
2. **Corroborate, don't concatenate.** Value comes from independent agreement, not from republishing someone else's list.
3. **Be conservative.** A published block feed must be safe to drop traffic on. False positives are the primary risk.
4. **Be transparent.** Every published IP traces back to the sources, licences, and scores that put it there.
5. **Cost nothing to run.** Free tiers and GitHub-hosted runners only.
6. **Stay current, stay boring.** Newest tool that has universal support and can be swapped out later.

---

## Technology stack

Full rationale, alternatives considered, and measurements in [`docs/DECISIONS.md`](docs/DECISIONS.md).

| Layer | Choice | Rationale |
|---|---|---|
| Runtime | **Python 3.13** (floor 3.11, CI also tests 3.14) | One release behind newest — complete wheel coverage, supported to Oct 2029 |
| Packaging | **uv** + `pyproject.toml` + `uv.lock`, exact version pinned in CI | Fast, but chosen because its metadata is standard `[project]` — pip and Poetry read the same file |
| HTTP | **httpx** (sync) | HTTP/2, real timeouts, first-class test mocking |
| Validation | **pydantic v2** | Publishes a JSON Schema for consumers for free |
| Retries | **tenacity** | Policy for 429/5xx that transport-level retry doesn't cover |
| CLI / logs / config | **typer**, **structlog** (JSON), **pyyaml** | Boring, stable, SIEM-ingestible logs |
| Interop | **stix2** (OASIS) | Actively maintained; the price of admission to real TIPs |
| Quality | **ruff**, **mypy --strict**, **pytest** + **pytest-httpx** | One linter binary; no unit test touches the network |
| State | `feeds/all.json` — no database | Self-contained repo, every state change reviewable in a diff |

Deliberately **not** used: `netaddr` (stdlib `ipaddress` suffices), `orjson`/`pandas`/`polars` (wrong tool at 50k records), a database, free-threaded Python, and a TAXII server.

---

## Architecture

```
 upstream sources ──► collectors ──► normalizer ──► scorer ──► filters ──► emitters ──► feeds/
   (HTTP fetch)        (per-source     (dedupe,      (independence  (allowlist,  (txt, csv, json,
                        parsers)        CIDR expand,   -weighted,     aging,       stix, misp,
                                        validate)      saturating)    sanity caps) nftables)
```

| Stage | Responsibility |
|---|---|
| Collect | Fetch over HTTPS with retry/backoff, ETag caching, per-source timeout and minimum interval. A failing source degrades the run; it never fails it. |
| Normalize | Parse into a common record: `ip`, `cidr`, `source`, `independence_class`, `first_seen`, `last_seen`, `categories[]`. Validate as public IPv4/IPv6. |
| Score | Independence-weighted confidence with recency decay and exponential saturation. |
| Filter | Drop allowlisted, reserved, and known-good infrastructure. Enforce CIDR-width and feed-size caps. Enforce per-source `redistribute` flags. |
| Emit | Write feed artifacts, `feeds/manifest.json`, and a run report. |
| Publish | Commit changed files to `main`; open an issue on anomalies. |

---

## Sources

Configured entirely in [`sources.yaml`](sources.yaml). Adding a source means adding a YAML entry and, if the format is new, a parser — never a pipeline change.

**Nine independent voting classes**, each a distinct sensor network, reporter community, or research team. Seven are active on a fresh clone — AbuseIPDB and ThreatFox ship disabled until their free API keys are in repo secrets, so the pipeline must be correct without them and simply gain accuracy when they're added.

| Source | Class | Weight | Volume | Notes |
|---|---|---|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) v4/v6 | `spamhaus` | 1.0 | 1,687 + 92 CIDRs | Auto-promotes to high confidence |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | `abusech` | 1.0 | 5 IPs | Dormant but near-zero FP |
| [SSLBL](https://sslbl.abuse.ch/) | `abusech` | 1.0 | 0 currently | Wired up, harmless |
| ThreatFox | `abusech` | 1.0 | key required | Auth-Key mandatory |
| [Blocklist.de](https://blocklist.de/) | `blocklist_de` | 0.8 | 28,605 | Largest independent sensor net |
| [CINS Army](https://cinsscore.com/) | `cins` | 0.8 | 15,000 | No formal licence — see ADR-012 |
| [AbuseIPDB](https://docs.abuseipdb.com/) | `abuseipdb` | 0.9 | 10,000 | Scoring only, not redistributed |
| GreenSnow | `greensnow` | 0.6 | 3,595 | |
| Binary Defense | `binary_defense` | 0.6 | 3,300 | Requires browser-like UA |
| bruteforceblocker | `bruteforceblocker` | 0.6 | 549 | Upstream of ET compromised-ips |

**Not voting, and why** — the important half of the design:

| Source | Status | Reason |
|---|---|---|
| IPsum L3–L8 | Prior only, weight 0 | Aggregates 30+ lists including most of ours. 35% of Blocklist.de and 64% of Binary Defense reappear inside it. |
| FireHOL level1 | Disabled | Its header declares it composed of sources we already ingest — and it spans 611M addresses including `224.0.0.0/3`. |
| ET compromised-ips | Disabled | Jaccard **0.953** against bruteforceblocker. A mirror, not a second opinion. |
| DShield | Disabled | **CC BY-NC-SA 2.5** — NonCommercial and ShareAlike are incompatible with freely redistributable output. |
| Tor exits | Tag only | Blocking Tor is the consumer's policy choice, not a threat assertion. |

---

## Scoring

```
raw = Σ over distinct independence classes:
        max(weight × recency_factor × severity for sources in that class)

recency_factor = max(0.2, 1 − days_since_last_seen / ttl_days)
score = 100 × (1 − exp(−raw))
```

One vote per class, and exponential saturation, so no single source can alone reach the top band. Spamhaus DROP membership and active abuse.ch C2 listings promote directly — justified by precision rather than agreement.

Measured against live data on 2026-08-11, of 54,241 unique candidate IPs:

| Distinct classes | IPs | Share | Band |
|---|---|---|---|
| 1 | 42,034 | 77.5% | withheld |
| 2 | 10,294 | 19.0% | medium |
| 3+ | 1,913 | 3.5% | high |

Expected published high-confidence feed: **~2,000–4,000 entries** — the same order of magnitude as the original 2022 list. Discarding 77% of the input is the product working, not a bug.

---

## Published feeds

Canonical base URL is GitHub Pages; `raw.githubusercontent.com` is a mirror. Pages is used because raw is capped near 5,000 requests/hour/IP and does not honour authentication — the wrong shape for a feed pulled by many hosts behind shared NAT.

| File | Contents |
|---|---|
| `feeds/high-confidence.txt` | One IP/CIDR per line. Safe-to-block tier. |
| `feeds/medium-confidence.txt` | Challenge / rate-limit tier. |
| `feeds/all.csv` | `ip,score,classes,sources,categories,first_seen,last_seen` — MISP CSV and OpenCTI CSV mappers |
| `feeds/all.json` + `feeds/schema.json` | Full provenance, with a published pydantic-generated schema |
| `feeds/stix-bundle.json` | STIX 2.1 — OpenCTI, Elastic, most TIPs |
| `feeds/misp-manifest.json` | Native MISP feed |
| `feeds/nftables.conf`, `iptables.ipset`, `cloudflare.txt` | Enforcement-ready |
| `feeds/manifest.json` | Timestamps, per-source status and licence, counts, deltas |
| `feeds/CHANGELOG.md` | Human-readable per-run diff |

```bash
curl -sS https://neilweitzel.github.io/xfeeds/high-confidence.txt \
  | grep -v '^#' | sudo ipset restore -! -
```

---

## Safety rails (non-negotiable)

- **Allowlist last.** Applied after every other stage, from live upstreams: Cloudflare, Google Cloud, Googlebot, Bingbot, GitHub, plus static RFC1918/bogons and public resolvers. A failed allowlist fetch is a hard failure, not a warning.
- **CIDR width cap.** Reject prefixes wider than /22 (IPv4) or /48 (IPv6) unless from Spamhaus DROP.
- **Churn guard.** A run that would add or remove more than 25% of the feed fails, opens an issue, and leaves the previous feed in place.
- **Redistribution flags enforced in code.** Sources marked `redistribute: false` inform scoring and never reach an emitter.
- **Provenance always.** No IP ships without a named source in `all.json`.
- **Staleness detection.** A source whose last-updated header exceeds 30 days raises a warning, so a dead upstream is never mistaken for a quiet internet.

---

## Repository layout (target)

```
xfeeds/
├── README.md
├── sources.yaml              # source registry — the only place feeds are configured
├── allowlist.txt
├── pyproject.toml / uv.lock
├── docs/DECISIONS.md         # architecture decision record
├── src/xfeeds/
│   ├── cli.py                # xfeeds run | validate | diff | explain <ip>
│   ├── collectors/           # plaintext, netset, json, spamhaus, abuseipdb, threatfox
│   ├── normalize.py
│   ├── score.py              # independence-class weighting
│   ├── filters.py            # allowlist, CIDR caps, redistribute flags
│   ├── emit/                 # txt, csv, json, stix, misp, nftables, ipset, cloudflare
│   └── report.py
├── tests/                    # recorded fixtures per source; no network in unit tests
├── feeds/                    # generated output — committed, served via Pages
├── legacy/IP_List            # original 2022 ThreatX SOC snapshot, frozen
└── .github/workflows/
    ├── update-feeds.yml      # cron */6h + workflow_dispatch
    ├── pages.yml             # publish feeds/ to GitHub Pages
    └── ci.yml                # ruff, mypy, pytest on PR
```

---

## Automation

`update-feeds.yml`:

- Triggers: `schedule` every 6 hours (offset off the hour) and `workflow_dispatch`.
- Steps: checkout → `astral-sh/setup-uv` at a pinned version → restore HTTP cache → `xfeeds run` → validate → churn guard → commit `chore(feeds): refresh <ISO8601> (+N/-M)` → push → deploy Pages.
- Secrets, all optional — absent keys degrade to unauthenticated sources rather than failing: `ABUSEIPDB_API_KEY`, `THREATFOX_AUTH_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`.
- Concurrency group so overlapping runs cancel.
- On failure or churn trip: open/update an issue with the run report.

The 6-hour cadence is set by the tightest external constraint: AbuseIPDB allows **5 blacklist calls/day** on the free tier, and Spamhaus requires automated fetches at least an hour apart.

---

## Roadmap

**Phase 2a — aggregation MVP**
- [ ] `sources.yaml` loader + collectors for the nine voting classes
- [ ] Normalizer, live allowlist fetching, CIDR caps, `redistribute` enforcement
- [ ] Independence-weighted scoring + aging with persisted state
- [ ] `high-confidence.txt`, `all.csv`, `all.json`, `schema.json`, `manifest.json`
- [ ] `update-feeds.yml` on a 6-hour cron with churn guard; Pages deploy
- [ ] Unit tests with recorded fixtures; CI on PR
- [ ] `xfeeds explain <ip>` — why an IP is or isn't in the feed

**Phase 2b — enrichment & interop**
- [ ] AbuseIPDB and ThreatFox collectors with quota-aware caching
- [ ] GreyNoise RIOT suppression on sampled top candidates (see open items in the ADR)
- [ ] ASN/country annotation
- [ ] STIX 2.1, MISP manifest, nftables, ipset, Cloudflare emitters
- [ ] `CHANGELOG.md` generation

**Phase 2c — enforcement integrations**
- [ ] Reference `fail2ban` action and Cloudflare IP Access Rules sync
- [ ] nginx/HAProxy deny-map output
- [ ] False-positive PR workflow against `allowlist.txt`
- [ ] Status badge generated from `manifest.json`

**Phase 3 — original telemetry**
- [ ] Honeypot collectors (SSH/HTTP tarpit) feeding xfeeds a tenth, first-party independence class — restoring the original-research character of the 2022 dataset without a commercial WAF.

---

## Non-goals

- Not a replacement for a commercial threat intel platform.
- IPs only in Phase 2 — no domains, URLs, or hashes.
- No paid data sources.
- No redistribution of any feed whose licence forbids it.
- No TAXII server.

---

## Contributing

Open an issue to propose a source — include URL, format, cadence, licence, and **what makes it independent of the existing classes**. A source that mirrors one already ingested adds no value and will be class-pinned rather than merged.

False-positive reports are triaged first. Include the IP, why it is legitimate, and observable evidence.

## License

Code: MIT. Aggregated feed data is provided as-is with no warranty. Upstream source licences apply and are recorded per-source in `sources.yaml` and in every `feeds/manifest.json`. Feeds derived from Spamhaus DROP carry Spamhaus attribution as required.

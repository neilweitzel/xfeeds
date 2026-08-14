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

**Nine independent voting classes**, each a distinct sensor network, reporter community, or research team. AbuseIPDB and ThreatFox are keyed sources: both are enabled in `sources.yaml`, and both skip cleanly when their key is absent from the environment, so a fresh clone with no secrets still produces a correct feed and simply gains accuracy once the keys are set. `ABUSEIPDB_API_KEY` was added to repo secrets on 2026-08-14; AbuseIPDB remains `redistribute: false` per ADR-012, so it raises confidence without contributing rows to any published file.

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

Only classes we are licensed to republish count toward the threshold that admits a record. Sources we may consume but not republish (AbuseIPDB, GreenSnow, ThreatFox) can raise a record from medium to high, but can never bring one into the feed on their own, and their names are withheld from published records so the feed cannot disclose their membership. See ADR-035.

Measured against live data on 2026-08-11, of 54,241 unique candidate IPs:

| Distinct classes | IPs | Share | Band |
|---|---|---|---|
| 1 | 42,034 | 77.5% | withheld |
| 2 | 10,294 | 19.0% | medium |
| 3+ | 1,913 | 3.5% | high |

Expected published high-confidence feed: **~2,000–4,000 entries** — the same order of magnitude as the original 2022 list. Discarding 77% of the input is the product working, not a bug.

---

## Using the feeds

Live at **https://neilweitzel.github.io/xfeeds/** — a dashboard with current
counts, history and per-source status, plus every artifact below.

Pages is the canonical URL rather than `raw.githubusercontent.com`, which caps
near 5,000 requests/hour/IP and blocks the IP for 30 minutes when exceeded.

| File | Use |
|---|---|
| `high-confidence.txt` | Safe-to-block. One IP or CIDR per line, `#` comments. |
| `medium-confidence.txt` | Challenge or rate-limit rather than a hard block. |
| `all.csv` | MISP CSV feeds, OpenCTI CSV mappers, Splunk lookups. |
| `all.json` + `schema.json` | Full provenance, with a published JSON Schema. |
| `stix-bundle.json` | STIX 2.1 — OpenCTI, Elastic, most TIPs. |
| `misp-manifest.json` | Native MISP feed. |
| `nftables.conf`, `iptables.ipset` | Enforcement-ready firewall formats. |
| `manifest.json` | Per-source status, licences, counts, deltas. |
| `history.json` | Rolling per-run history behind the charts. |

**ipset / iptables**

```bash
curl -sS https://neilweitzel.github.io/xfeeds/iptables.ipset | sudo ipset restore -!
sudo iptables -I INPUT -m set --match-set xfeeds src -j DROP
```

**nftables**

```bash
curl -sSO https://neilweitzel.github.io/xfeeds/nftables.conf
sudo nft -f nftables.conf
```

**Anything else** — pfSense and OPNsense URL tables, MikroTik address lists,
Cloudflare lists, nginx `deny` maps: point them at `high-confidence.txt`.

Pull every 6 hours or less often. The feed is rebuilt on a 6-hour cadence, so
polling faster only wastes both our bandwidth.

### Why an address is or is not listed

```bash
uv run xfeeds explain 45.33.32.156
```

Prints the sources that reported it, their independence classes and weights, the
score, and — if it was excluded — which specific rule excluded it. This is the
tool for triaging a false-positive report.

## Safety rails (non-negotiable)

- **Allowlist last.** Applied after every other stage, from live upstreams: Cloudflare, Google Cloud, Googlebot, Bingbot, GitHub, plus static RFC1918/bogons and public resolvers. A failed allowlist fetch is a hard failure, not a warning.
- **CIDR width cap.** Reject prefixes wider than /22 (IPv4) or /48 (IPv6) unless from Spamhaus DROP.
- **Churn guard.** A run that would add or remove more than 25% of the feed fails, opens an issue, and leaves the previous feed in place.
- **Redistribution flags enforced in code.** Sources marked `redistribute: false` inform scoring and never reach an emitter.
- **Provenance always.** No IP ships without a named source in `all.json`.
- **Staleness detection.** A source whose last-updated header exceeds 30 days raises a warning, so a dead upstream is never mistaken for a quiet internet.

## What the dashboard shows

**The IPv4 space as one strip.** 512 slices of 8.4 million addresses, log-scaled, lowest address on the left. It answers something the feed files cannot: how much of the internet we see activity in at all. Currently 402 of 512 slices. Multicast and reserved space is shaded so an empty tail is not mistaken for a broken chart.

**There is no map, deliberately.** The country in an IP-to-ASN table is where the AS *number is registered* — for a hosting company that is where its paperwork lives, not where traffic came from. A chart headed "listed addresses by country" would put 19,000 addresses on Romania because M247 is registered there, and be the most confidently wrong thing on the page. Address space is the coordinate system this data actually has.

**Networks ranked by persistence, not volume.** Sorted by how many distinct days a network appeared, because individual addresses churn out within about a week: a big one-day number is an incident, a network seen on nine separate days is a pattern. Every row divides by the address space the ASN announces, which is what separates a disproportionately hostile small network from a merely enormous one — DigitalOcean at 716 address-days per million announced against ChinaNet at 18.

**30- and 60-day windows are real, not padded.** bruteforceblocker publishes about a month of dated history and ipthreat about ten days; both are preserved in `source_last_reported` and drive `feeds/asn-history.json`. Those dates deliberately do **not** touch `last_seen`, so upstream history cannot silently restate confidence scores. Windows shorter than the history available say so on the page.

Statistics are computed over **every** source, including those whose licences forbid republishing their addresses — a count is a derived fact, not an extract, so this is where GreenSnow and ThreatFox appear by name against a number. Two rules keep it that way, both enforced by tests: no individual address is ever emitted, and cells below 5 addresses fold into an unnamed bucket.

ASN data from [iptoasn.com](https://iptoasn.com/) (Public Domain, PDDL v1.0). No geography is published anywhere, including as a table column: the country in an IP-to-ASN table is a registration detail, not a location.

## Two tiers

Most public IP feeds that forbid something forbid *commercial use*, not redistribution. Those are two different restrictions, and treating them the same was costing real coverage.

| | Primary — `feeds/` | Non-commercial — `feeds/noncommercial/` |
|---|---|---|
| Licence | Source terms only; no commercial restriction | CC BY-NC-SA 4.0 |
| Use at work, or in a paid product | Yes | **No** |
| Published addresses (last run) | 4,204 | **5,281** |
| Extra sources published in full | — | Turris Sentinel, StopForumSpam |

If you are running a home lab, a personal server, a school or a charity, take the non-commercial tier: it sees about a quarter more. If you are at a company or building anything anyone pays for, take the primary feed. The distinction is real, not a formality — `feeds/noncommercial/LICENSE.txt` states it plainly and every file in that directory leads with a banner.

The tier is built by a second scoring pass rather than by filtering the first, because which sources are publishable changes what counts as corroboration, which changes the confidence bands.

One rule in that second pass is not obvious: **CC BY-SA and CC BY-NC-SA cannot be combined in one file.** ShareAlike forbids applying additional terms to an adaptation, and NonCommercial is an additional term. So ipthreat.net data, which carries ShareAlike but not NonCommercial, is excluded from the non-commercial tier by `noncommercial_sources()`, with a test that asserts it never leaks in. See ADR-041.

## Where the data comes from

Every published file names its contributing sources and carries their terms in the header. Licence conclusions in `sources.yaml` quote the upstream text verbatim rather than paraphrasing it — a paraphrase is how we came to spend a week not republishing a feed that was always fine to republish, and to keep republishing two that were not (ADR-039, ADR-040).

Threat data provided by [IPThreat at https://ipthreat.net](https://ipthreat.net). Spamhaus DROP data is © The Spamhaus Project SLU and its attribution travels with the data as their terms require. The [Turris Sentinel](https://view.sentinel.turris.cz/) greylist is CC BY-NC-SA 4.0 and appears only in the non-commercial tier.

### How long an address stays listed

**Only while a source still reports it.** An address leaves the feed on the next run after its last source delists it — there is no independent retention window, and nothing is held for 30, 60 or 90 days.

This is deliberate. Around 86% of blocklisted addresses are short-lived offenders averaging about a week of activity, and dynamically allocated addresses are typically delisted upstream within three days ([AsiaCCS 2019](https://internetmaliciousactivity.github.io/submission/asiaccs2019_accepted_paper.pdf), [IMC 2020](https://www.isi.edu/people-mirkovic/wp-content/uploads/sites/52/2023/10/imc2020.pdf)). Holding entries longer mostly accumulates addresses that have since been reassigned to somebody innocent: reused addresses have been measured sitting in public blocklists for up to 44 days, affecting as many as 78 legitimate users. If you are going to drop traffic on this feed without reviewing it, that is the failure mode that matters.

What we do keep is history. `first_seen` survives delisting and re-listing, so a repeat offender is visible as one, and `ttl_days` lets a source's vote decay gracefully rather than vanish if that source misses a fetch (ADR-037).

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

**Phase 2a — aggregation MVP** ✅ shipped
- [x] Source registry, collectors and parsers for every voting class
- [x] Live allowlist fetching, CIDR caps, `redistribute` enforcement
- [x] Independence-weighted scoring, recency decay, ageing with persisted state
- [x] All output formats, manifest, rolling history
- [x] Churn guard, run report, `xfeeds explain`
- [x] 6-hour scheduled refresh, self-committing, Pages dashboard
- [x] 52 tests, no network access in the suite

**Phase 2b — enrichment**
- [x] AbuseIPDB and ThreatFox collectors (quota-aware; keys configured)
- [ ] ASN and country annotation
- [ ] GreyNoise RIOT suppression on sampled top candidates

**Phase 2c — enforcement integrations**
- [ ] Reference `fail2ban` action and Cloudflare IP Access Rules sync
- [ ] False-positive PR workflow against `allowlist.txt`
- [ ] Source health monitor with automatic issue filing

**Phase 3 — original telemetry**
- [ ] Honeypot collectors feeding xfeeds a first-party independence class,
      restoring the original-research character of the 2022 dataset without a
      commercial WAF.

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

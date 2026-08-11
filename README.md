# xfeeds

**A self-updating, open threat intelligence feed.**

xfeeds publishes curated lists of known-bad IP addresses that anyone can pull into a firewall, WAF, reverse proxy, or SIEM. The repository itself is the distribution mechanism: feeds are plain text files in `feeds/`, regenerated on a schedule by GitHub Actions and served for free over `raw.githubusercontent.com`.

---

## Background

xfeeds started as a one-time publication. During a ThreatX SOC "do good" day, ~5 million WAF match events were analyzed to profile the sources of nefarious HTTP traffic. The resulting IPs were validated against GreyNoise to strip benign scanner noise — GreyNoise had previously seen 71 of them and had already tagged 33 as malicious, leaving 2,901 previously-unpublished bad actors. That original snapshot lives on as `legacy/IP_List` (2,973 entries, April 2022).

That dataset is now stale and there is no longer a private WAF telemetry source behind it. **Phase 2 replaces the one-time human curation with an automated aggregation pipeline built on public, free-to-use intelligence sources.**

---

## Phase 2 goals

1. **Automate.** No manual steps. A scheduled workflow ingests upstream sources, normalizes, scores, filters, and commits refreshed feeds.
2. **Aggregate, don't duplicate.** Value comes from cross-source corroboration and scoring, not from republishing a single upstream list.
3. **Be conservative.** A published block list must be safe to drop traffic on. False positives are the primary risk.
4. **Be transparent.** Every published IP is traceable to the sources and scores that put it there.
5. **Cost nothing to run.** Free API tiers and GitHub-hosted runners only.

---

## Architecture

```
 upstream sources ──► collectors ──► normalizer ──► scorer ──► filters ──► emitters ──► feeds/
   (HTTP fetch)        (per-source     (dedupe,      (weighted   (allowlist,   (txt, csv,
                        parsers)        CIDR expand,  confidence, aging,        json, MISP,
                                        validate)     provenance) sanity caps)  nftables)
```

**Pipeline stages**

| Stage | Responsibility |
|---|---|
| Collect | Fetch each source over HTTPS with retry/backoff, ETag/If-Modified-Since caching, and per-source timeout. A failing source degrades the run; it never fails it. |
| Normalize | Parse into a common record: `ip`, `cidr`, `source`, `first_seen`, `last_seen`, `categories[]`, `raw_confidence`. Validate as public IPv4/IPv6. |
| Enrich | Optional GreyNoise RIOT/classification lookups and ASN/country annotation for a small sample of candidates (rate-limit bound). |
| Score | Weighted confidence per IP: source count, source weight, recency, category severity. |
| Filter | Drop allowlisted, reserved/bogon, and known-good infrastructure ranges. Enforce max-CIDR-size and max-feed-size caps. |
| Emit | Write feed artifacts, `feeds/manifest.json`, and a run report. |
| Publish | Commit changed files back to `main` with a deterministic message; open an issue on anomalies. |

---

## Sources

All Tier 1 sources are free, unauthenticated, and directly downloadable.

### Tier 1 — no key required

| Source | URL | Type | Cadence |
|---|---|---|---|
| Spamhaus DROP (v4/v6/ASN) | `https://www.spamhaus.org/drop/drop_v4.json` | Hijacked/criminal netblocks ([Spamhaus](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)) | 2h |
| abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Active botnet C2 | 30m |
| abuse.ch SSLBL | `https://sslbl.abuse.ch/blacklist/sslipblacklist.txt` | Malicious TLS infrastructure | 30m |
| Blocklist.de | `https://lists.blocklist.de/lists/all.txt` | Fail2ban-reported attackers ([blocklist.de](https://blocklist.de/)) | 30m |
| CINS Army | `https://cinsscore.com/list/ci-badguys.txt` | Scored attacker IPs | 6h |
| Emerging Threats compromised | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | Compromised hosts | daily |
| DShield recommended block | `https://feeds.dshield.org/block.txt` | /24 attack sources | daily |
| IPsum (levels 3–8) | `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt` | Cross-list aggregate, level = corroboration count | daily |
| FireHOL level 1 | `https://iplists.firehol.org/files/firehol_level1.netset` | Low-FP composite | daily |
| Tor exit nodes | `https://check.torproject.org/torbulkexitlist` | Annotation only — **never** auto-blocked | hourly |

### Tier 2 — free API key required (repo secrets)

| Source | Endpoint | Free-tier limit | Use |
|---|---|---|---|
| AbuseIPDB blacklist | `GET https://api.abuseipdb.com/api/v2/blacklist` | 10,000 IPs/pull, **5 blacklist calls/day** ([AbuseIPDB docs](https://docs.abuseipdb.com/)) | Primary reputation input |
| GreyNoise Community | `GET https://api.greynoise.io/v3/community/{ip}` | ~50 lookups/week on the free community tier ([GreyNoise](https://docs.greynoise.io/docs/using-the-greynoise-community-api)) | Noise/RIOT suppression on a sampled subset only |
| abuse.ch ThreatFox | `POST https://threatfox-api.abuse.ch/api/v1/` | Auth token, generous | C2 IOC enrichment |
| AlienVault OTX | OTX DirectConnect API | Free account | Context/pulse enrichment |

> **Rate-limit note:** the AbuseIPDB blacklist endpoint allows only 5 calls/day on a free account, so the scheduled pull runs at most every 6 hours and the response is cached in the repo. GreyNoise's weekly quota is far too small for per-IP validation of the whole candidate set; it is used only to spot-check the highest-scoring new entries and to suppress RIOT-listed benign infrastructure.

Every source must be declared in `sources.yaml` with `name`, `url`, `parser`, `weight`, `categories`, `license`, `ttl_days`, and `enabled`. Adding a source means adding a YAML entry and (if needed) a parser — no pipeline changes.

---

## Scoring model

For each IP, confidence is computed as:

```
score = Σ (source_weight × recency_factor × category_severity)
recency_factor = max(0.2, 1 - days_since_last_seen / ttl_days)
```

Normalized to 0–100. Suggested tiers:

- **90+** — corroborated by multiple independent high-weight sources, recent. → `feeds/high-confidence.txt`
- **60–89** — solid signal, suitable for challenge/rate-limit rather than hard block. → `feeds/medium-confidence.txt`
- **<60** — retained internally for corroboration, not published as a block feed.

Aging: an IP with no observation from any source for `ttl_days` (default 14, configurable per source) decays out and is removed. Removals are logged, never silent.

---

## Published feeds

| File | Contents |
|---|---|
| `feeds/high-confidence.txt` | One IP/CIDR per line, `#` comments. Safe-to-block tier. |
| `feeds/medium-confidence.txt` | Lower-confidence tier. |
| `feeds/all.csv` | `ip,score,sources,categories,first_seen,last_seen` |
| `feeds/all.json` | Full records including per-source provenance. |
| `feeds/misp.json` | MISP-compatible feed manifest. |
| `feeds/nftables.conf`, `feeds/iptables.ipset`, `feeds/cloudflare.txt` | Enforcement-ready formats. |
| `feeds/manifest.json` | Generated-at timestamp, per-source status, counts, added/removed deltas. |
| `feeds/CHANGELOG.md` | Human-readable per-run diff summary. |

Consumers pull directly:

```bash
curl -sS https://raw.githubusercontent.com/neilweitzel/xfeeds/main/feeds/high-confidence.txt \
  | grep -v '^#' | sudo ipset restore -! -
```

---

## Safety rails (non-negotiable)

- **Allowlist first.** `allowlist.txt` is applied after every stage. Seeded with RFC1918/bogons, root and public DNS resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9), major CDN/cloud health-check ranges, search-engine crawlers, and Cloudflare/Fastly/Akamai edge ranges pulled from their published JSON.
- **CIDR sanity cap.** Reject any prefix broader than /22 for IPv4 (/48 IPv6) unless it comes from Spamhaus DROP and is explicitly whitelisted as an allowed wide block.
- **Churn guard.** If a run would add or remove more than 25% of the current feed, the workflow fails, opens an issue, and leaves the previous feed in place.
- **Tor is annotated, not blocked.** Exit nodes are tagged in the CSV/JSON outputs only.
- **Provenance always.** No IP is published without at least one named source recorded in `all.json`.
- **License compliance.** Each source's terms are recorded in `sources.yaml`; sources restricted to non-commercial use are flagged in the manifest so downstream users can filter them out.

---

## Repository layout (target)

```
xfeeds/
├── README.md
├── sources.yaml              # source registry — the single place feeds are configured
├── allowlist.txt
├── src/xfeeds/
│   ├── cli.py                # `xfeeds run`, `xfeeds validate`, `xfeeds diff`
│   ├── collectors/           # one module per source type (plaintext, json, csv, api)
│   ├── normalize.py
│   ├── enrich.py             # GreyNoise / OTX / ASN annotation
│   ├── score.py
│   ├── filters.py
│   ├── emit/                 # txt, csv, json, misp, nftables, ipset, cloudflare
│   └── report.py
├── tests/                    # fixtures per source; no network calls in unit tests
├── feeds/                    # generated output — committed
├── legacy/IP_List            # original 2022 ThreatX SOC snapshot, frozen
└── .github/workflows/
    ├── update-feeds.yml      # cron */6h + workflow_dispatch
    └── ci.yml                # lint, type-check, tests on PR
```

---

## Automation

`update-feeds.yml`:

- Triggers: `schedule` (every 6 hours, offset off the hour) and `workflow_dispatch`.
- Steps: checkout → setup Python 3.12 → restore HTTP cache → `xfeeds run` → validate → `git diff --exit-code` guard → commit `chore(feeds): refresh YYYY-MM-DDTHH:MMZ (+N/-M)` → push.
- Secrets: `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY`, `THREATFOX_AUTH_KEY`. All optional — the pipeline runs Tier 1-only if a key is absent.
- Concurrency group so overlapping runs cancel.
- On failure or churn-guard trip: open/update a GitHub issue with the run report.

---

## Tech choices

- **Python 3.12**, `httpx` (async, HTTP/2), `pydantic` for record validation, `netaddr`/`ipaddress` for CIDR math, `ruff` + `mypy`, `pytest`.
- No database. State lives in `feeds/all.json` and is read back each run to compute `first_seen` and aging.
- Deterministic output ordering (sorted by IP as integer) so diffs are meaningful.

---

## Roadmap

**Phase 2a — aggregation MVP**
- [ ] `sources.yaml` registry + Tier 1 collectors
- [ ] Normalizer, allowlist, CIDR sanity caps
- [ ] Scoring + aging with persisted state
- [ ] `feeds/high-confidence.txt`, `all.csv`, `all.json`, `manifest.json`
- [ ] `update-feeds.yml` on a 6-hour cron with churn guard
- [ ] Unit tests with recorded fixtures; CI on PR

**Phase 2b — enrichment & formats**
- [ ] AbuseIPDB blacklist collector with daily-quota-aware caching
- [ ] GreyNoise RIOT/noise suppression on sampled top candidates
- [ ] ThreatFox + OTX category enrichment; ASN/country annotation
- [ ] nftables, ipset, Cloudflare, and MISP emitters
- [ ] `feeds/CHANGELOG.md` generation

**Phase 2c — enforcement integrations**
- [ ] Reference `fail2ban` action and Cloudflare IP Access Rules sync script
- [ ] Optional nginx/HAProxy deny-map output
- [ ] Feedback loop: consumers can open a PR against `allowlist.txt` with justification
- [ ] Public status page / badge from `manifest.json`

**Phase 3 — original telemetry**
- [ ] Lightweight honeypot collectors (SSH/HTTP tarpit) feeding xfeeds with first-party observations, restoring the original-research character of the 2022 dataset without a commercial WAF.

---

## Non-goals

- Not a replacement for a commercial threat intel platform.
- No domain, URL, or hash indicators in Phase 2 — IPs only.
- No paid data sources.
- No redistribution of any feed whose license forbids it.

---

## Contributing

Open an issue to propose a source (include URL, format, update cadence, and license) or to report a false positive (include the IP, why it is legitimate, and observable evidence). False-positive reports are triaged first.

## License

Code: MIT. Aggregated feed data is provided as-is with no warranty; upstream source licenses apply and are recorded in `sources.yaml`.

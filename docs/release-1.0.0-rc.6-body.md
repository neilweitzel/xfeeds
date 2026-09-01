## xfeeds v1.0.0-rc.6

Sixth release candidate, cut by the 1 September source review (#52). **No published output changes.** The review admitted no source; what restarted the burn-in clock is a latent defect it found in the freshness machinery while re-checking the dormant sources.

If you are consuming feeds, there is nothing to do. Feed paths, record schema, and existing manifest fields are unchanged from `rc.5`, and `rc.4`'s ADR-054 carry-forward fix remains the last change that altered published output. The manifest gains three fields and `feeds/` gains one file; both are additive.

### The defect

`docs/source-lifecycle.md` has specified a three-step priority order for determining how old a source's evidence is since 2026-08-18:

1. the feed's own timestamp in the payload
2. the HTTP `Last-Modified` header
3. a content-hash change

Only step 2 was ever implemented. ADR-052 flagged the rest as a follow-up in its Consequences section, but the item never made it into the open-items list, so it went quiet.

abuse.ch is why the order has step 1 first. It serves a `Last-Modified` that moves independently of its payload:

| Endpoint | HTTP `Last-Modified` | Payload `Last updated` | Real age |
|---|---|---|---|
| Feodo `ipblocklist.txt` | `Tue, 30 Jun 2026 04:53:05 GMT` | `2026-03-04 14:28:39 UTC` | 180 days |
| SSLBL `sslipblacklist.txt` | `Tue, 30 Jun 2026 04:53:19 GMT` | `2025-01-02 01:09:06 UTC` | 607 days |

Two feeds frozen fourteen months apart, reporting transport timestamps fourteen seconds apart. The manifest was recording Feodo's evidence as 63 days old when the tracker itself said 180.

The larger half of the same defect was quieter: the whole staleness check sat inside `if last_modified:`, so a source sending no such header was not freshness-checked **at all**. Three live sources send none — `abuseipdb_blacklist`, `ipsum_levels`, and `threatfox` — and had no freshness gate of any kind.

### The fix

All three priorities are now implemented in `src/xfeeds/freshness.py` (ADR-056). Nine payload formats are supported, every one taken from a real recorded response rather than invented: abuse.ch's header, DShield's ISO stamp, the HTTP-date that Spamhaus and bruteforceblocker repeat inside a comment, Dataplane's reporting window, FireHOL's file date, AbuseIPDB's `meta.generatedAt`, and Spamhaus DROP's trailing JSON metadata record.

Two guards, both prompted by things seen while measuring rather than anticipated:

- **The scan stops at the first data line.** Several feeds carry per-row dates — bruteforceblocker puts one on every row — and a whole-file sweep would report an arbitrary row's date as the feed's publication date.
- **A timestamp more than a day ahead of the run is discarded** in favour of the next priority. Not zero tolerance: observations are truncated to midnight UTC, and Spamhaus's JSON metadata timestamp runs about half an hour ahead of the `Last-Modified` on its sibling text feed. A full day ahead is a broken clock, not evidence.

Staleness is also now decided once per source using the newest evidence across all of its URLs. Previously the last URL fetched silently overwrote the verdict of the earlier ones, which was arbitrary for `ipsum_levels` and its six files.

### Verified against a live run

All 22 reachable sources, 2026-09-01:

- `feodo_tracker` → basis `payload`, age **180 days**, against the 63 the header claimed. Its 5 records are marked stale evidence.
- Nine sources moved from the header to their own declared timestamp: bruteforceblocker, six Dataplane feeds, DShield, and both Spamhaus DROP families.
- `ipsum_levels` → basis `content-hash`, where it was previously ungated.
- No source was newly marked stale, and no new warnings were raised.

**This fix is protective, not corrective.** Feodo was already dormant and therefore already non-admitting, and both the old and new ages exceed its 7-day threshold, so today's feed is byte-for-byte what it would have been. What changes is that a future source whose CDN refreshes `Last-Modified` faster than its own TTL can no longer vote at full strength over frozen evidence.

### New artifacts

- `feeds/manifest.json` gains `evidence_time`, `evidence_age_days`, and `evidence_basis` per source, so which mechanism decided a staleness verdict is visible in the output. `last_modified` keeps its existing meaning as the raw transport signal and is reported alongside rather than instead — the two being conflated is what hid this in the first place.
- `feeds/source-freshness.json` records when each source's body last changed. It is **committed** rather than cached, which is deliberate: a cold `actions/cache` would reset every source's change history to "changed just now", making a permanently frozen upstream look permanently fresh. That is the exact failure the content-hash step exists to catch, so its state cannot live somewhere that silently resets.

### The source review itself

Twelve further candidates surveyed, none admitted. Full report in #52. Two worth naming:

**sefinek stays disabled, now on measurement rather than a README (ADR-057).** The standing open item asked for a churn measurement across several runs. The list is published from a git repository, so its whole history was read directly instead — 140 upstream commits between 2026-08-01 and 2026-09-01, sampled daily. IPv4 grew 209,443 → 215,654 and IPv6 5,085 → 5,490, with **zero removals** on any sample. "Generally not removed" turns out to mean a removal rate of exactly zero.

It is rejected under the all-time-list rule despite having the cleanest licence of any candidate (MIT), the best independence measured anywhere (max Jaccard 0.0035 against a 0.5 threshold), and 5,490 host-level IPv6 addresses — which would have been the only thing found in two cycles capable of closing the long-standing IPv6 gap. A source that never retracts means our TTL can never age out anything it asserts, and IPv6 makes that worse rather than better because SLAAC privacy addresses rotate faster than IPv4 ones.

**HoneyDB is not usable.** Evaluated with a live Community API key. The data is real and would have passed independence, and a distributed honeypot network would have been a genuinely new class. But the Community tier reads "internal, non-commercial use only — no redistribution or embedding in products or services", with redistribution reserved to a paid Commercial/OEM licence. A public feed is what that forbids. It also would not have helped: zero IPv6, and its `last_seen` was already five days behind.

Two coverage gaps are recorded and left open: `botnet-c2` currently has no admitting source at all, and IPv6 still has exactly one independence class.

### Burn-in

`rc.6` is under a roughly one-month window closing **on or after 2026-10-01**. The next scheduled source review falls on that same date.

The clock restarted because the change touches `src/` and `sources.yaml`, not because output moved — the rule keys off the paths a commit touched, precisely so nobody has to make that judgement under release pressure.

### Not archived

No DOI is minted for a release candidate. `CITATION.cff` carries only the concept DOI, which is version-agnostic, and its `version` tracks `pyproject.toml` exactly per ADR-055. Pipeline version and archive version converge at `v1.0.0`.

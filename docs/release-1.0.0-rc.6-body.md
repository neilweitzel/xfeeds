## xfeeds v1.0.0-rc.6

Sixth release candidate, cut by the 1 September source review (#52). **No published output changes.** The review admitted no source. What restarted the burn-in clock is what it found while re-checking the dormant sources: a freshness gate that could not see a frozen payload (ADR-056), a manifest that overstated how many independent classes actually stand behind the feed (ADR-058), and a staleness model with no end to it (ADR-059).

If you are consuming feeds, there is nothing to do. Feed paths, record schema, and every existing manifest field are unchanged from `rc.5`, and `rc.4`'s ADR-054 carry-forward fix remains the last change that altered published output. The manifest gains seven fields and `feeds/` gains one file; all additive.

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

### Staleness now ends

Stale used to be terminal. A source could sit in it indefinitely — still fetched four times a day, still voting at a damped weight on evidence nobody had vouched for in months, still allowed to upgrade records. Feodo Tracker sat there for 180 days.

There is now a ceiling. Past 90 days a source is **Expired** and contributes nothing: records dropped before scoring, and excluded from carry-forward too. That second half matters more than it looks — `carried_observations` reads sightings out of state rather than out of the fetch, so dropping an expired source at collection alone would have achieved nothing and it would have kept voting from state for a further `ttl_days`.

Ninety days is set against `docs/staleness-analysis.md`: at least twice the longest window in which a blocklisted address is still describing the present.

**Re-admission requires a review.** An expired source does not resurrect itself when upstream publishes again — the fresh data is the prompt to review, not the review. The expiry date is latched in `feeds/source-freshness.json`, and the source stays out until `sources.yaml` carries a `reviewed_on` date on or after it:

```yaml
- name: some_source
  reviewed_on: 2026-10-14
```

A review dated before the expiry does nothing, so one written in June cannot retroactively authorise an expiry in August. Clearing the latch does not vouch for the data either — normal freshness rules apply, so a source readmitted with 45-day-old evidence lands in Stale, not Active.

`dormant: true` now means the same thing: manual expiry. Half-counting evidence from a threat we had already declared dead was a distinction without a purpose. `reviewed_on` deliberately cannot clear it — a maintainer's statement is only undone by a maintainer.

Expired sources are **still fetched**, on purpose. The fetch stops being a scoring input and becomes a review trigger: `evidence_age_days` falling in the manifest is what tells you the upstream is alive again.

Lifecycle states go from five to four, all driven by one number.

Surfaces updated to match: the source health table shows `expired` in its own colour and reads **not contributing** under Publication — it previously read the licence flag alone, so Feodo Tracker being CC0 printed "yes" next to a source supplying zero records. The README carries the three-state table, and ADR-052/053 now open with supersession notes so nobody follows the old dormant behaviour.

#### Feodo Tracker, measured before it was dropped

All 5 of its addresses were **already withheld**, and none appeared in the published feed. Dropping the source moved neither the high nor the medium count. Every mechanism built around it — the damped vote, the upgrade path, the suppressed warning — had been doing no work for months. The only thing keeping it alive was that nothing had a clock on it.

### The manifest was overstating the corroboration base

Found while writing up the coverage gaps, and fixed here rather than deferred (ADR-058).

`active_voting_classes` was being read as a measure of corroboration capacity. It is not one. ADR-053 made a class count toward *admission* only when it is both redistributable and vouched for today — enforced in `score.py`, reported nowhere.

The numbers are worse than the `botnet-c2` case that prompted the look:

| | Count |
|---|---|
| Voting classes | **13** |
| Admitting classes | **6** |
| Voting-only | 7 — `abusech`, `abuseipdb`, `dataplane`, `dshield`, `greensnow`, `stopforumspam`, `turris` |

Four categories have no admitting class at all — `botnet-c2`, `abuse`, `spam-source`, `telnet-attack`. Every one of those restrictions was already documented per-source in `sources.yaml`; the aggregate was visible nowhere, and the dashboard homepage was rendering "13 independent evidence classes" to anyone who visited.

The manifest now carries `active_admitting_classes`, `voting_only_classes`, `category_coverage`, and per-source `admits` / `admitting_blocked_by`. `active_voting_classes` keeps its exact previous meaning and value — it is a published contract — and is simply no longer the only thing said. The homepage now quotes the admitting count.

No scoring change and no output change: `score.py` already had all of this right.

To be precise about what a zero means: it does not mean nothing in that category is published. An address can still reach the feed on two other admitting classes that also saw it. It means no address is admitted on that category's evidence alone.

### The source review itself

Twelve further candidates surveyed, none admitted. Full report in #52. Two worth naming:

**sefinek stays disabled, now on measurement rather than a README (ADR-057).** The standing open item asked for a churn measurement across several runs. The list is published from a git repository, so its whole history was read directly instead — 140 upstream commits between 2026-08-01 and 2026-09-01, sampled daily. IPv4 grew 209,443 → 215,654 and IPv6 5,085 → 5,490, with **zero removals** on any sample. "Generally not removed" turns out to mean a removal rate of exactly zero.

It is rejected under the all-time-list rule despite having the cleanest licence of any candidate (MIT), the best independence measured anywhere (max Jaccard 0.0035 against a 0.5 threshold), and 5,490 host-level IPv6 addresses — which would have been the only thing found in two cycles capable of closing the long-standing IPv6 gap. A source that never retracts means our TTL can never age out anything it asserts, and IPv6 makes that worse rather than better because SLAAC privacy addresses rotate faster than IPv4 ones.

**HoneyDB is not usable.** Evaluated with a live Community API key. The data is real and would have passed independence, and a distributed honeypot network would have been a genuinely new class. But the Community tier reads "internal, non-commercial use only — no redistribution or embedding in products or services", with redistribution reserved to a paid Commercial/OEM licence. A public feed is what that forbids. It also would not have helped: zero IPv6, and its `last_seen` was already five days behind.

Two coverage gaps remain open, and both are now machine-visible in `category_coverage` rather than living in an issue comment.

**`botnet-c2` is corroboration-only** — ThreatFox watches it and votes; nothing can publish on C2 evidence alone. Searched properly this cycle, and the free ecosystem has no fix: ET's `emerging-botcc.rules` is a BSD-licensed wrapper around abuse.ch and carries the identical five dead addresses as Feodo; Viriback states no licence anywhere and accumulates back to 2019; TweetFeed is genuinely CC0 and C2-tagged but its sensor method is "somebody tweeted it" across 67 unlinked reporters; criminalip publishes a deliberate 50-address daily sample under a bespoke licence. The free C2 ecosystem consolidated into abuse.ch, which then moved C2 behind restrictive terms. ThreatFox is the only live, high-quality option and licence is the single thing blocking it.

**IPv6 still has exactly one independence class** after a second cycle. Worth knowing operationally: `spamhaus_drop_v6` publishes its 92 records by solo-promotion, which a stale source cannot do, so if it ever crosses 30 days the IPv6 feeds empty out. Measured cadence over June–September is 9–12 days, worst observed gap 12 against a 30-day threshold — comfortable, but there is no second source to absorb it.

### Burn-in

`rc.6` is under a roughly one-month window closing **on or after 2026-10-01**. The next scheduled source review falls on that same date.

The clock restarted because the change touches `src/` and `sources.yaml`, not because output moved — the rule keys off the paths a commit touched, precisely so nobody has to make that judgement under release pressure.

### Not archived

No DOI is minted for a release candidate. `CITATION.cff` carries only the concept DOI, which is version-agnostic, and its `version` tracks `pyproject.toml` exactly per ADR-055. Pipeline version and archive version converge at `v1.0.0`.

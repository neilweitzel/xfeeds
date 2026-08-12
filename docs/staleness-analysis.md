# Staleness, TTL, and candidate corroboration sources

Working notes, 2026-08-12. Measured against the live feed and upstream sources,
not estimated.

## 1. What xfeeds does today

Publication is **purely source-driven**. `pipeline.py` scores only the records
returned by the current run; `merge_with_state` carries `first_seen` forward and
ages state entries out, but deliberately does *not* resurrect a record no source
reported this run:

> "Within its grace period. We keep the age accounting but do NOT resurrect the
> record into the feed: with no source reporting it this run there is no current
> evidence to publish."

Verified against `all.json`: **4,240 of 4,240 published records have
`last_seen` == today**. The effective retention window for publication is
therefore **zero days** — an address leaves the feed on the next run after its
last source stops listing it.

`ttl_days` currently controls only two things:

1. `recency_factor()` — score decay by age of the most recent sighting.
2. The state grace period (`max_ttl` = 30 days, set by Spamhaus) for `first_seen`
   accounting and churn reporting.

## 2. Defect found: score decay is inert

`recency_factor(last_seen, now, ttl_days) = max(0.2, 1 - age/ttl)`.

Because scoring only ever sees observations collected in the current run,
`age` is always 0 and the factor is always **1.00**. The decay curve is
computed, tested, and never applied in production.

| age of sighting | ttl=7 | ttl=10 | ttl=30 |
|---|---|---|---|
| 0d | 1.00 | 1.00 | 1.00 |
| 3d | 0.57 | 0.70 | 0.90 |
| 7d | 0.20 | 0.30 | 0.77 |
| 30d | 0.20 | 0.20 | 0.20 |

This is not currently causing wrong output, but it means the per-source
`ttl_days` values are close to decorative, and a single-source outage silently
demotes records instead of degrading them gracefully.

## 3. Why 90 days would be wrong

The published measurement literature is consistent and points the other way:

- 86.4% of blocklisted IPs are short-lived offenders, average presence about one
  week (*A Decade of Mal-Activity Reporting*, AsiaCCS 2019).
- Blocklisted addresses are removed within ~9 days on average; **dynamically
  allocated addresses within ~3 days** (*Quantifying the Impact of Blocklisting
  in the Age of Address Reuse*, IMC 2020).
- Reused addresses can sit in blocklists for up to **44 days** and affect as many
  as **78 legitimate users**. About 60% of blocklists contain at least one NATed
  address; 53% list at least one dynamic address.
- Over 50% of malicious IPs go dark within a week of first observation.

A 90-day window would hold addresses roughly 10× longer than the median offender
remains active, and squarely inside the range where ISP reassignment turns an
entry into a false positive against a residential customer. For a feed whose
stated audience is people who will drop traffic on it without a review step, that
is the wrong direction.

The one countervailing datapoint: the most recurrent offenders have a ~5.5 week
report cycle, so aggressive delisting does lose repeat infrastructure. That is an
argument for *remembering* history, not for *publishing* stale entries — which is
what `first_seen` retention already gives us.

## 4. Recommendation on TTL

Keep publication source-driven. Do not add an independent retention window.

Two changes worth making:

1. **Wire up the decay.** Allow a source's vote to persist for up to its
   `ttl_days` at `recency_factor` weight when that source missed a run, so a
   transient upstream outage degrades confidence smoothly instead of dropping a
   voting class outright. Bounded by TTL, so it cannot accumulate.
2. **Document the policy** in the README and dashboard: "an address is listed
   only while a source still reports it; we do not hold entries after they are
   delisted upstream." This is a genuine differentiator against feeds that
   accumulate.

Per-source TTLs stay short and stay differentiated: 7d for abuse.ch C2 (fast
infrastructure turnover), 10d for brute-force sensors, 30d for Spamhaus DROP
(hijacked netblocks are a slow, structural signal), 2d for Tor.

## 5. Candidate corroboration sources

The `redistribute: false` mechanism already implemented in `filters.py` means a
source can vote without its rows ever being emitted — publication requires at
least one *redistributable* source. That reopens sources previously excluded on
licence grounds, **for scoring only**.

### Turris Sentinel greylist — measured, high value

- CC BY-NC-SA 4.0 (`LICENSE.txt`), 9,719 addresses, CSV with attack-type tags.
- Independent vantage point: CZ.NIC consumer router sensor network, versus the
  US-centric server honeypots that dominate our current set.
- **Only 7.7% overlap with what we publish** (548 exact, 203 inside a published
  CIDR) — genuinely independent, not a reshuffle of the same data.
- **Would promote 477 of 1,837 medium-confidence records to high** — about a 20%
  increase in the high-confidence set — without redistributing a single Turris
  address.

### DShield / SANS recommended block list — low value

- CC BY-NC-SA 2.5, PGP-signed, but `block.txt` is only the top 20 /24 subnets.
  Real independence, negligible volume. Not worth a collector on its own.

### The licensing question this raises

NonCommercial is satisfied — we do not sell. ShareAlike attaches only when you
*Share* Adapted Material, and vote-only use shares nothing. Under CC 4.0 the
database provision makes a database Adapted Material when it includes "all or a
substantial portion of the database contents"; a numeric confidence adjustment
includes none of it.

The gray area is real and should not be papered over: **a vote can change
whether a record is published**, because 1 class = withheld but 2 classes =
medium. If a Turris vote lifts a record from withheld to medium, our decision to
publish that address was caused by their list, even though the address itself
came from a redistributable source.

Containment option, in decreasing order of caution:

- **(A) Band-upgrade only.** Count NC-SA classes only for records that already
  reach 2 redistributable classes — they can promote medium → high, never
  withheld → medium. Their data never determines membership, only stated
  confidence. Legally clean; captures the 477-record gain measured above, which
  is precisely the medium → high case.
- **(B) Full vote.** Also allow withheld → medium. Larger recall gain, but the
  publish decision becomes attributable to their list.
- **(C) Precision instrument only.** Use for disagreement detection and false
  positive hunting, never in scoring.

Option A is recommended: the measured benefit is almost entirely in the
medium → high band, so the cautious choice costs little.

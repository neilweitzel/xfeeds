# Turris greylist backfill — measurement, 2026-09-01

Measured against 30 real daily snapshots from the Turris archive
(`view.sentinel.turris.cz/greylist-data/archive/2026/`), 2026-08-02 to 2026-08-31,
and against the published feed of 2026-09-01. Not estimated.

Answers the ADR-050 open item: *"Backfill the Turris archive: 2,404 daily
snapshots exist back to 2020, and a 30-day union is 75,454 unique addresses
against 9,488 in one snapshot. Same licence, no new endpoint, but it interacts
with state and ageing so it needs its own measurement."*

## The headline is a trap

| | Addresses |
|---|---|
| Latest single snapshot | 10,041 |
| Naive 30-day union | **85,266** (8.5×) |

That 8.5× is what makes the backfill look like the biggest lever left. It is not,
because of how the union is composed:

| Appears on ≥ N of 30 days | Addresses | Share of union |
|---|---|---|
| 1 | 85,266 | 100% |
| 2 | 43,087 | 50.5% |
| 3 | 28,766 | 33.7% |
| 5 | 17,460 | 20.5% |
| 7 | 12,541 | 14.7% |
| 10 | 7,425 | 8.7% |
| 30 | 121 | 0.1% |

**49.5% of the union — 42,179 addresses — appears on exactly one day.** A naive
union treats a single sighting from four weeks ago as current corroboration,
which is the failure mode `docs/staleness-analysis.md` measured against: reused
addresses can sit in a blocklist up to 44 days and hit as many as 78 legitimate
users, and dynamically allocated addresses turn over in about three.

## What it would actually buy

Turris is `redistribute: false`, so it cannot admit an address — it can only
upgrade one that two open classes already published. A `medium` record has two
open classes and a total below three, so gaining one restricted class takes it to
`high`.

Published feed on 2026-09-01: 8,616 records (6,952 high, 1,664 medium). 595
medium records already carry a Turris class from today's snapshot.

| Backfill window | Turris addresses | Extra medium → high |
|---|---|---|
| today only (current behaviour) | 10,041 | — |
| seen ≥1 day in 30 (naive union) | 85,266 | **732** |
| seen ≥2 days | 43,087 | **693** |
| seen ≥3 days | 28,766 | 596 |
| seen ≥5 days | 17,460 | 456 |
| seen ≥7 days | 12,541 | 302 |
| seen ≥10 days | 7,425 | 184 |

**A ≥2-day filter captures 693 of the 732 upgrades — 95% of the entire benefit —
while discarding 42,179 single-day transients.** Going from ≥2 to ≥1 doubles the
address count to buy 39 more upgrades.

## Recommendation

**Do the backfill, with a "seen on at least two separate days" requirement. Do not
do a naive union.**

The filter is not a tuning parameter, it is the project's own idea applied inside
a source: an address that Turris saw once and never again is a single sighting,
and single sightings are what this feed exists not to publish. Requiring two
separate days is Turris corroborating itself over time, the same way we require
two classes corroborating each other.

### Why this is a low-risk change

- **The published count does not move.** Turris cannot admit, so 8,616 stays
  8,616. Only band composition shifts: high 6,952 → 7,645 (+10.0%), medium
  1,664 → 971.
- **Well inside the churn guard.** A 10% move against a 25% abort threshold.
- **No licence change.** Same CC BY-NC-SA source, same endpoint, still
  `redistribute: false`, still never republished.

### How to implement it — not by fetching the archive

The obvious implementation is wrong. Pulling 30 archive files on every run means
30 extra requests four times a day against a volunteer-run sensor network, for
data that changes once a day.

Keep a rolling per-source sighting window in state instead: record which
addresses Turris reported each day, retain 30 days, and re-cast an address that
met the two-day rule. One fetch per run, and the window builds itself. This is
adjacent to `carried_observations`, which already re-casts sightings from state —
but that is bounded by `ttl_days` and only fires when a source misses a run, so it
is a related mechanism rather than the same one.

That is a scoring change with real blast radius, and it needs its own tests
before it goes near a release.

### Sequencing

**After `v1.0.0`.** It touches `src/` and `sources.yaml`, so it restarts the RC
burn-in clock, and it is additive work with no deadline. The measurement is done
and recorded here so the implementation does not have to rediscover it.

## What was checked and is not a concern

- **Archive availability.** All 30 requested days were present; the archive runs
  back to 2020 with PGP signatures alongside each file.
- **Licence.** Unchanged — `LICENSE.txt` sits in the same directory and the terms
  are the CC BY-NC-SA already assessed in ADR-050.
- **Format.** Identical CSV shape (`Address,Tags`) across all 30 files, so the
  existing parser needs no change.

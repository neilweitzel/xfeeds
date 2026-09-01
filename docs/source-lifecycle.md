# Source lifecycle and discovery policy

Operating policy for how xfeeds sources enter monitoring, degrade when they go
stale, retire, and how new sources are discovered and admitted. This document
governs changes to `sources.yaml` and the scoring pipeline's treatment of
source freshness.

It supplements `docs/DECISIONS.md` (architecture decision records) and
`AGENTS.md` (coding-agent instructions). Where this document and an earlier
ADR conflict, the ADR is superseded — see the revision log at the bottom.

---

## Core invariant: fetch time is not evidence time

A successful HTTP fetch means the endpoint answered. It does **not** mean the
data is fresh. Feodo Tracker returns HTTP 200 with a `Last updated` header of
2026-03-04 — the transport is live, the evidence is 166 days old (180 as of
2026-09-01).

The transport can also lie about itself, which is a distinct problem from the
transport merely being live. On 2026-09-01 both Feodo Tracker and SSLBL served
`Last-Modified: Tue, 30 Jun 2026 04:53 GMT` over payloads declaring 2026-03-04
and 2025-01-02 — two feeds frozen fourteen months apart reporting transport
timestamps fourteen seconds apart. A source's own statement about when it
published outranks anything its CDN says on its behalf.

Published records must be supported by **fresh enough evidence**. The
source-declared update time — feed header, `Last-Modified`, content hash
change, or API timestamp — controls evidence freshness. Fetch time is
transport freshness only.

The scoring pipeline must treat a stale source's records as aged evidence,
not as current observations, regardless of whether the fetch succeeded.

---

## Source lifecycle states

Every source is in one of four states. Three of them are decided by a single
number — how old the source's own evidence is — so there is one question to ask
about a source and one place the answer comes from.

| State | Trigger | Votes? | Admits? | Promotes? |
|---|---|---|---|---|
| **Active** | evidence within `min(30, ttl_days)` | full weight | yes | yes |
| **Stale** | evidence older than that, up to the expiry ceiling | damped ×0.2 | no | no |
| **Expired** | evidence past the expiry ceiling, or `dormant: true` | **no** | no | no |
| **Retired** | `enabled: false` | not even fetched | — | — |

### 1. Active

Fetches successfully, evidence is current. Nothing special.

### 2. Stale

The source still answers, but its own declared update time is older than
`min(30 days, ttl_days)`.

- Manifest reports `status: "stale"` and the run report raises a warning.
- **Cannot admit and cannot promote** (ADR-053). It may strengthen a record that
  already stands on live corroboration; it can never be one of the two classes
  that publish one.
- **Votes at a damped weight**, `score.STALE_EVIDENCE_FACTOR` (0.2). The damping
  is explicit because `recency_factor` would not do it: that decays on when we
  last *saw* an address, which is today on every successful fetch, so a frozen
  upstream would otherwise vote at full strength forever.

Stale is now a **bounded** state. It used to be terminal, which is what ADR-059
fixed.

### 3. Expired

Evidence older than `EXPIRY_DAYS` (90), **or** the maintainer set `dormant: true`.

- **Contributes nothing.** Records are dropped before the scorer sees them. Not a
  damped vote, not a non-admitting vote — nothing.
- **Cannot be carried forward from state either.** This matters more than it
  looks: `carried_observations` re-casts recent sightings for sources that missed
  a run, reading them out of state rather than out of the fetch. Without an
  explicit exclusion, dropping an expired source at collection would achieve
  nothing — it would keep voting from state for a further `ttl_days`.
- **Still fetched, on purpose.** The fetch stops being a scoring input and becomes
  a review trigger: `evidence_age_days` falling in the manifest is what tells a
  maintainer the upstream is alive again and it is worth running the reactivation
  review.
- **Latched.** See below.

Ninety days is chosen against `docs/staleness-analysis.md`: 86% of blocklisted
addresses are short-lived offenders averaging about a week, reused addresses can
sit in blocklists up to 44 days before they start hitting somebody innocent, and
the most recurrent offenders cycle on about 5.5 weeks. At 90 days a source's
entire corpus is at least twice the longest of those windows. It is deliberately
far longer than any `ttl_days`: staleness already says "your data is old", and
expiry says "you have stopped being a source".

### Re-admission requires a review, and the latch enforces it

An expired source **does not come back on its own**. When upstream starts
publishing again, the fresh data is the prompt to review, not the review.

The pipeline records the expiry date in `feeds/source-freshness.json`. The source
stays expired until `sources.yaml` carries a `reviewed_on` date **on or after**
it. A review dated earlier does nothing, so a review written before an expiry
cannot retroactively authorise it.

```yaml
- name: some_source
  reviewed_on: 2026-10-14   # clears an expiry latched on or before this date
```

Clearing the latch does not vouch for the data — it only removes the block.
Normal freshness rules then apply, so a source readmitted while its evidence is
still 45 days old lands in Stale, not Active.

The reactivation review is the checklist that was always written down and never
enforced: licence and redistribution rights, attribution requirements, sensor
method and provenance, content shape, and independence class. Upstream terms and
methods change while a source is away — SSLBL and ThreatFox both diverged from
Feodo's CC0 — so none of it can be assumed. If the licence or method has changed,
cut a new ADR before setting `reviewed_on`.

Editing `reviewed_on` is a `sources.yaml` change, which restarts the RC burn-in
clock. That is deliberate: readmitting a source is a scoring change.

### `dormant` is manual expiry

`dormant: true` means a maintainer has concluded the tracked threat itself is
gone. It produces exactly the Expired state, and `reviewed_on` deliberately
**cannot** clear it — only removing the flag can. Otherwise a routine review date
would quietly resurrect a source somebody had killed on purpose.

Before ADR-059, dormant meant a damped, non-admitting vote. Half-counting
evidence from a threat we had already declared dead was a distinction without a
purpose, and it let Feodo Tracker sit in that state for 180 days.

### 4. Retired

`enabled: false`. The endpoint is dead, legally unusable, replaced by a paid
service, or the threat category is permanently gone. Not fetched at all. The
entry stays in `sources.yaml` with the reason, so a later discovery sweep does
not re-add it. Example: SSLBL, retired 2025-01-03 with a deprecation notice in
its own payload.

Use Retired over Expired when there is nothing left to watch for. Use `dormant`
when the endpoint still answers and might one day carry real data again.

---

## Freshness policy

### How evidence age is determined

Priority order for determining a source's evidence age:

1. **Feed-level timestamp in the payload** — e.g., Feodo's `Last updated`
   header line, AbuseIPDB's `meta.generatedAt`, Spamhaus DROP's trailing
   `{"type": "metadata"}` record.
2. **HTTP `Last-Modified` response header** — when the payload has no
   embedded timestamp.
3. **Content hash change** — when neither is available, a hash of the
   fetched body compared to the previous run. If the hash is unchanged,
   the evidence age is the time since the last observed change, not the
   fetch time.

All three are implemented in `src/xfeeds/freshness.py` as of ADR-056. Until
then only step 2 existed, which understated Feodo's evidence age by 118 days
and left the three sources that send no `Last-Modified` with no freshness
gate at all. The order is absolute: a payload timestamp wins even when the
HTTP header is newer, because that combination is the defect, not a tie.

Two constraints on step 1 worth knowing before adding a format:

- **Only the leading comment block is searched.** Several feeds carry
  per-row dates, and a whole-file sweep reports one arbitrary row's date as
  the feed's publication date.
- **A timestamp more than a day ahead of the run is discarded** and the next
  priority used. Observations are truncated to midnight UTC, so a feed
  published at midday is legitimately "ahead" of the run; a full day ahead is
  a broken clock.

The step-3 history lives in `feeds/source-freshness.json`, which is
**committed**, unlike `.cache/state.json`. A cache that goes cold would reset
every source's change history to "changed just now", making a permanently
frozen upstream look permanently fresh — the exact failure the step exists to
catch. In `feeds/` a reset is visible in a diff.

The manifest reports `evidence_time`, `evidence_age_days`, and
`evidence_basis` per source, so which mechanism decided is observable in the
published output. `last_modified` remains the raw transport signal and is
deliberately reported separately — the two being conflated is what hid the
original defect.

### Freshness threshold

A source is stale when its evidence age exceeds:

```
min(30 days, source.ttl_days)
```

The 30-day ceiling is absolute — no source is considered fresh after 30
days regardless of its TTL. Source TTLs are already differentiated in
`sources.yaml` (7d for abuse.ch C2, 10d for brute-force sensors, 30d for
Spamhaus DROP), and the shorter of the two governs.

### What staleness changes in scoring

| Behavior | Active | Stale | Expired |
|---|---|---|---|
| Vote in scoring | full weight | damped ×0.2 | **none — records dropped** |
| Counts toward admission | yes | no | no |
| Upgrades an already-admitted record | yes | yes | no |
| Solo-promotion | if otherwise qualified | no | no |
| Carried forward from state | yes | yes | **no** |
| Still fetched | yes | yes | yes, as a review trigger |
| Returns automatically | — | yes, when upstream publishes | **no — needs `reviewed_on`** |

The promotion gate is the ADR-052 change and the carry-forward exclusion is the
ADR-059 one. Both close the same shape of hole: a source that has stopped
publishing but keeps answering HTTP 200 must not keep influencing the feed
through a side channel.

---

## Source discovery process

This is a **review service**, not an auto-add service. The output of every
discovery cycle is a report (GitHub issue or `docs/` note), not a direct
modification to `sources.yaml`. Sources are admitted only through a PR that
updates `sources.yaml`, `DECISIONS.md`, and the test suite.

### When to run a discovery cycle

| Trigger | Cadence |
|---|---|
| Routine | Quarterly after v1.0.0; monthly during RC burn-in |
| Source retirement | Within one cycle of retiring a source |
| Threat ecosystem disruption | Immediately after a major takedown, law-enforcement operation, or malware family collapse that affects tracked sources |
| Coverage gap | When a threat category goes quiet or a source goes dormant |
| Repeated false positives | When false-positive reports suggest a source is admitting bad data |
| Licence/terms change | When a source's licence changes and may force tier reassignment or retirement |
| IPv6 or address-family gap | When a specific gap is identified (e.g., the open IPv6 host-source item from ADR-033) |

### What a discovery cycle does

1. **Survey candidate feeds** matching the current coverage gaps. Sources
   surveyed and rejected are recorded with the reason, so the same ground
   is not re-covered. ADR-033 is the model — it surveyed 20 candidates and
   documented each rejection.
2. **Evaluate each candidate** against the admission criteria below.
3. **Produce a report** (GitHub issue or `docs/source-discovery-YYYY-MM.md`)
   listing candidates, evaluations, and recommendations.
4. **Open PRs** for any candidates recommended for admission. Each PR is
   self-contained: `sources.yaml` entry, parser, test fixture, ADR, and
   scoring test.

### Admission criteria

A candidate source must pass every gate. Failing any one is a rejection,
recorded so the candidate is not re-surveyed.

| Gate | Requirement |
|---|---|
| **Licence and redistribution** | Explicit written licence permitting redistribution, or `redistribute: false` for scoring-only. No licence = no admission. `NOASSERTION` on GitHub = no licence. |
| **Attribution** | If attribution is required, the emitter must carry it into output headers. |
| **Independence** | Must not be a mirror or aggregate of existing sources. Measure Jaccard overlap against current sources. If >0.5 overlap with any single existing source, it shares that source's independence class and cannot add a vote. |
| **Sensor method** | Must document how indicators are collected and verified. "Scraped from other lists" is not a sensor method. |
| **Update cadence** | Must have a declared update frequency or a feed-level timestamp that allows freshness evaluation. Sources with no timestamp and no content change detection cannot be evaluated for staleness. |
| **Endpoint stability** | Must be a stable URL, not a ad-hoc paste. Auth requirements are acceptable if the key is free. |
| **Volume and churn** | Must not push the published feed outside its committed volume range without an explicit ADR. Measure churn across several runs before enabling. |
| **False-positive risk** | Cloud-hosted and dynamically allocated IPs are high FP risk. All-time lists that never remove entries are rejected unless they document a verification step. |
| **Address families** | IPv4, IPv6, or both. IPv6 host-level sources are specifically valuable (open item from ADR-033). |
| **Parser feasibility** | Must be parseable with the existing parser framework or a new parser that fits the architecture. A new parser requires a test fixture from a real response. |

### What discovery does not do

- Does not auto-enable sources. Every admission is a manual PR with review.
- Does not add sources to fix volume. Volume is not a reason to admit a
  source that fails licence, independence, or FP-risk gates.
- Does not re-survey candidates already rejected in a prior cycle unless
  the rejection reason has changed (e.g., a source gained a licence file).

---

## Required changes for any source lifecycle action

Every PR that changes a source's state (enable, disable, retire, mark
dormant, reactivate) or adds a new source must include:

- [ ] `sources.yaml` update with the state change and updated `notes`
- [ ] `docs/DECISIONS.md` ADR entry or revision
- [ ] `docs/source-methodology-2026-08.md` update if sensor method or
      licence changed
- [ ] Parser and test fixture if a new source or changed content shape
- [ ] Scoring test if voting or promotion behavior changes
- [ ] Manifest and run-report behavior verified against a live run
- [ ] `CHANGELOG.md` entry
- [ ] Statement of whether the RC burn-in clock restarts

### What restarts the RC burn-in clock

This is the authoritative statement; [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
defers to it.

**Restarts the clock, and requires cutting a new candidate:**

- Any change to `sources.yaml`. Not only corrective ones — admitting a source,
  retiring one, or marking one dormant all count.
- Any change under `src/`. Again, not only corrective ones.
- Any change under `.github/workflows/`. A workflow governs how and when feeds
  are produced and published, so changing one changes the thing under
  observation.

**Does not restart the clock:**

- Routine `chore(feeds): refresh` commits, and the `chore(dashboard): re-render`
  commits that accompany them. These are the pipeline running, which is the point
  of the window.
- Documentation, including `docs/`, `README.md`, `CHANGELOG.md`, and this file.
- Citation metadata that does not alter pipeline behaviour: `CITATION.cff`,
  `.zenodo.json`, `LICENSE`.
- Release and audit tooling under `scripts/`. Nothing in `src/` imports it and it
  runs only from CI or by hand, so it cannot change feed output. If a script ever
  becomes part of producing a feed, move it under `src/` and it falls under the
  rule above.

**Deliberately not carved out:** presentation-only code under `src/`, such as
`src/xfeeds/dashboard.py`. It is genuinely downstream of feed generation — it only
reads `feeds/*.json` and writes HTML — so an exception would be defensible. It is
not granted, because "is this change really presentation-only?" is a judgement
call made under release pressure, and the rule's value comes from not having to
make it. Two dashboard commits landed during the `rc.3` window (PRs #45 and #46)
and the ambiguity was only resolved because `rc.4` was cut for an unrelated
reason. Treat `src/` as `src/`.

---

## Feodo Tracker: worked example

Feodo Tracker is the case both policies were written for, and it has now been
through all of it.

**2026-08-18 (ADR-052).** Evidence 166 days old, endpoint returning HTTP 200 with
5 records. Marked dormant: could not solo-promote, voted at a damped weight, the
recurring staleness warning suppressed. abuse.ch's own FAQ explained the lull —
the families it tracks (Emotet, Dridex, TrickBot, QakBot, BazarLoader) have
almost no live C2 left after the 2021 Emotet takedown and Operation Endgame.

**2026-08-19 (ADR-053).** Also made non-admitting: its class stopped counting
toward the two that publish an address.

**2026-09-01 (ADR-056).** Found that its evidence was 180 days old, not the 63 the
manifest reported — abuse.ch rotates its HTTP `Last-Modified` independently of
the payload, and the pipeline was reading the header.

**2026-09-01 (ADR-059).** Expired. It now contributes nothing at all.

The measurement that settled it: **all 5 of its addresses were already withheld,
and none appeared in the published feed.** Dropping the source moved neither the
high nor the medium count. It had been contributing nothing of consequence for
months while still being fetched four times a day and still carrying enough
apparatus — a damped vote, an upgrade path, a suppressed warning — to look like a
live part of the system.

That is the argument for an expiry ceiling in one source: the intermediate states
were doing no work, and the only thing keeping the source alive was that nothing
had a clock on it.

It stays `enabled: true` and `dormant: true`. The fetch is the review trigger. If
`evidence_age_days` in the manifest ever starts falling, that is the prompt to run
the reactivation review and remove the flag.

**Do not replace it with ET botcc.** Measured 2026-09-01:
`rules.emergingthreats.net/blockrules/emerging-botcc.rules` is generated from
abuse.ch's own trackers and contains the identical five addresses. Same class,
same dead data, BSD wrapper.

---

## Revision log

| Date | Change |
|---|---|
| 2026-08-18 | Initial policy. Supersedes the Feodo "wait a month" note from the 2026-08-15 DECISIONS.md pass. Adds stale-source lifecycle, freshness-gated promotion, and source discovery process. |
| 2026-09-01 | Freshness priority order is now implemented in full (ADR-056), not just step 2. Documents the payload-beats-header rule, the header-block and future-timestamp guards, the committed step-3 ledger, and the new manifest fields. Records that the 2026-09-01 discovery cycle admitted nothing and closed the sefinek churn item as decided-no (ADR-057). |
| 2026-09-01 | **Staleness is no longer terminal (ADR-059).** Adds the Expired state and a 90-day ceiling: past it a source contributes nothing, cannot be carried forward from state, and does not return without a recorded `reviewed_on`. `dormant` becomes manual expiry rather than a damped vote. Lifecycle states rewritten from five to four, all driven by one number. |

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
2026-03-04 — the transport is live, the evidence is 166 days old.

Published records must be supported by **fresh enough evidence**. The
source-declared update time — feed header, `Last-Modified`, content hash
change, or API timestamp — controls evidence freshness. Fetch time is
transport freshness only.

The scoring pipeline must treat a stale source's records as aged evidence,
not as current observations, regardless of whether the fetch succeeded.

---

## Source lifecycle states

Every source in `sources.yaml` is in one of five states. The state determines
whether the source can vote, corroboration, solo-promote, and how loudly it
alerts.

### 1. Active

- Source fetches successfully.
- Source-declared update time is within its freshness policy (see below).
- May vote normally.
- May solo-promote if it otherwise qualifies (CC0, documented verification,
  redistributable, not a compromised-host tag).

### 2. Stale watch

- Source still fetches, but its own declared update timestamp exceeds the
  freshness threshold (default: 30 days, or the source's own `ttl_days`,
  whichever is shorter).
- The manifest reports `status: "stale"` and the run report raises a
  staleness warning. These already exist and fire correctly.
- **Cannot solo-promote, and cannot admit.** Its records are *non-admitting*
  (ADR-053): they may strengthen a record that already qualifies on live
  corroboration, but they never count toward the independence classes that
  admit one, and they never promote. This is the same asymmetry
  licence-restricted sources get.
- **Votes at a damped weight.** `score.STALE_EVIDENCE_FACTOR` (0.2) is applied
  on top of `recency_factor`. The damping is applied explicitly because
  `recency_factor` alone would not do it: it decays on when we last *saw* the
  address, which equals now on every successful fetch, so an upstream frozen
  for months would otherwise vote at full strength forever.
- Records that were solo-promoted by this source in a prior active period
  fall out of the feed on the next run unless another fresh source
  corroborates them. This is the existing source-driven publication model
  working as designed — no resurrection, no retention window.

### 3. Dormant (reviewed stale)

- A maintainer has reviewed the stale source and determined the tracked
  threat family or network is genuinely inactive — not a broken fetch, not
  a transient outage, but the threat itself is diminished or dismantled.
- The source stays configured in `sources.yaml` so it wakes up
  automatically if upstream publishes fresh data. No code change is needed
  to reactivate.
- It does not generate a "needs review" alert every run. The staleness
  warning is suppressed or downgraded to an informational log line once the
  source is marked dormant in `sources.yaml`.
- Still cannot solo-promote, and is still non-admitting with a damped vote
  (ADR-053) — regardless of evidence freshness, because dormant is a
  maintainer's statement that the tracked threat itself is gone. A live HTTP 200
  from a dead tracker is not evidence about today.
- It stays enabled rather than disabled precisely because it can still upgrade a
  record that two live classes already admitted.

### 4. Retired (disabled)

- The endpoint is deprecated, dead, legally unusable, replaced by a paid-only
  service, or the threat category is permanently gone.
- `enabled: false` in `sources.yaml`. The entry is kept with documentation
  explaining why it was retired, so a future source-discovery sweep does not
  re-add it.
- Example: SSLBL, retired 2025-01-03 with a deprecation notice in its own
  payload. Example: ELLIO, which 301-redirected to an account-gated platform.

### 5. Reactivated

- Upstream publishes a genuinely fresh update (new `Last updated` header,
  new content, changed hash).
- Before restoring normal scoring and promotion, re-check:
  - Licence and redistribution rights (upstream terms change — see SSLBL
    and ThreatFox's divergence from Feodo's CC0).
  - Attribution requirements.
  - Sensor method and provenance (upstream may have changed methodology).
  - Content shape (parser may need updates).
  - Independence class (upstream may have merged with another source).
- If all checks pass, the source returns to Active. If the licence or
  method has changed, cut a new ADR before re-enabling.

---

## Freshness policy

### How evidence age is determined

Priority order for determining a source's evidence age:

1. **Feed-level timestamp in the payload** — e.g., Feodo's `Last updated`
   header line, ThreatFox API response timestamp.
2. **HTTP `Last-Modified` response header** — when the payload has no
   embedded timestamp.
3. **Content hash change** — when neither is available, a hash of the
   fetched body compared to the previous run. If the hash is unchanged,
   the evidence age is the time since the last observed change, not the
   fetch time.

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

| Behavior | Active | Stale / Dormant |
|---|---|---|
| Vote in scoring | Yes, full weight | Yes, damped by `STALE_EVIDENCE_FACTOR` (0.2) |
| Counts toward admission | Yes | **No** — non-admitting (ADR-053) |
| Upgrades an already-admitted record | Yes | Yes |
| Solo-promotion | Yes, if otherwise qualified | **No** |
| Records age out | Normal `ttl_days` | Same — source-driven publication means records leave when no fresh source reports them |

The promotion gate is the key change. The existing code already prevents
carried observations (from state, not current run) from promoting. The gap is
that a stale source returning the same frozen body every run still counts as
a current observation. The fix: a source whose evidence age exceeds the
freshness threshold is treated as carried for promotion purposes, even when
the fetch succeeded.

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

Feodo Tracker is the concrete case this policy was written for.

**Current state:** Stale watch, moving to Dormant.

- The endpoint is live (HTTP 200) but evidence is 166 days old (last updated
  2026-03-04).
- The staleness warning fires correctly every run.
- abuse.ch's FAQ explains the lull: the families Feodo tracks (Emotet,
  Dridex, TrickBot, QakBot, BazarLoader) have almost no live C2 left after
  the 2021 Emotet takedown and Operation Endgame (2024–2026).
- It is the only CC0 source that can solo-promote, and its false-positive
  rate is near zero — but its 5 records are 166-day-old evidence with no
  corroboration.

**Action under this policy:**

1. Mark feodo_tracker as dormant in `sources.yaml` (new `dormant: true` flag
   or equivalent, with a maintainer note referencing this policy).
2. Gate solo-promotion on evidence freshness in the scoring code. Feodo's
   5 solo-promoted high-confidence records fall out of the feed on the next
   run unless another fresh source corroborates them.
3. Suppress the recurring staleness warning — it has been reviewed and
   explained. Replace with an informational log line.
4. Keep the source configured. If abuse.ch publishes a fresh update, the
   source reactivates automatically after the reactivation checks pass.
5. Cut `rc.2` — this is a `sources.yaml` + scoring-code change that
   restarts the burn-in clock.

**Supersedes:** The note in DECISIONS.md (2026-08-15) saying "If it is still
dead in a month, remove the promotion path rather than leave it looking
active." The month has not passed, but the policy here is broader and the
action is the same: gate promotion on freshness, not on a calendar.

---

## Revision log

| Date | Change |
|---|---|
| 2026-08-18 | Initial policy. Supersedes the Feodo "wait a month" note from the 2026-08-15 DECISIONS.md pass. Adds stale-source lifecycle, freshness-gated promotion, and source discovery process. |

# Post-burn-in backlog

Canonical, single-source-of-truth backlog for work after the initial stable
release. Plans stay in this repository rather than scattered across chat
threads, task links, or external notes.

## Ground rule

**The initial burn-in is complete.** See the
[October 2026 release record](RELEASE_2026-10-05.md) for promotion evidence,
the scoped PR #55 disposition, and the separately tagged scheduler patch.
Items not explicitly included there remain backlog, not release blockers.

`v1.0.0` and `v1.0.1` are published. They are not made prereleases again by
later work. The "burn-in impact" entries below retain the original planning
classification: changes during a future candidate window must follow
[`source-lifecycle.md`](source-lifecycle.md), not move existing stable tags.

The next source-review issue is scheduled for **2026-10-08 at 09:00 UTC
(5:00 AM EDT)**, subject to GitHub scheduling. This opens a review, not a source
promotion: the workflow neither researches nor enables candidates automatically.
Every admission still needs evidence, an independently reviewable PR, tests, and
an explicit decision.

## Next minor: v1.1.0 (candidate window open)

`v1.1.0-rc.1` was cut on 2026-10-08 and `v1.1.0-rc.2` on 2026-10-09 (ADR-071, the
scanner-cap fix). `v1.0.1` stays the stable release until v1.1.0 is promoted
through [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md).

| Status | Work |
|---|---|
| In the window | Six October-review sources (ADR-065 to ADR-070), contribution reporting (3.4, ADR-064), scanner caps on every tier (ADR-071) |
| Rejected | AbuseIPDB Basic (4.2): not paying; free tier stays |
| Blocked | Spur (3.1): feeds need a paid subscription |
| Not in this window | Retention telemetry (4.1), promotion config (1.2/1.5), repository growth (1.3), dashboard restructure (2.1) |

## How to use this backlog

1. Items are grouped by theme, then ordered within a theme by value / effort.
2. Every item carries: rationale, source link, scope, burn-in impact,
   acceptance criteria, dependencies, and status.
3. When an item moves from `backlog` to active work, link the GitHub issue or
   PR in its Execution field. Do not delete the item; update its status.
4. When an item is closed, rejected, deferred, or superseded, record the
   decision inline. The Decision log at the bottom of this file summarises
   those transitions so the "why" is preserved.

Statuses: `backlog` · `active` · `blocked` · `done` · `deferred` · `rejected` ·
`superseded`.

---

## 1. Muse external-review follow-ups

Source: independent code review (Muse), summarised in the wiki entry for
xfeeds. The review validated scoring, stage ordering, deterministic output,
and fixture strategy. The items below are the durable, accepted follow-ups.

### 1.1 Document the consumer contract: band is policy-authoritative

- **Rationale.** Restricted-corroborated evidence and two-class redistributable
  evidence can produce a HIGH-band record with a lower raw score than a
  MEDIUM-band record. That is intentional under ADR-053: the band reflects
  corroboration structure and licensing, and the score orders within a band.
  Muse's underlying concern is real: the contract is not documented crisply
  enough for a reviewer reading the code cold to infer it.
- **Scope.** README and/or `AGENTS.md` gains a "Consumer contract" section:
  "Band is authoritative for policy decisions (block/monitor/ignore). Score is
  a within-band ordering signal, not a threshold. Consumers should not
  threshold on `score >= N` across bands." Plus a regression test asserting
  band-crossing score inversions are permitted, not a bug.
- **Burn-in impact.** README and `AGENTS.md` edits are `docs/`-adjacent and do
  not restart burn-in. The regression test is a test-only addition under
  `tests/`; confirm with a path-scoped diff check that no `src/` file is
  modified. If the test requires importing helpers that today live in `src/`,
  add the test as a pure black-box assertion on the manifest output to keep
  the change out of `src/`.
- **Acceptance criteria.**
  1. Consumer-contract section exists in README with a short worked example.
  2. `AGENTS.md` cross-references the new section.
  3. Regression test proves a restricted-corroborated HIGH-band record with a
     lower score than a two-class MEDIUM-band record is legal.
  4. Path-scoped diff check confirms no in-scope files touched by the docs
     portion; test-only portion clearly separated in its own commit.
- **Status.** `done`.
- **Execution.** October 2026 release: README consumer contract, AGENTS cross-link,
  and `test_emitted_band_is_authoritative_despite_cross_band_score_inversion`
  assert on emitted JSON and the high-confidence feed. No `src/` change.

### 1.2 Replace hardcoded Spamhaus solo promotion with `solo_promote` config

- **Rationale.** `src/xfeeds/score.py` currently identifies Spamhaus DROP by
  hardcoded source IDs, and also permits fresh redistributable `abusech`
  observations that are not tagged `compromised-host`, to promote by themselves.
  Spamhaus is the only currently active admitting promotion family; that does
  not mean the abuse.ch code path is absent.
  The docstring warns the scorer is "the easiest thing to get subtly wrong,"
  and yet source identity is baked into the scorer rather than declared in
  `sources.yaml`. Adding a per-source `solo_promote: true` flag follows the
  existing per-source policy pattern and generalises cleanly if any future
  source ever documents an active verification step.
- **Scope.** Add a `solo_promote` field to the source config schema; move
  Spamhaus DROP v4 and v6 to `solo_promote: true` in `sources.yaml`; replace
  the hardcoded identifier check with a config lookup. Explicitly represent
  existing abuse.ch eligibility too, without enabling any dormant, disabled,
  or restricted source, and preserve the compromised-host exclusion.
- **Burn-in impact.** **Restarts burn-in.** Touches `sources.yaml` and
  `src/`, and changes voting/promotion behaviour. This must batch with other
  scorer-adjacent post-burn-in work, not ship alone.
- **Acceptance criteria.**
  1. `sources.yaml` schema documents `solo_promote`, default `false`.
  2. Active Spamhaus DROP v4/v6 retain promotion. Existing abuse.ch policy
     remains equivalent under dormant/disabled/restricted configurations.
  3. `score.py` no longer references source IDs for promotion behaviour.
  4. Tests cover unflagged/flagged sources, restricted/stale/carried evidence,
     the abuse.ch branch, and compromised hosts. Replay fixtures before and
     after to demonstrate no policy drift.
  5. Manifest and run-report unchanged in shape.
- **Status.** `backlog`.
- **Dependencies.** Stable promotion complete; batching decision with 1.5 below.
- **Execution.** _new RC will be cut when this batch lands_.

### 1.3 Repository / distribution growth measurement study

- **Rationale.** Muse flagged monotonic pack growth from committing feeds to
  `main`. Their recommended fix (orphan branch or separate repo) would break
  the heartbeat's committed-manifest comparison, fragment the rc.5-to-v1
  longitudinal dataset that is Git history, and undermine the shared `pages`
  concurrency contract. The underlying problem is real but the solution
  shape must preserve the audit trail.
- **Scope.** Read-only measurement first: current pack size, weekly growth,
  contributor clone P50, CI checkout time. Then decide between: orphan
  `feeds` branch in the same repo (history intact, `git clone
  --single-branch main` cheap), scheduled `git gc --aggressive` plus
  documented partial-clone recipes for consumers, or status quo.
- **Burn-in impact.** Measurement is read-only and can start before promotion
  as long as no in-scope files are touched. Implementation of any chosen
  option almost certainly touches `.github/workflows/` and therefore
  restarts burn-in; it must ship post-promotion.
- **Acceptance criteria.**
  1. `docs/repo-growth-measurement.md` records raw measurements with dates
     and methodology.
  2. Decision recorded (which option, or "no action") with rationale.
  3. If action is taken, the audit trail and heartbeat contract are
     explicitly preserved and tested.
- **Status.** `backlog` (measurement portion may begin as read-only work
  before promotion).
- **Execution.** _tracking issue TBD_.

### 1.4 Correct `AGENTS.md` `stix2` drift

- **Rationale.** `AGENTS.md` lists `stix2` in the dependency list. `emit.py`
  hand-builds STIX for determinism (intentional, per the churn-guard ADR),
  and nothing imports `stix2`. Doc drift only.
- **Scope.** Remove `stix2` from the dependency list in `AGENTS.md`; add a
  one-line note that STIX 2.1 output is produced by a deterministic
  hand-built emitter.
- **Burn-in impact.** `AGENTS.md` is a docs edit and does not restart
  burn-in.
- **Acceptance criteria.**
  1. `AGENTS.md` no longer lists `stix2`.
  2. A grep for `stix2` in the tree returns no live-code references.
- **Status.** `done`.
- **Execution.** October 2026 release documentation removes the nonexistent
  dependency from AGENTS and the README technology table.

### 1.5 Correct `MEDIUM_CONFIDENCE_CLASSES` docstring drift

- **Rationale.** The `MEDIUM_CONFIDENCE_CLASSES` docstring says
  "redistributable classes only," while the code and the `_band` docstring
  say "redistributable and vouched," matching ADR-053.
- **Scope.** One-line docstring correction in `src/xfeeds/score.py`.
- **Burn-in impact.** **Restarts burn-in** under the "treat `src/` as
  `src/`" rule (see `docs/source-lifecycle.md`). Even a docstring edit inside
  a `src/` file restarts the clock. Must batch with 1.2.
- **Acceptance criteria.**
  1. Docstring matches ADR-053 wording.
  2. Bundled with 1.2 in the same RC-cutting PR.
- **Status.** `backlog`.
- **Dependencies.** Batch with 1.2.
- **Execution.** _same RC as 1.2_.

### 1.6 Reviewer onboarding: point at load-bearing ADRs

- **Rationale.** A sharp external reviewer took hours to infer contracts
  (band vs. score, restricted vs. redistributable) that ADRs 040 and 053
  already settle. `AGENTS.md` should point reviewers at the ADRs to read
  first for corroboration and licensing semantics.
- **Scope.** Add a "Read these ADRs first" section to `AGENTS.md` (or a
  dedicated `docs/REVIEWER_ONBOARDING.md`) listing ADRs 040, 053, and any
  others that define public contracts.
- **Burn-in impact.** Docs only; does not restart burn-in.
- **Acceptance criteria.**
  1. Reviewer onboarding block exists and links to the ADRs by number and
     path.
  2. A new reviewer can locate band-vs-score semantics from
     `AGENTS.md` in one hop.
- **Status.** `done`.
- **Execution.** October 2026 release: AGENTS reviewer contract links.

## 2. Dashboard restructure

Source: `docs/DASHBOARD.md` planning and the direction-A revision brief.

### 2.1 Operator-first dashboard restructure

- **Rationale.** Reorder the dashboard around operator workflow: headline
  counts, IP lookup, downloads, and setup first; analysis behind them.
- **Scope.**
  - Reorder sections operator-first.
  - Consolidate three history views into one feed-health panel.
  - Add sticky section navigation.
  - Cut and relocate excess explanatory prose; retain required attribution
    and the IPv6 safety explanation.
  - Add accessible hover/focus tooltips and a print stylesheet.
  - Update or create `docs/DASHBOARD.md` as the detailed reader's guide.
  - Add dashboard regression tests for order, attribution, accessibility,
    determinism, downloads, and load-bearing explanations.
- **Burn-in impact.** Implementation touches `src/xfeeds/dashboard.py`,
  which is deliberately not carved out from the burn-in rule (see
  `docs/source-lifecycle.md`: "presentation-only code under `src/` ... it is
  not granted"). **Restarts burn-in.** Post-promotion only.
- **Acceptance criteria.**
  1. Live dashboard shows operator-first section order.
  2. Unified feed-health panel replaces the three prior history views.
  3. Sticky nav present; print stylesheet present; accessible hints tested.
  4. `docs/DASHBOARD.md` reflects the new layout.
  5. Regression tests cover the acceptance points above and remain
     deterministic.
- **Status.** `backlog`.
- **Execution.** _tracking issue TBD post-promotion_.

## 3. Source-discovery improvements

Source: this project's source-review workflow and the discovery lane
retrospective triggered by the Spur miss.

### 3.1 Add Spur as a private, redistribute-false scoring source

- **Rationale.** Spur covers anonymous VPNs, datacenter and ISP proxies,
  residential and malware proxies, peer-to-peer / blockchain proxies, ZTNA,
  and IPv6 — a real coverage gap for inbound abuse that current sources do
  not fill. Public docs do not prohibit downstream use for scoring, but they
  do not grant redistribution either; treat as scoring-only until the
  agreement is verified.
- **Scope.**
  - Start with the daily **Anonymous** feed. Not Residential. Not Realtime.
  - `redistribute: false`. No Spur IPs, service tags, derived attribution,
    or Spur-origin field in any public artifact. Records live only in
    private run state.
  - Corroboration-only: no solo-promotion; conservative initial weight;
    short TTL aligned to the daily feed timestamp.
  - Publish a source note naming Spur, its credentialed scoring-only role,
    non-redistribution behaviour, and a GitHub issue/PR contact path for
    correction or removal requests.
  - Access is an **ongoing subscription**, not a time-limited trial: a trial
    cannot contribute to the long-term dataset. The first 14–30 days of the
    subscription are the measurement window for overlap, incremental
    detections, high/medium movement, churn, and allowlist/false-positive
    reports before any reweighting or considering the residential feed.
  - Terms are read as written under ADR-060, as for every source: no
    redistribution, so `redistribute: false`, with the standard issue/PR
    objection path. No permission request is part of the plan.
- **Burn-in impact.** **Restarts burn-in.** Requires `sources.yaml`
  admission and probably `src/` and `.github/workflows/` changes. Post
  rc.7 promotion, through the normal source-admission PR path.
- **Acceptance criteria.**
  1. Spur documented in `sources.yaml` with `redistribute: false` and
     corroboration-only settings.
  2. Public artifacts contain no Spur-origin identifier.
  3. Measurement report at day 14 and day 30 covering the metrics above.
  4. Decision to keep, reweight, expand to residential, or retire, with
     rationale.
- **Status.** `backlog`.
- **Dependencies.** Stable promotion complete; source review 2026-10-08 or later;
  an approved ongoing subscription before any fetch. Feeds are not in the free
  Community plan, so a $0 path does not exist today.
- **Execution.** 2026-10-08 review: Spur's free Community plan includes no feeds
  (250 manual lookups); feed tiers are sales-quoted. Blocked only on a
  subscription decision; the config and parser can follow the day one exists. See [`source-discovery-2026-10.md`](source-discovery-2026-10.md).

### 3.2 Add a commercial credentialed scoring-only discovery lane

- **Rationale.** The initial source sweep optimised for public,
  redistributable IOC feeds and missed the commercial, credentialed
  scoring-only category despite policy permitting `redistribute: false`
  sources. The Spur miss is a discovery-process gap, not an
  evaluated-and-rejected outcome.
- **Scope.**
  - Add distinct candidate lanes to the discovery template: malware/C2,
    botnet/abuse, proxy/anonymization, fraud infrastructure, IPv6, and
    commercial credentialed scoring-only.
  - Require, for each lane, a documented "top candidates considered" list
    and a reason for every exclusion (including "not evaluated").
  - Add an explicit rule: paid or authenticated access is not a
    disqualifier; evaluate under `redistribute: false`.
  - Add an "incremental coverage hypothesis" per candidate: gap filled,
    expected overlap, expected false-positive risk, and the outcome that
    would justify keeping it.
- **Burn-in impact.** Docs-only changes to the discovery workflow do not
  restart burn-in. Changes to the review workflow file under
  `.github/workflows/` **would** restart burn-in and must be batched with
  other workflow work post-promotion.
- **Acceptance criteria.**
  1. Discovery brief documents the lane taxonomy.
  2. Next review uses the lane taxonomy and records exclusion reasons.
- **Status.** `done` (docs). The issue-template checklist in
  `source-review.yml` still says "free auth acceptable"; that one line moves with
  the next batched workflow change rather than on its own.
- **Execution.** 2026-10-08 review: lane taxonomy and the paid-access rule in
  `SOURCE_DISCOVERY_BRIEF.md` and `source-lifecycle.md`; first lane-structured
  report in [`source-discovery-2026-10.md`](source-discovery-2026-10.md) (issue #62).

### 3.3 Maintain a persistent candidate backlog

- **Rationale.** Candidates need durable state (`new`, `researching`,
  `burn-in`, `accepted`, `rejected`, `revisit-date`) so the discovery
  process does not repeatedly re-evaluate the same sources or lose track of
  ones deferred for capacity reasons.
- **Scope.** A candidate register lives either in `docs/` (Markdown table)
  or as pinned GitHub issues with a standard template. Every entry carries
  status, last-reviewed date, and next-revisit date.
- **Burn-in impact.** Docs-only or issue-only; does not restart burn-in.
- **Acceptance criteria.**
  1. Register exists with the current known candidates, including Spur.
  2. Review workflow references it.
- **Status.** `done`. Criterion 2 is met through the brief, which the review
  issue links; a direct link in the issue template batches with the 3.2 workflow
  line.
- **Execution.** [`SOURCE_CANDIDATES.md`](SOURCE_CANDIDATES.md), created in the
  2026-10-08 review with Spur, AbuseIPDB, every candidate from that cycle, and
  the earlier ADR rejections.

---

### 3.4 Report how every production source is used and what it contributes

- **Rationale.** Identifying overlap and expressing confidence is the product.
  `class_overlap` showed symmetric Jaccard for 20 pairs, and nothing showed
  which published records a source stands behind or is decisive for.
- **Scope.** `insights.json` → `class_contribution` and an analysis-page panel:
  per class, published and high records supported, leave-one-class-out
  withheld and lose-high counts, and asymmetric containment (ADR-064). The
  register's production section documents each source's role.
- **Burn-in impact.** Touches `src/`; v1.1.0 window.
- **Acceptance criteria.** Aggregate only; restricted classes show zero
  `would_be_withheld_without_it`; computed every run; panel rendered and tested.
- **Status.** `done` (v1.1.0-rc.1).
- **Execution.** PR #65 (code), register production section (docs).

### 3.5 Ongoing access only

- **Decision.** A time-limited trial or evaluation licence is not a source.
  Paid sources are evaluated on an ongoing subscription; purchases stay a
  maintainer decision. Recorded in the brief, lifecycle gate, and register.
- **Status.** `done` (2026-10-08).

---

## 4. Measurement-first follow-ups

### 4.1 Retention observability before dynamic-host expiry

- **Rationale.** Recovered from the September 3 planning decision: determine
  whether growth is healthy net-new intelligence or insufficient retirement.
  The earlier conversation drafted an issue, but the live repository has no
  corresponding issue; this backlog entry is the durable tracking record.
- **Scope.** Track qualifying fresh observations separately from collection
  time; distinguish host IPs, IPv4 prefixes, and IPv6 prefixes. Publish safe
  aggregates for age buckets, confidence bands, support counts, additions,
  removals, and net change. Keep restricted per-record provenance private.
- **Acceptance criteria.** Buckets reconcile to totals; unchanged fetches do
  not reset evidence age; deterministic outputs; no admission/scoring change;
  existing URLs and schemas remain compatible. Measure for at least 30 days.
- **Decision gate.** Only then consider targeted expiry for aging dynamic hosts.
  No universal maximum age for curated netblocks. Enforcement requires its own
  ADR, tests, candidate/release decision, and separately reviewed PR.
- **Status.** `backlog`; proposed v1.1.0 measurement work, not a v1 release blocker.
- **Execution.** Not started.

### 4.2 AbuseIPDB Basic expansion experiment

- **Rationale.** Recovered from the September 3 decision to evaluate Basic after
  initial burn-in, rather than automatically adopting a larger feed.
- **Scope.** Subject to approved subscription/access, use one account/token and
  one response with identical query parameters to compare ranks 1–10,000 against
  10,001–100,000. AbuseIPDB is already in production on the free tier; this
  item only applies if the account moves to Basic as a kept plan, since a
  trial-only expansion would not contribute to the long-term dataset.
- **Acceptance criteria.** Measure incremental fresh coverage, independent
  corroboration, false-positive exposure, churn, and safe output impact.
  Preserve `redistribute: false`; no raw trial rows in public artifacts.
  Record keep/revert/expand decision from evidence, not gross list size.
- **Dependencies.** October 8 review or later; explicit purchase approval and
  source-configuration review. No subscription bought or production limit raised.
- **Status.** `rejected` (2026-10-08). The maintainer is not paying for
  AbuseIPDB; it stays in production on the free tier (10,000 rows, confidence
  100). Reopen only if that decision changes.
- **Execution.** Not started. 2026-10-08 review: AbuseIPDB lists Basic at
  $25/month with 100 blacklist requests/day up to 100,000 IPs, and states that
  all plans include a free 30-day trial. Per the ongoing-access rule (2026-10-08
  decision log) the trial alone is not a reason to run it; the config change is
  `limit: 100000` once the account is on Basic.

## Decision log

- **2026-10-08, v1.1.0-rc.1 cut.** Six admissions (#68-#73) and contribution
  reporting (#65) merged; `v1.1.0-rc.1` tagged. Item 3.4 done. The candidate window
  starts with the first scheduled refresh on rc.1.

- **2026-10-08, v1.1.0 window opened.** Licences are read as written with
  objections through issues or PRs (ADR-060); no permission or clarification
  requests to publishers are part of any source plan. AbuseIPDB stays on the free
  tier (4.2 rejected). Carpathian is read as written: its page says it buys and
  resells no one else's data, so its rows are first-party, and stale permabans are
  handled by per-row `last_seen`. It joins the v1.1.0 batch.

- **2026-10-08, second pass.** Overlap is corroboration: containment is
  recorded, never a rejection reason (ADR-064; corrects #64). Ongoing access
  only: trial-only sources are rejected (3.5). The register now covers
  production sources, every candidate, and every historical rejection. Ready
  for v1.1.0: ReportedIP, Sblam (scoring-only), jacobrakai, ISC
  `sources/attacks`, ISC scanner labels, plus contribution reporting (3.4).
  Spur and AbuseIPDB Basic proceed only as ongoing subscriptions.

- **2026-10-08, source review (#62).** Lane-structured review recorded in
  [`source-discovery-2026-10.md`](source-discovery-2026-10.md); 3.2 and 3.3 done
  as docs. Three no-cost candidates are ready for a next-minor window: a
  ReportedIP shadow trial, a DShield API upgrade inside the existing class, and
  ISC research-scanner labels as a benign cap. No source enabled.

- **2026-10-05, quality audit.** Verified published tags, build/test health, live
  feed integrity, and immutable archive. Removed obsolete pre-release timing,
  corrected the promotion-refactor scope to preserve abuse.ch behavior, and
  restored retention and AbuseIPDB plans omitted from the canonical backlog.
  October 8 is discovery/review, not automatic source promotion.

- **2026-10-05.** Initial burn-in completed. Items 1.1, 1.4, and 1.6 are
  included in stable-release preparation. Scheduler repairs and quarterly review
  cadence are a separately tagged operational patch; remaining research, source,
  and scoring work is not silently added to the release.

- **2026-09-17.** Backlog file created after the Muse review and the Spur
  discussion produced follow-ups scattered across chat threads and an
  incorrectly created Apple Note. Apple Notes is not the project's planning
  system and will not be used for xfeeds work again. This file is the
  canonical location; individual items link out to GitHub issues and PRs
  once they enter active work.
- **2026-09-17.** Scope of this PR is deliberately limited to
  `docs/POST_BURN_IN_BACKLOG.md`. No in-scope files (`sources.yaml`,
  `src/`, `.github/workflows/`) are touched, so the rc.7 burn-in window is
  not restarted.

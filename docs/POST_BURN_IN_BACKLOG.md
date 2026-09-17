# Post-burn-in backlog

Canonical, single-source-of-truth backlog for work that is **deferred until the
current release-candidate burn-in window closes**. This file exists so planned
work is durable, reviewable, and discoverable in the repository rather than
scattered across chat threads, task links, or external notes.

## Ground rule

**Nothing in this file is worked on before the rc.7 burn-in window closes.**

Per [`docs/source-lifecycle.md`](source-lifecycle.md), the burn-in clock is
restarted by any change to `sources.yaml`, `src/`, or `.github/workflows/`.
This document, and any planning-only follow-ups added to it, live under
`docs/` and therefore do not restart the clock.

Stable-release eligibility: on or after **2026-10-01**, subject to the
release checklist and the path-scoped diff check.

The next source review opens **2026-10-08**, deliberately after the eligibility
date so admission work cannot restart the release window on promotion day.

### What is allowed before burn-in closes

- Editing this document.
- Read-only measurements that do not touch `sources.yaml`, `src/`, or
  `.github/workflows/` (for example, cloning the repository and measuring
  pack size or clone time from a scratch checkout).
- Opening tracking issues that describe post-burn-in work without changing
  in-scope files.

### What is not allowed before burn-in closes

- Any change under `sources.yaml`, `src/`, or `.github/workflows/`, for any
  reason. Even a "docs-only" edit inside a `src/` file (for example, a
  docstring correction) is a `src/` change and restarts the window.
- Admitting, retiring, or reweighting any source.
- Merging or opening a PR whose diff touches the paths above.

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
- **Status.** `backlog`.
- **Execution.** _tracking issue TBD post-2026-10-01_.

### 1.2 Replace hardcoded Spamhaus solo promotion with `solo_promote` config

- **Rationale.** `src/xfeeds/score.py` currently identifies Spamhaus DROP by
  hardcoded source IDs as the sole feed permitted to promote by itself.
  The docstring warns the scorer is "the easiest thing to get subtly wrong,"
  and yet source identity is baked into the scorer rather than declared in
  `sources.yaml`. Adding a per-source `solo_promote: true` flag follows the
  existing per-source policy pattern and generalises cleanly if any future
  source ever documents an active verification step.
- **Scope.** Add a `solo_promote` field to the source config schema; move
  Spamhaus DROP v4 and v6 to `solo_promote: true` in `sources.yaml`; replace
  the hardcoded identifier check in `score.py` with a lookup against the
  config; adjust or add scoring tests to cover the flag.
- **Burn-in impact.** **Restarts burn-in.** Touches `sources.yaml` and
  `src/`, and changes voting/promotion behaviour. This must batch with other
  scorer-adjacent post-burn-in work, not ship alone.
- **Acceptance criteria.**
  1. `sources.yaml` schema documents `solo_promote`, default `false`.
  2. Spamhaus DROP v4 and v6 carry `solo_promote: true`; no other source
     does.
  3. `score.py` no longer references source IDs for promotion behaviour.
  4. Scoring tests cover: unflagged single-source → not promoted; flagged
     single-source → promoted; flag interaction with restricted evidence.
  5. Manifest and run-report unchanged in shape.
- **Status.** `backlog`.
- **Dependencies.** rc.7 promotion; batching decision with 1.5 below.
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
- **Status.** `backlog`. Safe to ship as a docs-only PR any time; deferred
  to post-promotion to keep the reviewer window clean.
- **Execution.** _tracking issue TBD_.

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
- **Status.** `backlog`.
- **Execution.** _tracking issue TBD_.

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

### 3.1 Trial Spur as a private, redistribute-false scoring source

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
  - Measure 14–30 days of overlap, incremental detections, high/medium
    movement, churn, and allowlist/false-positive reports before any
    reweighting or considering the residential feed.
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
- **Dependencies.** rc.7 promotion; source review 2026-10-08 or later.
- **Execution.** _tracking issue and PR TBD_.

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
- **Status.** `backlog`.
- **Execution.** _tracking issue TBD_.

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
- **Status.** `backlog`.
- **Execution.** _tracking issue TBD_.

---

## Decision log

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

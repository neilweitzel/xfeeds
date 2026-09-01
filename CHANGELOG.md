# Changelog

All notable changes to xfeeds are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versioning applies to the **pipeline and its published contracts** — feed paths,
record schema, and manifest fields — not to the feed contents, which change every
six hours by design. A consumer pinning a tag still fetches the same live URLs.

## [Unreleased]

## [1.0.0-rc.6] — 2026-09-01

Cut by the 1 September source review. **No published output changes.** The review
admitted no source, and the one defect it found was latent rather than active — but
it touches `src/` and `sources.yaml`, so the burn-in clock restarts and the window
now closes on or after **2026-10-01**.

### Fixed

- **Evidence age is now determined by the payload first, then the HTTP header, then
  a content hash (ADR-056).** `docs/source-lifecycle.md` has specified that priority
  order since 2026-08-18 and only the middle step was ever implemented.

  abuse.ch is why the order matters. It serves a `Last-Modified` that moves
  independently of its payload: on 2026-09-01 both Feodo Tracker and SSLBL returned
  `Last-Modified: Tue, 30 Jun 2026 04:53 GMT` while their payloads declared
  2026-03-04 and 2025-01-02 — two feeds frozen fourteen months apart reporting
  transport timestamps fourteen seconds apart. The manifest was recording Feodo's
  evidence as 63 days old when the tracker itself said 180.

  The larger half of the same defect: where no `Last-Modified` was sent, staleness
  was not evaluated at all, because the whole check sat inside `if last_modified:`.
  Three live sources (`abuseipdb_blacklist`, `ipsum_levels`, `threatfox`) send none,
  so they had no freshness gate of any kind.

  Nine payload formats are supported, every one taken from a real recorded response.
  Two guards worth knowing: the scan stops at the first data line, because several
  feeds carry per-row dates that a whole-file sweep would misread as the feed's own;
  and a timestamp more than a day ahead of the run is discarded in favour of the next
  priority, because a broken upstream clock must not manufacture freshness.

  Verified against a live run of all 22 reachable sources. Feodo now reports basis
  `payload` at 180 days; nine sources moved from the header to their own declared
  timestamp; `ipsum_levels` is gated by content hash where it was previously ungated.
  No source was newly marked stale and no new warnings were raised. **The fix is
  protective, not corrective** — Feodo was already dormant and therefore already
  non-admitting, and both the old and new ages exceed its 7-day threshold.

- Staleness is now decided once per source, using the newest evidence across all of
  its URLs. Previously the last URL fetched silently overwrote the verdict of the
  earlier ones, which was arbitrary for `ipsum_levels` and its six files.


- **`RELEASE_CHECKLIST.md` no longer contradicts `source-lifecycle.md` about what
  restarts the burn-in clock.** Step 3 claimed that any content in this file's
  `[Unreleased]` section meant the clock had restarted and the release should not
  proceed. That is wrong. `source-lifecycle.md` is the authoritative statement and
  explicitly excludes documentation, this changelog, citation metadata, and
  `scripts/` — precisely the changes that collect in `[Unreleased]` during a
  candidate window. Only `sources.yaml`, `src/`, and `.github/workflows/` restart
  it.

  The contradiction was live rather than hypothetical: ADR-055 (#49) landed an
  hour after `rc.5` was tagged, touching none of the restarting paths, so step 1
  read the clock as intact while step 3 read it as restarted. Step 3 now defers to
  the path list and gives the `git diff` invocation that settles it.

### Added

- `feeds/manifest.json` gains `evidence_time`, `evidence_age_days`, and
  `evidence_basis` per source, so which mechanism decided a staleness verdict is
  visible in the published output. `last_modified` keeps its existing meaning as the
  raw transport signal and is now reported alongside rather than instead — the two
  being conflated is what hid the original defect.
- `feeds/source-freshness.json`, recording when each source's body last changed.
  Committed rather than cached: a cold `actions/cache` would otherwise reset every
  source's change history to "changed just now", making a permanently frozen upstream
  look permanently fresh.

### Changed

- **`sefinek_malicious_ip` stays disabled, now on measured evidence (ADR-057).** The
  ADR-048/051 open item asked for a churn measurement across several runs. The list
  is published from a git repository, so its whole history was read directly instead:
  across 140 upstream commits between 2026-08-01 and 2026-09-01, IPv4 grew
  209,443 → 215,654 and IPv6 5,085 → 5,490 with **zero removals** on any daily
  sample. Rejected under the all-time-list rule despite MIT licensing, the best
  independence of any candidate measured (max Jaccard 0.0035 against a 0.5
  threshold), and 5,490 host-level IPv6 addresses — which would have been the only
  thing found in two cycles capable of closing the ADR-033 IPv6 item.
- The 2026-09-01 discovery cycle surveyed twelve further candidates and admitted
  none. Recorded in issue #52 and in the open items, so the same ground is not
  re-covered. HoneyDB is called out specifically: its data would have passed
  independence and a distributed honeypot network would be a genuinely new class, but
  the Community tier forbids redistribution and embedding outright.

- **One version number is now used everywhere, always (ADR-055).** Landed in #49
  shortly after `rc.5` was tagged, so it ships in this candidate. Between
  `rc.3` and `rc.5` the repository carried two at once: `pyproject.toml` said
  `1.0.0rc5` while `CITATION.cff` said `1.0.0-rc.3`. That was deliberate and
  documented, and it was still wrong.

  The cause was a false constraint. `CITATION.cff` listed a **version-specific**
  DOI for `rc.3` alongside the concept DOI, which pinned the file to that one
  archive — so its `version` field had to lag whenever a candidate was not
  deposited. The version DOI was never required to be there. `CITATION.cff` now
  lists only the concept DOI, which is version-agnostic and therefore never
  constrains the version field, and its `version` tracks `pyproject.toml`
  exactly.

  Two spellings of the one version remain, and are not a disagreement: PEP 440
  requires `1.0.0rc5` in `pyproject.toml` while `CITATION.cff` and the git tag use
  `1.0.0-rc.5`. Forcing one spelling would break either packaging or tag
  conventions, so CI compares them on a canonical form.

  A version-specific DOI may still appear in `CITATION.cff`, but only when it
  names the same version as the rest of the file — in practice at a final release,
  once that release is deposited. Version DOIs per release are recorded in
  `docs/CITABILITY.md`, and remain discoverable from the concept DOI's Zenodo
  version list. `rc.3`'s DOI is unaffected and still resolves.

- `scripts/check_version_agreement.py` is correspondingly stricter. It previously
  had to tolerate the divergence, so it could only demand agreement once
  `pyproject.toml` named a final release — meaning the check was inert during
  every candidate window, which is when changes actually land. That exemption is
  gone. It now also verifies that any non-concept DOI describes the file's own
  version, that the concept DOI is present, and that `date-released` is a real,
  non-future date. All eight behaviours were confirmed by deliberately breaking
  the state.

- Cutting a release candidate now includes bumping `CITATION.cff`, not just
  `pyproject.toml` and the tag. `docs/RELEASE_CHECKLIST.md` step 2 no longer
  documents an intentional disagreement, and instead describes adding the version
  DOI back at promotion.

- `docs/source-lifecycle.md` records that `scripts/` does not restart the burn-in
  clock: nothing in `src/` imports it and it runs only from CI or by hand, so it
  cannot change feed output.

## [1.0.0-rc.5] — 2026-08-24

Fifth release candidate, cut the same day as `rc.4`. No pipeline behaviour
changed; `rc.5` exists because a pre-promotion audit hardened the release path,
and one of those changes touched `.github/workflows/ci.yml`, which restarts the
burn-in clock by policy.

Cutting it the same day costs nothing. `rc.4` was tagged 2026-08-24, so both
windows close on or after **2026-09-24**. The alternative — deferring the version
guard to after promotion, where the checklist had it filed as optional — would
have meant the guard was absent for the one release it was designed to protect.

### Added

- `scripts/check_version_agreement.py`, wired into the `citation` CI job. A
  published Zenodo record is immutable, so a wrong version string in it is
  permanent, and the existing citation checks covered ORCID and licence but not
  version. A blunt equality check between `pyproject.toml` and `CITATION.cff`
  would false-fail, because the CFF deliberately tracks the most recent
  *archived* version while the pipeline moves ahead during a candidate window.
  The guard instead asserts three things that hold regardless: the CFF's
  `version` agrees with the version its own version-DOI `description` names;
  `pyproject.toml` and `CITATION.cff` agree exactly once `pyproject.toml` names
  a final release; and `date-released` is a real, non-future ISO date.

### Changed

- `docs/source-lifecycle.md` now carries the authoritative list of what restarts
  the RC burn-in clock, and `docs/RELEASE_CHECKLIST.md` defers to it rather than
  restating it. The checklist had asserted that workflow changes restart the
  clock while citing a document that did not say so. Presentation-only code under
  `src/` is explicitly *not* carved out, with the reasoning recorded.
- `docs/RELEASE_CHECKLIST.md` corrections found in a pre-promotion audit:
  - The `pyproject.toml` version was described as `1.0.0rc3`; it is `1.0.0rc4`.
  - Two sections contradicted each other on `.zenodo.json` — one said it carries
    no version field, the other said to keep its version in sync. It carries
    none, and the earlier claim that Zenodo derives the version from the git tag
    is wrong for this record: it is API-managed, so the version comes from the
    metadata payload. That payload is now listed as a fourth place carrying a
    version.
  - The `[Unreleased]` changelog section was described as holding the PR #42
    metadata work. That content moved into `[1.0.0-rc.4]` when the candidate was
    cut, so the instruction to "move everything under `[Unreleased]`" would have
    silently done nothing.
  - The freshness check demanded a manifest `generated_at` within six hours.
    Scheduled runs are six hours apart but GitHub's queue delivers them late:
    observed gaps reached 7.17h. Relaxed to eight hours so the check cannot fail
    on a healthy pipeline.
  - The Zenodo step 6 sequence was pseudo-code. It is now the exact call
    sequence, with three documented API behaviours that are easy to get wrong —
    `newversion` takes the version id and rejects the concept id, its response is
    the original record rather than the new draft, and the new draft inherits a
    snapshot of the previous version's files. That last one means the `rc.3`
    tarball must be deleted before publishing or the record permanently carries
    both, so it is now also listed as an irreversible failure mode.

## [1.0.0-rc.4] — 2026-08-24

Fourth release candidate. The `rc.3` burn-in window surfaced a carry-forward
defect that had been demoting corroborated records on three refreshes out of
every four, so the candidate is re-cut rather than promoted. This candidate also
carries the citation and licensing metadata that made the project archivable.

The defect was found from a user observation about addition counts spiking on a
regular cycle. The spikes were real and were correctly guessed to be time-locked,
but the accompanying collapse in *removals* at the same hour is what identified
the cause as internal rather than upstream. Burn-in windows exist for exactly
this.

### Added

#### Project metadata
- `LICENSE` at the repository root. The README had declared MIT since the start,
  but with no licence file the claim was unverifiable by tooling and blocked
  archival — Zenodo and most package indexes expect a licence file so reuse terms
  are unambiguous. `pyproject.toml` now carries `license = "MIT"` and
  `license-files`, so the SPDX expression travels with the built distribution.
- `CITATION.cff` (CFF 1.2.0), which makes GitHub render a "Cite this repository"
  button with pre-formatted APA and BibTeX. Author identity is anchored to ORCID
  iD 0009-0007-2546-2331.
- `.zenodo.json`, committed ahead of any deposit. Without it the Zenodo GitHub
  integration derives authorship from repository contributors, which would credit
  coding-agent and automation commits as authors of the archived record. It
  cannot be added retroactively to a published record, so it has to precede the
  first archived release.
- A `citation` CI job that validates the CFF against its schema, parses
  `.zenodo.json`, and asserts the ORCID iD and licence agree across
  `CITATION.cff`, `.zenodo.json`, and `pyproject.toml`. Metadata that drifts is
  worse than absent metadata, so it is checked rather than trusted.
- `docs/CITABILITY.md`, recording the archival plan: no DOI is minted for a
  release candidate, the clean-provenance tier is the only one eligible for an
  open-access dataset deposit, and the Zenodo webhook choice is one-time and
  irreversible.
- `docs/RELEASE_CHECKLIST.md`, enumerating the `v1.0.0` promotion steps. Three
  files now carry a version string and nothing enforces that they agree; because
  a Zenodo deposit is immutable, a missed bump would permanently disagree with
  the repository's own citation metadata. The checklist also records which steps
  are irreversible and flags the `source-review.yml` cadence switch that has to
  land after the release rather than in it.

### Changed

- The README Releases section named `v1.0.0-rc.1` as the candidate under burn-in;
  corrected to `v1.0.0-rc.3` and made explicit which change classes restart the
  window.
- The README `## License` section now states per-tier data terms in a table
  rather than a single sentence. Code is MIT; feed data is not uniformly
  licensed and cannot be relicensed by aggregation, so the primary, clean, and
  non-commercial tiers are described separately with links to their generated
  licence manifests.

### Fixed

#### Pipeline
- Carry-forward no longer skips a sighting from earlier the same UTC day
  (ADR-054). Observation timestamps are truncated to the day, so a source seen on
  an earlier run of the same day had an age of exactly `0.0` — which the guard
  `age_days <= 0.0` discarded along with genuinely nonsensical negative ages. The
  effect was that carry-forward worked on the first run of each day and was
  silently inert on the other three: a source missing from a mid-day fetch had
  neither a fresh observation nor a carried one, so its independence class
  vanished and every record relying on it was demoted until the next UTC midnight.
  This was the exact regression `carried_observations` was added to prevent
  (ADR-037). Only negative ages are rejected now.

  The visible symptom was a sawtooth in feed size — 6,898 published records at
  01:58 UTC on 2026-08-24 against 6,324 at 13:14, a 9% swing driven purely by
  sampling time. Published volume now settles higher and flatter. That is a
  correction rather than an inflation: the affected records always had the
  corroboration, and the pipeline was failing to count it.

  Per-run churn measurements taken before this fix are overstated and should not
  be cited.

## [1.0.0-rc.3] — 2026-08-19

Third release candidate. The rc.2 burn-in window showed that ADR-052 had stated
the right invariant — fetch time is not evidence time — but only implemented half
of it. A stale or dormant source could not solo-promote, yet it still voted at
full weight and its independence class still counted toward the two classes
required to publish. ADR-053 closes both halves: evidence nobody is vouching for
today is non-admitting.

### Fixed

#### Pipeline
- Unvouched evidence is now non-admitting (ADR-053). ADR-052 stopped a stale or
  dormant source solo-promoting, but its independence class still counted toward
  the two classes required to publish — so an address could be admitted on one
  live source plus an upstream frozen months earlier. Stale and dormant classes
  now join the same non-admitting lane as licence-restricted sources: they may
  upgrade a record that already qualifies on live corroboration, never admit one.
- Stale and dormant votes are actually damped now (ADR-053). ADR-052 described
  corroboration "at a decayed weight", but `recency_factor` decays on
  `last_seen`, which equals the current run on every successful fetch — so a
  frozen upstream voted at full strength indefinitely. A new
  `STALE_EVIDENCE_FACTOR` (0.2, matching `recency_factor`'s floor) applies the
  intended decay.
- Promotion, vote damping, and the admission lane now derive from a single
  `evidence_vouched` predicate, so the three gates cannot drift apart.

#### Dashboard
- Restored the console and analysis footer's vertical padding, which gave the
  licence-tier block visibly cramped spacing beneath the about section. The
  `footer` rule set `padding: 26px 0 44px`, but `<footer class="shell">` meant
  `.shell`'s own `padding` shorthand won on specificity and zeroed it. Now set as
  longhand on `footer.shell`, which preserves `.shell`'s responsive horizontal
  padding at every breakpoint and in print.
- Increased the about band's bottom padding for a balanced transition into the
  footer.

### Changed
- `restricted_corroboration` now counts unvouched classes as well as
  licence-restricted ones. Source names remain omitted, for the same disclosure
  reason as before.
- `uv.lock` corrected: it still recorded the project version as `1.0.0rc1` after
  the rc.2 bump.

## [1.0.0-rc.2] — 2026-08-18

Second release candidate. The rc.1 burn-in window caught a source (Feodo
Tracker) that had been stale for 166 days but could still solo-promote IPs
into the published feed on old evidence. ADR-052 generalises the fix into a
standing policy: fetch time is not evidence time.

### Added

#### Pipeline
- Freshness-gated promotion (ADR-052): a source whose HTTP Last-Modified
  exceeds `min(30 days, ttl_days)` cannot solo-promote. Stale-evidence
  observations may still vote and corroborate at a decayed weight, but cannot
  put IPs into the high-confidence feed on their own.
- Dormant source state (ADR-052): a source marked `dormant: true` in
  `sources.yaml` stays enabled for corroboration but cannot solo-promote, and
  the recurring staleness warning is downgraded to an informational log line.
  Reactivation requires a maintainer review and removing the flag.
- Source lifecycle and discovery policy (`docs/source-lifecycle.md`): defines
  five lifecycle states (Active, Stale watch, Dormant, Retired, Reactivated),
  freshness thresholds, and a recurring source discovery review process with
  documented admission criteria.
- Source discovery review workflow (`.github/workflows/source-review.yml`):
  opens a recurring GitHub issue with a review checklist. Monthly during RC
  burn-in, quarterly after v1.0.0. Does not auto-enable sources.

### Changed
- Feodo Tracker marked `dormant: true`. The families it tracks (Emotet, Dridex,
  TrickBot, QakBot, BazarLoader) have almost no live C2 left after the 2021
  Emotet takedown and Operation Endgame (2024–2026). Its 5 solo-promoted
  records fall out of the high-confidence feed unless fresh evidence from
  another source corroborates them.
- Staleness threshold now uses `min(STALENESS_DAYS, source.ttl_days)` instead
  of a flat 30-day ceiling, so short-TTL sources are caught sooner.
- Dashboard text dedup: removed redundant licence-tier, attribution, and
  false-positive text that appeared two or three times across the about
  section, licensing section, and shared footer. Each piece of information now
  appears once.

### Notes
- This is a `sources.yaml` + scoring-code change that restarts the RC burn-in
  clock.
- ADR-052 supersedes the Feodo-specific note from the 2026-08-15 review pass.

## [1.0.0-rc.1] — 2026-08-18

First candidate for a stable release. The pipeline has run unattended on a
six-hour schedule since 2026-08-12, publishing primary, non-commercial, and
clean-provenance feeds with watchdogs in place. This tag opens a roughly
one-month burn-in window; if no corrective work is needed it will be promoted
to `1.0.0` unchanged.

### Added

#### Pipeline
- Automated collect → normalize → score → filter → emit pipeline, declared in
  `sources.yaml` and run every six hours by GitHub Actions (#4, #8, #9).
- Independence-weighted scoring: only the strongest contribution within a source
  family counts, so mirrored and aggregated public blocklists cannot manufacture
  corroboration (#9).
- Restricted sources may upgrade an indicator's confidence band but can never
  independently admit a record or have their identity published (#13).
- ThreatFox collector plus a compromised-host safeguard (#10).
- AbuseIPDB blacklist collector, consumed for scoring only (#20).
- GreyNoise benign-scanner handling that caps confidence from high to medium
  rather than deleting the record, preserving the consumer's policy choice (#22).
- `benign_scanners_capped` surfaced in the manifest, not only the run report (#23).
- Local cache-seeding helper for offline development (#22).

#### Feeds and licensing
- Per-source licence verification, a separate non-commercial tier, and the
  IPThreat source (#14).
- Clean-provenance tier accepting only sources with a named written licence
  permitting commercial redistribution, with a generated licence-and-credit
  manifest (#24).
- Licence re-audit admitting DataPlane and DShield and rejecting two redundant
  aggregators (#21).
- Aggregate-only credit for sources whose terms grant no redistribution, plus
  published aggregate statistics (#15, #16).
- Dual-track IPv6 support: suffixed `-v4` and `-v6` files alongside stable
  combined URLs, IPv6-aware lookup, a dedicated `iptables6` output, and
  reach-based aggregation expressed in covered `/64` networks (#26, #27).
- Output formats: plain text by confidence band, CSV, JSON, JSON Schema,
  STIX 2.1 bundle, MISP manifest, `iptables`/`ipset`, and `nftables`.

#### Dashboard
- Reader-facing dashboard on GitHub Pages with IP lookup and integration
  examples (#12).
- IPv4 address-spectrum view, run timeline, and ASN windows ranked by
  persistence (#17, #19).
- Operator console plus a separate analysis surface, with a data-first hero and
  consolidated history charts (#29, #33, #34).
- Rationale moved into a reader's guide so the page itself carries data (#31).

#### Operations
- Heartbeat watchdog comparing the committed manifest against the one served by
  GitHub Pages, alerting after four missed refreshes (#28).
- Weekly keepalive protecting the scheduled workflow from GitHub's
  inactivity-based disablement of public-repository schedules (#28).
- Refresh pushes rebase and retry instead of failing when a manual and a
  scheduled run race on `main` (#25).
- Pages publication fallback path and a way to republish on code change (#32).

#### Project
- README, architecture decisions, and a locked source registry (#1, #2).
- `AGENTS.md`, a dependency-ordered task pack, and recorded real-world fixtures
  so coding-agent work stays aligned and tests stay network-free (#3).

### Changed
- FireHOL Level 1 and Emerging Threats compromised IPs disabled after overlap
  analysis; IPsum demoted to a corroboration prior (#2).
- Wide analysis tables wrapped in scroll containers for mobile (#35).

### Removed
- Registration-country mapping, because ASN registration location does not
  establish traffic origin (#18).

### Notes
- Failing checks are repaired rather than suppressed. Disabling, ignoring, or
  loosening a check to make it green is not an accepted fix, and defects found
  by manual review get a regression test.
- No unit test touches the network.

[Unreleased]: https://github.com/neilweitzel/xfeeds/compare/v1.0.0-rc.3...HEAD
[1.0.0-rc.3]: https://github.com/neilweitzel/xfeeds/releases/tag/v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/neilweitzel/xfeeds/releases/tag/v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/neilweitzel/xfeeds/releases/tag/v1.0.0-rc.1

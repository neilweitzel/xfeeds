# Changelog

All notable changes to xfeeds are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versioning applies to the **pipeline and its published contracts** — feed paths,
record schema, and manifest fields — not to the feed contents, which change every
six hours by design. A consumer pinning a tag still fetches the same live URLs.

## [Unreleased]

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

# Post-release quality audit

## Conclusion

No release-blocking implementation defect was found in this audit. v1.0.0 and
v1.0.1 remain stable releases; no tag was moved, no source was enabled, and no
new burn-in was started. This is verified evidence with a stated boundary, not
a guarantee that GitHub or upstream providers cannot fail.

## Checks repeated

| Check | Result |
|---|---|
| Remote annotated tags | v1.0.0 peels to `b65cf654f0fcb027c3ccd4eb868f13314dc6b833`; v1.0.1 to `548f6d94e1ae344d6015e09d5f88ada00ef5aeed` |
| Current production code | Main differs from v1.0.1 only in documentation; runtime, source config, workflows, package/lock/CFF agree |
| Local quality | 293 tests, strict mypy, lint, formatting, locked dependency sync all pass |
| Packaging | v1.0.1 source distribution and wheel build successfully |
| GitHub CI | All four Python jobs (3.11–3.14) and citation checks pass; latest audited main run `37317966916` |
| Live file equality | Eight files matched committed bytes: manifest, combined JSON, four IPv4/IPv6 band files, clean and noncommercial manifests |
| Feed integrity | All 10,239 primary, 17,527 noncommercial, and 134 clean records pass model validation, uniqueness, global-address, band-count, family-split and configured source-rights checks |
| Source health | 23 active sources OK; Feodo is the sole acknowledged expiry; IPv6 feed has 91 high-confidence records |
| Archival identity | Downloaded Zenodo tarball reproduces the expected SHA-256 and embedded v1.0.0 commit |
| Archival metadata | v1.0.0, 2026-10-05, MIT software, one creator with correct ORCID, same concept record, one file |
| ORCID | New version DOI present, DataCite listed as source |
| Open work | No open issues or PRs at audit start; this audit's documentation PR is separate |

Evidence: [release history](https://github.com/neilweitzel/xfeeds/releases),
[CI run](https://github.com/neilweitzel/xfeeds/actions/runs/37317966916),
[live manifest](https://neilweitzel.github.io/xfeeds/manifest.json),
[Zenodo record](https://zenodo.org/records/23163156),
[ORCID](https://orcid.org/0009-0007-2546-2331).
The record-level checks establish internal consistency and configured rights
enforcement, not ground-truth maliciousness for every address.

## Corrections made without changing production

- Removed obsolete pre-release freeze/eligibility wording from the backlog.
- Corrected the dashboard guide's HIGH threshold and active-source denominator.
- Corrected the future promotion-config task: the scorer has an abuse.ch branch
  as well as Spamhaus, so a refactor must not silently remove that behavior.
- Added the previously discussed retention telemetry and AbuseIPDB expansion
  experiment to the canonical repository backlog.
- Flagged the free-only discovery wording for reconciliation before paid-source
  evaluations. No paid access is approved or purchased by this audit.

## Remaining verification boundary

The first complete automatic reservation/fetch/commit/deploy cycle under v1.0.1
has not yet occurred. The live guard's premature-dispatch skip passed, and local
tests cover admission, quota persistence, failures, UTC rollover, and missed
slots. The next eligible hourly opportunity is October 5 at 19:17 UTC
(3:17 PM EDT), subject to GitHub delays. Existing heartbeat and Pages fallback
remain in place; no outside monitoring task was created.

## Next minor and source review

The proposed next minor is v1.1.0, not another v1.0.0 release candidate.
Its scope and release date remain proposals in
[`POST_BURN_IN_BACKLOG.md`](POST_BURN_IN_BACKLOG.md#proposed-next-minor-v110).

Wait until the October 8 review before starting source-admission changes.
The scheduled workflow opens an issue at 09:00 UTC (5:00 AM EDT), not an
automatic promotion. Evaluate Spur's private corroboration-only trial,
AbuseIPDB's larger-corpus experiment, and a second IPv6 admitting source.
Current-source health/licensing review, commercial evaluation lanes, and a
persistent candidate register come before any admission.

Keep measurement, scorer refactoring, and source admissions in separate PRs.
The 30-day retention study and 14–30-day Spur evaluation are evidence windows
for those changes, not extensions of the already completed stable-release burn-in.

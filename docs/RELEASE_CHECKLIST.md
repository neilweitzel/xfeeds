# Stable release checklist

The October 2026 execution record is
[`RELEASE_2026-10-05.md`](RELEASE_2026-10-05.md). The v1.0.0 baseline is rc.7 plus
PR #55, not rc.6. Operational changes after promotion get their own patch tag.

## Verify the baseline

- Review changes against the candidate:
  `git diff --name-only v1.0.0-rc.7..HEAD -- sources.yaml src/ .github/workflows/`.
  Record every nonempty result rather than assuming documentation makes it safe.
  The owner-approved PR #55 disposition applies only to this release; see
  [`source-lifecycle.md`](source-lifecycle.md#what-restarts-the-rc-burn-in-clock).
- Run `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy --strict src tests`, `uv run pytest`,
  `uv run xfeeds validate`, and `python3 scripts/check_version_agreement.py`.
- CI must pass on the release commit. Review open issues/PRs and false positives.
- Check recent Update feeds, Publish to Pages, and Heartbeat outcomes.
  A successful stood-down run is not a successful refresh.
- Compare the committed and live
  [manifest](https://neilweitzel.github.io/xfeeds/manifest.json); they must agree
  and `generated_at` must be under 12 hours old at promotion.
- Confirm `source-freshness.json` persists and changes selectively, acknowledged
  expiry is distinguished from unreviewed expiry, and `spamhaus_drop_v6` is fresh.

## Version and publish

- Bump `pyproject.toml`, regenerate `uv.lock`, update `CITATION.cff` version and
  actual release date, and update README, CHANGELOG, and release body together.
- Keep the concept DOI in CFF. Only list a version DOI when it describes the
  same version as CFF; older version DOIs belong in `CITABILITY.md`.
- Merge the reviewed release PR after CI, tag that exact commit, and publish a
  full GitHub release, not a prerelease. Never move an existing release tag.
- The v1.0.0 tag preserves the burned-in baseline. Scheduler hardening and the
  quarterly source-review switch follow under v1.0.1.

## Zenodo archival: irreversible publication

This record is API-managed, not webhook-managed. See
[`CITABILITY.md`](CITABILITY.md) and the
[Zenodo REST API documentation](https://developers.zenodo.org/).

- Validate the approved vault credential without logging it.
- Discover the latest published version under concept record `22045733`.
  Initially that is version `22045734` (rc.3). Call `newversion` on the latest
  **version ID**, never on the concept ID.
- Follow the returned `links.latest_draft`. Reuse an existing draft after an
  interruption rather than creating competing drafts.
- Inspect inherited files. Remove the old tarball from the **unpublished draft**
  before upload; never delete a published record.
- Build from the exact release tag, not a working tree. A software-only archive
  excludes generated `feeds/`, `legacy/`, and recorded upstream fixture payloads.
  The omission of source-response fixtures means a full fixture-based test run
  requires the GitHub checkout. Do not describe the archive as a feed dataset or
  silently apply MIT to upstream data.
- Copy authorship, description, keywords, licence, and related identifiers from
  `.zenodo.json`; explicitly set the archived version and publication date in
  the API payload. `.zenodo.json` deliberately has no version field.
- Verify draft title, version, date, MIT software licence, one creator
  (`Weitzel, Neil`, ORCID `0009-0007-2546-2331`), and exactly one correct tarball.
  Verify uploaded file size and checksum.
- Obtain approval for the exact draft and file before `actions/publish`.
  **Publication is irreversible.** An API credential approval alone is not
  publication approval.
- Verify the published record and concept-version relationship. Add the version
  DOI to README and `CITABILITY.md`; add to CFF only if CFF still names that version.
- Verify DataCite propagation on [ORCID](https://orcid.org/0009-0007-2546-2331).
  If delayed, record pending verification; do not claim success or add it by hand.

## Close out

- Confirm live deployment, matching manifests, heartbeat and version agreement.
- Switch source reviews to `0 9 8 1,4,7,10 *` after stable promotion.
  October 8 remains scheduled.
- Update the canonical backlog and release record with outcomes and remaining
  approvals. Do not silently fold source trials or scoring changes into release.
- An optional dataset deposit is distinct and must contain `feeds/clean/` only.

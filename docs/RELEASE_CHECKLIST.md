# v1.0.0 release checklist

Promoting the final release candidate to `v1.0.0`. This is the first release that gets archived with a permanent identifier, so several steps here are irreversible — they are marked.

Companion documents: [`CITABILITY.md`](CITABILITY.md) for why archival is sequenced this way, [`source-lifecycle.md`](source-lifecycle.md) for the source review policy, and [`CHANGELOG.md`](../CHANGELOG.md) for release history.

---

## 1. Confirm the burn-in window closed cleanly

- [ ] At least one month has elapsed since the current candidate was tagged. `v1.0.0-rc.4` was tagged **2026-08-24**, so the window closes on or after **2026-09-24**.

  Earlier candidates, for context: `rc.3` was tagged 2026-08-19 and its window was cut short by ADR-054, a scoring fix for a carry-forward defect that had been demoting records on three runs out of every four. Finding that during burn-in is the window working as intended, not a setback.
- [ ] No change to `sources.yaml` or `src/` has landed since the candidate was cut. Per [`source-lifecycle.md`](source-lifecycle.md), **any** change to either restarts the clock — not only corrective ones. Workflow changes restart it too. Documentation-only changes and routine refresh commits do not.
- [ ] `git log v1.0.0-rc.4..main --oneline` shows only routine `chore(feeds): refresh` commits, plus any docs-only commits.
- [ ] CI is green on `main`.
- [ ] The last four scheduled cycles each show Update feeds → Publish to Pages → Heartbeat all succeeding.
- [ ] No open pull requests and no unresolved issues, including no open false-positive reports.
- [ ] The live manifest at [neilweitzel.github.io/xfeeds/manifest.json](https://neilweitzel.github.io/xfeeds/manifest.json) has a `generated_at` within the last six hours, and the committed manifest matches it.

If any box fails, fix the cause and cut `rc.5` rather than releasing.

### The 1 September source review falls inside this window

`source-review.yml` opens a review issue on the first of each month during burn-in. For the `rc.4` window that lands on **2026-09-01**, a little over three weeks before the window closes.

Opening the issue is harmless — the workflow does not auto-enable anything, it only prompts a human review. The decision point is what gets merged afterward:

| Review outcome | Effect on `v1.0.0` |
|---|---|
| Review completed, nothing merged | None. Release proceeds on schedule. |
| A candidate source admitted (`sources.yaml` PR) | Restarts burn-in from the merge date. Release slips roughly a month. |
| A source marked dormant or retired (`sources.yaml`) | Same — restarts the clock. |
| Findings recorded, admission PRs held | None. Release proceeds; merge the admissions after `v1.0.0`. |

The default is to **run the review and hold any admission PRs until after promotion**. Admission is additive work with no deadline, and a source admitted the week before a release has had no burn-in of its own.

One exception: if the review finds a source *admitting bad data* — repeated false positives traceable to it — that is corrective. Fix it immediately and accept the slip, because a release that publishes known-bad indicators is worse than a late release.

The review report template already requires a statement of whether the clock restarts, so record the decision there.

## 2. Bump every version reference together

Three places carry a version and **nothing enforces that they agree**. Missing one leaves the Zenodo record permanently disagreeing with the repository's own citation metadata.

- [ ] `pyproject.toml` → `version = "1.0.0"` (currently `1.0.0rc3`)
- [ ] `CITATION.cff` → `version: 1.0.0`
- [ ] `CITATION.cff` → `date-released: "YYYY-MM-DD"`, set to the actual release date
- [ ] The git tag itself → `v1.0.0`

`.zenodo.json` deliberately carries no version field — Zenodo derives it from the tag. Leave it alone.

Verify after editing:

```bash
grep -E '^(version|license)' pyproject.toml
grep -E '^(version|date-released|license):' CITATION.cff
cffconvert --validate -i CITATION.cff
```

## 3. Update stale prose

- [ ] `README.md` — the Releases section names the current candidate as being under burn-in, and explains that `rc.4` exists because of ADR-054. Update it to describe `v1.0.0` as released, and drop the burn-in sentences.
- [ ] `README.md` — the `## Citation` section carries an interim repository citation naming the current candidate version. Replace it with the resolved DOI citation once minted (step 6).
- [ ] `CHANGELOG.md` — move everything under `## [Unreleased]` into a new `## [1.0.0] — YYYY-MM-DD` section, leaving `[Unreleased]` empty. The metadata work from PR #42 currently sits there.

## 4. Prepare Zenodo — the API path

The `rc.3` deposit was created through the Zenodo REST API rather than the GitHub webhook, because GitHub's sudo-mode 2FA blocked the webhook authorisation. `v1.0.0` follows the same path — a Zenodo record cannot switch from API-managed to webhook-managed after the fact.

Note that `rc.4` was deliberately **not** deposited to Zenodo. Release candidates do not need DOIs, and the existing concept DOI already resolves to the newest published version; minting a DOI per candidate would clutter the record's version history for no benefit.

- [ ] Confirm the Zenodo access token is still valid. The `xfeeds-deposit` token has scopes `deposit:write` and `deposit:actions`. If it has been revoked, create a new one under [Applications → Personal access tokens](https://zenodo.org/account/settings/applications/) and register it in the credentials vault as `zenodo.org`.
- [ ] Note the concept record ID `22045733` — the new version is created against this record, not against the version-specific `22045734`.
- [ ] Confirm `.zenodo.json` on `main` reflects the version being released. Zenodo's REST API respects the metadata sent with the deposit, not the file on disk, so the actual authority is the JSON in the API call — but keeping the checked-in file in sync avoids drift.

## 5. Tag and release

- [ ] Land steps 2 and 3 on `main` in a single release commit.
- [ ] Tag `v1.0.0` on that commit and push the tag.
- [ ] Publish the GitHub release. Follow the existing pattern in `docs/release-1.0.0-rc.4-body.md` for the release body, and add a corresponding `docs/release-1.0.0-body.md`.
- [ ] Mark it a full release, **not** a pre-release — this is what distinguishes it from the candidates.

## 6. Publish and wire the new version DOI back in

Run the API sequence against the existing concept record `22045733`:

```bash
# 1. Create a new-version draft of the concept record
curl -X POST \
  https://zenodo.org/api/deposit/depositions/22045734/actions/newversion
# response contains links.latest_draft, which is the new draft's URL

# 2. Fetch that draft to get its new id and bucket URL
# 3. Upload the v1.0.0 source tarball to the bucket
# 4. PUT updated metadata (version, publication_date, notes)
# 5. POST /actions/publish on the new draft
```

All five calls take `api_credentials=["custom-cred:zenodo.org"]` — the token stays out of the shell.

- [ ] The new version DOI is issued. The concept DOI (`10.5281/zenodo.22045733`) now resolves to it automatically.
- [ ] Record the new version DOI. Allow about a day for it to resolve through doi.org.
- [ ] Check the record's author list shows only Neil Weitzel with the ORCID iD attached, no bot accounts.
- [ ] Confirm the record's licence reads MIT.
- [ ] Update the DOI badge line in `README.md` — the badge already tracks the concept DOI, so only the version-specific reference below it needs updating.
- [ ] Update the version DOI entry under `identifiers:` in `CITATION.cff`.
- [ ] Bump `date-released` in `CITATION.cff` to match the tag date.

## 7. Confirm the ORCID side

DataCite auto-update is already enabled and DataCite is a trusted party on the ORCID record, so this should require no action — only verification.

- [ ] The Zenodo DOI appears under Works on [the ORCID record](https://orcid.org/0009-0007-2546-2331).
- [ ] It carries the green verified check mark with DataCite as the source. If it is instead attributed to Neil, it was added manually and should be removed and left to auto-update.
- [ ] Do **not** add the work by hand. Auto-update only fires for DOIs registered after the token was enabled, and only when the ORCID iD sits in the DOI's `creators` metadata — which `.zenodo.json` ensures.

## 8. Switch the source review cadence

- [ ] `.github/workflows/source-review.yml` — the schedule is monthly during burn-in and must be switched to quarterly after promotion. The file documents this inline; change the cron from `0 9 1 * *` to `0 9 1 */3 *`.

Note this is a workflow change, so land it **after** the release is cut rather than in the release commit.

## 9. Post-release, optional

- [ ] **Dataset deposit.** A dated, immutable snapshot as a separate Zenodo deposit with upload type `dataset`, related to the software concept DOI by `isSupplementTo`. Deposit **`feeds/clean/` only** — it is the only tier whose sources grant written redistribution permission including commercial use. See `CITABILITY.md` for why the primary and non-commercial tiers are ineligible.
- [ ] **Version-agreement CI guard.** Extend the `citation` job to assert that `pyproject.toml` and `CITATION.cff` report the same version, so step 2 cannot silently drift in future releases.
- [ ] **Methods write-up.** The independence-class model, freshness-gated promotion, and redistribution-aware publication are the citable contributions. See `CITABILITY.md`.

---

## Irreversible steps, summarised

| Step | Why it cannot be undone |
|---|---|
| Enabling the Zenodo webhook | An existing record cannot be bound to the integration afterward, and no DOI can be pre-reserved for a webhook release |
| Publishing the Zenodo record | Files are frozen; corrections require a new version, and the original DOI persists |
| Any version mismatch at step 2 | The archived snapshot's metadata is immutable, so a wrong version string is permanent |

Everything else — tags, releases, README and CHANGELOG edits — can be corrected after the fact.

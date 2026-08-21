# v1.0.0 release checklist

Promoting the final release candidate to `v1.0.0`. This is the first release that gets archived with a permanent identifier, so several steps here are irreversible — they are marked.

Companion documents: [`CITABILITY.md`](CITABILITY.md) for why archival is sequenced this way, [`source-lifecycle.md`](source-lifecycle.md) for the source review policy, and [`CHANGELOG.md`](../CHANGELOG.md) for release history.

---

## 1. Confirm the burn-in window closed cleanly

- [ ] At least one month has elapsed since the current candidate was tagged. `v1.0.0-rc.3` was tagged **2026-08-19**, so the window closes on or after **2026-09-19**.
- [ ] No change to `sources.yaml` or `src/` has landed since the candidate was cut. Per [`source-lifecycle.md`](source-lifecycle.md), **any** change to either restarts the clock — not only corrective ones. Workflow changes restart it too. Documentation-only changes and routine refresh commits do not.
- [ ] `git log v1.0.0-rc.3..main --oneline` shows only routine `chore(feeds): refresh` commits, plus any docs-only commits.
- [ ] CI is green on `main`.
- [ ] The last four scheduled cycles each show Update feeds → Publish to Pages → Heartbeat all succeeding.
- [ ] No open pull requests and no unresolved issues, including no open false-positive reports.
- [ ] The live manifest at [neilweitzel.github.io/xfeeds/manifest.json](https://neilweitzel.github.io/xfeeds/manifest.json) has a `generated_at` within the last six hours, and the committed manifest matches it.

If any box fails, fix the cause and cut `rc.4` rather than releasing.

### The 1 September source review falls inside this window

`source-review.yml` opens a review issue on the first of each month during burn-in. For the `rc.3` window that lands on **2026-09-01**, about two and a half weeks before the window closes.

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

- [ ] `README.md` — the Releases section names `v1.0.0-rc.1` as the candidate under burn-in. Update it to describe `v1.0.0` as released, and drop the burn-in sentence.
- [ ] `README.md` — the `## Citation` section carries an interim repository citation reading "Version 1.0.0-rc.3". Replace it with the resolved DOI citation once minted (step 6).
- [ ] `CHANGELOG.md` — move everything under `## [Unreleased]` into a new `## [1.0.0] — YYYY-MM-DD` section, leaving `[Unreleased]` empty. The metadata work from PR #42 currently sits there.

## 4. Prepare Zenodo — before tagging

Do this **before** creating the release, because the webhook only archives releases published after the repository is enabled.

- [ ] Sign in at [zenodo.org](https://zenodo.org/) using **Log in with ORCID**, not GitHub, so the account is bound to ORCID iD [0009-0007-2546-2331](https://orcid.org/0009-0007-2546-2331) from the start.
- [ ] Profile menu → GitHub → **Sync now** → toggle `neilweitzel/xfeeds` **on**.
- [ ] Confirm the webhook appears under repository Settings → Webhooks.
- [ ] Confirm `.zenodo.json` is present on `main`. Without it, Zenodo builds the author list from repository contributors and credits coding-agent and automation commits as authors.

**Irreversible:** an existing Zenodo record cannot later be bound to the GitHub integration, and a DOI cannot be pre-reserved for a webhook-triggered release. Choosing the webhook path here forecloses the manual-upload path.

## 5. Tag and release

- [ ] Land steps 2 and 3 on `main` in a single release commit.
- [ ] Tag `v1.0.0` on that commit and push the tag.
- [ ] Publish the GitHub release. Follow the existing pattern in `docs/release-1.0.0-rc.3-body.md` for the release body, and add a corresponding `docs/release-1.0.0-body.md`.
- [ ] Mark it a full release, **not** a pre-release — this is what distinguishes it from the candidates.

## 6. Confirm the DOI and wire it back in

- [ ] Zenodo shows the repository as received, then published. Allow up to an hour for the DOI to be issued and about a day for it to resolve through doi.org.
- [ ] Record both DOIs. Zenodo issues a **version DOI** for this exact snapshot and a **concept DOI** that always resolves to the newest version.
- [ ] Check the Zenodo record's author list shows only Neil Weitzel with the ORCID iD attached, and no bot or agent accounts.
- [ ] Confirm the record's licence reads MIT.
- [ ] Add the DOI badge to `README.md`:
      `[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)`
- [ ] Replace the interim citation in the README `## Citation` section with the concept DOI. Cite the concept DOI in prose; cite the version DOI where reproducibility matters.
- [ ] Add `identifiers:` to `CITATION.cff` carrying the concept DOI, so the "Cite this repository" button emits a DOI-bearing citation.

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

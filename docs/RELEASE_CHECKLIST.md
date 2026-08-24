# v1.0.0 release checklist

Promoting the final release candidate to `v1.0.0`. This is the first release that gets archived with a permanent identifier, so several steps here are irreversible — they are marked.

Companion documents: [`CITABILITY.md`](CITABILITY.md) for why archival is sequenced this way, [`source-lifecycle.md`](source-lifecycle.md) for the source review policy, and [`CHANGELOG.md`](../CHANGELOG.md) for release history.

---

## 1. Confirm the burn-in window closed cleanly

- [ ] At least one month has elapsed since the current candidate was tagged. `v1.0.0-rc.4` was tagged **2026-08-24**, so the window closes on or after **2026-09-24**.

  Earlier candidates, for context: `rc.3` was tagged 2026-08-19 and its window was cut short by ADR-054, a scoring fix for a carry-forward defect that had been demoting records on three runs out of every four. Finding that during burn-in is the window working as intended, not a setback.
- [ ] Nothing has landed since the candidate was cut that restarts the clock. [`source-lifecycle.md`](source-lifecycle.md#what-restarts-the-rc-burn-in-clock) is the authoritative list: `sources.yaml`, anything under `src/`, and anything under `.github/workflows/` all restart it, corrective or not. Documentation, citation metadata, and routine refresh commits do not.
- [ ] `git log v1.0.0-rc.4..main --oneline` shows only routine `chore(feeds): refresh` commits, plus any docs-only commits.
- [ ] CI is green on `main`.
- [ ] The last four scheduled cycles each show Update feeds → Publish to Pages → Heartbeat all succeeding.
- [ ] No open pull requests and no unresolved issues, including no open false-positive reports.
- [ ] The live manifest at [neilweitzel.github.io/xfeeds/manifest.json](https://neilweitzel.github.io/xfeeds/manifest.json) has a `generated_at` within the last **eight** hours, and the committed manifest matches it.

  Eight rather than six deliberately. `update-feeds.yml` is scheduled `17 */6 * * *`, so four runs a day is the intent, but GitHub's scheduled-workflow queue runs late under load: observed gaps between consecutive runs over 2026-08-19 to 2026-08-24 ranged from 5.03h to **7.17h**, median 5.8h. A six-hour bound would fail this check on a perfectly healthy pipeline.

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

**Four** places carry a version and **nothing enforces that they agree**. Missing one leaves the Zenodo record permanently disagreeing with the repository's own citation metadata, and the Zenodo record is immutable.

- [ ] `pyproject.toml` → `version = "1.0.0"` (currently `1.0.0rc4`)
- [ ] `CITATION.cff` → `version: 1.0.0` (currently `1.0.0-rc.3`, deliberately — see below)
- [ ] `CITATION.cff` → `date-released: "YYYY-MM-DD"`, set to the actual release date
- [ ] The git tag itself → `v1.0.0`
- [ ] The `version` field in the **Zenodo API metadata payload** at step 6. This is the one that ends up permanently in the archived record.

### Why `CITATION.cff` currently disagrees with `pyproject.toml`

This is intentional and is not the drift this section warns about. `pyproject.toml` names the **pipeline** version (`1.0.0rc4`). `CITATION.cff` names the most recent **archived** version a reader can actually retrieve (`1.0.0-rc.3`), because its `identifiers:` block carries the version DOI for that archive. Candidates after `rc.3` are not deposited individually, so bumping the CFF to `rc.4` would advertise a version DOI that resolves to different code.

At `v1.0.0` the two converge, and the file carries an inline comment saying so. If you are reading this during promotion: set both to `1.0.0`, and remove that comment from `CITATION.cff` since it no longer applies.

### `.zenodo.json` carries no version field

That is deliberate, but not for the reason an earlier draft of this checklist gave. Zenodo does **not** derive the version from the git tag for this record — that only happens for webhook-managed deposits, and this record is API-managed (see step 4). The version reaches Zenodo through the metadata payload you `PUT` in step 6, and that payload is the sole authority. `.zenodo.json` supplies authorship, licence, description, and keywords only.

So: leave `.zenodo.json` alone, and do not treat it as a version reference to keep in sync. Get the version right in the step 6 payload.

Verify after editing:

```bash
grep -E '^(version|license)' pyproject.toml
grep -E '^(version|date-released|license):' CITATION.cff
cffconvert --validate -i CITATION.cff
python3 scripts/check_version_agreement.py
```

That last script is also a CI gate, so a version mismatch fails the build rather than reaching Zenodo. It knows `CITATION.cff` may lag `pyproject.toml` during a candidate window and only demands exact agreement once `pyproject.toml` names a final release — which is this step. It also asserts the CFF's `version` agrees with the version its own version-DOI `description` names, so you cannot bump one without the other.

## 3. Update stale prose

- [ ] `README.md` — the Releases section names the current candidate as being under burn-in, and explains that `rc.4` exists because of ADR-054. Update it to describe `v1.0.0` as released, and drop the burn-in sentences.
- [ ] `README.md` — the `## Citation` section carries an interim repository citation naming the current candidate version. Replace it with the resolved DOI citation once minted (step 6).
- [ ] `CHANGELOG.md` — add a `## [1.0.0] — YYYY-MM-DD` section above `## [1.0.0-rc.4]`.

  Note that `[Unreleased]` is currently **empty**: the metadata work from PR #42 and the ADR-054 fix were both moved into the `[1.0.0-rc.4]` section when that candidate was cut. So unless new work has landed since, there is nothing to move — the `[1.0.0]` entry should state that `rc.4` was promoted unchanged and point at its section rather than duplicating it. If `[Unreleased]` does have content, that content is by definition a post-`rc.4` change, which means the burn-in clock restarted and you should not be releasing yet.

## 4. Prepare Zenodo — the API path

The `rc.3` deposit was created through the Zenodo REST API rather than the GitHub webhook, because GitHub's sudo-mode 2FA blocked the webhook authorisation. `v1.0.0` follows the same path — a Zenodo record cannot switch from API-managed to webhook-managed after the fact.

Note that `rc.4` was deliberately **not** deposited to Zenodo. Release candidates do not need DOIs, and the existing concept DOI already resolves to the newest published version; minting a DOI per candidate would clutter the record's version history for no benefit.

- [ ] Confirm the Zenodo access token is still valid. The `xfeeds-deposit` token has scopes `deposit:write` and `deposit:actions`. If it has been revoked, create a new one under [Applications → Personal access tokens](https://zenodo.org/account/settings/applications/) and register it in the credentials vault as `zenodo.org`.
- [ ] Note the concept record ID `22045733` — the new version is created against this record, not against the version-specific `22045734`.
- [ ] Confirm `.zenodo.json` on `main` still has the correct authorship, licence, and description. It carries no version field and needs none — see step 2. The authority for every field is the payload sent in the step 6 `PUT`, so treat the checked-in file as the template you copy from, not as the thing Zenodo reads.

## 5. Tag and release

- [ ] Land steps 2 and 3 on `main` in a single release commit.
- [ ] Tag `v1.0.0` on that commit and push the tag.
- [ ] Publish the GitHub release. Follow the existing pattern in `docs/release-1.0.0-rc.4-body.md` for the release body, and add a corresponding `docs/release-1.0.0-body.md`.
- [ ] Mark it a full release, **not** a pre-release — this is what distinguishes it from the candidates.

## 6. Publish and wire the new version DOI back in

Every call takes `api_credentials=["custom-cred:zenodo.org"]`, which injects the token through the HTTPS proxy — it never appears in the shell, in a file, or in a log. Do not paste the token into a command.

Three things about this API are easy to get wrong, all confirmed against the [Zenodo REST API documentation](https://developers.zenodo.org/):

1. **`newversion` must be called on the latest *version* id (`22045734`), not the concept id (`22045733`).** The concept id is rejected. This is the opposite of the intuition that you version the concept record.
2. **The response to `newversion` is the *original* resource, not the new draft.** The draft is at `links.latest_draft`.
3. **The new draft inherits a snapshot of the previous version's files.** So the `rc.3` tarball is already sitting in the draft. Delete it before uploading, or the published record permanently carries both. The documentation is explicit that replacing a file means delete-then-upload; there is no in-place replace.

Also: only one unpublished new-version draft can exist at a time, and repeated `newversion` calls are no-ops while it exists. If something goes wrong mid-sequence, find the existing draft rather than expecting a fresh one.

```bash
# 1. Create the new-version draft. Prints the draft URL.
curl -sS -X POST \
  "https://zenodo.org/api/deposit/depositions/22045734/actions/newversion" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['links']['latest_draft'])"

# 2. Fetch the draft. Capture its id (NEW_ID) and links.bucket (BUCKET_URL).
curl -sS "https://zenodo.org/api/deposit/depositions/NEW_ID" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['id'], d['links']['bucket'])"

# 3. Delete the inherited rc.3 tarball FIRST. List, then delete by id.
#    Expect 204 No Content.
curl -sS "https://zenodo.org/api/deposit/depositions/NEW_ID/files" \
  | python3 -c "import json,sys; [print(f['id'], f['filename']) for f in json.load(sys.stdin)]"
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE \
  "https://zenodo.org/api/deposit/depositions/NEW_ID/files/STALE_FILE_ID"

# 4. Build the tarball from the tag, not the working tree, so the archive
#    cannot contain uncommitted changes. Then upload to the bucket.
git archive --format=tar.gz --prefix=xfeeds-1.0.0/ -o /tmp/xfeeds-1.0.0.tar.gz v1.0.0
curl -sS -X PUT --upload-file /tmp/xfeeds-1.0.0.tar.gz \
  "BUCKET_URL/xfeeds-1.0.0.tar.gz"

# 5. PUT the metadata. Copy authorship, licence, description, and keywords from
#    .zenodo.json, then add `version` and `publication_date`. The `version`
#    here is what becomes permanent in the archived record.
curl -sS -X PUT "https://zenodo.org/api/deposit/depositions/NEW_ID" \
  -H "Content-Type: application/json" \
  -d @/tmp/zenodo-metadata-1.0.0.json

# 6. Verify the draft BEFORE publishing. Last reversible moment.
curl -sS "https://zenodo.org/api/deposit/depositions/NEW_ID" \
  | python3 -m json.tool \
  | grep -E '"(version|publication_date|license|title)"|orcid|"name"|filename'

# 7. Publish. IRREVERSIBLE. Expect 202 Accepted.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  "https://zenodo.org/api/deposit/depositions/NEW_ID/actions/publish"
```

- [ ] Before running step 7, confirm on the draft: `version` is `1.0.0`, exactly one creator (`Weitzel, Neil`) with the ORCID iD attached and no bot accounts, licence `MIT`, and **exactly one file** named `xfeeds-1.0.0.tar.gz`.

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
- [ ] **Methods write-up.** The independence-class model, freshness-gated promotion, and redistribution-aware publication are the citable contributions. See `CITABILITY.md`.

---

## Irreversible steps, summarised

| Step | Why it cannot be undone |
|---|---|
| Enabling the Zenodo webhook | An existing record cannot be bound to the integration afterward, and no DOI can be pre-reserved for a webhook release |
| Publishing the Zenodo record | Files are frozen; corrections require a new version, and the original DOI persists |
| Any version mismatch at step 2 | The archived snapshot's metadata is immutable, so a wrong version string is permanent. `scripts/check_version_agreement.py` now guards this in CI, but it cannot check the version inside the step 6 API payload — verify that by hand at step 6 item 6 |
| Publishing with the inherited `rc.3` tarball still attached | A new-version draft copies the previous version's files. Publish without deleting it and the record permanently contains two tarballs, one of which is not the released version. Step 6 item 3 exists for this |

Everything else — tags, releases, README and CHANGELOG edits — can be corrected after the fact.

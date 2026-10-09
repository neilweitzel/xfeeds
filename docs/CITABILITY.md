# Citability and archival

How xfeeds becomes citable research output, what is already in place, and what is deliberately deferred.

Author identity is anchored to ORCID iD [0009-0007-2546-2331](https://orcid.org/0009-0007-2546-2331).

---

## In place

| Component | File | Purpose |
|---|---|---|
| Code licence | `LICENSE` | MIT. Previously declared in the README but never present as a file, which blocked archival and made reuse terms unverifiable by tooling. |
| Packaging metadata | `pyproject.toml` | `license = "MIT"` and `license-files` so the SPDX identifier travels with the built distribution. |
| Citation metadata | `CITATION.cff` | CFF 1.2.0. Drives GitHub's "Cite this repository" button and is read as a metadata fallback by several archives. |
| Archive metadata | `.zenodo.json` | Authoritative author and licence metadata for a future Zenodo deposit. |
| CI enforcement | `.github/workflows/ci.yml` (`citation` job) | Validates the CFF against its schema, parses `.zenodo.json`, and asserts that the ORCID iD and licence agree across all three metadata files. |

Consistent with the project rule that failing checks are repaired rather than suppressed, the citation metadata is validated on every pull request rather than trusted to stay correct by hand.

### Why `.zenodo.json` exists before any Zenodo deposit

Without it, the Zenodo GitHub integration derives its author list from repository contributors. This repository's history includes coding-agent and automation commits, which would be credited as authors of the archived record. `.zenodo.json` overrides that inference, so it must be committed *before* the first archived release, not after.

---

## Archived releases

The project has one concept DOI and version-specific archive DOIs:

| DOI | Meaning |
|---|---|
| [10.5281/zenodo.22045733](https://doi.org/10.5281/zenodo.22045733) | **Concept DOI.** Always resolves to the newest published version. Cite this in prose. |
| [10.5281/zenodo.22045734](https://doi.org/10.5281/zenodo.22045734) | **Version DOI** for `v1.0.0-rc.3`. Cite where exact reproducibility matters. |
| [10.5281/zenodo.23163156](https://doi.org/10.5281/zenodo.23163156) | **Version DOI** for stable `v1.0.0`, published 2026-10-05. |

### Where to find a version DOI

This table is the record of version DOIs per release. `CITATION.cff` lists only the concept DOI, by design — see [ADR-055](DECISIONS.md). A concept DOI is version-agnostic, so it stays correct whatever version the file describes; a version-specific DOI would pin the file to one archive and force its `version` field to lag the pipeline whenever a candidate is not deposited. Keeping the version DOIs here instead means one version number is used everywhere in the repository, always.

Every version DOI is also discoverable from the concept DOI's Zenodo version list.

| Release | Archived | Version DOI |
|---|---|---|
| `v1.0.0-rc.3` | 2026-08-21 | [10.5281/zenodo.22045734](https://doi.org/10.5281/zenodo.22045734) |
| `v1.0.0-rc.4` | not deposited | — |
| `v1.0.0-rc.5` | not deposited | — |
| `v1.0.0` | 2026-10-05 | [10.5281/zenodo.23163156](https://doi.org/10.5281/zenodo.23163156) |
| `v1.0.1` | GitHub release only | Not deposited; operational patch |
| `v1.1.0-rc.1` | GitHub prerelease only | Not deposited; release candidate |
| `v1.1.0-rc.2` | GitHub prerelease only | Not deposited; release candidate |

Release candidates are not deposited by default. A version DOI may be added to
`CITATION.cff` only while its version matches that archive. Main now describes
v1.1.0-rc.2, so it retains the concept DOI and records the v1.0.0 version DOI here
rather than implying that a later version was archived.

### Verified v1.0.0 deposit

The owner approved publication on 2026-10-05. The published record contains
one file, `xfeeds-1.0.0.tar.gz` (408,658 bytes), from tag `v1.0.0` at
`b65cf654f0fcb027c3ccd4eb868f13314dc6b833`. The archive excludes generated
`feeds/`, `legacy/`, and `tests/fixtures/sources/` payloads; it archives software,
not an upstream feed dataset. For the full fixture-based test suite use the
GitHub tag. The GitHub tag itself was not changed to remove these directories.

SHA-256: `44fbc5cdb36add0972f94ee2420d0f352e9bd2cdd0ef7c78286ec1291558af18`.
The uploaded MD5 matches `0d9d250925aada0d76a182cda4c87254`.
Zenodo confirms one creator (Neil Weitzel with ORCID), MIT software licence,
version 1.0.0, and the existing concept record
([published record](https://zenodo.org/records/23163156)).
DataCite reports the DOI as `findable` with the same version and ORCID
([DOI metadata](https://api.datacite.org/dois/10.5281/zenodo.23163156)).
The [ORCID public record](https://orcid.org/0009-0007-2546-2331) now includes
`10.5281/zenodo.23163156` with DataCite as its source, verified through the public
Works API on 2026-10-05. No work was added manually.

`rc.3` was archived on 2026-08-21 through the Zenodo REST API rather than the
GitHub webhook. v1.0.0 was likewise archived by API; GitHub release publication
did not automatically create the deposit.

Release candidates were originally deferred, on the reasoning that a permanent identifier on a snapshot expected to change is the wrong artifact. That reasoning still holds for the version DOI, which is deliberately not being cited as the primary identifier. It does not hold for the concept DOI, which is version-agnostic and updated automatically when `v1.0.0` is archived. Publishing early therefore costs nothing that the concept-DOI abstraction does not already recover.

## `v1.0.0` promotion

The promotion procedure is enumerated step by step in
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md), including the version references that
must be bumped together. In outline, when `v1.0.0` is promoted:

1. Bump every version reference and cut the tag as documented in the release checklist.
2. Create a new version of the existing Zenodo record via the REST API, upload the `v1.0.0` source tarball, replace the metadata, and publish. This mints a new version DOI and updates the concept DOI to point at it.
3. The record's ORCID iD is unchanged, so DataCite auto-update pushes the new version DOI to the ORCID Works section automatically.
4. Update the DOI badge, the version-DOI line, and the `CITATION.cff` identifiers to reference the new version DOI. The concept DOI stays the same.

DataCite auto-update is already authorised on the ORCID record, so no further ORCID action is required.

---

## Dataset deposits

A dataset deposit is distinct from the software archive and is frequently the more-cited artifact. It is a dated, immutable snapshot rather than a live URL.

**Deposit the clean-provenance tier only.** `feeds/clean/` is the only tier whose sources carry written permission for redistribution including commercial use. Depositing the primary tier would republish material from publishers that have issued no reuse grant, and depositing the non-commercial tier into an open-access repository would conflict with its CC BY-NC-SA terms, since a Zenodo deposit cannot impose a non-commercial condition on downstream consumers.

A deposit should contain:

- the published indicator set at a fixed `generated_at` timestamp, in CSV and JSON
- `sources.yaml` as it stood, so independence classes are reconstructable
- the tier's generated `LICENSE.txt`
- a methodology note covering scoring, independence classes, freshness gating, and tier semantics

Upload type `dataset`, open access, with a `related_identifiers` entry using relation `isSupplementTo` pointing at the software concept DOI. Quarterly cadence is sufficient; feeds refresh every six hours and are not individually citable.

---

## Written output

The pipeline's methodological contributions — the independence-class model, freshness-gated promotion, and redistribution-rights-aware publication — are the citable ideas rather than the code. A methods write-up should quantify the counterfactual: feed composition under naive union, under raw source-count voting, and under independence-aware scoring, showing how much of a naively aggregated feed rests on a single sensor family.

The supporting numbers are all derivable from committed pipeline state and should be produced by a re-runnable analysis script in this repository rather than computed once by hand, so the evaluation stays reproducible as sources change.

Note for `cs.CR` submission: arXiv requires endorsement for a first submission to a category, expedited by an institutional email address. A Zenodo preprint deposit reaches a DOI and an ORCID entry with no endorsement gate and does not preclude a later arXiv submission.

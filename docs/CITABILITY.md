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

The project has two DOIs:

| DOI | Meaning |
|---|---|
| [10.5281/zenodo.22045733](https://doi.org/10.5281/zenodo.22045733) | **Concept DOI.** Always resolves to the newest published version. Cite this in prose. |
| [10.5281/zenodo.22045734](https://doi.org/10.5281/zenodo.22045734) | **Version DOI** for `v1.0.0-rc.3`. Cite where exact reproducibility matters. |

### Where to find a version DOI

This table is the record of version DOIs per release. `CITATION.cff` lists only the concept DOI, by design — see [ADR-055](DECISIONS.md). A concept DOI is version-agnostic, so it stays correct whatever version the file describes; a version-specific DOI would pin the file to one archive and force its `version` field to lag the pipeline whenever a candidate is not deposited. Keeping the version DOIs here instead means one version number is used everywhere in the repository, always.

Every version DOI is also discoverable from the concept DOI's Zenodo version list.

| Release | Archived | Version DOI |
|---|---|---|
| `v1.0.0-rc.3` | 2026-08-21 | [10.5281/zenodo.22045734](https://doi.org/10.5281/zenodo.22045734) |
| `v1.0.0-rc.4` | not deposited | — |
| `v1.0.0-rc.5` | not deposited | — |
| `v1.0.0` | pending | pending |

Release candidates are not deposited by default: a candidate does not need a permanent identifier, and a DOI per candidate would add four unciteable entries to the record for every one that matters. The exception is deliberate — if a paper or talk needs to cite an exact pre-release snapshot, deposit that candidate on purpose and add its version DOI to `CITATION.cff`, which will then agree with the version field. At `v1.0.0` the version DOI is added back permanently.

`rc.3` was archived on 2026-08-21 through the Zenodo REST API rather than the GitHub webhook, because the webhook path was blocked by a two-factor authentication challenge that could not be cleared through automation. Consequence: this record cannot be bound to Zenodo's GitHub integration later, so the `v1.0.0` archive will also be created by API rather than fired automatically by a release.

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

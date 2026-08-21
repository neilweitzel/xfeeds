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

## Deferred until `v1.0.0`

**No DOI is minted for a release candidate.** Release tags version the pipeline and its published contracts, and `v1.0.0-rc.3` is inside a burn-in window where corrective changes restart the candidate. Archiving a candidate would put a permanent identifier on a snapshot expected to change.

The promotion procedure is enumerated step by step in
[`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md), including the version references that
must be bumped together. In outline, when `v1.0.0` is promoted:

1. Log in to Zenodo **with ORCID** rather than GitHub, so the account is bound to the iD from the start.
2. Enable the `neilweitzel/xfeeds` repository in Zenodo's GitHub settings. This installs a release webhook.
3. Promote and publish the `v1.0.0` release. Zenodo archives it and mints two DOIs: a version DOI for that snapshot, and a concept DOI that always resolves to the newest version.
4. Add the DOI badge and the resolved citation to the README `## Citation` section, replacing the interim repository citation.
5. Authorize DataCite as a trusted party in ORCID so subsequent release DOIs populate the ORCID record without manual entry.

Two constraints worth knowing before step 2: an existing Zenodo record cannot be retroactively bound to the GitHub integration, and a DOI cannot be pre-reserved for a webhook-triggered release. The webhook path and the manual-upload path are a one-time, irreversible choice.

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

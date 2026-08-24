## xfeeds v1.0.0-rc.5

Fifth release candidate, cut the same day as `rc.4`. **No pipeline behaviour changed.** `rc.5` exists because a pre-promotion audit hardened the release path, and one of those changes touched `.github/workflows/ci.yml`, which restarts the burn-in clock by policy.

Cutting it the same day costs nothing. `rc.4` was tagged 2026-08-24 and so was this, so both windows close on or after **2026-09-24**. The alternative — deferring the version guard until after promotion, where the checklist had it filed as optional — would have meant the guard was absent for the one release it was designed to protect.

If you are consuming feeds, there is nothing to do. Feed paths, record schema, and manifest fields are unchanged from `rc.4`, and `rc.4`'s ADR-054 carry-forward fix is the last change that altered published output.

### What changed since rc.4

**A CI guard against permanent citation drift.** `scripts/check_version_agreement.py`, wired into the `citation` job. A published Zenodo record is immutable, so a wrong version string in it is permanent — the release checklist lists that as an irreversible failure mode — yet the existing citation checks covered ORCID and licence but not version.

A blunt equality check between `pyproject.toml` and `CITATION.cff` would false-fail on a healthy state, because the CFF deliberately tracks the most recent *archived* version while the pipeline moves ahead during a candidate window. So the guard asserts what holds regardless:

1. The CFF's `version` agrees with the version its own version-DOI `description` names — the drift that actually bites, since bumping one without the other advertises a DOI that resolves to different code.
2. `pyproject.toml` and `CITATION.cff` agree exactly once `pyproject.toml` names a final release. That is the promotion moment.
3. `date-released` is a real ISO date and not in the future.

Each failure mode was tested by deliberately breaking the state and confirming a non-zero exit, rather than assumed.

**One owner for the burn-in rule.** `docs/source-lifecycle.md` now carries the authoritative list of what restarts the clock, and `docs/RELEASE_CHECKLIST.md` defers to it. The checklist had asserted that workflow changes restart the clock while citing a document that did not say so. Presentation-only code under `src/` is deliberately not carved out, with the reasoning recorded: the rule's value is in not having to make that judgement under release pressure.

**Release checklist defects, found by audit:**

- `pyproject.toml` was described as `1.0.0rc3`. It was not.
- Two sections contradicted each other on `.zenodo.json` — one said it carries no version field, the other said to keep its version in sync. It carries none, and the stated reason was also wrong: Zenodo does not derive the version from the git tag for this record, because the record is API-managed. The version comes from the metadata payload, which is now listed as a fourth place carrying a version and flagged as the one that becomes permanent.
- An instruction that would have silently done nothing: "move everything under `[Unreleased]`" into the release section, when that content had already moved into `[1.0.0-rc.4]`.
- A check that could fail on a healthy pipeline. Manifest freshness was bounded at six hours; scheduled runs are six hours apart, but GitHub's queue delivers late and observed gaps reached 7.17h. Relaxed to eight, with the measurement recorded.
- Pseudo-code for the irreversible step. The Zenodo publish sequence is now exact, with three API behaviours verified against Zenodo's documentation: `newversion` takes the version id and rejects the concept id, its response is the original record rather than the new draft, and **the new draft inherits a snapshot of the previous version's files** — so publishing without first deleting the inherited `rc.3` tarball leaves the record permanently carrying two archives. That is now in the irreversible-steps table.

### Burn-in

`rc.5` is under a roughly one-month window closing **on or after 2026-09-24** — unchanged from `rc.4`, since both were tagged the same day.

The 1 September source review falls inside it. Opening that issue is harmless; the workflow prompts a human review and auto-enables nothing. The default is to run the review and hold any source-admission PRs until after promotion, since a source admitted the week before a release has had no burn-in of its own.

### Not archived

No DOI is minted for a release candidate. `CITATION.cff` still names `rc.3`, the most recent archived version a reader can actually retrieve, and the new CI guard now enforces that this stays internally consistent. Pipeline version and archive version converge at `v1.0.0`.

**Full changelog:** [`CHANGELOG.md`](../CHANGELOG.md) · **Promotion procedure:** [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)

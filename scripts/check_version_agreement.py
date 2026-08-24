#!/usr/bin/env python3
"""Assert the citation metadata cannot drift in ways that end up permanent.

A Zenodo record is immutable once published, so a wrong version string there is
forever. The `citation` CI job already checks that ORCID and licence agree across
`CITATION.cff`, `.zenodo.json`, and `pyproject.toml`. Version agreement is harder,
because the files legitimately disagree during a release-candidate window:

* `pyproject.toml` names the **pipeline** version, e.g. `1.0.0rc4`.
* `CITATION.cff` names the most recent **archived** version, e.g. `1.0.0-rc.3`,
  because its `identifiers:` block carries that archive's version DOI. Candidates
  are not deposited individually, so the CFF deliberately lags.

A blunt equality check would fail on that healthy state. So this asserts the three
invariants that must hold regardless:

1. `CITATION.cff`'s `version` agrees with the version its own version-DOI
   `description` names. This is the drift that actually bites: bumping one and not
   the other silently advertises a DOI that resolves to different code.
2. When `pyproject.toml` names a **final** release (no `rc`/`a`/`b`/`.dev`
   marker), the two files must agree exactly. That is precisely the promotion
   moment the checklist warns about.
3. `date-released` parses as a real ISO date and is not in the future.

Run: python3 scripts/check_version_agreement.py
"""

from __future__ import annotations

import datetime as dt
import pathlib
import re
import sys
from typing import NoReturn

ROOT = pathlib.Path(__file__).resolve().parent.parent

PRERELEASE = re.compile(r"(rc|a|b|\.dev|\.post)", re.IGNORECASE)


def fail(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def normalise(v: str) -> str:
    """`1.0.0rc4` and `1.0.0-rc.4` are the same version, spelled two ways.

    PEP 440 wants the former, CFF and git tags conventionally use the latter.
    Compare on a canonical form rather than forcing one spelling on both.
    """
    return v.strip().lower().replace("-", "").replace("_", "").replace(".", "")


def main() -> int:
    cff_text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    # --- pull the fields, tolerating quotes and comments ---------------------
    m = re.search(r"^version:\s*['\"]?([^'\"\s#]+)", cff_text, re.MULTILINE)
    if not m:
        fail("no `version:` field in CITATION.cff")
    cff_version = m.group(1)

    m = re.search(r"^date-released:\s*['\"]?([0-9]{4}-[0-9]{2}-[0-9]{2})", cff_text, re.MULTILINE)
    if not m:
        fail("no valid `date-released:` (YYYY-MM-DD) in CITATION.cff")
    cff_date = m.group(1)

    m = re.search(r"^version\s*=\s*['\"]([^'\"]+)['\"]", pyproject_text, re.MULTILINE)
    if not m:
        fail("no `version =` in pyproject.toml")
    py_version = m.group(1)

    # --- invariant 1: CFF version agrees with its own version-DOI description -
    descriptions = re.findall(r"description:\s*Version DOI for\s+v?([^\s#]+)", cff_text)
    if not descriptions:
        fail(
            "CITATION.cff has no `description: Version DOI for vX.Y.Z` entry under "
            "`identifiers:`. That description is how a reader knows which release the "
            "version DOI points at, so it must name a version."
        )
    if len(descriptions) > 1:
        fail(f"CITATION.cff names more than one version DOI: {descriptions}")
    doi_version = descriptions[0]

    if normalise(doi_version) != normalise(cff_version):
        fail(
            f"CITATION.cff `version: {cff_version}` disagrees with its version-DOI "
            f"description, which names v{doi_version}.\n"
            "  The version DOI is immutable and resolves to one specific archive. If "
            "the version field moved, the DOI and its description must move with it, "
            "or the file advertises a DOI that resolves to different code."
        )

    # --- invariant 2: at a final release, everything converges ---------------
    py_is_prerelease = bool(PRERELEASE.search(py_version))
    if not py_is_prerelease:
        if normalise(py_version) != normalise(cff_version):
            fail(
                f"pyproject.toml is at final release `{py_version}` but CITATION.cff "
                f"says `{cff_version}`.\n"
                "  During a release-candidate window these may differ: the CFF tracks "
                "the most recent archived version while the pipeline moves ahead. At a "
                "final release they must agree, because that is the version being "
                "archived, and Zenodo metadata is permanent.\n"
                "  See docs/RELEASE_CHECKLIST.md step 2."
            )
    else:
        print(
            f"note: pyproject is a prerelease ({py_version}); CITATION.cff may "
            f"legitimately lag at {cff_version} (most recent archived version)."
        )

    # --- invariant 3: the release date is real -------------------------------
    try:
        released = dt.date.fromisoformat(cff_date)
    except ValueError:
        fail(f"`date-released: {cff_date}` is not a valid ISO date")
    if released > dt.datetime.now(tz=dt.UTC).date():
        fail(f"`date-released: {cff_date}` is in the future")

    print(
        f"ok: pyproject={py_version}  CITATION.cff={cff_version} "
        f"(DOI describes v{doi_version}, released {cff_date})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

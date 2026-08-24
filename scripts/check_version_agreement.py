#!/usr/bin/env python3
"""Assert that one version number is used everywhere, with no exceptions.

A published Zenodo record is immutable, so a wrong version string in it is
permanent. The `citation` CI job checks that ORCID and licence agree across
`CITATION.cff`, `.zenodo.json`, and `pyproject.toml`. This adds version.

Per ADR-055 there is exactly **one** version number for the project, and every
file that names a version must name that one. Two spellings are unavoidable and
are not a disagreement:

* `pyproject.toml` must use PEP 440, e.g. `1.0.0rc5`.
* `CITATION.cff` and the git tag use the conventional form, e.g. `1.0.0-rc.5`.

So the comparison is done on a canonical form rather than as raw strings. Every
other kind of divergence is a failure.

Invariants:

1. `pyproject.toml` and `CITATION.cff` name the same version. Always \u2014 there is
   no release-candidate exemption, which is the whole point of ADR-055.
2. If `CITATION.cff` lists a version-specific DOI, its description names that
   same version. A version DOI pins the file to one archive, so it may only be
   present when it agrees. The concept DOI is version-agnostic and is exempt.
3. `date-released` is a real ISO date and is not in the future.

Run: python3 scripts/check_version_agreement.py
"""

from __future__ import annotations

import datetime as dt
import pathlib
import re
import sys
from typing import NoReturn

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The concept DOI is version-agnostic: it always resolves to the newest published
# version, so it never constrains the version field.
CONCEPT_DOI = "10.5281/zenodo.22045733"


def fail(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def normalise(v: str) -> str:
    """Canonical form for comparison.

    `1.0.0rc5` and `1.0.0-rc.5` are the same version spelled two ways: PEP 440
    mandates the former in pyproject.toml, while CFF and git tags conventionally
    use the latter. Strip the separators rather than forcing one spelling on both,
    which would either break packaging or break tag conventions.
    """
    return v.strip().lower().lstrip("v").replace("-", "").replace("_", "").replace(".", "")


def main() -> int:
    cff_text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    pyproject_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

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

    # --- invariant 1: one version, everywhere, always ------------------------
    if normalise(py_version) != normalise(cff_version):
        fail(
            f"version mismatch.\n"
            f"  pyproject.toml : {py_version}\n"
            f"  CITATION.cff   : {cff_version}\n"
            "  Per ADR-055 these must always name the same version, including during\n"
            "  a release-candidate window. Bump both together, and the git tag with\n"
            "  them. Differing spellings are fine (PEP 440 vs the tag form); differing\n"
            "  versions are not.\n"
            "  See docs/RELEASE_CHECKLIST.md step 2."
        )

    # --- invariant 2: a version-specific DOI must agree ----------------------
    # Parse identifier entries as (value, description) pairs so a version DOI
    # cannot be present while describing some other release.
    entries = re.findall(
        r"-\s*type:\s*doi\s*\n\s*value:\s*([^\s#]+)\s*\n\s*description:\s*([^\n]+)",
        cff_text,
    )
    if not entries:
        fail("CITATION.cff lists no DOI under `identifiers:`; the concept DOI must be present")

    saw_concept = False
    for value, description in entries:
        if value.strip() == CONCEPT_DOI:
            saw_concept = True
            continue
        # Any non-concept DOI is version-specific and must name this version.
        named = re.search(r"v?([0-9]+\.[0-9]+\.[0-9]+[^\s,;]*)", description)
        if not named:
            fail(
                f"version-specific DOI {value} has description {description!r}, which "
                "does not name a version. A version DOI pins this file to one archive, "
                "so its description must say which release it is."
            )
        if normalise(named.group(1)) != normalise(cff_version):
            fail(
                f"version-specific DOI {value} describes v{named.group(1)} but "
                f"CITATION.cff is at version {cff_version}.\n"
                "  A version DOI resolves to one immutable archive. It may only appear "
                "here while it names the version this file describes \u2014 otherwise the "
                "file advertises a DOI that resolves to different code.\n"
                "  If this version is not deposited, remove the version DOI and keep "
                "only the concept DOI, which is version-agnostic. See ADR-055."
            )

    if not saw_concept:
        fail(f"the concept DOI {CONCEPT_DOI} is missing from CITATION.cff `identifiers:`")

    # --- invariant 3: the release date is real -------------------------------
    try:
        released = dt.date.fromisoformat(cff_date)
    except ValueError:
        fail(f"`date-released: {cff_date}` is not a valid ISO date")
    if released > dt.datetime.now(tz=dt.UTC).date():
        fail(f"`date-released: {cff_date}` is in the future")

    version_dois = [v for v, _ in entries if v.strip() != CONCEPT_DOI]
    suffix = f", version DOI {version_dois[0]}" if version_dois else ", concept DOI only"
    print(
        f"ok: one version everywhere \u2014 pyproject={py_version}, "
        f"CITATION.cff={cff_version} (released {cff_date}{suffix})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

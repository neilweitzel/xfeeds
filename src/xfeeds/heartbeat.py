"""Measure freshness without confusing unavailable evidence with old evidence.

Standalone stdlib entry point for Actions: no pipeline dependencies or upstream
collector calls. curl supplies a total request deadline, not just a read timeout.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

State = Literal["fresh", "stale", "unreachable", "invalid"]
ATTEMPTS = 3
RETRY_HTTP = {408, 429, 500, 502, 503, 504}
RETRY_CURL = {5, 6, 7, 18, 28, 52, 55, 56}


@dataclass(frozen=True)
class Check:
    """Keep unknown age distinct from a measured age in every output."""

    state: State
    timestamp: str | None = None
    age_hours: float | None = None
    detail: str = ""


def measure(body: str, now: datetime, max_age: float) -> Check:
    """Reject malformed or future timestamps instead of reporting fresh data."""
    try:
        payload = json.loads(body)
        stamp = payload.get("generated_at") if isinstance(payload, dict) else None
        if not isinstance(stamp, str):
            raise TypeError("missing or non-string generated_at")
        generated = datetime.fromisoformat(stamp)
        if generated.tzinfo is None:
            raise ValueError("generated_at has no timezone")
        age = (now - generated).total_seconds() / 3600
        if age < 0:
            raise ValueError("generated_at is in the future")
    except (TypeError, ValueError, OverflowError):
        return Check("invalid", detail="Invalid JSON or missing/invalid/future generated_at.")
    return Check("stale" if age >= max_age else "fresh", generated.isoformat(), age)


def probe_pages(url: str, now: datetime, max_age: float) -> tuple[Check, list[str]]:
    """Retry only transient transport/HTTP failures with a fixed total budget.

    Three attempts, each capped by curl at 30 seconds and the subprocess at 35,
    separated by 5 and 10 seconds: at most 120 seconds of request/backoff time.
    No Retry-After header can extend this budget. A successful but invalid or
    stale manifest is evidence, not a transport error, and is not retried.
    """
    history: list[str] = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "manifest.json"
        for attempt in range(1, ATTEMPTS + 1):
            # A prior partial response must never become the next attempt's data.
            output.unlink(missing_ok=True)
            try:
                result = subprocess.run(
                    [
                        "curl",
                        "--disable",
                        "--silent",
                        "--show-error",
                        "--location",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--connect-timeout",
                        "10",
                        "--max-time",
                        "30",
                        "--output",
                        str(output),
                        "--write-out",
                        "%{http_code}",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=35,
                    check=False,
                )
                status = result.stdout.strip()
                history.append(f"attempt {attempt}: HTTP {status}, curl exit {result.returncode}")
                if result.returncode == 0 and status == "200":
                    try:
                        # A refresh may publish while retries are in flight. Compare
                        # against observation time, not the probe's earlier start.
                        observed = now + timedelta(seconds=time.monotonic() - started)
                        return measure(
                            output.read_text(encoding="utf-8"), observed, max_age
                        ), history
                    except (OSError, UnicodeError):
                        return Check("invalid", detail="Manifest body is unreadable."), history
                retry = result.returncode in RETRY_CURL or (
                    result.returncode == 0 and status.isdigit() and int(status) in RETRY_HTTP
                )
            except subprocess.TimeoutExpired:
                history.append(f"attempt {attempt}: subprocess deadline exceeded (35s)")
                retry = True
            except OSError:
                history.append(f"attempt {attempt}: curl could not be executed")
                retry = False
            if not retry or attempt == ATTEMPTS:
                break
            time.sleep(5 * attempt)
    return Check("unreachable", detail=history[-1]), history


def diagnose(repo: Check, pages: Check, max_age: float) -> str:
    """State only what each observation proves; avoid guessing a deployment cause."""
    findings: list[str] = []
    if repo.state == "stale":
        findings.append(
            f"Committed feed is at least {max_age:g}h old. "
            "Check refresh failures, skipped runs, and scheduling."
        )
    elif repo.state == "invalid":
        findings.append("Committed manifest is missing or invalid; pipeline freshness is unknown.")
    if pages.state == "unreachable":
        findings.append(
            "Published manifest is unreachable from this runner. Its freshness is unknown. "
            "This is an availability/HTTP failure, not proof that publishing stopped. "
            "Check Pages availability, networking, and the HTTP/transport results below."
        )
    elif pages.state == "invalid":
        findings.append(
            "Published manifest was retrieved but is invalid; its freshness is unknown. "
            "Check the published artifact and generated_at."
        )
    elif pages.state == "stale":
        findings.append(
            f"Published feed is at least {max_age:g}h old. "
            + (
                "The committed feed is fresh; investigate deployment or CDN propagation."
                if repo.state == "fresh"
                else "Compare refresh and deployment history."
            )
        )
    if repo.state == "stale" and pages.state == "fresh":
        findings.append("Published feed is fresh; investigate repository/publication divergence.")
    return " ".join(findings) or "Committed and published manifests are both fresh."


def main() -> int:
    """Write machine-readable evidence; the issue step owns unhealthy run failure."""
    now = datetime.now(UTC)
    max_age = float(os.environ.get("MAX_AGE_HOURS", "24"))
    if not 0 < max_age < float("inf"):
        raise ValueError("MAX_AGE_HOURS must be positive and finite")
    try:
        repo = measure(Path("feeds/manifest.json").read_text(encoding="utf-8"), now, max_age)
    except (OSError, UnicodeError):
        repo = Check("invalid", detail="Committed manifest is missing or unreadable.")
    pages, attempts = probe_pages(
        os.environ["PAGES_URL"].rstrip("/") + "/manifest.json", now, max_age
    )
    report = {
        "repo": asdict(repo),
        "pages": asdict(pages),
        "attempts": attempts,
        "unhealthy": repo.state != "fresh" or pages.state != "fresh",
        "diagnosis": diagnose(repo, pages, max_age),
        "max_age_hours": max_age,
        "checked_at": now.isoformat(),
    }
    Path("heartbeat-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write(
            f"## Heartbeat\n\n{report['diagnosis']}\n\n"
            f"Committed: **{repo.state}**. Published: **{pages.state}**.\n\n"
            + "\n".join(f"- {item}" for item in attempts)
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

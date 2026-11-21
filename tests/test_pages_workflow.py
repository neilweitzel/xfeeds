"""Check that the Pages fallback retries deploy-pages after the artifact-listing race.

These tests read the real workflow file and play out its step conditions for the
outcomes that matter. They model only the small part of the Actions expression
language that pages.yml uses (`a == 'b'` joined by `&&`), and fail loudly on
anything else rather than guessing. They do not prove how GitHub's runner or the
artifact API behaves; they prove the workflow asks for the intended steps.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/pages.yml"
DEPLOY = "actions/deploy-pages@v4"
CLAUSE = re.compile(r"^(steps\.[a-z_]+\.(?:outputs\.[a-z_]+|outcome)) == '([a-z]+)'$")


def deploy_steps(text: str) -> list[dict[str, Any]]:
    workflow = yaml.safe_load(text)
    steps: list[dict[str, Any]] = workflow["jobs"]["deploy"]["steps"]
    return steps


def evaluate(condition: str | None, context: dict[str, str]) -> bool:
    """Evaluate the `if:` subset used by pages.yml, rejecting anything wider."""
    if condition is None:
        return True
    result = True
    for clause in condition.split("&&"):
        match = CLAUSE.match(clause.strip())
        if match is None:
            raise AssertionError(f"unsupported condition in pages.yml: {condition!r}")
        result = result and context.get(match.group(1), "") == match.group(2)
    return result


def play(text: str, stale: bool, deploy_results: list[str]) -> tuple[list[str], bool]:
    """Return the deploy-pages steps that ran and whether the job succeeded.

    deploy_results supplies the outcome of each deploy-pages invocation in order.
    A failed step with continue-on-error records outcome "failure" but does not
    fail the job, matching GitHub's outcome/conclusion split.
    """
    context = {"steps.freshness.outputs.stale": "true" if stale else "false"}
    results = iter(deploy_results)
    ran: list[str] = []
    job_ok = True
    for step in deploy_steps(text):
        if step.get("uses") != DEPLOY or not evaluate(step.get("if"), context):
            continue
        outcome = next(results)
        ran.append(step["id"])
        context[f"steps.{step['id']}.outcome"] = outcome
        if outcome == "failure" and step.get("continue-on-error") is not True:
            job_ok = False
    return ran, job_ok


def current() -> str:
    """Read pages.yml, or replay an older commit's copy for a regression check.

    Setting PAGES_REGRESSION_REF=d77c6390 replays the workflow that failed on
    2026-11-20; the race test must fail there.
    """
    baseline = os.environ.get("PAGES_REGRESSION_REF")
    if baseline:
        return subprocess.check_output(
            ["git", "show", f"{baseline}:.github/workflows/pages.yml"], cwd=ROOT, text=True
        )
    return WORKFLOW.read_text()


def test_first_attempt_success_does_not_retry() -> None:
    assert play(current(), stale=True, deploy_results=["success"]) == (["deployment"], True)


def test_artifact_race_is_retried_once_and_the_job_succeeds() -> None:
    ran, job_ok = play(current(), stale=True, deploy_results=["failure", "success"])
    assert ran == ["deployment", "deployment_retry"]
    assert job_ok


def test_persistent_deploy_failure_still_fails_the_job() -> None:
    ran, job_ok = play(current(), stale=True, deploy_results=["failure", "failure"])
    assert ran == ["deployment", "deployment_retry"]
    assert not job_ok


def test_current_pages_never_deploys() -> None:
    assert play(current(), stale=False, deploy_results=[]) == ([], True)


def test_retry_waits_first_and_is_the_only_tolerated_failure() -> None:
    steps = deploy_steps(current())
    ids = [step.get("id") for step in steps]
    first, retry = ids.index("deployment"), ids.index("deployment_retry")
    wait = steps[first + 1]
    assert retry == first + 2
    assert wait["run"] == "sleep 30"
    assert wait["if"] == steps[retry]["if"]
    assert steps[retry]["uses"] == DEPLOY
    assert "continue-on-error" not in steps[retry]
    tolerated = [step.get("id") for step in steps if "continue-on-error" in step]
    assert tolerated == ["deployment"]
    job = yaml.safe_load(current())["jobs"]["deploy"]
    assert "continue-on-error" not in job
    url = job["environment"]["url"]
    assert "steps.deployment.outputs.page_url" in url
    assert "steps.deployment_retry.outputs.page_url" in url

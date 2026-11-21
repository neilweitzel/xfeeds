"""Check that both Pages publishers retry deploy-pages after the artifact-listing race.

These tests read the real workflow files and play out their step conditions for
the outcomes that matter. They model only the small part of the Actions
expression language the deploy jobs use (`a == 'b'` joined by `&&`), and fail
loudly on anything else rather than guessing. They do not prove how GitHub's
runner or the artifact API behaves; they prove the workflows ask for the
intended steps.

Setting PAGES_REGRESSION_REF replays both workflows from an older commit. At
d77c6390 (the 2026-11-20 failures) both race cases must fail; at 6f3cde9 (the
2026-11-21 failure) the update-feeds case must fail.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = "actions/deploy-pages@v4"
CLAUSE = re.compile(r"^(steps\.[a-z_]+\.(?:outputs\.[a-z_]+|outcome)) == '([a-z]+)'$")

# (workflow file, deploy job, whether the job gates on the freshness check)
PUBLISHERS = [
    pytest.param("pages.yml", "deploy", True, id="pages"),
    pytest.param("update-feeds.yml", "deploy-pages", False, id="update-feeds"),
]


def read(name: str) -> str:
    """Read a workflow, or an older commit's copy when replaying a regression."""
    baseline = os.environ.get("PAGES_REGRESSION_REF")
    if baseline:
        return subprocess.check_output(
            ["git", "show", f"{baseline}:.github/workflows/{name}"], cwd=ROOT, text=True
        )
    return (ROOT / ".github/workflows" / name).read_text()


def job(name: str, job_id: str) -> dict[str, Any]:
    workflow = yaml.safe_load(read(name))
    found: dict[str, Any] = workflow["jobs"][job_id]
    return found


def evaluate(condition: str | None, context: dict[str, str]) -> bool:
    """Evaluate the `if:` subset used by the deploy jobs, rejecting anything wider."""
    if condition is None:
        return True
    result = True
    for clause in condition.split("&&"):
        match = CLAUSE.match(clause.strip())
        if match is None:
            raise AssertionError(f"unsupported condition in workflow: {condition!r}")
        result = result and context.get(match.group(1), "") == match.group(2)
    return result


def play(
    name: str, job_id: str, deploy_results: list[str], stale: bool = True
) -> tuple[list[str], bool]:
    """Return the deploy-pages steps that ran and whether the job succeeded.

    deploy_results supplies the outcome of each deploy-pages invocation in order.
    A failed step with continue-on-error records outcome "failure" but does not
    fail the job, matching GitHub's outcome/conclusion split.
    """
    context = {"steps.freshness.outputs.stale": "true" if stale else "false"}
    results = iter(deploy_results)
    ran: list[str] = []
    job_ok = True
    for step in job(name, job_id)["steps"]:
        if step.get("uses") != DEPLOY or not evaluate(step.get("if"), context):
            continue
        outcome = next(results)
        ran.append(step["id"])
        context[f"steps.{step['id']}.outcome"] = outcome
        if outcome == "failure" and step.get("continue-on-error") is not True:
            job_ok = False
    return ran, job_ok


@pytest.mark.parametrize(("name", "job_id", "gated"), PUBLISHERS)
def test_first_attempt_success_does_not_retry(name: str, job_id: str, gated: bool) -> None:
    assert play(name, job_id, ["success"]) == (["deployment"], True)


@pytest.mark.parametrize(("name", "job_id", "gated"), PUBLISHERS)
def test_artifact_race_is_retried_once_and_the_job_succeeds(
    name: str, job_id: str, gated: bool
) -> None:
    ran, job_ok = play(name, job_id, ["failure", "success"])
    assert ran == ["deployment", "deployment_retry"]
    assert job_ok


@pytest.mark.parametrize(("name", "job_id", "gated"), PUBLISHERS)
def test_persistent_deploy_failure_still_fails_the_job(name: str, job_id: str, gated: bool) -> None:
    ran, job_ok = play(name, job_id, ["failure", "failure"])
    assert ran == ["deployment", "deployment_retry"]
    assert not job_ok


def test_current_pages_never_deploys() -> None:
    assert play("pages.yml", "deploy", [], stale=False) == ([], True)


@pytest.mark.parametrize(("name", "job_id", "gated"), PUBLISHERS)
def test_retry_waits_first_and_is_the_only_tolerated_failure(
    name: str, job_id: str, gated: bool
) -> None:
    deploy_job = job(name, job_id)
    steps = deploy_job["steps"]
    ids = [step.get("id") for step in steps]
    first, retry = ids.index("deployment"), ids.index("deployment_retry")
    wait = steps[first + 1]
    assert retry == first + 2
    assert wait["run"] == "sleep 30"
    assert wait["if"] == steps[retry]["if"]
    assert "steps.deployment.outcome == 'failure'" in steps[retry]["if"]
    assert ("steps.freshness.outputs.stale == 'true'" in steps[retry]["if"]) is gated
    assert steps[first]["uses"] == steps[retry]["uses"] == DEPLOY
    assert "continue-on-error" not in steps[retry]
    tolerated = [step.get("id") for step in steps if "continue-on-error" in step]
    assert tolerated == ["deployment"]
    assert "continue-on-error" not in deploy_job
    url = deploy_job["environment"]["url"]
    assert "steps.deployment.outputs.page_url" in url
    assert "steps.deployment_retry.outputs.page_url" in url


def test_publishers_still_share_the_pages_group_without_cancelling() -> None:
    """The retry lengthens a deploy job; overlap protection must stay intact."""
    pages = yaml.safe_load(read("pages.yml"))
    assert pages["concurrency"] == {"group": "pages", "cancel-in-progress": False}
    primary = job("update-feeds.yml", "deploy-pages")
    assert primary["concurrency"] == {"group": "pages", "cancel-in-progress": False}

"""Exercise the probe, workflow command, and issue lifecycle without networking."""

import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from xfeeds import heartbeat

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 30, 13, 38, tzinfo=UTC)
FRESH = json.dumps({"generated_at": (NOW - timedelta(hours=5)).isoformat()})


@pytest.mark.parametrize(
    "body",
    [
        "{",
        "[]",
        "{}",
        '{"generated_at": null}',
        '{"generated_at": 123}',
        '{"generated_at": "bad"}',
        '{"generated_at": "2026-10-30T08:00:00"}',
        '{"generated_at": "2026-10-31T08:00:00Z"}',
    ],
)
def test_invalid_evidence_never_becomes_fresh_or_stale(body: str) -> None:
    result = heartbeat.measure(body, NOW, 24)
    assert result.state == "invalid"
    assert result.age_hours is None
    assert result.timestamp is None


@pytest.mark.parametrize("seconds,state", [(86399, "fresh"), (86400, "stale"), (90000, "stale")])
def test_exact_freshness_boundary(seconds: int, state: str) -> None:
    body = json.dumps({"generated_at": (NOW - timedelta(seconds=seconds)).isoformat()})
    assert heartbeat.measure(body, NOW, 24).state == state


def test_timezone_offsets_are_respected() -> None:
    body = '{"generated_at": "2026-10-30T04:38:00-04:00"}'
    assert heartbeat.measure(body, NOW, 24).age_hours == 5


def probe(
    monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, str, str] | Exception]
) -> tuple[heartbeat.Check, list[str], list[int]]:
    calls: list[list[str]] = []
    delays: list[int] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["timeout"] == 35
        assert command[command.index("--max-time") + 1] == "30"
        assert command[command.index("--connect-timeout") + 1] == "10"
        assert "--retry" not in command  # No hidden retry loop multiplying the budget.
        path = Path(command[command.index("--output") + 1])
        assert not path.exists()  # Prior response/partial body must have been removed.
        response = responses[len(calls) - 1]
        if isinstance(response, Exception):
            raise response
        code, status, body = response
        path.write_text(body)
        return subprocess.CompletedProcess(command, code, status, "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(time, "sleep", delays.append)
    result, history = heartbeat.probe_pages("https://example.invalid/manifest.json", NOW, 24)
    assert len(calls) == len(history)
    return result, history, delays


@pytest.mark.parametrize("status", ["408", "429", "500", "502", "503", "504"])
def test_transient_http_recovers_without_an_incident(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    result, history, delays = probe(monkeypatch, [(0, status, FRESH), (0, "200", FRESH)])
    assert result.state == "fresh"
    assert len(history) == 2
    assert delays == [5]
    assert f"HTTP {status}" in history[0]


@pytest.mark.parametrize("code", [5, 6, 7, 18, 28, 52, 55, 56])
def test_transient_network_error_recovers(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    result, _, delays = probe(monkeypatch, [(code, "000", FRESH), (0, "200", FRESH)])
    assert result.state == "fresh"
    assert delays == [5]


def test_persistent_503_has_unknown_age_and_bounded_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, history, delays = probe(monkeypatch, [(0, "503", FRESH)] * 3)
    assert result.state == "unreachable"
    assert result.age_hours is None
    assert len(history) == 3
    assert delays == [5, 10]
    diagnosis = heartbeat.diagnose(heartbeat.measure(FRESH, NOW, 24), result, 24)
    assert "freshness is unknown" in diagnosis
    assert "not proof that publishing stopped" in diagnosis
    assert "9999" not in diagnosis
    assert "at least 24h old" not in diagnosis


def test_subprocess_deadline_is_retried_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    result, history, delays = probe(monkeypatch, [subprocess.TimeoutExpired("curl", 35)] * 3)
    assert result.state == "unreachable"
    assert len(history) == 3
    assert delays == [5, 10]


def test_refresh_published_during_request_is_not_mistaken_for_future_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = iter([0.0, 20.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    body = json.dumps({"generated_at": (NOW + timedelta(seconds=10)).isoformat()})
    result, _, _ = probe(monkeypatch, [(0, "200", body)])
    assert result.state == "fresh"


@pytest.mark.parametrize("code,status", [(0, "404"), (0, "403"), (60, "000")])
def test_permanent_http_or_tls_failure_does_not_retry(
    monkeypatch: pytest.MonkeyPatch, code: int, status: str
) -> None:
    result, history, delays = probe(monkeypatch, [(code, status, FRESH)])
    assert result.state == "unreachable"
    assert len(history) == 1
    assert not delays


def test_missing_curl_is_an_availability_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    result, history, delays = probe(monkeypatch, [FileNotFoundError()])
    assert result.state == "unreachable"
    assert "could not be executed" in history[0]
    assert not delays


@pytest.mark.parametrize(
    "body,state", [("{", "invalid"), ('{"generated_at":"2026-10-28T00:00:00Z"}', "stale")]
)
def test_retrieved_bad_or_stale_manifest_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, body: str, state: str
) -> None:
    result, _, delays = probe(monkeypatch, [(0, "200", body)])
    assert result.state == state
    assert not delays


@pytest.mark.parametrize(
    "repo,pages,expected",
    [
        ("fresh", "fresh", "both fresh"),
        ("stale", "stale", "Check refresh failures"),
        ("fresh", "stale", "deployment or CDN propagation"),
        ("stale", "fresh", "repository/publication divergence"),
        ("invalid", "fresh", "pipeline freshness is unknown"),
        ("fresh", "invalid", "retrieved but is invalid"),
        ("stale", "unreachable", "Committed feed is at least 24h old"),
        ("invalid", "unreachable", "Published manifest is unreachable"),
    ],
)
def test_distinct_and_combined_diagnoses(
    repo: heartbeat.State, pages: heartbeat.State, expected: str
) -> None:
    diagnosis = heartbeat.diagnose(heartbeat.Check(repo), heartbeat.Check(pages), 24)
    assert expected in diagnosis
    if pages == "unreachable":
        assert "freshness is unknown" in diagnosis


def test_main_preserves_pages_check_when_repository_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAGES_URL", "https://example.invalid")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary"))
    monkeypatch.setattr(
        heartbeat, "probe_pages", lambda *args: (heartbeat.Check("fresh", age_hours=5), ["ok"])
    )
    assert heartbeat.main() == 0
    report = json.loads((tmp_path / "heartbeat-report.json").read_text())
    assert report["repo"]["state"] == "invalid"
    assert report["pages"]["state"] == "fresh"
    assert report["unhealthy"] is True


def test_workflow_command_recovers_from_real_incident_pattern(tmp_path: Path) -> None:
    """Execute the actual workflow command with a fake curl, never a socket.

    Setting HEARTBEAT_REGRESSION_REF to a commit replays that workflow instead.
    Its single 503 produces stale=true, proving this acceptance test fails there.
    """
    baseline = os.environ.get("HEARTBEAT_REGRESSION_REF")
    text = (
        subprocess.check_output(
            ["git", "show", f"{baseline}:.github/workflows/heartbeat.yml"], cwd=ROOT, text=True
        )
        if baseline
        else (ROOT / ".github/workflows/heartbeat.yml").read_text()
    )
    workflow = yaml.safe_load(text)
    step = next(s for s in workflow["jobs"]["heartbeat"]["steps"] if "run" in s)
    (tmp_path / "feeds").mkdir()
    body = json.dumps({"generated_at": (datetime.now(UTC) - timedelta(hours=5)).isoformat()})
    (tmp_path / "feeds/manifest.json").write_text(body)
    (tmp_path / "src/xfeeds").mkdir(parents=True)
    shutil.copy(ROOT / "src/xfeeds/heartbeat.py", tmp_path / "src/xfeeds/heartbeat.py")
    fake = tmp_path / "curl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "count = pathlib.Path('attempt-count')\n"
        "n = int(count.read_text()) + 1 if count.exists() else 1\n"
        "count.write_text(str(n))\n"
        "if n == 1:\n"
        "    print('503')\n"
        "    sys.exit(22 if '-fsS' in sys.argv else 0)\n"
        "flag = '--output' if '--output' in sys.argv else '-o'\n"
        "pathlib.Path(sys.argv[sys.argv.index(flag)+1]).write_text("
        "pathlib.Path('feeds/manifest.json').read_text())\n"
        "print('200')\n"
    )
    fake.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "PAGES_URL": "https://example.invalid",
        "MAX_AGE_HOURS": "24",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }
    subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, check=True, timeout=15)
    assert (tmp_path / "attempt-count").read_text() == "2"
    report = json.loads((tmp_path / "heartbeat-report.json").read_text())
    assert report["unhealthy"] is False
    assert report["repo"]["state"] == report["pages"]["state"] == "fresh"


def issue_run(
    tmp_path: Path,
    *,
    unhealthy: bool,
    issues: list[dict[str, Any]],
    history_fails: bool = False,
) -> dict[str, Any]:
    """Run the exact Actions JS module against a recording GitHub API double."""
    report = {
        "repo": {"state": "fresh", "timestamp": "2026-10-30T08:38:00Z", "age_hours": 5},
        "pages": {
            "state": "unreachable" if unhealthy else "fresh",
            "timestamp": None if unhealthy else "2026-10-30T08:38:00Z",
            "age_hours": None if unhealthy else 5,
        },
        "unhealthy": unhealthy,
        "diagnosis": "Published manifest is unreachable; freshness is unknown.",
        "attempts": ["attempt 1: HTTP 503, curl exit 0"] * 3,
        "max_age_hours": 24,
        "checked_at": NOW.isoformat(),
    }
    (tmp_path / "input.json").write_text(
        json.dumps({"report": report, "issues": issues, "historyFails": history_fails})
    )
    script = """
const fs = require('fs');
const input = JSON.parse(fs.readFileSync('input.json', 'utf8'));
const result = { calls: [], failures: [], warnings: [] };
const record = name => async args => { result.calls.push({ name, ...args }); };
const github = {
  paginate: async () => input.issues,
  rest: {
    issues: {
      listForRepo: () => {},
      create: record('create'), update: record('update'), createComment: record('comment'),
    },
    actions: { listWorkflowRuns: async () => {
      if (input.historyFails) throw new Error('unavailable');
      return { data: { workflow_runs: [] } };
    } },
  },
};
const context = { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 };
const core = { setFailed: msg => result.failures.push(msg), warning: msg => result.warnings.push(msg) };
require(process.argv[1])({ github, context, core, report: input.report })
  .then(() => console.log(JSON.stringify(result)))
  .catch(err => { console.error(err); process.exitCode = 1; });
"""
    result = subprocess.run(
        ["node", "-e", script, str(ROOT / ".github/scripts/heartbeat.cjs")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    value: dict[str, Any] = json.loads(result.stdout)
    return value


def test_unavailable_alert_has_no_fake_age_and_fails_the_job(tmp_path: Path) -> None:
    result = issue_run(tmp_path, unhealthy=True, issues=[])
    assert result["failures"]
    call = result["calls"][0]
    assert call["name"] == "create"
    assert call["title"] == "xfeeds: heartbeat health check failed"
    assert "| unreachable | unknown | unknown |" in call["body"]
    assert "9999" not in call["body"]
    assert "feed has not refreshed" not in call["body"]
    assert "HTTP 503" in call["body"]


def test_existing_legacy_issue_is_migrated_not_duplicated(tmp_path: Path) -> None:
    result = issue_run(
        tmp_path,
        unhealthy=True,
        issues=[{"number": 77, "title": "xfeeds: feed has stopped updating"}],
    )
    assert [call["name"] for call in result["calls"]] == ["update", "comment"]
    assert all(call["issue_number"] == 77 for call in result["calls"])
    assert result["calls"][0]["title"] == "xfeeds: heartbeat health check failed"


def test_history_failure_does_not_hide_the_primary_alert(tmp_path: Path) -> None:
    result = issue_run(tmp_path, unhealthy=True, issues=[], history_fails=True)
    assert result["failures"]
    assert result["warnings"]
    assert result["calls"][0]["name"] == "create"
    assert "history unavailable" in result["calls"][0]["body"]


def test_recovery_closes_legacy_and_new_issues_but_not_unrelated_issues(tmp_path: Path) -> None:
    result = issue_run(
        tmp_path,
        unhealthy=False,
        issues=[
            {"number": 77, "title": "xfeeds: feed has stopped updating"},
            {"number": 78, "title": "xfeeds: heartbeat health check failed"},
            {"number": 79, "title": "unrelated"},
            {"number": 80, "title": "xfeeds: heartbeat health check failed", "pull_request": {}},
        ],
    )
    assert not result["failures"]
    assert [call["issue_number"] for call in result["calls"]] == [77, 77, 78, 78]
    assert all(call["state"] == "closed" for call in result["calls"] if call["name"] == "update")


def test_healthy_run_without_open_incident_is_quiet(tmp_path: Path) -> None:
    assert issue_run(tmp_path, unhealthy=False, issues=[])["calls"] == []


def test_workflow_wires_tested_probe_and_incident_handler_without_weakening_checks() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/heartbeat.yml").read_text())
    assert workflow[True]["schedule"] == [{"cron": "47 */6 * * *"}]
    assert "workflow_dispatch" in workflow[True]
    assert workflow["env"]["MAX_AGE_HOURS"] == "24"
    assert workflow["permissions"] == {
        "actions": "read",
        "contents": "read",
        "issues": "write",
    }
    assert workflow["concurrency"] == {"group": "heartbeat", "cancel-in-progress": False}
    job = workflow["jobs"]["heartbeat"]
    assert job["timeout-minutes"] == 10
    assert "continue-on-error" not in job
    checkout, probe_step, incident = job["steps"]
    assert checkout["with"]["ref"] == "main"
    assert probe_step["run"] == "python3 src/xfeeds/heartbeat.py"
    assert "heartbeat-report.json" in incident["with"]["script"]
    assert "./.github/scripts/heartbeat.cjs" in incident["with"]["script"]
    assert all("if" not in step and "continue-on-error" not in step for step in job["steps"])

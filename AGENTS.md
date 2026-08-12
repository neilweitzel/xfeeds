# AGENTS.md — instructions for coding agents working in this repository

Read this before planning any task. It encodes decisions that are already settled and mistakes that are easy to make here.

## What this project is

xfeeds aggregates public IP threat-intelligence feeds and publishes a corroborated block list that other people load into firewalls. **The output can cause real outages for real people.** A false positive here means someone's legitimate traffic gets dropped. Bias every judgement call toward publishing less.

Read [`README.md`](README.md) for the spec and [`docs/DECISIONS.md`](docs/DECISIONS.md) for the architecture decision record before writing code.

## Settled decisions — do not re-litigate

These were decided with measured evidence. If you believe one is wrong, **say so in your task summary and proceed as specified anyway**. Do not silently substitute your own choice.

- **Python 3.13** target, 3.11 floor. The Jules VM ships 3.12 by default — the setup script installs 3.13 via `uv`. Do not downgrade the project to 3.12 to avoid the setup step.
- **uv** for packaging, with `pyproject.toml` and a committed `uv.lock`.
- **Dependencies are deliberately few**: `httpx`, `pydantic` v2, `tenacity`, `typer`, `structlog`, `pyyaml`, `stix2`. Dev: `ruff`, `mypy`, `pytest`, `pytest-httpx`.
- **Do not add** `netaddr`, `orjson`, `pandas`, `polars`, `requests`, `aiohttp`, or any database. Standard-library `ipaddress` and `json` are sufficient and intentional. Adding a dependency requires a new ADR entry.
- **`httpx` is used synchronously.** Do not introduce `asyncio`. Twelve sources do not need an event loop.
- **No TAXII server.** STIX 2.1 is emitted as static bundles.
- The source list in `sources.yaml` is final for Phase 2. **Do not enable a disabled source, and do not add new ones**, without an explicit instruction saying so.

## The single most important concept: independence classes

Most public blocklists copy from each other. `sources.yaml` gives every source an `independence_class`, and **the scorer must count at most one vote per class**. Two sources in the same class contribute one vote, not two — take the maximum, never the sum.

Getting this wrong produces a feed that looks highly corroborated and is actually one source echoed five times. Any change to scoring must have a test proving that adding a second source to an existing class does not increase the score.

## Hard rules

1. **No network access in unit tests.** Ever. Real recorded responses live in `tests/fixtures/sources/`. Use `pytest-httpx` to serve them. A test that reaches the internet is a broken test — it fails in CI and it makes the suite non-deterministic.
2. **`redistribute: false` is enforced in code, not documentation.** Sources with that flag may influence scoring but must never appear in any file under `feeds/`. This is a licensing obligation. There must be a test for it.
3. **The allowlist is applied last**, after every other stage, and a failed allowlist fetch is a hard error that aborts the run. Never publish a feed built from a partial allowlist.
4. **Deterministic output.** Sort by IP as an integer, not as a string. Running the pipeline twice on the same input must produce byte-identical files, or every scheduled run creates diff noise.
5. **A failing source degrades the run; it never fails it.** One dead upstream must not stop the other eleven. Record the failure in the manifest.
6. **Never commit secrets.** All API keys come from environment variables, and every keyed source must work — or cleanly skip — when its key is absent.
7. **Preserve upstream attribution.** Spamhaus requires that credit and the date/copy text remain with the data. Emitters must carry per-source attribution into the output headers.

## Conventions

- Package layout is `src/xfeeds/`, tests in `tests/`, entry point `xfeeds` via typer.
- Type hints everywhere; `mypy --strict` must pass with no `# type: ignore` unless accompanied by a comment explaining why.
- `ruff check` and `ruff format` must pass. Line length 100.
- Logs are structured JSON via `structlog`. No bare `print()` outside the CLI's user-facing output.
- Pydantic models for every parsed record — do not pass raw dicts between stages.
- Commit messages use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
- Docstrings on every public function explaining *why*, not *what*.

## Test fixtures

`tests/fixtures/sources/` holds **real, trimmed responses** recorded on 2026-08-11, with comment and header lines preserved verbatim so parsers are exercised against genuine header formats. `MANIFEST.json` records each file's origin URL and original line count.

Do not assert on volumes from fixtures — they are truncated. Assert on parsing behaviour: header skipping, CIDR handling, malformed-line rejection, encoding.

Parsers must survive things these fixtures actually contain: `\r\n` line endings (abuse.ch), `;`-prefixed comments (Spamhaus text), tab-separated columns with trailing fields (bruteforceblocker), and JSON-lines rather than a JSON array (Spamhaus DROP).

## Traps specific to this codebase

- **Spamhaus DROP JSON is newline-delimited JSON objects, not a JSON array.** `json.loads` on the whole body fails. Parse line by line, and skip the trailing metadata line.
- **Binary Defense returns a 301 to an HTML page without a browser-like User-Agent.** Send the configured UA and reject any `text/html` response as a source failure.
- **`224.0.0.0/3` appears in FireHOL level1** — 537 million addresses of multicast space. The CIDR width cap exists precisely to catch things like this. Never bypass it.
- **Feodo Tracker currently has ~5 entries and a last-updated header from March 2026.** That is expected, not a bug. Emit a staleness warning past 30 days; do not "fix" it.
- **SSLBL is currently empty.** A source returning zero valid records is a warning, not an error.
- **Tor exit nodes appear inside other feeds** (265 of them in IPsum L3). They must be tagged and capped below the high-confidence threshold, never blocked outright.
- **AbuseIPDB free tier allows only 5 blacklist calls per day.** Cache the response; never call it in a loop or a test.

## Definition of done for any task here

- `ruff check`, `ruff format --check`, and `mypy --strict` all pass.
- `pytest` passes with no network access.
- New behaviour has a test; new *risk-bearing* behaviour has a test for the failure mode, not just the happy path.
- `README.md` or `docs/DECISIONS.md` updated if behaviour diverges from what they describe.
- The task summary states plainly anything you could not do, guessed at, or disagreed with.

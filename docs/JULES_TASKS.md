# Jules task pack — building xfeeds Phase 2

Copy-paste prompts, sequenced into waves. Each task produces one branch and one pull request.

## Before you start

1. **Connect the repo** in Jules and select branch `main`.
2. **Set the environment setup script** to the contents of [`scripts/jules-setup.sh`](../scripts/jules-setup.sh). Jules VMs ship Python 3.12 and an older `uv`; the script installs Python 3.13 to match ADR-001. Save it as a snapshot so every task reuses it.
3. **`AGENTS.md` is read automatically** from the repo root. It carries the settled decisions, hard rules, and known traps — that is why these prompts stay short. Do not paste its contents into prompts.
4. **Always review the plan before approving.** If a plan proposes adding a dependency, using `asyncio`, or enabling a disabled source, reject it and reply with the relevant `AGENTS.md` rule.

### Wave structure

Free-tier Jules allows 3 concurrent tasks and 15 per day. Tasks within a wave touch disjoint files and can run in parallel; waves are strictly ordered.

| Wave | Tasks | Notes |
|---|---|---|
| 1 | T1 | Solo. Everything else depends on it. **Merge before starting wave 2.** |
| 2 | T2, T3, T4 | Parallel — disjoint paths |
| 3 | T5, T7 | Parallel |
| 4 | T6 | Solo. Integration; needs T2–T5 merged. |
| 5 | T8, T9, T10 | Parallel. Phase 2b. |

Merge each wave before starting the next. Parallel tasks all branch from `main`, so unmerged work is invisible to siblings.

---

## Wave 1

### T1 — Project scaffold, config loader, and CI

```
Set up the xfeeds project skeleton and the sources.yaml loader. Read README.md,
docs/DECISIONS.md, and AGENTS.md first — the stack is already decided, do not
substitute alternatives.

Create:

1. pyproject.toml for a uv-managed package named "xfeeds", requires-python
   ">=3.11", targeting 3.13. Runtime deps: httpx, pydantic>=2, tenacity, typer,
   structlog, pyyaml. Dev extras: ruff, mypy, pytest, pytest-httpx.
   Configure ruff (line length 100) and mypy (strict) in pyproject.toml.
   Commit uv.lock.

2. src/xfeeds/models.py — pydantic v2 models:
   - SourceConfig: every field used in sources.yaml, including
     independence_class, weight, vote, redistribute, categories, ttl_days,
     min_interval_seconds, license, license_risk, enabled, parser, auth fields.
     Defaults must come from the `defaults` block in sources.yaml.
   - AllowlistSourceConfig
   - Registry: the whole file, with validators that reject:
       * a duplicate source name
       * a weight outside 0..1
       * a source referencing a parser name that does not exist
       * a voting source with weight 0
   - IndicatorRecord: ip_or_cidr, source name, independence_class, first_seen,
     last_seen, categories, tags. Use ipaddress types, not strings.

3. src/xfeeds/config.py — load and validate sources.yaml, applying the defaults
   block. Expose a helper returning the set of ACTIVE voting independence
   classes (enabled AND vote=true).

4. src/xfeeds/cli.py — typer app exposing `xfeeds validate`, which loads
   sources.yaml, prints a table of sources grouped by independence class showing
   enabled/vote/redistribute, prints the active voting class count, and exits
   non-zero on any validation error. Register the `xfeeds` entry point.

5. src/xfeeds/logging.py — structlog configured for JSON output.

6. .github/workflows/ci.yml — on pull_request and push to main. Use
   astral-sh/setup-uv pinned to a specific version. Matrix over Python 3.11,
   3.12, 3.13, plus 3.14 with continue-on-error true. Steps: ruff check, ruff
   format --check, mypy --strict, pytest.

7. tests/test_config.py — load the real sources.yaml and assert it is valid,
   that exactly 7 voting classes are active with no API keys present, and that
   each invalid-config case above is rejected. No network access.

Acceptance: `uv run xfeeds validate` succeeds against the committed sources.yaml
and reports 7 active voting classes. ruff, mypy --strict, and pytest all pass.

Out of scope: collectors, scoring, emitters. Do not create files under
src/xfeeds/collectors/, emit/, or write anything to feeds/.
```

---

## Wave 2 — parallel

### T2 — Source collectors and parsers

```
Implement the fetching and parsing layer. Read AGENTS.md first, especially the
"Traps specific to this codebase" section — several of those traps are exactly
what this task has to handle.

Create src/xfeeds/collectors/ with:

- base.py: a synchronous httpx client wrapper providing per-source timeout,
  the configured User-Agent, ETag / If-Modified-Since conditional requests with
  an on-disk cache, tenacity retry with exponential backoff on 429 and 5xx
  (never on 4xx), and enforcement of each source's min_interval_seconds.
  A source that fails returns a structured failure result — it must never raise
  out of the collector layer, because one dead upstream must not stop the run.
  Reject responses whose content-type is text/html as a source failure.

- Parsers, one per format, each taking raw bytes and returning IndicatorRecords:
  plain_text, netset, spamhaus_json, spamhaus_asn_json, dshield,
  bruteforceblocker, ipsum_levels.
  Register them in a name -> parser mapping that config.py validates against.

Parser requirements drawn from the real fixtures:
- Spamhaus DROP JSON is newline-delimited JSON objects, NOT a JSON array, and
  has a trailing metadata line to skip.
- abuse.ch files use \r\n line endings.
- Spamhaus text uses ';' comment prefixes; most others use '#'.
- bruteforceblocker is tab-separated with header lines and trailing columns.
- dshield gives "startaddr endaddr netmask ..." and must become a CIDR.
- ipsum_levels files are plain IPs; the level number is metadata supplied by the
  caller, not present in the file.
- Every parser must skip malformed lines and count them, not crash.
- Reject non-global addresses (private, loopback, link-local, reserved,
  multicast) at parse time.

Tests in tests/test_collectors.py: drive every parser from the recorded fixtures
in tests/fixtures/sources/ using pytest-httpx. Cover header skipping, CRLF,
malformed lines, empty sources (sslbl is currently empty — that is a warning,
not an error), and the text/html rejection path. No network access; see
tests/fixtures/sources/MANIFEST.json for provenance. Do not assert on record
counts as a proxy for feed size — the fixtures are truncated.

Out of scope: scoring, filtering, emitting, and the keyed sources
(AbuseIPDB, ThreatFox) which are handled in a later task.
```

### T3 — Allowlist and safety filters

```
Implement the safety layer. Read AGENTS.md first. This is the code that stops
xfeeds from causing an outage, so favour rejecting over publishing everywhere
there is doubt.

Create:

1. allowlist.txt — a static allowlist with a comment explaining each entry:
   RFC1918 ranges, loopback, link-local, CGNAT, multicast and reserved space,
   and the public resolvers 1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 208.67.222.222.

2. src/xfeeds/allowlist.py — build the effective allowlist by fetching the
   allowlist_sources in sources.yaml (Cloudflare, Google Cloud, Googlebot,
   Bingbot, GitHub meta) and unioning them with allowlist.txt.
   A failed allowlist fetch is a HARD ERROR that aborts the run — never build a
   feed from a partial allowlist. Parsers for each JSON shape live here.
   Provide fast containment lookup for both individual IPs and CIDRs; a
   candidate overlapping an allowlisted network in either direction is removed.

3. src/xfeeds/filters.py, applied in this order:
   - drop anything on the allowlist
   - drop non-global addresses
   - CIDR width cap: reject prefixes wider than /22 IPv4 or /48 IPv6, unless the
     record came from spamhaus_drop_v4/v6
   - redistribute enforcement: records whose only sources are all marked
     redistribute:false must be excluded from anything destined for feeds/,
     while remaining available for scoring
   - tag_only enforcement: tor_exits records are tagged, never emitted as blocks

Tests in tests/test_filters.py using the recorded allowlist fixtures:
- 224.0.0.0/3 from the firehol fixture is rejected by the width cap
- a Spamhaus /20 is allowed through the cap but a /8 from any other source is not
- an IP inside a Cloudflare range is removed
- a record sourced only from a redistribute:false source never reaches output
- a tor-tagged record is never emitted as a block
- allowlist fetch failure raises rather than returning a partial allowlist

No network access — use pytest-httpx with the fixtures.

Out of scope: scoring, collectors, emitters.
```

### T4 — Independence-weighted scorer and state

```
Implement scoring and aging. Read the "independence classes" section of
AGENTS.md and ADR-020 in docs/DECISIONS.md before planning. This is the core of
the product and the easiest thing to get subtly wrong.

Create:

1. src/xfeeds/score.py implementing exactly:

     raw = sum over DISTINCT independence classes of:
             max(weight * recency_factor * severity) across sources in that class
     recency_factor = max(0.2, 1 - days_since_last_seen / ttl_days)
     score = 100 * (1 - exp(-raw))

   One vote per class — take the maximum within a class, never the sum.
   Sources with vote:false contribute no votes at all.
   IPsum is a bounded prior only: level >= 5 adds a small fixed bonus capped so
   it can never by itself move a record between bands.
   Direct promotions to high confidence, bypassing the threshold: membership in
   Spamhaus DROP, or an active abuse.ch C2 listing.
   Records tagged tor-exit are hard-capped just below the high-confidence
   threshold regardless of score.
   Bands: high >= 3 distinct voting classes, medium = 2, withheld = 1.

2. src/xfeeds/state.py — load and save prior state from feeds/all.json so
   first_seen is preserved across runs and last_seen is refreshed. Age records
   out after their source's ttl_days with no observation. Removals are recorded
   in the run report, never silent. Missing state file must be handled as a
   clean first run.

Tests in tests/test_score.py — these matter more than the implementation:
- REGRESSION TEST, the important one: adding a second source in an ALREADY
  PRESENT independence class does not increase the score. Adding a source in a
  NEW class does.
- a single source, at any weight, never reaches the high band by score alone
- recency_factor floors at 0.2 and never goes negative for very stale records
- a Spamhaus record is promoted to high with only one class present
- a tor-tagged record with 4 classes still does not reach the high band
- the IPsum bonus alone cannot move a record between bands
- first_seen survives a state round-trip; an aged-out record is dropped and
  reported

Use hand-built fixtures for these — do not fetch anything.

Out of scope: collectors, filters, emitters, CLI wiring.
```

---

## Wave 3 — parallel

### T5 — Core emitters and manifest

```
Implement output generation. Read AGENTS.md, especially the determinism and
attribution rules.

Create src/xfeeds/emit/ producing, under feeds/:

- high-confidence.txt and medium-confidence.txt — one IP or CIDR per line, with
  a comment header carrying generation timestamp, entry count, the project URL,
  and per-source attribution. Spamhaus attribution and its date/copy text must
  be preserved verbatim where its data contributed — this is a licence
  obligation, not a nicety.
- all.csv — columns ip,score,band,classes,sources,categories,tags,first_seen,last_seen
- all.json — full records with per-source provenance
- schema.json — generated from the pydantic model via model_json_schema()
- manifest.json — generated_at, per-source status (ok / failed / stale / empty),
  record counts, licence and licence_risk per contributing source, band counts,
  and added/removed deltas versus the previous run

Hard requirements:
- Deterministic output: sort by IP as an INTEGER, not lexically. Two runs over
  identical input must produce byte-identical files, otherwise every scheduled
  run generates diff noise.
- Records excluded by redistribute:false must not appear in ANY file here.
- Stable field ordering in CSV and JSON.

Tests in tests/test_emit.py:
- byte-identical output across two runs on the same input
- integer sort ordering, verified with addresses that sort differently as
  strings (e.g. 9.9.9.9 before 10.0.0.1)
- a redistribute:false record is absent from every emitted file
- Spamhaus attribution present in the text feed header when its data is included
- schema.json validates all.json

Out of scope: STIX, MISP, nftables, ipset, and Cloudflare emitters — later task.
Do not wire up the run orchestration; that is T6.
```

### T7 — Scheduled workflow and Pages publishing

```
Add the automation workflows. Read the Automation section of README.md and
ADR-004. This task only touches .github/ — do not modify src/.

Create .github/workflows/update-feeds.yml:
- Triggers: schedule every 6 hours at :17 past the hour (offset to avoid the
  thundering herd on upstream sources), plus workflow_dispatch.
- Concurrency group so overlapping runs cancel.
- Steps: checkout, astral-sh/setup-uv pinned, uv python install 3.13, uv sync,
  restore the HTTP cache via actions/cache, run `uv run xfeeds run`, then commit
  changed files under feeds/ with the message
  `chore(feeds): refresh <ISO8601> (+N/-M)` and push to main.
- Secrets ABUSEIPDB_API_KEY, THREATFOX_AUTH_KEY, GREYNOISE_API_KEY, OTX_API_KEY
  passed as env. All optional: absent keys must not fail the workflow.
- Minimal permissions: contents write, issues write, pages write, id-token write.
- On failure, or when the run reports a churn-guard trip, open or update a
  GitHub issue titled "xfeeds run failure" with the run report attached.
  Do not open a duplicate issue if an open one already exists.

Create .github/workflows/pages.yml to publish the feeds/ directory to GitHub
Pages using actions/deploy-pages, triggered after a successful feed refresh.
Set correct content types so .txt files serve as text/plain.

Also add a dependabot.yml keeping github-actions and uv dependencies current,
grouped into a single weekly PR.

Note: `xfeeds run` does not exist yet — it lands in T6. Write the workflow
against that interface as specified in README.md; do not implement the CLI here,
and do not stub it in src/.

Acceptance: both workflows pass actionlint and the YAML is valid.
```

---

## Wave 4

### T6 — Pipeline orchestration, churn guard, and explain

```
Wire the stages into a working pipeline. Collectors, filters, scorer, and
emitters are already merged — read them before planning, and reuse rather than
reimplement. Read AGENTS.md.

Create:

1. src/xfeeds/pipeline.py — orchestrate collect, normalize, score, filter, emit
   in that order, with the allowlist applied last before emission. Sources are
   processed independently: any single source failure is recorded and the run
   continues. Emit a staleness warning when a source's last-updated header is
   more than 30 days old.

2. Churn guard, enforced before anything is written: if the run would add or
   remove more than 25% of the current high-confidence feed, abort, write the
   run report, exit non-zero, and leave the existing feeds untouched. Provide
   --force to override for a deliberate first run or intentional large change.

3. src/xfeeds/report.py — a run report (JSON plus a human-readable summary)
   covering per-source status and timing, records in and out at each stage,
   band counts, added and removed deltas, and every warning raised.

4. Extend the CLI:
   - `xfeeds run [--dry-run] [--force] [--only SOURCE]`
   - `xfeeds diff` — compare the working tree's feeds/ against the previous
     committed state
   - `xfeeds explain <ip>` — show every source that reported the address, its
     independence class and weight, the recency factor, the computed score, the
     resulting band, and if it is excluded, which specific rule excluded it.
     This is the debugging tool for false-positive reports, so make the output
     genuinely readable.

5. An end-to-end test in tests/test_pipeline.py driving the whole pipeline from
   the recorded fixtures with pytest-httpx, asserting that feeds are produced,
   that output is deterministic across two runs, and that the churn guard trips
   on a synthetic 50% swing. Also assert the pipeline completes successfully
   when a source returns a 500.

Then perform a real first run locally and commit the generated feeds/ directory
so the repository ships with a working feed. Use --force for this initial run
since there is no baseline. In the PR description, report the actual band
counts you got and how they compare to the estimates in ADR-020
(~77.5% withheld, ~19% medium, ~3.5% high; expected high-confidence feed of
roughly 2,000-4,000 entries). If your numbers differ substantially, say so
explicitly rather than adjusting the thresholds to match.
```

---

## Wave 5 — parallel, Phase 2b

### T8 — Authenticated collectors

```
Add the two keyed sources. Read AGENTS.md and the notes in sources.yaml for each.

1. AbuseIPDB blacklist collector (src/xfeeds/collectors/abuseipdb.py):
   GET https://api.abuseipdb.com/api/v2/blacklist with the key in a `Key` header.
   Free tier permits only FIVE blacklist calls per day and locks
   confidenceMinimum at 100 with a 10,000 entry cap. Cache the response to disk
   and refuse to call the endpoint if a cached response is younger than
   min_interval_seconds. Surface X-RateLimit-* headers into the run report.
   This source is redistribute:false — verify with a test that its records
   influence scoring but never reach feeds/.

2. ThreatFox collector (src/xfeeds/collectors/threatfox.py):
   POST https://threatfox-api.abuse.ch/api/v1/ with the Auth-Key header.
   Extract ip:port IOCs, keeping only the IP. abuse.ch made authentication
   mandatory in June 2025, so send the key on every request.

Both must skip cleanly with a logged warning when their key is absent — no
failure, no exception. Set enabled:true for both in sources.yaml, since absent
keys are now handled gracefully.

Record fixtures for both under tests/fixtures/sources/ by hand-writing
representative responses based on the documented response shapes — do NOT call
the live APIs from tests, and do not consume the daily quota.

Verify `xfeeds validate` reports 9 active voting classes once keys are present
and still 7 when they are not.
```

### T9 — Interoperability emitters

```
Add the remaining output formats so xfeeds can be consumed by threat
intelligence platforms and firewalls directly. Read ADR-005 and ADR-006.

Add to src/xfeeds/emit/:
- stix.py — a STIX 2.1 bundle using the `stix2` library. One Indicator object
  per record with a STIX pattern of the form [ipv4-addr:value = '...'],
  valid_from, labels from categories, and confidence mapped from score.
  Add a single Identity object for xfeeds as created_by_ref.
- misp.py — a native MISP feed: manifest.json plus per-event JSON, following the
  MISP feed layout so the feed URL can be added directly to a MISP instance.
- firewall.py — nftables set syntax, iptables/ipset restore format, and a
  Cloudflare IP Access Rules list.

All must respect redistribute:false and carry attribution, same as the core
emitters. All must be deterministic.

Tests: validate the STIX bundle parses back through the stix2 library, that the
MISP manifest matches the documented feed structure, and that the nftables and
ipset outputs are syntactically valid. Determinism test for each.

Do not add a TAXII server — explicitly out of scope per ADR-006.
```

### T10 — Source health monitor (create as a Jules Scheduled Task)

```
Add a source health monitor that detects when an upstream feed silently dies.

Create src/xfeeds/health.py and a `xfeeds health` CLI command that, for every
enabled source, reports reachability, HTTP status, response size versus the last
recorded run, the age of any last-updated header, and the parsed record count
versus the trailing average.

It flags: a source unreachable for more than 24 hours, a record count that moved
more than 50% versus the trailing 7-run average, a last-updated header older
than 30 days, and any source that starts requiring authentication when it
previously did not.

Add .github/workflows/source-health.yml running it daily and opening a GitHub
issue when anything is flagged, updating the existing issue rather than opening
duplicates.

Store trailing history in feeds/health-history.json, capped at the last 30 runs
so the file cannot grow without bound.
```

Set T10 up through Jules' **Scheduled Tasks** (Planning dropdown → Scheduled Task) on a weekly cadence, with a prompt such as: *"Review open source-health issues in this repo. If a source has been failing for more than 7 days, open a PR disabling it in sources.yaml with a note explaining why, and update docs/DECISIONS.md."*

---

## Reviewing what comes back

Jules is good at the mechanical work and weakest exactly where this project is riskiest. Check these regardless of how clean the diff looks:

- **The independence rule.** Confirm the scorer takes the max within a class rather than summing. This is the one bug that would quietly invalidate the whole feed.
- **Filter ordering.** The allowlist must run last. An allowlist applied before scoring can be undone by a later stage.
- **New dependencies.** `AGENTS.md` forbids several by name. Check `pyproject.toml` on every PR.
- **Tests that reach the network.** Grep for `httpx.get` and real URLs in `tests/`.
- **Determinism.** If the churn guard fires on a no-op run, sorting or timestamp handling is non-deterministic.
- **Silently widened caps.** Verify the /22 rule survived contact with real Spamhaus data.

Before merging T6, sanity-check the generated feed by hand: pick ten entries from `high-confidence.txt`, run `xfeeds explain` on each, and confirm the sources cited are genuinely independent of one another.

# Source discovery agent brief

Step-by-step instructions for a coding agent performing a source-discovery
review cycle. Triggered by the `source-review.yml` workflow or by a
maintainer. This document is the single entry point — an agent that reads
this and the files it links to should be able to complete a review cycle
without further guidance.

Read [`AGENTS.md`](../AGENTS.md) first for the hard rules and settled
decisions. Read [`docs/source-lifecycle.md`](source-lifecycle.md) for the
full policy. This brief is the operational checklist.

---

## What you are doing

Surveying candidate IP threat-intelligence feeds against documented
admission criteria, producing a report, and opening PRs for any that pass.
You are **not** auto-enabling sources. Every admission is a PR that a
human reviews and merges.

## What already exists — do not re-survey

Before looking for new candidates, read these to avoid re-covering ground:

1. **[`docs/DECISIONS.md`](DECISIONS.md)** — every ADR. Especially:
   - ADR-033 (2026-08-12): surveyed 20 candidates, rejected all. The
     table records each rejection and why.
   - ADR-052: the source lifecycle and discovery policy.
   - Any later ADR that may have added or retired a source.
2. **[`sources.yaml`](../sources.yaml)** — the current source list with
   notes, licence fields, and `dormant` / `enabled` flags.
3. **[`docs/source-methodology-2026-08.md`](source-methodology-2026-08.md)**
   — what each current source documents about its sensor method and scoring.
4. **[`tests/fixtures/sources/MANIFEST.json`](../tests/fixtures/sources/MANIFEST.json)**
   — the real responses recorded for each source, with origin URLs.
5. **[`docs/SOURCE_CANDIDATES.md`](SOURCE_CANDIDATES.md)** — the persistent
   candidate register: every candidate considered, its status, and the
   condition under which a rejected or deferred one should be revisited.
   Update it at the end of every review.

A candidate rejected in ADR-033 or a later ADR should not be re-surveyed
unless the rejection reason has changed (e.g., a source gained a licence
file, or its endpoint came back online).

## Step 1: Identify coverage gaps

Check the current state of the feed:

```bash
# What sources are stale or dormant?
grep -E "dormant: true|enabled: false" sources.yaml

# What does the live manifest say about source health?
curl -s https://neilweitzel.github.io/xfeeds/manifest.json | python3 -m json.tool | grep -A5 '"status"'
```

Look for:
- **Threat categories with no active source** — e.g., if the only
  botnet-c2 source is dormant, that is a gap.
- **Address-family gaps** — the open item for a second IPv6 host-level
  source that permits redistribution.
- **Independence-class gaps** — if a class is carried by a single source
  and that source goes stale, the class is effectively gone.
- **Sources that were disabled and might have replacements.**

## Step 2: Survey candidates

Survey by **lane**, not by search query. Each lane gets its own table, a short
"top candidates considered" list, and a reason for every exclusion, including
"not evaluated" with the reason it was not. A lane with no viable candidate is
a finding, not an omission.

| Lane | What it covers |
|---|---|
| `c2` | Malware distribution and command-and-control infrastructure |
| `abuse` | Botnet, brute-force, scanning, and exploitation sensors (honeypots, community reports) |
| `proxy` | Proxy and anonymization infrastructure (VPN, residential, open proxies) |
| `fraud` | Spam, forum abuse, and fraud infrastructure |
| `ipv6` | Host-level IPv6 sources, the standing ADR-033 gap |
| `commercial` | Credentialed or paid sources evaluated as `redistribute: false` scoring-only |
| `fp` | False-positive controls: benign-scanner and known-good inputs that cap or exclude |
| `existing` | Higher-volume or better endpoints from publishers already configured |

**Paid or authenticated access is not a disqualifier.** Evaluate it under
`redistribute: false`. Record price, quota, and terms, but do not buy or
create an account; list what access the maintainer would need instead.
**A time-limited trial or evaluation licence is not a path to a source.** It
cannot contribute to the long-term dataset, so evaluate the ongoing plan or
reject the candidate as trial-only.

Search in:

- **GitHub** — search for repositories with IP blocklists, threat feeds,
  or IOC collections. Check the licence file before anything else, and read
  the git history: it measures churn and removals directly (ADR-057).
- **Abuse.ch and similar platforms** — check for new endpoints from
  publishers already in the source list.
- **Security vendor community feeds** — free tiers with usable terms.
- **Commercial vendors** — scoring-only candidates for the `commercial` lane.
- **Academic or research projects** — honeypot networks, scanner
  observatories.
- **Aggregator source lists** — aggregators are rejected as sources, but
  their published input lists are a cheap way to find primary publishers.

For each candidate, record in a table:

| Candidate | URL | Volume | Licence | Independence | Sensor method | Verdict |
|---|---|---|---|---|---|---|

For each candidate that survives to a recommendation, add an **incremental
coverage hypothesis**: the gap it fills, expected overlap, expected
false-positive risk, and the measured outcome that would justify keeping it.

## Step 3: Evaluate against admission criteria

Each candidate must pass **every** gate. Failing any one is a rejection,
recorded with the reason.

### Licence and redistribution

- Does the source have an explicit written licence? Check the repository,
  the feed page, and the response headers.
- `NOASSERTION` on GitHub = no licence = rejection.
- If the licence permits redistribution, note whether it is CC0, MIT,
  BSD, CC BY, CC BY-SA, or CC BY-NC-SA. This determines tier placement.
- If the licence does not permit redistribution but permits use, the
  source can be `redistribute: false` (scoring only).

### Independence

- Fetch the candidate's data and compare against the current published
  feed. Compute Jaccard overlap:

  ```python
  # candidate_ips = set of IPs from the candidate feed
  # published_ips = set of IPs from feeds/all.json (the "indicators" list)
  overlap = len(candidate_ips & published_ips) / len(candidate_ips | published_ips)
  ```

- If overlap > 0.5 with any single existing source, the candidate shares
  that source's independence class and cannot add a vote. Record the
  measurement and reject.
- Also compute **containment**, because Jaccard cannot see a subset:

  ```python
  containment = len(candidate_ips & source_ips) / len(candidate_ips)
  ```

  Record it; do not reject on it. Overlap between independent sensors is
  corroboration, which is what xfeeds measures and publishes (ADR-064). High
  containment is a prompt to check provenance: the candidate shares the
  other source's class only if the publisher says it ingests that source or
  the sets are near-identical. Rutgers' attacker list (93.7% inside
  Blocklist.de, and its status page names a Blocklist.de listing as a trigger)
  is derived. Sblam (72.5% inside StopForumSpam, collected from spam submitted
  to its own classifier) is corroborating. Report containment against
  aggregates such as IPsum for context only.
- If overlap is low, assign a new `independence_class` name.

### Sensor method

- Does the source document how it collects indicators? "Scraped from
  other lists" is not a sensor method.
- Look for: honeypot networks, log analysis, human investigation,
  community submissions with review, active verification.
- Check [`docs/source-methodology-2026-08.md`](source-methodology-2026-08.md)
  for the format of what to record.

### Update cadence and freshness

- Does the source have a feed-level timestamp (Last-Modified header,
  payload header, API timestamp)?
- If there is no freshness signal, the freshness gate from ADR-052 cannot
  work, and the source should be rejected.

### Endpoint stability

- Is the URL stable, or is it an ad-hoc paste?
- What access does it need? A free key is fine. Paid or credentialed access is
  acceptable for a `redistribute: false` source on an ongoing basis; any
  purchase is a separate maintainer decision. Trial-only access is a rejection.

### Volume and churn

- Fetch the feed a few times if possible. How many records? Does it
  change between fetches?
- A source that never changes is either dead or an all-time list. All-time
  lists that never remove entries are high false-positive risk.

### False-positive risk

- Are the IPs cloud-hosted or dynamically allocated? These get recycled
  and are high FP risk.
- Does the source document a verification step or a removal policy?

### Address families

- Does it carry IPv4, IPv6, or both? IPv6 host-level sources are
  specifically valuable (open item from ADR-033).

## Step 4: Produce the report

Write the report as a comment on the source-review GitHub issue (or as a
new `docs/source-discovery-YYYY-MM.md` file if no issue exists). Include:

- The coverage gaps identified.
- The candidate table with all evaluations.
- For each rejection: the candidate, the gate it failed, and the evidence.
- For each candidate recommended for admission: a summary of why it
  passes every gate.
- One section per lane from Step 2, including lanes with no viable candidate.
- The access the maintainer would need to provide (accounts, subscriptions,
  tokens).

Then update [`docs/SOURCE_CANDIDATES.md`](SOURCE_CANDIDATES.md): add every new
candidate, update the status and last-reviewed date of every candidate
re-checked, and set the revisit condition. The register is the durable state;
the dated report is the evidence.

## Step 5: Open PRs for admitted sources

For each candidate that passes all gates, open one PR. The PR must include:

### sources.yaml entry

Copy an existing source as a template. Fill in:

```yaml
- name: candidate_name
  credit: "Human-readable credit line"
  url: https://candidate.example.com/feed.txt
  parser: plain_text  # or the appropriate parser
  independence_class: new_class
  weight: 0.8  # 0.6–1.0 based on sensor quality
  categories: [scanning]  # from the source's own taxonomy
  ttl_days: 10  # based on the source's update cadence
  license: "Named licence"
  license_url: https://candidate.example.com/license
  notes: >
    Brief description of the source, its sensor method, and any
    caveats discovered during evaluation.
```

### Parser (if needed)

If the source uses a format not handled by an existing parser, add one to
`src/xfeeds/collectors/parsers.py`. The existing parsers are: `plain_text`,
`abuseipdb`, `bruteforceblocker`, `cloudflare_json`, `dataplane`, `dshield`,
`github_meta`, `google_json`, `ipsum_levels`, `ipthreat`, `netset`,
`spamhaus_asn_json`, `spamhaus_json`, `threatfox_api`, `turris_greylist`.

### Test fixture

Fetch a real response from the endpoint and save a trimmed version to
`tests/fixtures/sources/candidate_name.txt`. Update
`tests/fixtures/sources/MANIFEST.json` with the origin URL and original line
count. The fixture must preserve header lines verbatim so the parser is
exercised against genuine formats.

### ADR entry

Add an entry to `docs/DECISIONS.md` recording:
- The source, its URL, and its licence.
- The Jaccard overlap measurement against existing sources.
- The sensor method documented by the publisher.
- The independence class assignment.
- The weight and TTL chosen, with reasoning.

### Scoring test

Add a test to `tests/test_pipeline.py` proving the new source:
- Votes in its independence class.
- Does not increase the score when a second source in the same class is
  added (the critical invariant).
- Promotes or not, as configured, with the expected band.

### PR description

Include in the PR body:
- The coverage gap this source fills.
- The licence audit result.
- The Jaccard overlap measurement.
- Whether this change restarts the RC burn-in clock (it does — any
  `sources.yaml` change restarts it).

## Step 6: After the PR merges

- The pipeline picks up the new source on the next scheduled `Update feeds`
  run (target cadence every 6 hours; the trigger fires at `17 */3 * * *` and a
  guard stands down the extra slots - see ADR-062).
- Confirm the source appears in the manifest with `status: "ok"` and a
  non-zero record count after the first run.
- If the source is stale on first run, the freshness gate will prevent it
  from solo-promoting. That is correct behaviour, not a bug.
- The burn-in clock restarts. If this was during an RC window, a new RC
  tag is needed (e.g., `rc.3`).

## What not to do

- Do not auto-enable sources. Every admission is a PR for human review.
- Do not add a source to fix volume. Volume is not a reason to admit a
  source that fails licence, independence, or FP-risk gates.
- Do not re-survey candidates already rejected in ADR-033 or a later ADR
  unless the rejection reason has changed.
- Do not add a dependency to parse the source. The existing parsers and
  standard-library `json` / `ipaddress` are sufficient. If a new
  dependency is truly needed, it requires a new ADR entry.
- Do not weaken any check to make the PR pass. Fix the code.

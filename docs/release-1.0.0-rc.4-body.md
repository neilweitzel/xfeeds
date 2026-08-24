## xfeeds v1.0.0-rc.4

Fourth release candidate. The `rc.3` burn-in window surfaced a **carry-forward defect that had been demoting corroborated records on three refreshes out of every four**, so the candidate is re-cut rather than promoted to `v1.0.0`. This candidate also carries the citation and licensing metadata that made the project archivable and citable.

### What changed since rc.3

- **Carry-forward no longer discards a sighting from earlier the same UTC day (ADR-054).** Observation timestamps are truncated to the UTC day — deliberately, because TTLs are measured in days and microsecond stamps would rewrite every row of `all.json` on every run. State `last_seen` values use the same stamp. So a source seen on an earlier run of the *same* day had an age of exactly `0.0`, and `carried_observations` threw it away, because its guard rejected `age_days <= 0.0` along with genuinely nonsensical negative ages.

  The effect: carry-forward worked on the first run of each UTC day and was silently inert on the other three. A source missing from a mid-day fetch had neither a fresh observation nor a carried one, so its whole independence class vanished and every record relying on it dropped a class — often below the publication threshold — until the next UTC midnight. That is precisely the regression `carried_observations` was written to prevent (ADR-037), described in its own docstring.

  Only negative ages are rejected now. `recency_factor` already handled zero age correctly, returning `1.0`, which is right: the source did see the address today. Carried records stay flagged and still cannot promote, so this restores corroboration counting without letting a carried vote admit an address on its own.

- **Citation and licensing metadata.** `LICENSE` at the repository root (the README had claimed MIT since the start, but with no licence file the claim was unverifiable by tooling and blocked archival), `CITATION.cff` anchored to ORCID iD `0009-0007-2546-2331`, and `.zenodo.json` committed ahead of any deposit so archived authorship is not derived from repository contributors — which would otherwise credit automation commits as authors.

- **A `citation` CI job.** Validates the CFF against its schema and asserts the ORCID iD and licence agree across `CITATION.cff`, `.zenodo.json`, and `pyproject.toml`. Metadata that drifts is worse than metadata that is absent, so it is checked rather than trusted.

- **DOI wiring.** The concept DOI [10.5281/zenodo.22045733](https://doi.org/10.5281/zenodo.22045733) and the ORCID iD are now cited on the README, the live dashboard, and in `CITATION.cff`. The ORCID iD icon is inlined as SVG rather than hot-linked, preserving the dashboard's zero third-party requests.

- **Documentation.** `docs/CITABILITY.md` records the archival plan; `docs/RELEASE_CHECKLIST.md` enumerates the `v1.0.0` promotion steps, including the version strings that nothing enforces agreement between and the `source-review.yml` cadence switch that must land after the release rather than in it.

### How the defect was found

A user observation, and a good one: addition counts were spiking on roughly every fourth refresh. The guess was that upstream sources publish on daily schedules.

The additions half was correct — every spike lands at 01:00–02:00 UTC without exception. But measuring the same window showed removals collapsing from a mean of ~550 per run to ~30 at that same hour:

| Hour UTC | Runs | Mean added | Mean removed |
|---:|---:|---:|---:|
| **01–02** | **5** | **786** | **30** |
| 07 | 5 | 249 | 595 |
| 13 | 5 | 360 | 545 |
| 18–19 | 5 | 488 | 536 |

Upstream publication cadence explains more additions. It does not explain removals nearly stopping. That asymmetry is what located the cause inside the pipeline rather than upstream.

The visible symptom was a sawtooth in feed size, peaking on the first run after UTC midnight and decaying across the day:

```
2026-08-22  01:51 → 6153    07:00 → 5852    13:02 → 5694    18:50 → 5782
2026-08-23  02:00 → 6657    07:02 → 6385    13:03 → 6196    18:49 → 6136
2026-08-24  01:58 → 6898    07:29 → 6515    13:14 → 6324
```

### What this means for consumers

- **Feed size no longer depends on the hour you sample it.** Before this fix the published feed held 6,898 records at 01:58 UTC on 2026-08-24 and 6,324 at 13:14 — a 9% swing from sampling time alone. Anyone comparing xfeeds against another feed was comparing against a moving target.
- **Published volume settles higher and flatter.** This is a correction, not an inflation: the affected records always had the corroboration, and the pipeline was failing to count it.
- **No schema or contract change.** Feed paths, record schema, and manifest fields are unchanged. Nothing to migrate.
- **Per-run churn figures measured before this fix are overstated** and should not be cited.

### Burn-in

`rc.4` starts a fresh roughly one-month window. It closes **on or after 2026-09-24**. If no corrective work is needed it will be promoted to `v1.0.0` unchanged; corrective pipeline, source-configuration, or workflow changes cut a new candidate and restart the window, while routine refresh commits and documentation do not.

The 1 September source review falls inside this window. Opening that issue is harmless — the workflow prompts a human review and auto-enables nothing. The default is to run the review and hold any source-admission PRs until after promotion, since a source admitted the week before a release has had no burn-in of its own.

### Not archived

No DOI is minted for a release candidate. The concept DOI always resolves to the newest *published* version, and `CITATION.cff` deliberately still names `rc.3` — the most recent archived version a reader can actually retrieve. Both move together at `v1.0.0`.

**Full changelog:** [`CHANGELOG.md`](../CHANGELOG.md) · **Decision record:** ADR-054 in [`docs/DECISIONS.md`](DECISIONS.md)

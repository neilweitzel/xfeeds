## xfeeds v1.1.0-rc.1

First v1.1.0 release candidate. It opens the window for the sources accepted in the October 2026 source review (#62) and makes each source's contribution a measured output. **Feed paths, record schema, and every existing manifest field are unchanged.** Additive only: the manifest gains `research_scanners_capped`; `insights.json` gains `class_contribution`.

### Sources admitted

| Source | Class | Role | Tiers | ADR |
|---|---|---|---|---|
| ReportedIP (CC BY 4.0) | `reportedip` | Admitting; 82 IPv6 hosts | primary, NC, clean | ADR-067 |
| jacobrakai honeypot (CC0) | `jacobrakai` | Admitting; first admitting class for `telnet-attack` | primary, NC, clean | ADR-066 |
| Carpathian (CC BY 4.0) | `carpathian` | Admitting; rows limited to 30 days by their own `last_seen` | primary, NC, clean | ADR-069 |
| Sblam | `sblam` | Voting-only `spam-source` | none | ADR-065 |
| SANS ISC `sources/attacks` | `dshield` (existing) | Voting-only in every tier; ~9,200 dated hosts | none | ADR-068 |
| SANS ISC research-scanner labels | none | Benign cap after GreyNoise: high to medium only | none | ADR-070 |

Active voting classes: 13 to 17. Licences are read as written (ADR-060); every feed header carries the issue/PR path for corrections.

### Contribution report (ADR-064)

Every run now records, per independence class: published and high records it supports, records that would be withheld or lose high confidence without it (leave-one-class-out rescoring), and asymmetric containment against every other class. The analysis page shows it as **What each class contributes**. Overlap between independent sensors is corroboration and is reported, not penalised. Voting-only classes must show zero records withheld without them; a live scratch run confirmed it.

### What to expect

- Upper-bound estimates from the review: ReportedIP up to about 4,384 new primary records, mostly medium, and about 701 medium-to-high upgrades (inside the 25% churn guard). The research-scanner cap moves some high records to medium.
- New code paths: `dshield_api`, `carpathian_json`, and `isc_threatintel` parsers; `SourceConfig.max_row_age_days`; the `benign_cap` source role.

### Window

`sources.yaml` and `src/` changed, so this is a new candidate window. It runs on the normal GitHub-only schedule (four refreshes per UTC day at most, best-effort). `v1.0.1` stays the stable release until v1.1.0 is promoted through the release checklist.

PRs: #65, #68, #69, #70, #71, #72, #73.

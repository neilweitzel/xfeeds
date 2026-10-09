## xfeeds v1.1.0-rc.2

Second v1.1.0 release candidate, one day into the window opened by `v1.1.0-rc.1`. **No source or scoring change.** Feed paths, record schema, and existing manifest fields are unchanged.

### Fixed

- **Scanner caps on every published tier (ADR-071).** `feeds/noncommercial/` had never received the GreyNoise cap (ADR-049) or, since rc.1, the research-scanner cap (ADR-070), with no recorded reason. On 2026-10-09 it published 20,199 records, 18,893 high, uncapped. All three tiers now use one shared cap path, GreyNoise first, and each tier's manifest reports its own `benign_scanners_capped` and `research_scanners_capped` (the clean tier previously reported 0 while capping).

### Changed

- The source-review issue template now matches the admission rules: licences read as written (ADR-060), containment recorded as corroboration (ADR-064), ongoing access only.

### Window

`src/` and `.github/workflows/` changed, so the window restarts with the first scheduled refresh on rc.2. `v1.0.1` remains the stable release.

PRs: #75 and the release PR.

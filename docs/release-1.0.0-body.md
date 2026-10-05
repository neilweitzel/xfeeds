# xfeeds v1.0.0

First stable release of the independence-aware threat-intelligence pipeline.
Promotes rc.7 plus the reporting-only correction in
[PR #55](https://github.com/neilweitzel/xfeeds/pull/55), observed unchanged since
September 2. No new source, scoring, expiry, or licensing behavior.

- Independent source families vote once; restricted evidence may corroborate but
  cannot admit or identify its source in public records.
- Primary, noncommercial, and clean-provenance tiers retain distinct rights.
- Stable feed paths and IPv4/IPv6 outputs remain unchanged.
- Consumer documentation clarifies that band, not a cross-band score threshold,
  determines policy.
- Health reporting separates acknowledged dormant sources from missing ones.

The release versions software and contracts, not the continuously refreshed feed
contents. Feed timing remains best-effort; scheduler hardening follows in a
separate patch rather than being represented as burned-in code.

[Release evidence and work items](https://github.com/neilweitzel/xfeeds/blob/main/docs/RELEASE_2026-10-05.md)
and [changelog](https://github.com/neilweitzel/xfeeds/blob/main/CHANGELOG.md).
Zenodo archival under concept DOI
[10.5281/zenodo.22045733](https://doi.org/10.5281/zenodo.22045733) is a separate,
approval-gated step; publication will be recorded when complete.

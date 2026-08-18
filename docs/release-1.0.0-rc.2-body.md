## xfeeds v1.0.0-rc.2

Second release candidate. The freshness-gated promotion policy (ADR-052)
establishes that **fetch time is not evidence time**: a source whose own
declared update timestamp exceeds its freshness threshold cannot
solo-promote, even when the fetch succeeded. Stale-evidence observations
may still vote and corroborate, but cannot put IPs into the high-confidence
feed on their own.

### What changed since rc.1

- **Freshness-gated promotion.** A source whose HTTP Last-Modified exceeds
  `min(30 days, ttl_days)` cannot solo-promote. The core invariant: a
  successful fetch is not the same as fresh evidence. Feodo Tracker was
  returning HTTP 200 with the same 5 IPs every run on a 166-day-old
  `Last-Modified` header — the pipeline treated that as current evidence.
  It no longer does.
- **Dormant source state.** Feodo Tracker marked `dormant: true`. The
  families it tracks (Emotet, Dridex, TrickBot, QakBot, BazarLoader) have
  almost no live C2 left after the 2021 Emotet takedown and Operation
  Endgame (2024–2026). It stays enabled for corroboration and will
  reactivate if upstream publishes fresh data, but cannot solo-promote
  while dormant.
- **Source lifecycle and discovery policy.** A new policy document
  (`docs/source-lifecycle.md`) defines five lifecycle states — Active,
  Stale watch, Dormant, Retired, Reactivated — freshness thresholds, and a
  recurring source discovery review process with documented admission
  criteria.
- **Source discovery review workflow.** A new GitHub Actions workflow
  opens a recurring issue with a review checklist. Monthly during RC
  burn-in, quarterly after v1.0.0. Does not auto-enable sources.
- **Dashboard text dedup.** Removed redundant text that appeared two or
  three times across the about section, licensing section, and shared
  footer. No visible text was lost; each piece of information now appears
  once.

### Impact on the published feed

Feodo Tracker's 5 solo-promoted high-confidence records fall out of the
feed on the next run after this merge. No other record is affected — Feodo
does not corroborate any other indicator. The high-confidence feed drops
from 4,356 to 4,351.

Feed URLs are stable and served from GitHub Pages. Pinning this tag does
not change what you fetch.

### Why a second candidate

The rc.1 burn-in window caught a source (Feodo Tracker) that had been stale
for 166 days but could still solo-promote IPs into the published feed on
old evidence. ADR-052 generalises the fix into a standing policy rather
than an ad-hoc patch, and the source discovery workflow ensures the
pipeline regularly evaluates new sources as threat ecosystems evolve.

### Reporting a problem during the candidate window

False positives are the primary risk in a feed you drop traffic on. If an
address should not be listed, open an issue or a pull request against
`allowlist.txt`. Include the address and why it is legitimate — the run
report and `xfeeds explain` will show which sources put it there.

Full history in [`CHANGELOG.md`](https://github.com/neilweitzel/xfeeds/blob/main/CHANGELOG.md).
Dashboard at https://neilweitzel.github.io/xfeeds/.

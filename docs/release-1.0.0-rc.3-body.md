## xfeeds v1.0.0-rc.3

Third release candidate. ADR-052 stated the right invariant — **fetch time is
not evidence time** — but implemented only half of it. A stale or dormant
source could not solo-promote, yet it still voted at full weight and its
independence class still counted toward the two classes required to publish an
address. ADR-053 closes both halves: **evidence nobody is vouching for today is
non-admitting.**

### What changed since rc.2

- **Unvouched evidence cannot admit a record.** `evidence_stale` and `dormant`
  previously appeared only in the promotion gate. The voting path above it added
  the source's independence class to the admitting count unconditionally, so a
  stale source could supply *one of the two classes* that publish an address —
  half the admitting evidence coming from an upstream frozen months earlier.
  Stale and dormant classes now join the same non-admitting lane as
  licence-restricted sources: they may raise confidence in a record that already
  stands on live corroboration, but they never admit one and they never promote.
- **Stale votes are actually damped now.** ADR-052 described corroboration "at a
  decayed weight", but `recency_factor` decays on when the address was last
  *seen*, which equals the current run on every successful fetch. Feodo Tracker
  answers HTTP 200 each run, so its five records were re-collected as fresh
  sightings and voted at full strength against content frozen on 2026-03-04 —
  about 168 days. A new `STALE_EVIDENCE_FACTOR` (0.2, matching `recency_factor`'s
  own floor) applies the decay that was intended.
- **One predicate, three gates.** Vote weight, admission lane, and promotion now
  all derive from a single `evidence_vouched` value rather than repeating the
  same two conditions, so the gates cannot drift apart in future changes.
- **Console and analysis footer spacing.** The footer rule set
  `padding: 26px 0 44px`, but the element is `<footer class="shell">` and
  `.shell`'s own `padding` shorthand won on specificity and zeroed it. The
  licence-tier block therefore sat directly beneath the about section with no
  separation. Now set as longhand on `footer.shell`, which restores the vertical
  rhythm without clobbering the responsive horizontal padding at the 820px
  breakpoint or in print.

### Impact on the published feed

**None at cut time.** This is a tightening of the admission rule that nothing
currently depends on:

- Feodo Tracker is the only stale or dormant source across the 24 active sources.
- Its five addresses appear in no published artifact.
- **0 of 5,326** published records cited it, so no record loses a class it was
  relying on.

Counts are unchanged at 4,365 high-confidence, 961 medium, 5,326 published in
the primary tier and 9,728 in the non-commercial tier. Publication now requires
two independence classes that are vouched for *today*, so the rule binds on
future runs rather than this one.

Feed URLs are stable and served from GitHub Pages. Pinning this tag does not
change what you fetch.

### Why a third candidate

The rc.2 window did what a burn-in window is for: it surfaced that the policy
document and the code had diverged. ADR-052's own text promised decaying weight
and "cannot put IPs into the feed on their own"; the implementation delivered
neither in full. Since this changes how records are admitted, the scoring
contract moved and the candidate clock restarts rather than shipping it as a
patch on top of rc.2.

Two rc.2 tests asserted the old contract — stale or dormant plus one live class
publishing at medium. They were rewritten to assert the new contract and renamed
for the regression they now guard, rather than removed.

### Known limitation, deliberately deferred

Evidence-age decay is applied only to sources already flagged stale or dormant,
not to every source with a `Last-Modified` header. Generalising it needs a
per-source `expected_update_days`: `ttl_days` currently means "how long we carry
an observation", not "how fast we expect upstream to publish", and conflating the
two would penalise healthy sources for a normal cadence — `spamhaus_drop_v6` had
a six-day-old header against a 7-day TTL and would have been damped to the floor.
Tracked as an open item in ADR-053.

### Reporting a problem during the candidate window

False positives are the primary risk in a feed you drop traffic on. If an
address should not be listed, open an issue or a pull request against
`allowlist.txt`. Include the address and why it is legitimate — the run report
and `xfeeds explain` will show which sources put it there.

Full history in [`CHANGELOG.md`](https://github.com/neilweitzel/xfeeds/blob/main/CHANGELOG.md).
Dashboard at https://neilweitzel.github.io/xfeeds/.

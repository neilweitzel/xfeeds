# xfeeds v1.0.1

GitHub-only scheduler hardening after the burned-in v1.0.0 release.

- Hourly trigger opportunities recover sooner when GitHub misses a slot.
- Four refresh attempts per UTC day match the upstream reset boundary.
- A 5h30 minimum interval provides 30 minutes of scheduling tolerance without
  front-loading the daily allowance.
- Manual and scheduled triggers share the same guard; churn `force` does not
  bypass quotas. Failed attempts retain a committed reservation.
- Concurrent triggers do not cancel an active refresh.
- Source reviews switch to January/April/July/October 8.
- Regression coverage includes the October 5 skip, midnight, timezones,
  duplicates, failed attempts, corrupted state, and workflow wiring.

No scoring, source admissions, indicator schema, or existing feed URLs change.
No external service or recurring Computer task is required. GitHub timing remains
best-effort; this patch reduces avoidable gaps, not all possible outages.

The new operational code is separately versioned and is not represented as having
completed v1.0.0's September burn-in.

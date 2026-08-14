"""GreyNoise benign-scanner suppression.

Why this exists
---------------
A blocklist's worst failure is not missing an attacker, it is dropping traffic
somebody needed. Several of the feeds here report *any* unsolicited connection,
so security researchers, uptime monitors and academic scanners accumulate reports
and eventually reach two independent classes on the strength of activity nobody
actually wants blocked. Measured on 2026-08-14, **17% of the published feed**
(85 of a 500-address sample) was classified ``benign`` by GreyNoise.

That is the same class of judgement as ADR-013 made about Tor exits: scanning by a
known research operator is a policy question for the consumer, not a threat
assertion we should be making at high confidence. So a benign classification caps
a record at MEDIUM rather than deleting it. MEDIUM is documented as "challenge or
rate-limit rather than a hard block", which is exactly the right handling for a
Censys or Shadowserver prober.

Licensing constraint, and it is strict
--------------------------------------
The GreyNoise EULA forbids free customers from distributing or publishing the
Platform to third parties. So this module may only ever *remove* confidence. It
must never put a GreyNoise classification, tag, provider name, or the fact of
GreyNoise membership into anything under ``feeds/``:

* No tag is added to a capped record — a ``greynoise-benign`` tag would disclose
  their dataset one address at a time, which is redistribution with extra steps.
* Only an aggregate count reaches the manifest. A count is a statistic derived
  from the data, not an extract of it — the same reasoning ADR-044 applied to the
  insights layer.

What the free tier actually gives us
------------------------------------
The key in use reports ``plan: Business - Free``. The API confirms in
``request_metadata.restricted_fields`` that ``business_service_intelligence`` — the
dataset formerly called RIOT, which identifies benign *business* infrastructure like
CDNs and public DNS — is **not** entitled; it is a separately licensed add-on that
attaches only to paid tiers. ``internet_scanner_intelligence.classification`` *is*
available, and for a blocklist it is the more directly useful of the two.

Operational stance: this is optional enrichment and never load-bearing. No key, a
network failure, a quota rejection, or a malformed response all degrade to "cap
nothing" and the run completes normally. A feed that fails to build because an
enrichment API was down would be a worse outcome than one that is 17% noisier.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
import structlog

from xfeeds.models import Band, ScoredIndicator

logger = structlog.get_logger(__name__)

API_URL = "https://api.greynoise.io/v3/ip?quick=true"
"""Quick mode returns only found/classification per address.

The full response for 500 addresses is 5.5 MB; quick mode is 80 KB and carries
every field this module reads. Asking for less also means fewer restricted fields
to ignore.
"""

ENV_VAR = "GREYNOISE_API_KEY"

MAX_BATCH = 10_000
"""Documented maximum addresses per POST body."""

BENIGN = "benign"


def _classifications(addresses: list[str], api_key: str, timeout: float) -> dict[str, str]:
    """Return ``{address: classification}`` for one batch, or ``{}`` on any failure."""
    try:
        response = httpx.post(
            API_URL,
            headers={"key": api_key, "Accept": "application/json"},
            json={"ips": addresses},
            timeout=timeout,
        )
    except httpx.RequestError as e:
        logger.warning("greynoise_unreachable", error=str(e))
        return {}

    # 206 Partial Content is the normal answer when some addresses fall outside
    # the plan's lookback window. The body is still valid for the rest.
    if response.status_code not in (200, 206):
        logger.warning(
            "greynoise_rejected",
            status=response.status_code,
            body=response.text[:200],
        )
        return {}

    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("greynoise_bad_json", error=str(e))
        return {}

    rows = payload.get("data")
    if not isinstance(rows, list):
        logger.warning("greynoise_unexpected_payload")
        return {}

    out: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = row.get("ip")
        scanner: Any = row.get("internet_scanner_intelligence") or {}
        if not isinstance(scanner, dict) or not isinstance(address, str):
            continue
        classification = scanner.get("classification")
        if isinstance(classification, str) and classification:
            out[address] = classification
    return out


def benign_addresses(records: list[ScoredIndicator], timeout: float = 60.0) -> set[str]:
    """Return the subset of ``records`` GreyNoise classifies as benign scanners.

    Only single addresses are submitted. A CIDR cannot be looked up as one entity,
    and expanding a /20 into 4,096 lookups to spend quota on a network we are
    publishing as a block anyway would be both wasteful and wrong.

    Returns an empty set whenever the answer is unknown, so every caller treats
    "no key", "API down" and "nothing is benign" identically.
    """
    api_key = os.environ.get(ENV_VAR)
    if not api_key:
        logger.info("greynoise_skipped", reason=f"{ENV_VAR} is not set")
        return set()

    addresses = sorted({str(r.ip_or_cidr) for r in records if "/" not in str(r.ip_or_cidr)})
    if not addresses:
        return set()

    benign: set[str] = set()
    classified = 0
    for start in range(0, len(addresses), MAX_BATCH):
        batch = addresses[start : start + MAX_BATCH]
        results = _classifications(batch, api_key, timeout)
        classified += len(results)
        benign.update(a for a, c in results.items() if c == BENIGN)

    logger.info(
        "greynoise_lookup_complete",
        submitted=len(addresses),
        classified=classified,
        benign=len(benign),
    )
    return benign


def cap_benign_scanners(records: list[ScoredIndicator], benign: set[str]) -> int:
    """Demote benign-classified records from HIGH to MEDIUM in place. Returns the count.

    Deliberately a demotion and not a deletion: the consumer who *does* want to
    block research scanners can still find these in the medium-confidence tier and
    act on them, which keeps the policy choice where ADR-013 put it — with the
    consumer. Nothing is written onto the record, because a marker would leak the
    GreyNoise classification into the published feed.

    WITHHELD records are left alone. They are not published, so there is no
    false-positive risk to remove, and moving one would silently promote it.
    """
    capped = 0
    for record in records:
        if record.band is Band.HIGH and str(record.ip_or_cidr) in benign:
            record.band = Band.MEDIUM
            capped += 1
    return capped

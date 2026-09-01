"""Evidence age determination.

`docs/source-lifecycle.md` states the core invariant: **fetch time is not evidence
time.** A successful HTTP fetch means the endpoint answered, not that the data
behind it is current. This module answers the narrower question the scorer needs:
*how old is the evidence this source is asserting?*

The policy sets a priority order, and this module implements it in full:

1. **Feed-level timestamp in the payload** — the source's own statement about when
   it last published.
2. **HTTP ``Last-Modified``** — used only when the payload carries no timestamp.
3. **Content-hash change** — when neither exists, evidence age is the time since
   the body last actually changed.

Priority 1 is first for a measured reason, not a theoretical one. abuse.ch serves
a ``Last-Modified`` that moves independently of its payload: on 2026-09-01 both
Feodo Tracker and SSLBL returned ``Last-Modified: Tue, 30 Jun 2026 04:53 GMT``
while their payloads declared 2026-03-04 and 2025-01-02 respectively. Two feeds
frozen fourteen months apart reported transport timestamps fourteen seconds
apart. Trusting the header there understates Feodo's evidence age by 118 days.

Priority 3 exists because a header is not guaranteed. Three sources
(``abuseipdb_blacklist``, ``ipsum_levels``, ``threatfox``) return no
``Last-Modified`` at all, so before this module they had no freshness gate of any
kind — a frozen upstream would have voted at full strength indefinitely.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

FRESHNESS_LEDGER_PATH = Path("feeds/source-freshness.json")
"""Committed, unlike ``.cache/state.json``.

Priority 3 measures "time since the body last changed", which is only meaningful
if the record of the last change survives. ``.cache/state.json`` is restored from
an ``actions/cache`` entry that can and does go cold, and a cold cache would reset
every source's change history to "changed just now" — making a permanently frozen
upstream look permanently fresh, which is the exact failure this module exists to
prevent. So the ledger lives in ``feeds/`` with the other committed artifacts,
where a reset is visible in a diff instead of silent.
"""

HEADER_SCAN_LINES = 40
"""Only the leading comment block is searched for a timestamp.

Bounded deliberately. Several feeds carry per-row dates in the body
(bruteforceblocker's ``# Last Reported`` column, Dataplane's per-row timestamps),
and a whole-file regex sweep would happily pick one of those up and report a
single row's date as the feed's publication date.
"""

FUTURE_TOLERANCE = timedelta(days=1)
"""How far ahead of the run a payload timestamp may sit before it is discarded.

Not zero, for two reasons. Observations are truncated to midnight UTC, so a feed
published at 12:44 today legitimately carries a timestamp after ``observed_on``.
And Spamhaus's JSON metadata timestamp is its generation time while the sibling
text feed advertises an ``Expires`` an hour later, so an hour of drift between a
feed's own clock and ours is normal. A full day past the run is not, and a
timestamp that far ahead is a parse error or a broken upstream clock rather than
evidence — in which case the next priority is more trustworthy than this one.
"""


@dataclass(frozen=True)
class EvidenceAge:
    """When a source last published, and how we worked that out.

    ``basis`` is carried into the manifest so the mechanism behind a staleness
    decision is observable in the published output. A source marked stale on a
    content hash is a materially different claim from one marked stale on its own
    declared header, and an operator reading the manifest should not have to guess
    which happened.
    """

    timestamp: datetime | None
    basis: str

    @property
    def known(self) -> bool:
        """True when the age rests on evidence rather than on nothing."""
        return self.timestamp is not None

    def age_days(self, observed_on: datetime) -> int | None:
        """Whole days of evidence age, floored at zero.

        Floored because a feed published later today than midnight UTC is not
        negatively old; it is current.
        """
        if self.timestamp is None:
            return None
        return max(0, (observed_on - self.timestamp).days)


def parse_http_date(value: str | None) -> datetime | None:
    """Parse an RFC 7231 HTTP-date, returning None rather than raising.

    A malformed upstream header must degrade the freshness signal, never fail the
    run - rule 5 in AGENTS.md.
    """
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def content_digest(content: bytes) -> str:
    """Stable digest of a response body, for priority-3 change detection."""
    return hashlib.sha256(content).hexdigest()


def _as_utc(value: datetime) -> datetime:
    """Naive timestamps from feed headers are UTC; every feed we parse says so."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _abusech(match: re.Match[str]) -> datetime | None:
    """``# Last updated: 2026-03-04 14:28:39 UTC`` - Feodo Tracker, SSLBL."""
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _http_date_in_comment(match: re.Match[str]) -> datetime | None:
    """``; Last-Modified: Tue, 11 Aug 2026 11:17:49 GMT`` - Spamhaus text, bruteforceblocker."""
    return parse_http_date(match.group(1))


def _iso(match: re.Match[str]) -> datetime | None:
    """``#    updated: 2026-08-12T00:00:26.057308`` - DShield."""
    try:
        return _as_utc(datetime.fromisoformat(match.group(1)))
    except ValueError:
        return None


def _ctime(match: re.Match[str]) -> datetime | None:
    """``# This File Date  : Tue Aug 11 14:33:07 UTC 2026`` - FireHOL."""
    try:
        return datetime.strptime(match.group(1), "%a %b %d %H:%M:%S UTC %Y").replace(tzinfo=UTC)
    except ValueError:
        return None


def _window_end(match: re.Match[str]) -> datetime | None:
    """``# 2026-08-07 16:00 - 2026-08-14 16:00`` - Dataplane.org.

    Dataplane states a reporting window rather than a publication time. The end of
    the window is the newest moment the data can describe, so that is the evidence
    time; the start would overstate the age by a full week.
    """
    try:
        return datetime.strptime(match.group(2), "%Y-%m-%d %H:%M").replace(tzinfo=UTC)
    except ValueError:
        return None


TimestampHandler = Callable[[re.Match[str]], datetime | None]

_COMMENT_PATTERNS: list[tuple[re.Pattern[str], TimestampHandler]] = [
    # "Last updated" is matched before the bare "updated" pattern below, so
    # abuse.ch's header is read by its own rule rather than by DShield's.
    (
        re.compile(
            r"Last\s+updated:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s*UTC", re.IGNORECASE
        ),
        _abusech,
    ),
    (
        re.compile(
            r"Last-Modified:\s*(\w{3},\s*\d{1,2}\s+\w{3}\s+\d{4}\s[\d:]{8}\s*\w+)", re.IGNORECASE
        ),
        _http_date_in_comment,
    ),
    (
        re.compile(
            r"This File Date\s*:\s*(\w{3}\s+\w{3}\s+\d{1,2}\s+[\d:]{8}\s+UTC\s+\d{4})",
            re.IGNORECASE,
        ),
        _ctime,
    ),
    (re.compile(r"\bupdated:\s*(\d{4}-\d{2}-\d{2}T[\d:.]+)", re.IGNORECASE), _iso),
    (
        re.compile(
            r"^\s*[#;]\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})"
            r"\s*-\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*$"
        ),
        _window_end,
    ),
]


def _comment_feed_timestamp(text: str) -> datetime | None:
    """Search the leading comment block for a declared publication time.

    Stops at the first line that is neither a comment nor blank. Once real data
    starts, anything date-shaped belongs to a row rather than to the feed.
    """
    for index, line in enumerate(text.splitlines()):
        if index >= HEADER_SCAN_LINES:
            break
        stripped = line.strip()
        if not stripped:
            continue
        if stripped[0] not in "#;":
            break
        for pattern, handler in _COMMENT_PATTERNS:
            match = pattern.search(line)
            if match:
                parsed = handler(match)
                if parsed is not None:
                    return parsed
    return None


def _json_feed_timestamp(text: str) -> datetime | None:
    """Read a feed-level timestamp out of a JSON body.

    Two real shapes, both from sources that send no usable ``Last-Modified``:
    AbuseIPDB's ``meta.generatedAt``, and Spamhaus DROP's trailing
    newline-delimited ``{"type": "metadata", "timestamp": <epoch>}`` record.
    """
    stripped = text.strip()
    if not stripped:
        return None

    if stripped[0] == "{":
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            meta = payload.get("meta")
            if isinstance(meta, dict):
                generated = meta.get("generatedAt")
                if isinstance(generated, str):
                    try:
                        return _as_utc(datetime.fromisoformat(generated))
                    except ValueError:
                        return None

    # Spamhaus DROP is newline-delimited JSON with the metadata record last.
    for line in reversed(stripped.splitlines()[-3:]):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("type") == "metadata":
            epoch = record.get("timestamp")
            if isinstance(epoch, int | float) and epoch > 0:
                try:
                    return datetime.fromtimestamp(float(epoch), UTC)
                except (OSError, OverflowError, ValueError):
                    return None
    return None


def extract_feed_timestamp(content: bytes) -> datetime | None:
    """Priority 1: the timestamp a feed declares about itself, or None."""
    if not content:
        return None
    text = content.decode("utf-8", "replace")
    return _json_feed_timestamp(text) or _comment_feed_timestamp(text)


class FreshnessLedger:
    """Per-source record of when a body last actually changed.

    Deliberately records only the digest and the date it first appeared. Writing a
    "last checked" timestamp would make the file change on every run even when
    nothing upstream did, which breaks the byte-identical-output rule in AGENTS.md
    and buries the signal in diff noise.
    """

    def __init__(
        self,
        entries: dict[str, dict[str, str]] | None = None,
        expired: dict[str, str] | None = None,
    ) -> None:
        self._entries: dict[str, dict[str, str]] = dict(entries or {})
        self._expired: dict[str, str] = dict(expired or {})

    @classmethod
    def load(cls, path: Path = FRESHNESS_LEDGER_PATH) -> "FreshnessLedger":
        """Read the ledger, treating any damage as an empty ledger.

        A corrupt ledger must not fail the run. The cost of losing it is that
        hash-based ages restart from today, which the next few runs rebuild.
        """
        if not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("freshness_ledger_unreadable", path=str(path), error=str(exc))
            return cls()
        if not isinstance(payload, dict):
            return cls()
        sources = payload.get("sources")
        entries = (
            {
                key: value
                for key, value in sources.items()
                if isinstance(value, dict) and isinstance(value.get("digest"), str)
            }
            if isinstance(sources, dict)
            else {}
        )
        raw_expired = payload.get("expired")
        expired = (
            {k: v for k, v in raw_expired.items() if isinstance(v, str)}
            if isinstance(raw_expired, dict)
            else {}
        )
        return cls(entries, expired)

    def save(self, path: Path = FRESHNESS_LEDGER_PATH) -> None:
        """Write the ledger deterministically, sorted by source key."""
        payload = {
            "version": 1,
            "note": (
                "When each source's body last changed. Used as priority-3 evidence age "
                "for sources that declare no timestamp and send no Last-Modified. "
                "See docs/source-lifecycle.md."
            ),
            "sources": {key: self._entries[key] for key in sorted(self._entries)},
            # When each expired source crossed the line. This is the latch: a
            # source that has run out its clock stays out until a maintainer
            # records a review dated on or after this. Keeping it here rather than
            # in sources.yaml means the pipeline owns the fact and the maintainer
            # owns only the decision.
            "expired": {key: self._expired[key] for key in sorted(self._expired)},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def observe(self, key: str, digest: str, observed_on: datetime) -> datetime:
        """Record a digest and return when this body was first seen.

        Called for every source on every run, including ones whose age comes from
        priority 1 or 2. The history has to accumulate while it is not needed, so
        that it is already there on the day an upstream drops its header.
        """
        entry = self._entries.get(key)
        if entry and entry.get("digest") == digest:
            changed_at = parse_iso(entry.get("changed_at"))
            if changed_at is not None:
                return changed_at
        self._entries[key] = {"digest": digest, "changed_at": observed_on.isoformat()}
        return observed_on

    def mark_expired(self, source: str, observed_on: datetime) -> datetime:
        """Latch a source as expired and return when it first crossed.

        Idempotent: the date is set once and does not move while the source stays
        expired, so "how long has this been out" is answerable and a review dated
        against it means something.
        """
        existing = parse_iso(self._expired.get(source))
        if existing is not None:
            return existing
        self._expired[source] = observed_on.isoformat()
        return observed_on

    def expired_since(self, source: str) -> datetime | None:
        """When this source was latched as expired, if it is."""
        return parse_iso(self._expired.get(source))

    def clear_expiry(self, source: str) -> None:
        """Release the latch, after a review or after the source came back."""
        self._expired.pop(source, None)


def parse_iso(value: str | None) -> datetime | None:
    """Parse a stored ISO timestamp, tolerating a hand-edited ledger."""
    if not value:
        return None
    try:
        return _as_utc(datetime.fromisoformat(value))
    except ValueError:
        return None


def determine_evidence_age(
    content: bytes,
    last_modified_header: str | None,
    ledger: FreshnessLedger | None,
    key: str,
    observed_on: datetime,
) -> EvidenceAge:
    """Apply the priority order and return the resulting evidence age.

    The ledger is always updated, whichever priority wins, so that priority 3 has
    history available if a source later stops declaring a timestamp.
    """
    hash_changed_at: datetime | None = None
    if ledger is not None:
        hash_changed_at = ledger.observe(key, content_digest(content), observed_on)

    declared = extract_feed_timestamp(content)
    if declared is not None:
        if declared - observed_on > FUTURE_TOLERANCE:
            # A timestamp well ahead of the run is a broken clock or a misparse,
            # not evidence. Fall through rather than treat it as freshness.
            logger.warning(
                "feed_timestamp_in_future",
                source=key,
                declared=declared.isoformat(),
                observed_on=observed_on.isoformat(),
            )
        else:
            return EvidenceAge(declared, "payload")

    from_header = parse_http_date(last_modified_header)
    if from_header is not None:
        return EvidenceAge(from_header, "http-last-modified")

    if hash_changed_at is not None:
        return EvidenceAge(hash_changed_at, "content-hash")

    return EvidenceAge(None, "unknown")


@dataclass(frozen=True)
class SourceState:
    """What a source is allowed to contribute this run.

    Three states on one axis, so there is exactly one question to ask about a
    source and one place the answer comes from:

    ``fresh``
        Full vote, may admit, may promote.
    ``stale``
        Evidence past its freshness threshold but not yet expired. Damped vote,
        non-admitting, cannot promote (ADR-053).
    ``expired``
        Evidence past the expiry ceiling, or the maintainer marked it dormant.
        Contributes **nothing** - its records are dropped before the scorer sees
        them. Latched until reviewed.
    """

    name: str
    age: EvidenceAge
    expired_since: datetime | None = None
    reason: str | None = None

    @property
    def is_stale(self) -> bool:
        return self.name == "stale"

    @property
    def is_expired(self) -> bool:
        return self.name == "expired"


def classify_source(
    *,
    source_name: str,
    dormant: bool,
    freshness_days: int,
    expiry_days: int,
    reviewed_on: date | None,
    evidence: EvidenceAge | None,
    ledger: FreshnessLedger | None,
    observed_on: datetime,
) -> SourceState:
    """Decide what a source may contribute, and latch it if it has expired.

    The ordering matters and is deliberate:

    1. ``dormant`` wins outright. It is a maintainer's standing statement that the
       tracked threat is gone, and ``reviewed_on`` cannot override it - only
       removing the flag can. Otherwise a review date could quietly resurrect a
       source somebody had deliberately killed.
    2. A latched expiry survives fresh data. An upstream that starts publishing
       again does **not** re-admit itself; that is the entire point of the latch.
       Fresh data is the signal to go and review, not the review.
    3. A review dated on or after the expiry releases the latch. Dated before it,
       it does nothing - a review cannot pre-authorise an expiry that had not
       happened when it was written.
    """
    age = evidence or EvidenceAge(None, "unknown")

    if dormant:
        since = ledger.mark_expired(source_name, observed_on) if ledger else observed_on
        return SourceState(
            "expired",
            age,
            since,
            "dormant: maintainer confirmed the tracked threat is inactive",
        )

    latched = ledger.expired_since(source_name) if ledger else None
    if latched is not None:
        cleared = reviewed_on is not None and reviewed_on >= latched.date()
        if not cleared:
            days = max(0, (observed_on - latched).days)
            return SourceState(
                "expired", age, latched, f"expired {days} days ago and not reviewed since"
            )
        if ledger is not None:
            ledger.clear_expiry(source_name)

    if not age.known:
        return SourceState("fresh", age)

    days_old = age.age_days(observed_on)
    assert days_old is not None

    if days_old > expiry_days:
        since = ledger.mark_expired(source_name, observed_on) if ledger else observed_on
        return SourceState(
            "expired",
            age,
            since,
            f"evidence is {days_old} days old, past the {expiry_days}-day expiry ceiling",
        )

    if days_old > freshness_days:
        return SourceState(
            "stale", age, None, f"evidence is {days_old} days old, past {freshness_days} days"
        )

    return SourceState("fresh", age)


def newest(left: EvidenceAge | None, right: EvidenceAge) -> EvidenceAge:
    """Combine per-URL ages for a multi-URL source such as ``ipsum_levels``.

    The newest wins. A source that publishes several files is publishing if any
    one of them moved; judging it by its least-updated file would call an active
    upstream stale.
    """
    if left is None or not left.known:
        return right
    if not right.known:
        return left
    assert left.timestamp is not None and right.timestamp is not None
    return right if right.timestamp > left.timestamp else left

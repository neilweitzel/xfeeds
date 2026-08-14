import csv
import io
import ipaddress
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime

import structlog

from xfeeds.models import VALID_PARSERS, IndicatorRecord, IPOrNet, SourceConfig

logger = structlog.get_logger(__name__)

_UPSTREAM_ATTRIBUTION: dict[str, dict[str, str]] = {}
"""Attribution text harvested from source payloads, keyed by source name.

Spamhaus requires that its copyright and terms travel with the data. Parsers
report what they find here and the emitters read it, so the curated values in
sources.yaml are never overwritten by a parse.
"""


def record_upstream_attribution(
    source_name: str, *, copyright_text: str | None, terms_url: str | None
) -> None:
    """Record attribution a source declared inside its own payload."""
    entry = _UPSTREAM_ATTRIBUTION.setdefault(source_name, {})
    if copyright_text:
        entry["copyright"] = copyright_text
    if terms_url:
        entry["terms"] = terms_url


def upstream_attribution(source_name: str) -> dict[str, str]:
    """Return attribution recorded for a source, if any."""
    return dict(_UPSTREAM_ATTRIBUTION.get(source_name, {}))


_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _parse_reported_date(text: str) -> datetime | None:
    """Pull a YYYY-MM-DD out of an upstream comment field, truncated to the day.

    Truncated deliberately: these fields are used for daily history buckets, and
    keeping sub-day precision would make every run produce a different value for
    the same fact.
    """
    match = _DATE_RE.search(text)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _log_skips(source: str, malformed: int, non_global: int) -> None:
    """Report skipped lines, keeping malformed and non-global counts distinct."""
    if malformed or non_global:
        logger.warning(
            "parser_skipped_lines",
            source=source,
            malformed_lines=malformed,
            non_global_addresses=non_global,
        )


def _is_global(ip_or_cidr: IPOrNet) -> bool:
    """Return True if the address or network is globally routable.

    Non-global addresses are dropped at parse time so that reserved space can
    never reach the scorer. Note that this is distinct from a malformed line -
    the two are counted separately because conflating them makes both numbers
    useless for diagnosing a broken upstream.
    """
    return not (
        ip_or_cidr.is_private
        or ip_or_cidr.is_loopback
        or ip_or_cidr.is_link_local
        or ip_or_cidr.is_reserved
        or ip_or_cidr.is_multicast
    )


def plain_text(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse plain text IP lists."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0
    non_global_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue

        ip_str = line.split()[0].split("#")[0].split(";")[0].strip()

        try:
            ip_obj: (
                ipaddress.IPv4Address
                | ipaddress.IPv6Address
                | ipaddress.IPv4Network
                | ipaddress.IPv6Network
            )
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                ip_obj = ipaddress.ip_network(ip_str, strict=False)

            if not _is_global(ip_obj):
                non_global_count += 1
                continue

            yield IndicatorRecord(
                ip_or_cidr=ip_obj,
                source=config.name,
                independence_class=config.independence_class,
                first_seen=fetch_time,
                last_seen=fetch_time,
                categories=config.categories,
                tags=list(config.categories) if config.tag_only else [],
            )
        except ValueError:
            malformed_count += 1

    _log_skips(config.name, malformed_count, non_global_count)


def netset(content: bytes, config: SourceConfig, fetch_time: datetime) -> Iterator[IndicatorRecord]:
    """Parse netset files (which are essentially plain text but meant to be CIDRs)."""
    return plain_text(content, config, fetch_time)


def spamhaus_json(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse Spamhaus newline-delimited JSON."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0
    non_global_count = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            malformed_count += 1
            continue

        if data.get("type") == "metadata":
            # Spamhaus terminates the stream with a metadata object carrying the
            # copyright and terms text that AGENTS.md rule 9 requires we
            # propagate. Record it for the emitters instead of mutating the
            # curated config - a parser writing back into shared state makes
            # attribution order-dependent.
            record_upstream_attribution(
                config.name,
                copyright_text=data.get("copyright"),
                terms_url=data.get("terms"),
            )
            continue

        if "cidr" not in data:
            malformed_count += 1
            continue

        try:
            ip_obj = ipaddress.ip_network(data["cidr"], strict=False)
            if not _is_global(ip_obj):
                non_global_count += 1
                continue

            yield IndicatorRecord(
                ip_or_cidr=ip_obj,
                source=config.name,
                independence_class=config.independence_class,
                first_seen=fetch_time,
                last_seen=fetch_time,
                categories=config.categories,
            )
        except ValueError:
            malformed_count += 1

    _log_skips(config.name, malformed_count, non_global_count)


def spamhaus_asn_json(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse Spamhaus ASN newline-delimited JSON. Currently skips ASN completely in Phase 2a."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if data.get("type") == "metadata":
                record_upstream_attribution(
                    config.name,
                    copyright_text=data.get("copyright"),
                    terms_url=data.get("terms"),
                )
        except json.JSONDecodeError:
            continue

    return iter([])


def dshield(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse DShield format (startaddr endaddr netmask ...)."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0
    non_global_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue

        parts = line.split()
        if len(parts) < 3:
            malformed_count += 1
            continue

        startaddr = parts[0]
        endaddr = parts[1]
        try:
            start_ip = ipaddress.ip_address(startaddr)
            end_ip = ipaddress.ip_address(endaddr)

            for network in ipaddress.summarize_address_range(start_ip, end_ip):
                if not _is_global(network):
                    non_global_count += 1
                    continue

                yield IndicatorRecord(
                    ip_or_cidr=network,
                    source=config.name,
                    independence_class=config.independence_class,
                    first_seen=fetch_time,
                    last_seen=fetch_time,
                    categories=config.categories,
                )
        except (ValueError, TypeError):
            malformed_count += 1

    _log_skips(config.name, malformed_count, non_global_count)


def bruteforceblocker(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse bruteforceblocker (tab-separated, IP is first)."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0
    non_global_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if not parts:
            malformed_count += 1
            continue

        ip_str = parts[0].strip()

        # Column 2 is "# YYYY-MM-DD HH:MM:SS" - roughly a month of real history,
        # which the ASN windows use even though scoring does not.
        reported = None
        if len(parts) > 1:
            reported = _parse_reported_date(parts[1])

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not _is_global(ip_obj):
                non_global_count += 1
                continue

            yield IndicatorRecord(
                ip_or_cidr=ip_obj,
                source=config.name,
                independence_class=config.independence_class,
                first_seen=fetch_time,
                last_seen=fetch_time,
                categories=config.categories,
                source_last_reported=reported,
            )
        except ValueError:
            malformed_count += 1

    _log_skips(config.name, malformed_count, non_global_count)


def ipsum_levels(
    content: bytes, config: SourceConfig, fetch_time: datetime, level: int | None = None
) -> Iterator[IndicatorRecord]:
    """Parse an IPsum level file.

    The file itself is a bare IP list; the level is metadata the caller supplies
    from sources.yaml. It matters because the level number IS the upstream
    corroboration count, and ADR-011 uses it as a bounded prior rather than a
    vote. Losing it would make IPsum indistinguishable from a normal source.
    """
    for record in plain_text(content, config, fetch_time):
        if level is not None:
            record.tags = [*record.tags, f"ipsum-level-{level}"]
        yield record


def threatfox_api(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse the ThreatFox get_iocs JSON response.

    ThreatFox reports IOCs as "ip:port" with real first_seen/last_seen dates, so
    we use its dates rather than the fetch time - an address it last saw six days
    ago should decay accordingly.

    The ``is_compromised`` flag matters for safety. A compromised host is a
    legitimate server somebody hacked and is now using as command-and-control.
    Blocking it may block a real business, so those are tagged and deliberately
    excluded from the abuse.ch precision promotion in score.py: they still count
    as a normal vote, but they cannot reach the safe-to-block tier alone.
    """
    try:
        payload = json.loads(content.decode("utf-8", "replace"))
    except json.JSONDecodeError as e:
        logger.warning("threatfox_bad_json", source=config.name, error=str(e))
        return

    if payload.get("query_status") != "ok":
        logger.warning("threatfox_query_failed", status=payload.get("query_status"))
        return

    data = payload.get("data")
    if not isinstance(data, list):
        return

    malformed = 0
    non_global = 0
    for entry in data:
        if entry.get("ioc_type") != "ip:port":
            continue
        raw = str(entry.get("ioc", ""))
        host = raw.rsplit(":", 1)[0].strip("[]")  # strip the port, handle IPv6 brackets
        try:
            ip_obj: IPOrNet = ipaddress.ip_address(host)
        except ValueError:
            malformed += 1
            continue
        if not _is_global(ip_obj):
            non_global += 1
            continue

        tags: list[str] = []
        if str(entry.get("is_compromised", "")).lower() in {"1", "true"}:
            tags.append("compromised-host")
        malware = entry.get("malware_printable")
        if malware:
            tags.append(f"malware:{malware}")

        threat = str(entry.get("threat_type", ""))
        categories = ["botnet-c2"] if threat == "botnet_cc" else ["malware-infrastructure"]

        def _when(value: object, fallback: datetime) -> datetime:
            if not value:
                return fallback
            try:
                parsed = datetime.fromisoformat(str(value))
            except ValueError:
                return fallback
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

        first = _when(entry.get("first_seen"), fetch_time)
        last = _when(entry.get("last_seen"), first)

        yield IndicatorRecord(
            ip_or_cidr=ip_obj,
            source=config.name,
            independence_class=config.independence_class,
            first_seen=min(first, last),
            last_seen=max(first, last),
            categories=categories,
            tags=tags,
        )

    _log_skips(config.name, malformed, non_global)


# Register implemented parsers using their function names to avoid duplicating the list
def turris_greylist(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse the Turris Sentinel greylist CSV (``Address,Tags``).

    The tag column names the protocol the sensor network saw being abused, which
    maps onto our category vocabulary and so onto severity. Tag values are
    sometimes quoted and multi-valued.

    Note that this source is consumed under CC BY-NC-SA and is configured with
    ``redistribute: false``; the scorer keeps its name out of published output.
    """
    tag_categories = {
        "telnet": "brute-force",
        "ssh": "ssh-attack",
        "http": "web-attack",
        "https": "web-attack",
        "ftp": "brute-force",
        "smtp": "spam-source",
        "haas": "ssh-attack",
        "portscan": "scanning",
    }
    malformed_count = 0
    non_global_count = 0

    reader = csv.reader(io.StringIO(content.decode("utf-8", errors="replace")))
    for row in reader:
        if not row:
            continue
        address = row[0].strip()
        if not address or address.startswith("#") or address == "Address":
            continue
        try:
            ip_or_cidr = ipaddress.ip_address(address)
        except ValueError:
            malformed_count += 1
            continue
        if not _is_global(ip_or_cidr):
            non_global_count += 1
            continue

        raw_tags = row[1] if len(row) > 1 else ""
        seen = [t.strip().strip('"').lower() for t in raw_tags.replace("\n", ",").split(",")]
        categories = sorted({tag_categories[t] for t in seen if t in tag_categories})

        yield IndicatorRecord(
            ip_or_cidr=ip_or_cidr,
            source=config.name,
            independence_class=config.independence_class,
            first_seen=fetch_time,
            last_seen=fetch_time,
            categories=categories or list(config.categories),
            tags=sorted({f"turris-{t}" for t in seen if t}),
        )

    _log_skips(config.name, malformed_count, non_global_count)


def ipthreat(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse ipthreat.net lists: ``IP # ThreatLevel ISO8601Timestamp CountryCode``.

    plain_text can read the addresses out of this file, but it throws away the
    per-row timestamp and the per-row score. The timestamp gives about two weeks
    of real dated history on the first run, which the ASN windows use.

    The score is what ``min_score`` filters on, and reading it here is the reason
    we fetch ``threat-0.txt``. **The N in ipthreat's ``threat-N.txt`` is a minimum
    score, not a number of days** - verified 2026-08-14, ``threat-0`` has a minimum
    row score of 0 and ``threat-30`` a minimum of 30, and the files shrink as N
    rises. We previously read ``threat-30.txt`` believing it was a 30-day window,
    which silently discarded 96% of the feed. See ADR-050.
    """
    malformed_count = 0
    non_global_count = 0
    below_score = 0

    for raw in content.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        address, _, remainder = line.partition("#")
        try:
            ip_obj = ipaddress.ip_address(address.strip())
        except ValueError:
            malformed_count += 1
            continue
        if not _is_global(ip_obj):
            non_global_count += 1
            continue

        fields = remainder.split()
        reported = _parse_reported_date(fields[1]) if len(fields) > 1 else None
        tags = []
        if fields and fields[0].isdigit():
            level = int(fields[0])
            if config.min_score is not None and level < config.min_score:
                below_score += 1
                continue
            # Coarse bucket only. The exact level is upstream's scale, not ours, and
            # publishing it verbatim per address would imply we can compare it to
            # our own score.
            tags.append(f"ipthreat-level-{min(100, max(0, level // 25 * 25))}")
        elif config.min_score is not None:
            # A row with no parseable score cannot clear a floor. Dropping it is the
            # conservative reading; counting it as zero would be the same outcome.
            below_score += 1
            continue

        yield IndicatorRecord(
            ip_or_cidr=ip_obj,
            source=config.name,
            independence_class=config.independence_class,
            first_seen=fetch_time,
            last_seen=fetch_time,
            categories=list(config.categories),
            tags=tags,
            source_last_reported=reported,
        )

    if below_score:
        logger.info("ipthreat_below_min_score", source=config.name, dropped=below_score)
    _log_skips(config.name, malformed_count, non_global_count)


def abuseipdb(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse the AbuseIPDB ``/api/v2/blacklist`` JSON response.

    Shape is ``{"meta": {"generatedAt": ...}, "data": [{"ipAddress", "countryCode",
    "abuseConfidenceScore", "lastReportedAt"}, ...]}``.

    ``lastReportedAt`` is carried in ``source_last_reported`` rather than
    ``last_seen`` for the reason given on that field: this is a *reported* date
    from the upstream, and feeding it into ``last_seen`` would put it through
    ``recency_factor`` and restate the score. The blacklist is regenerated
    continuously, so every row is a current assertion regardless of when the last
    individual report landed.

    Confidence is bucketed to the nearest 25 rather than tagged verbatim. On the
    free tier ``confidenceMinimum`` is locked at 100 so the tag is constant today;
    bucketing keeps the tag meaningful if a paid tier ever lowers the floor, and
    avoids implying AbuseIPDB's scale is comparable to ours.

    Note that this source is ``redistribute: false`` (ADR-012), so nothing parsed
    here reaches ``feeds/`` - it votes in its own independence class and shows up
    in the aggregate insights only.
    """
    try:
        payload = json.loads(content.decode("utf-8", "replace"))
    except json.JSONDecodeError as e:
        # The endpoint also speaks text/plain when asked. Getting non-JSON back
        # means either the Accept negotiation changed or an error page was served,
        # and both are source failures rather than something to guess through.
        logger.warning("abuseipdb_bad_json", source=config.name, error=str(e))
        return

    if not isinstance(payload, dict):
        logger.warning("abuseipdb_unexpected_payload", source=config.name)
        return

    if payload.get("errors"):
        # AbuseIPDB reports quota exhaustion and a bad key as a 4xx with an
        # ``errors`` array; base.py turns those into failures, but a cached body
        # from such a response must not be mistaken for data.
        logger.warning("abuseipdb_api_error", source=config.name, errors=payload["errors"])
        return

    data = payload.get("data")
    if not isinstance(data, list):
        logger.warning("abuseipdb_no_data_array", source=config.name)
        return

    malformed_count = 0
    non_global_count = 0

    for entry in data:
        if not isinstance(entry, dict):
            malformed_count += 1
            continue

        try:
            ip_obj: IPOrNet = ipaddress.ip_address(str(entry.get("ipAddress", "")).strip())
        except ValueError:
            malformed_count += 1
            continue
        if not _is_global(ip_obj):
            non_global_count += 1
            continue

        tags: list[str] = []
        score = entry.get("abuseConfidenceScore")
        if isinstance(score, int | float) and not isinstance(score, bool):
            bucket = min(100, max(0, int(score) // 25 * 25))
            tags.append(f"abuseipdb-confidence-{bucket}")
        country = entry.get("countryCode")
        if isinstance(country, str) and len(country) == 2 and country.isalpha():
            tags.append(f"cc:{country.upper()}")

        reported = _parse_reported_date(str(entry.get("lastReportedAt") or ""))

        yield IndicatorRecord(
            ip_or_cidr=ip_obj,
            source=config.name,
            independence_class=config.independence_class,
            first_seen=fetch_time,
            last_seen=fetch_time,
            categories=list(config.categories),
            tags=tags,
            source_last_reported=reported,
        )

    _log_skips(config.name, malformed_count, non_global_count)


def dataplane(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse a Dataplane.org report: ``ASN | ASname | ipaddr | lastseen | category``.

    Five pipe-delimited columns, padded with spaces, behind about 70 lines of
    ``#`` header. ``plain_text`` cannot read this - it sees the ASN in column one
    and finds no bare address - and a source that silently yields zero records is
    worse than one that fails, so the shape is validated per row here.

    **The ``proto41`` report has six columns, not five**: it inserts ``firstseen``
    before ``lastseen``. Verified 2026-08-14 across all 17 IP-bearing reports; every
    other one is five. So the timestamp is read from the END of the row rather than
    a fixed index, which handles both layouts and any future column added in the
    middle.

    The per-row ``lastseen`` timestamp is the reason this parser exists rather than
    reusing a generic splitter. It gives seven days of real dated history on the
    first run, which the ASN windows need, and it goes into
    ``source_last_reported`` rather than ``last_seen`` for the reason documented on
    that field.
    """
    malformed_count = 0
    non_global_count = 0

    for raw in content.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        fields = [f.strip() for f in line.split("|")]
        if len(fields) < 3:
            malformed_count += 1
            continue

        try:
            ip_obj: IPOrNet = ipaddress.ip_address(fields[2])
        except ValueError:
            malformed_count += 1
            continue
        if not _is_global(ip_obj):
            non_global_count += 1
            continue

        tags: list[str] = []
        asn = fields[0]
        if asn.isdigit():
            tags.append(f"asn:{asn}")

        # Last column is the category, the one before it is always lastseen - true
        # for the five-column reports and for six-column proto41 alike.
        reported = _parse_reported_date(fields[-2]) if len(fields) > 3 else None

        yield IndicatorRecord(
            ip_or_cidr=ip_obj,
            source=config.name,
            independence_class=config.independence_class,
            first_seen=fetch_time,
            last_seen=fetch_time,
            categories=list(config.categories),
            tags=tags,
            source_last_reported=reported,
        )

    _log_skips(config.name, malformed_count, non_global_count)


_IMPLEMENTED = [
    threatfox_api,
    plain_text,
    threatfox_api,
    netset,
    spamhaus_json,
    spamhaus_asn_json,
    dshield,
    bruteforceblocker,
    ipsum_levels,
    turris_greylist,
    ipthreat,
    abuseipdb,
    dataplane,
]

PARSERS = {}
for _func in _IMPLEMENTED:
    if _func.__name__ not in VALID_PARSERS:
        raise RuntimeError(f"Parser '{_func.__name__}' is not in VALID_PARSERS")
    PARSERS[_func.__name__] = _func

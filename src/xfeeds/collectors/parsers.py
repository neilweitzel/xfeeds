import ipaddress
import json
from collections.abc import Iterator
from datetime import datetime

import structlog

from xfeeds.models import VALID_PARSERS, IndicatorRecord, SourceConfig

logger = structlog.get_logger(__name__)

IPOrNet = (
    ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network
)

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


# Register implemented parsers using their function names to avoid duplicating the list
_IMPLEMENTED = [
    plain_text,
    netset,
    spamhaus_json,
    spamhaus_asn_json,
    dshield,
    bruteforceblocker,
    ipsum_levels,
]

PARSERS = {}
for _func in _IMPLEMENTED:
    if _func.__name__ not in VALID_PARSERS:
        raise RuntimeError(f"Parser '{_func.__name__}' is not in VALID_PARSERS")
    PARSERS[_func.__name__] = _func

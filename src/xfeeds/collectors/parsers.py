import ipaddress
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import structlog

from xfeeds.models import VALID_PARSERS, IndicatorRecord, SourceConfig

logger = structlog.get_logger(__name__)


def _is_global(ip_or_cidr: Any) -> bool:
    """Return True if the IP or network is globally routable."""
    try:
        if isinstance(ip_or_cidr, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return (
                not ip_or_cidr.is_private
                and not ip_or_cidr.is_loopback
                and not ip_or_cidr.is_link_local
                and not ip_or_cidr.is_reserved
                and not ip_or_cidr.is_multicast
            )
    except Exception:
        return False
    return False


def plain_text(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse plain text IP lists."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0

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
                malformed_count += 1
                continue

            yield IndicatorRecord(
                ip_or_cidr=ip_obj,
                source=config.name,
                independence_class=config.independence_class,
                first_seen=fetch_time,
                last_seen=fetch_time,
                categories=config.categories,
                tags=["tor-exit"] if getattr(config, "tag_only", False) else [],
            )
        except ValueError:
            malformed_count += 1

    if malformed_count > 0:
        logger.warning(
            "Skipped malformed lines in source",
            source=config.name,
            malformed_count=malformed_count,
        )


def netset(content: bytes, config: SourceConfig, fetch_time: datetime) -> Iterator[IndicatorRecord]:
    """Parse netset files (which are essentially plain text but meant to be CIDRs)."""
    return plain_text(content, config, fetch_time)


def spamhaus_json(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse Spamhaus newline-delimited JSON."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0

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
            config.license = data.get("copyright")
            config.license_url = data.get("terms")
            continue

        if "cidr" not in data:
            malformed_count += 1
            continue

        try:
            ip_obj = ipaddress.ip_network(data["cidr"], strict=False)
            if not _is_global(ip_obj):
                malformed_count += 1
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

    if malformed_count > 0:
        logger.warning(
            "Skipped malformed lines in source",
            source=config.name,
            malformed_count=malformed_count,
        )


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
                config.license = data.get("copyright")
                config.license_url = data.get("terms")
        except json.JSONDecodeError:
            pass

    return iter([])


def dshield(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse DShield format (startaddr endaddr netmask ...)."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0

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
                    malformed_count += 1
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

    if malformed_count > 0:
        logger.warning(
            "Skipped malformed lines in source",
            source=config.name,
            malformed_count=malformed_count,
        )


def bruteforceblocker(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse bruteforceblocker (tab-separated, IP is first)."""
    lines = content.decode("utf-8", errors="replace").splitlines()
    malformed_count = 0

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
                malformed_count += 1
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

    if malformed_count > 0:
        logger.warning(
            "Skipped malformed lines in source",
            source=config.name,
            malformed_count=malformed_count,
        )


def ipsum_levels(
    content: bytes, config: SourceConfig, fetch_time: datetime
) -> Iterator[IndicatorRecord]:
    """Parse ipsum levels."""
    return plain_text(content, config, fetch_time)


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

"""The allowlist: the thing that stops xfeeds from causing an outage.

This is applied *after* every other stage. If a legitimate address reaches a
published feed, somebody's traffic gets dropped, so a failure to build the
allowlist is a hard error that aborts the run rather than a warning that
degrades it. Publishing a feed built from a partial allowlist is worse than
publishing nothing.
"""

import ipaddress
import json
from bisect import bisect_right
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import structlog

from xfeeds.collectors.base import fetch_source
from xfeeds.models import AllowlistSourceConfig, DefaultsConfig, IPNetwork, IPOrNet, SourceConfig

logger = structlog.get_logger(__name__)


class AllowlistError(RuntimeError):
    """Raised when the allowlist cannot be built. Always fatal to a run."""


def _networks_from_json(payload: Any, parser: str) -> list[IPNetwork]:
    """Extract CIDRs from the various JSON shapes upstream providers publish."""
    nets: list[IPNetwork] = []

    def add(value: str) -> None:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            logger.debug("allowlist_bad_cidr", parser=parser, value=value)

    if parser == "cloudflare_json":
        result = payload.get("result", {})
        for key in ("ipv4_cidrs", "ipv6_cidrs"):
            for cidr in result.get(key, []):
                add(cidr)
    elif parser == "google_json":
        # Shared by Google Cloud, Googlebot and Bingbot.
        for prefix in payload.get("prefixes", []):
            for key in ("ipv4Prefix", "ipv6Prefix"):
                if key in prefix:
                    add(prefix[key])
    elif parser == "github_meta":
        for key, value in payload.items():
            if isinstance(value, list) and key not in {"ssh_keys", "ssh_key_fingerprints"}:
                for item in value:
                    if isinstance(item, str) and "/" in item:
                        add(item)
    else:  # pragma: no cover - guarded by config validation
        raise AllowlistError(f"unknown allowlist parser: {parser}")
    return nets


def _networks_from_text(text: str) -> list[IPNetwork]:
    """Parse the static allowlist file: one CIDR or address per line, # comments."""
    nets: list[IPNetwork] = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            logger.warning("allowlist_bad_line", line=raw)
    return nets


class Allowlist:
    """Fast containment tests against a set of allowlisted networks.

    Overlap is checked in *both* directions: a candidate is removed if it sits
    inside an allowlisted network, and also if it is a supernet that would
    contain one. Blocking a /16 because one host in it misbehaved would take out
    every legitimate address in that /16 too.
    """

    def __init__(self, networks: Iterable[IPNetwork]) -> None:
        self._v4: list[tuple[int, int]] = []
        self._v6: list[tuple[int, int]] = []
        for net in networks:
            span = (int(net.network_address), int(net.broadcast_address))
            (self._v4 if net.version == 4 else self._v6).append(span)
        self._v4.sort()
        self._v6.sort()
        self._v4_starts = [s for s, _ in self._v4]
        self._v6_starts = [s for s, _ in self._v6]
        self.size = len(self._v4) + len(self._v6)

    def _spans(self, version: int) -> tuple[list[tuple[int, int]], list[int]]:
        return (self._v4, self._v4_starts) if version == 4 else (self._v6, self._v6_starts)

    def contains(self, item: IPOrNet) -> bool:
        """Return True if item overlaps the allowlist in either direction."""
        if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            low = high = int(item)
            version = item.version
        else:
            low = int(item.network_address)
            high = int(item.broadcast_address)
            version = item.version

        spans, starts = self._spans(version)
        if not spans:
            return False
        idx = bisect_right(starts, high) - 1
        # Walk back over any spans that could still overlap. Sorted by start, so
        # anything starting after `high` cannot overlap.
        while idx >= 0:
            start, end = spans[idx]
            if end >= low:
                return True
            if start < low - (1 << 24):  # far enough behind that nothing can reach
                break
            idx -= 1
        return False


def build_allowlist(
    sources: list[AllowlistSourceConfig],
    defaults: DefaultsConfig,
    static_path: Path = Path("allowlist.txt"),
) -> Allowlist:
    """Fetch every allowlist source and combine with the static file.

    Raises AllowlistError if any source fails. This is deliberate: silently
    shrinking the allowlist is how a feed ends up blocking Cloudflare.
    """
    networks: list[IPNetwork] = []
    failures: list[str] = []

    for source in sources:
        if source.path:
            path = Path(source.path)
            if not path.exists():
                failures.append(f"{source.name}: {path} not found")
                continue
            found = _networks_from_text(path.read_text(encoding="utf-8"))
        else:
            if not source.url:
                failures.append(f"{source.name}: neither url nor path configured")
                continue
            probe = SourceConfig(
                name=f"allowlist_{source.name}",
                url=source.url,
                parser="plain_text",
                independence_class="allowlist",
                weight=0.0,
                vote=False,
            )
            result = fetch_source(probe, defaults)
            if not result.success:
                failures.append(f"{source.name}: {result.error}")
                continue
            try:
                found = _networks_from_json(json.loads(result.content), source.parser)
            except json.JSONDecodeError as e:
                failures.append(f"{source.name}: invalid JSON ({e})")
                continue

        if not found:
            failures.append(f"{source.name}: produced zero networks")
            continue
        logger.info("allowlist_source_loaded", source=source.name, networks=len(found))
        networks.extend(found)

    if failures:
        raise AllowlistError(
            "refusing to build a partial allowlist; publishing a feed without it "
            "risks blocking legitimate infrastructure. Failures: " + "; ".join(failures)
        )

    allowlist = Allowlist(networks)
    logger.info("allowlist_built", networks=allowlist.size)
    return allowlist

"""IP to ASN and country enrichment, for aggregate reporting only.

This module exists to support :mod:`xfeeds.insights`, which publishes statistics
*about* the data rather than the data itself. Nothing here ever reaches a feed
file.

The mapping comes from iptoasn.com, which is dedicated to the public domain under
PDDL v1.0 and rebuilt hourly. That licence matters: an enrichment dataset with
redistribution conditions would drag its own obligations into every statistic we
publish, which is the problem this project already has enough of.

Only IPv4 is enriched. The u32 variant of the dataset gives integer range bounds
directly, so a lookup is a bisect over a sorted array with no per-query parsing.
IPv6 sightings are counted but reported as unenriched rather than guessed at.
"""

import bisect
import gzip
import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger(__name__)

IP2ASN_URL = "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz"
CACHE_PATH = Path(".cache/ip2asn-v4-u32.tsv.gz")
MAX_CACHE_AGE = timedelta(days=7)

ATTRIBUTION = "IP to ASN mapping by IPtoASN (Frank Denis), iptoasn.com"
ATTRIBUTION_URL = "https://iptoasn.com/"
ATTRIBUTION_LICENSE = "Public Domain (PDDL v1.0)"


@dataclass(frozen=True)
class AsnInfo:
    """What we know about the network an address sits in."""

    asn: int
    country: str
    name: str


UNKNOWN = AsnInfo(asn=0, country="??", name="unrouted or unknown")


class AsnIndex:
    """Sorted range index over the iptoasn table."""

    def __init__(self, starts: list[int], ends: list[int], infos: list[AsnInfo]) -> None:
        self._starts = starts
        self._ends = ends
        self._infos = infos
        self._by_asn: dict[int, AsnInfo] | None = None
        self._sizes: dict[int, int] | None = None

    def __len__(self) -> int:
        return len(self._starts)

    def lookup(self, address: ipaddress.IPv4Address) -> AsnInfo:
        """Return the ASN record containing this address, or UNKNOWN."""
        value = int(address)
        # Rightmost range whose start is <= value.
        i = bisect.bisect_right(self._starts, value) - 1
        if i < 0 or value > self._ends[i]:
            return UNKNOWN
        return self._infos[i]

    def announced_size(self, asn: int) -> int:
        """Total addresses this ASN announces, across all of its ranges.

        Needed to tell a large network with proportional noise apart from a small
        one that is almost entirely hostile. Without it a ranking of raw counts just
        rediscovers which providers are biggest, which nobody needed a threat feed
        to learn.
        """
        if self._sizes is None:
            sizes: dict[int, int] = {}
            for start, end, info in zip(self._starts, self._ends, self._infos, strict=True):
                sizes[info.asn] = sizes.get(info.asn, 0) + (end - start + 1)
            self._sizes = sizes
        return self._sizes.get(asn, 0)

    def by_asn(self, asn: int) -> AsnInfo | None:
        """Reverse lookup for reporting, so history rows can be labelled."""
        if self._by_asn is None:
            table: dict[int, AsnInfo] = {}
            for info in self._infos:
                table.setdefault(info.asn, info)
            self._by_asn = table
        return self._by_asn.get(asn)

    def summarise(self, item: object) -> AsnInfo:
        """Enrich a single address or the first address of a network.

        A published entry may be a CIDR. Networks in this feed are capped at /22
        (Spamhaus DROP excepted), so a prefix sits inside one announcement in the
        overwhelming majority of cases and its first address identifies it well
        enough for a count. This is a statistic, not an allocation record.
        """
        if isinstance(item, ipaddress.IPv4Address):
            return self.lookup(item)
        if isinstance(item, ipaddress.IPv4Network):
            return self.lookup(item.network_address)
        return UNKNOWN


def _download(path: Path, timeout: float = 60.0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("ip2asn_download_start", url=IP2ASN_URL)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(IP2ASN_URL, headers={"User-Agent": "xfeeds/2.0"})
        response.raise_for_status()
        path.write_bytes(response.content)
    logger.info("ip2asn_downloaded", bytes=len(path.read_bytes()))


def _is_fresh(path: Path, now: datetime) -> bool:
    if not path.exists():
        return False
    age = now - datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    return age < MAX_CACHE_AGE


def load_asn_index(
    path: Path = CACHE_PATH,
    *,
    now: datetime | None = None,
    allow_download: bool = True,
) -> AsnIndex | None:
    """Load the ASN index, downloading it if the cache is missing or stale.

    Returns ``None`` when the table is unavailable. Insights are a reporting
    nicety; failing to fetch them must never fail a feed run, so callers degrade
    to publishing statistics without ASN breakdowns.
    """
    now = now or datetime.now(UTC)
    if not _is_fresh(path, now):
        if not allow_download:
            return None
        try:
            _download(path)
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("ip2asn_unavailable", error=str(exc))
            if not path.exists():
                return None

    starts: list[int] = []
    ends: list[int] = []
    infos: list[AsnInfo] = []
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start, end, asn = int(parts[0]), int(parts[1]), int(parts[2])
                except ValueError:
                    continue
                starts.append(start)
                ends.append(end)
                infos.append(AsnInfo(asn=asn, country=parts[3] or "??", name=parts[4]))
    except (OSError, gzip.BadGzipFile) as exc:
        logger.warning("ip2asn_unreadable", error=str(exc))
        return None

    if not starts:
        return None
    # The published table is already sorted; sorting defensively is cheap next to
    # the download and makes the bisect contract explicit rather than assumed.
    if any(starts[i] > starts[i + 1] for i in range(len(starts) - 1)):
        order = sorted(range(len(starts)), key=starts.__getitem__)
        starts = [starts[i] for i in order]
        ends = [ends[i] for i in order]
        infos = [infos[i] for i in order]
    logger.info("ip2asn_loaded", ranges=len(starts))
    return AsnIndex(starts, ends, infos)

import ipaddress
import os
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPOrNet = IPAddress | IPNetwork


class Band(str, Enum):
    """Publication tier for an indicator.

    HIGH is safe to drop traffic on. MEDIUM is for challenge or rate-limit
    rather than a hard block. WITHHELD is never published - it is retained only
    so it can corroborate a future observation.
    """

    HIGH = "high"
    MEDIUM = "medium"
    WITHHELD = "withheld"


VALID_PARSERS = {
    "abuseipdb",
    "bruteforceblocker",
    "cloudflare_json",
    "dataplane",
    "dshield",
    "github_meta",
    "google_json",
    "ipsum_levels",
    "ipthreat",
    "netset",
    "plain_text",
    "spamhaus_asn_json",
    "spamhaus_json",
    "threatfox_api",
    "turris_greylist",
}


class SourceConfig(BaseModel):
    name: str
    url: str
    parser: str
    independence_class: str
    weight: float
    categories: list[str] = Field(default_factory=list)
    ttl_days: int = 14
    timeout_seconds: int | None = None
    min_interval_seconds: int | None = None
    license: str | None = None
    license_url: str | None = None
    license_risk: str | None = None
    attribution_required: bool | None = None
    credit: str | None = None
    """Human-readable credit line for published headers.

    Set for every source we republish, including the several that state no licence
    at all. Those grant us nothing in writing, which is a reason to name them
    clearly rather than an excuse not to.
    """
    enabled: bool = True
    vote: bool = True
    redistribute: bool = True
    """May be republished in the primary feed."""
    redistribute_noncommercial: bool = False
    """May be republished in the non-commercial tier only.

    For sources whose licence permits redistribution but forbids commercial use -
    currently CC BY-NC-SA material. Ignored unless ``redistribute`` is false.
    """
    explicit_grant: bool = False
    """The publisher has issued a WRITTEN licence that affirmatively permits
    redistribution, including commercially.

    This is a higher bar than ``redistribute``, and the distinction is the whole
    point of the clean tier. ``redistribute`` answers "would republishing this get
    us in trouble?", which for several sources is "probably not, they publish it
    freely and say nothing about reuse". That is fine for us and useless to a
    practitioner who has to satisfy their own legal review, because absence of a
    prohibition is not a grant.

    True only for a named, citable licence: CC0, Unlicense, MIT, BSD, or CC BY /
    BY-SA. False for "no terms found", for permissive prose without a licence, and
    for anything asserting copyright while declining to license it. Deliberately
    also False for aggregations of upstreams whose own terms are restrictive - a
    permissive licence over a re-publication does not launder what it contains.
    """
    noncommercial_compatible: bool = True
    """May appear in the non-commercial tier at all.

    False for sources under a plain ShareAlike licence. CC BY-SA forbids adding
    further restrictions to an adaptation, so ShareAlike-only data cannot legally
    be combined into a NonCommercial output. See ADR-041.
    """
    notes: str | None = None

    # Optional fields from sources.yaml
    method: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    auth_secret: str | None = None
    params: dict[str, Any] | None = None
    cache_response: bool | None = None
    levels: list[int] | None = None
    min_score: int | None = None
    """Drop rows whose upstream-declared confidence score is below this.

    For sources that publish a per-row score. Fetching the publisher's *widest*
    file and applying the floor here is strictly better than fetching a
    pre-filtered file: one request gets the whole corpus, the floor becomes a
    tunable number in review rather than a URL nobody re-examines, and the score
    is available for tagging either way. See ADR-050 for the measurement behind
    the value used for ipthreat.
    """
    gzipped: bool = False
    """Response body is gzip-compressed and must be inflated before parsing."""
    tag_only: bool = False
    require_user_agent: bool = False
    allow_stale_fallback: bool = False
    """Use the last cached copy if a fetch fails.

    Only appropriate for allowlist sources, where an out-of-date list is safer
    than no list. Threat feeds must never do this silently.
    """

    def resolved_auth_secret(self) -> str | None:
        """Return this source's API key from the environment, or None if unset.

        Secrets are never stored in config. A missing key is not an error at load
        time - keyed sources are expected to skip cleanly when their key is
        absent, so the pipeline still runs on the unauthenticated sources.
        """
        if not self.auth_secret:
            return None
        return os.environ.get(self.auth_secret) or None


class AllowlistSourceConfig(BaseModel):
    name: str
    parser: str
    url: str | None = None
    path: str | None = None
    notes: str | None = None


class DefaultsConfig(BaseModel):
    timeout_seconds: int = 25
    user_agent: str = "xfeeds/2.0 (+https://github.com/neilweitzel/xfeeds)"
    retries: int = 3
    ttl_days: int = 14
    vote: bool = True
    redistribute: bool = True
    enabled: bool = True


class Registry(BaseModel):
    version: int
    defaults: DefaultsConfig
    sources: list[SourceConfig]
    allowlist_sources: list[AllowlistSourceConfig]

    @model_validator(mode="after")
    def validate_registry(self) -> "Registry":
        names: set[str] = set()
        for source in self.sources:
            if source.name in names:
                raise ValueError(f"Duplicate source name found: {source.name}")
            names.add(source.name)

            if not (0.0 <= source.weight <= 1.0):
                raise ValueError(
                    f"Weight must be between 0.0 and 1.0 for source {source.name}, got {source.weight}"
                )

            if source.parser not in VALID_PARSERS:
                raise ValueError(f"Unknown parser '{source.parser}' for source {source.name}")

            if source.vote and source.weight == 0.0:
                raise ValueError(f"Source {source.name} is a voting source but has weight 0.0")

        for allowlist_source in self.allowlist_sources:
            if allowlist_source.parser not in VALID_PARSERS:
                raise ValueError(
                    f"Unknown parser '{allowlist_source.parser}' for allowlist source {allowlist_source.name}"
                )

        return self


class IndicatorRecord(BaseModel):
    ip_or_cidr: (
        ipaddress.IPv4Address
        | ipaddress.IPv6Address
        | ipaddress.IPv4Network
        | ipaddress.IPv6Network
    )
    source: str
    independence_class: str
    first_seen: datetime
    last_seen: datetime
    categories: list[str]
    tags: list[str] = Field(default_factory=list)
    source_last_reported: datetime | None = None
    """When the upstream feed says it last saw this address, if it says.

    Deliberately NOT ``last_seen``. Feeding a 31-day-old upstream date into
    ``last_seen`` would put it straight through ``recency_factor`` and silently
    restate every score, so this is carried alongside and consumed only by the
    history and insights layers. bruteforceblocker publishes about a month of dated
    history and ipthreat about ten days, which is what makes real 30- and 60-day
    windows possible before this project has been running that long.
    """
    carried: bool = False
    """Synthesised from prior state because this source missed the current run.

    A carried observation votes at a decayed weight so that a transient upstream
    outage degrades confidence smoothly instead of dropping a whole independence
    class. It deliberately cannot promote: promotion asserts "safe to block on
    this source's word alone", which requires the source to be saying it now.
    """


class ScoredIndicator(BaseModel):
    """One indicator after all observations of it have been collapsed and scored."""

    ip_or_cidr: IPOrNet
    score: float
    band: Band
    independence_classes: list[str]
    """Distinct classes that voted. Length drives the band, not the source count."""
    sources: list[str]
    categories: list[str]
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    promoted_by: str | None = None
    """Set when a high-precision source bypassed the corroboration threshold."""
    restricted_corroboration: int = 0
    """Count of independence classes that corroborated under a licence forbidding
    redistribution.

    Their names are deliberately omitted. Publishing "turris" against an address
    would disclose that the address is on the Turris greylist, which is the thing
    their licence does not let us republish. The count conveys the strength of the
    corroboration without republishing their membership.
    """

    def sort_key(self) -> tuple[int, int, int]:
        """Integer sort key.

        Sorting as strings puts 10.0.0.1 before 9.9.9.9, which makes diffs
        between runs unreadable and defeats the churn guard.
        """
        if isinstance(self.ip_or_cidr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return (self.ip_or_cidr.version, int(self.ip_or_cidr), 128)
        return (
            self.ip_or_cidr.version,
            int(self.ip_or_cidr.network_address),
            self.ip_or_cidr.prefixlen,
        )

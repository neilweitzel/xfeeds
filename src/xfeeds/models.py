import ipaddress
import os
from datetime import date, datetime
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
    dormant: bool = False
    """Manually expired: the maintainer has confirmed the tracked threat is gone.

    Identical in effect to running out the expiry clock (ADR-059) — the source
    keeps being fetched, and contributes **nothing** to scoring. It is not a
    damped vote and not a non-admitting vote; its records are dropped before the
    scorer sees them.

    It is still fetched on purpose. The fetch is what tells a maintainer the
    upstream has started publishing again, which is the signal to run the
    reactivation review. Clearing this flag is that review's outcome, and unlike
    clock expiry it cannot be cleared by ``reviewed_on`` — a maintainer's
    statement is only undone by a maintainer.

    Superseded ADR-052/053 behaviour, where dormant meant a damped, non-admitting
    vote. Half-counting evidence from a threat we have already declared dead was
    a distinction without a defensible purpose.
    """
    sighting_window_days: int | None = None
    """Days of per-address sighting history to keep for this source.

    Set only for sources that publish a daily snapshot of what they saw *today*
    and nothing about last week. An address is then contributed if it is in
    today's snapshot, or if it was seen on ``sighting_min_days`` distinct days
    within this window and most recently within ``ttl_days`` (ADR-061).

    Leave unset for sources that already publish their own history.
    """
    sighting_min_days: int = 2
    """Distinct days an address must appear on before history alone contributes it.

    Two, because one sighting is not corroboration — the same reason a single
    source cannot admit a record. Measured: 49.5% of the Turris 30-day union
    appears on exactly one day, and requiring two captures 95% of the available
    upgrades while discarding all of them.
    """
    expire_after_days: int | None = None
    """Days of stale evidence before this source's data is dropped entirely.

    Defaults to ``pipeline.EXPIRY_DAYS`` (90). Set it lower for a source whose
    data goes dangerous rather than merely useless when it ages.
    """
    reviewed_on: date | None = None
    """Date of the last maintainer review of this source.

    Clears a clock expiry when it is on or after the date the source expired: the
    source rejoins scoring under the normal freshness rules. An older date does
    nothing, so a review recorded before an expiry cannot silently authorise it.

    This is the "re-admitted upon review during a sources refresh" half of
    ADR-059. Editing it is a ``sources.yaml`` change, which restarts the RC
    burn-in clock — deliberately, because readmitting a source is a scoring
    change.
    """

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
    evidence_stale: bool = False
    """True when the source's own declared update time exceeds the freshness
    threshold (ADR-052).

    A successful HTTP fetch is not the same as fresh evidence. When a source's
    HTTP Last-Modified or payload-level timestamp is older than
    ``min(STALENESS_DAYS, ttl_days)``, the pipeline marks every observation from
    that source as stale. A stale-evidence observation still votes, but (ADR-053):

    - its weight is damped by ``score.STALE_EVIDENCE_FACTOR``, and
    - it is non-admitting: it may upgrade a record that already qualifies on live
      corroboration, but never counts toward the classes that admit one, and it
      cannot solo-promote.

    See ``docs/source-lifecycle.md``.
    """
    source_reference: str | None = None
    """Upstream ticket or listing identifier, where the source publishes one.

    The first question on any false-positive report is "why is this listed", and
    the strongest possible answer is the upstream's own reference rather than "a
    source we trust said so". Spamhaus DROP carries an ``sblid`` per netblock whose
    details are viewable at https://check.spamhaus.org/; that identifier was being
    discarded at parse time.

    Deliberately generic rather than ``sbl_id``: any source that publishes a
    stable per-record reference should populate this field.

    Never written to the plain-text feeds. Those are parsed by firewalls, and the
    header already carries attribution.
    """
    source_registry: str | None = None
    """Which RIR allocated the block, where the source states it.

    Carried for abuse-report routing - it identifies whose abuse contact path
    applies. It is **not** geolocation and must never be rendered as a country or
    region: see ADR on why no map is published. Aggregate charts derive the /12
    block from the address itself rather than reading this field, so the published
    statistics carry no registry claim at all.
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
    """Count of independence classes that corroborated but could not admit.

    Two kinds land here: a licence forbidding redistribution, and evidence nobody
    is vouching for today (a stale or dormant upstream, ADR-053).

    Their names are deliberately omitted. Publishing "turris" against an address
    would disclose that the address is on the Turris greylist, which is the thing
    their licence does not let us republish. The count conveys the strength of the
    corroboration without republishing their membership.
    """
    source_reference: str | None = None
    """Upstream listing identifier carried through from the observation.

    See :attr:`IndicatorRecord.source_reference`. Only set from a redistributable
    source: a reference is a citation, and citing a source we may not name would
    disclose its membership just as surely as listing it in ``sources``.
    """
    source_registry: str | None = None
    """RIR that allocated the block, for abuse-report routing. Never geolocation."""

    @property
    def address_family(self) -> str:
        """``"v4"`` or ``"v6"`` - the split that decides which feed file this joins."""
        return f"v{self.ip_or_cidr.version}"

    def blast_radius_64(self) -> int:
        """How many /64 subnets this entry covers.

        The honest unit for IPv6 scope. Entry count is close to meaningless when a
        /29 and a /48 both count as one line but differ by a factor of half a
        million. For IPv4 this returns the address count, which is the equivalent
        question at that scale.
        """
        item = self.ip_or_cidr
        if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return 1
        if item.version == 4:
            return item.num_addresses
        return 1 if item.prefixlen >= 64 else 2 ** (64 - item.prefixlen)

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

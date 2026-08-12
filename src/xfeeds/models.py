import ipaddress
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

VALID_PARSERS = {
    "abuseipdb",
    "bruteforceblocker",
    "cloudflare_json",
    "dshield",
    "github_meta",
    "google_json",
    "ipsum_levels",
    "netset",
    "plain_text",
    "spamhaus_asn_json",
    "spamhaus_json",
    "threatfox_api",
}


class SourceConfig(BaseModel):
    name: str
    url: str
    parser: str
    independence_class: str
    weight: float
    categories: list[str] = Field(default_factory=list)
    ttl_days: int = 14
    min_interval_seconds: int | None = None
    license: str | None = None
    license_url: str | None = None
    license_risk: str | None = None
    attribution_required: bool | None = None
    enabled: bool = True
    vote: bool = True
    redistribute: bool = True
    notes: str | None = None

    # Optional fields from sources.yaml
    method: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    auth_secret: str | None = None
    params: dict[str, Any] | None = None
    cache_response: bool | None = None
    levels: list[int] | None = None
    tag_only: bool | None = None
    require_user_agent: bool | None = None


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

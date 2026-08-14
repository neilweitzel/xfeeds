"""GreyNoise suppression tests.

No network, per AGENTS.md rule 1. The response shapes below are trimmed from real
``POST /v3/ip?quick=true`` answers recorded on 2026-08-14, including the 206 status
and the ``restricted_fields`` metadata the free tier returns.
"""

import ipaddress
from datetime import UTC, datetime

import pytest
from pytest_httpx import HTTPXMock

from xfeeds.greynoise import ENV_VAR, benign_addresses, cap_benign_scanners
from xfeeds.models import Band, ScoredIndicator

NOW = datetime(2026, 8, 14, tzinfo=UTC)


def scored(value: str, band: Band = Band.HIGH) -> ScoredIndicator:
    parsed = (
        ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    )
    return ScoredIndicator(
        ip_or_cidr=parsed,
        score=90.0,
        band=band,
        independence_classes=["alpha", "beta"],
        sources=["one", "two"],
        categories=["scanning"],
        tags=[],
        first_seen=NOW,
        last_seen=NOW,
    )


def quick_response(pairs: dict[str, str]) -> dict[str, object]:
    """Build a quick-mode body. business_service_intelligence is always null here.

    That is not laziness in the fixture - it is what the free tier returns, because
    that dataset is a separately licensed add-on. Anything relying on it would be
    reading a field that is restricted in production.
    """
    return {
        "data": [
            {
                "ip": ip,
                "business_service_intelligence": {"found": None, "trust_level": ""},
                "internet_scanner_intelligence": {"found": True, "classification": c},
            }
            for ip, c in pairs.items()
        ],
        "request_metadata": {
            "restricted_fields": ["business_service_intelligence", "cve", "scan_ports"],
            "ips_not_found": [],
            "invalid_ips": [],
        },
    }


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------


def test_no_key_means_no_lookup_and_no_capping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enrichment is optional. Absent key must not raise and must not call out.

    httpx_mock is deliberately NOT requested here: if the function tried a request
    there would be no mock to serve it and the test would error, which is the
    assertion.
    """
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert benign_addresses([scored("45.33.32.5")]) == set()


def test_benign_classification_is_extracted(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_VAR, "test-key")
    httpx_mock.add_response(
        status_code=206,  # the normal answer when some addresses are outside the window
        json=quick_response(
            {
                "64.62.156.10": "benign",
                "45.153.34.165": "malicious",
                "1.2.3.5": "suspicious",
                "1.2.3.6": "unknown",
            }
        ),
    )
    records = [scored(ip) for ip in ("64.62.156.10", "45.153.34.165", "1.2.3.5", "1.2.3.6")]

    assert benign_addresses(records) == {"64.62.156.10"}
    assert httpx_mock.get_requests()[0].headers["key"] == "test-key"


def test_cidrs_are_never_submitted(httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
    """A network cannot be looked up as one entity, and expanding it would burn quota."""
    import json as _json

    monkeypatch.setenv(ENV_VAR, "test-key")
    httpx_mock.add_response(json=quick_response({"45.33.32.5": "benign"}))

    benign_addresses([scored("45.33.32.5"), scored("1.10.16.0/20"), scored("1.19.0.0/16")])

    submitted = _json.loads(httpx_mock.get_requests()[0].content)["ips"]
    assert submitted == ["45.33.32.5"]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (429, {"message": "rate limit exceeded"}),
        (401, {"message": "bad key"}),
        (403, {"message": "not entitled"}),
        (500, {"message": "boom"}),
        (200, {"data": "not-a-list"}),
        (200, {"unexpected": True}),
    ],
)
def test_api_failure_degrades_to_capping_nothing(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch, status: int, body: dict[str, object]
) -> None:
    """A feed that fails to build because an enrichment API was down is a worse bug.

    Quota rejection is the realistic case here: the free tier's limits are not
    documented, so a 429 must be survivable rather than fatal.
    """
    monkeypatch.setenv(ENV_VAR, "test-key")
    httpx_mock.add_response(status_code=status, json=body)

    assert benign_addresses([scored("45.33.32.5")]) == set()


def test_network_error_degrades_to_capping_nothing(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    monkeypatch.setenv(ENV_VAR, "test-key")
    httpx_mock.add_exception(httpx.ConnectError("no route"))

    assert benign_addresses([scored("45.33.32.5")]) == set()


# --------------------------------------------------------------------------
# Capping
# --------------------------------------------------------------------------


def test_benign_high_is_demoted_to_medium_not_deleted() -> None:
    """Blocking a research scanner is the consumer's policy choice - ADR-013.

    So the record stays in the feed at medium, where the documented handling is
    challenge or rate-limit rather than a hard block.
    """
    records = [scored("64.62.156.10"), scored("45.153.34.165")]

    capped = cap_benign_scanners(records, {"64.62.156.10"})

    assert capped == 1
    assert records[0].band is Band.MEDIUM
    assert records[1].band is Band.HIGH
    assert len(records) == 2, "capping must never drop a record"


def test_capping_never_annotates_the_record() -> None:
    """A marker would disclose GreyNoise membership into a published file.

    Their terms forbid free customers republishing the platform, so the only thing
    that may leave this stage is an aggregate count.
    """
    record = scored("64.62.156.10")
    before_tags = list(record.tags)
    before_sources = list(record.sources)

    cap_benign_scanners([record], {"64.62.156.10"})

    assert record.tags == before_tags
    assert record.sources == before_sources
    assert "greynoise" not in repr(record).lower()


def test_medium_and_withheld_records_are_left_alone() -> None:
    """Withheld records are not published, so there is no exposure to remove.

    Touching one would risk promoting something the scorer deliberately held back.
    """
    medium = scored("1.2.3.5", band=Band.MEDIUM)
    withheld = scored("1.2.3.6", band=Band.WITHHELD)

    capped = cap_benign_scanners([medium, withheld], {"1.2.3.5", "1.2.3.6"})

    assert capped == 0
    assert medium.band is Band.MEDIUM
    assert withheld.band is Band.WITHHELD


def test_empty_benign_set_is_a_no_op() -> None:
    records = [scored("45.33.32.5"), scored("1.2.3.5")]
    assert cap_benign_scanners(records, set()) == 0
    assert all(r.band is Band.HIGH for r in records)

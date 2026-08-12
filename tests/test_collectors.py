import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from xfeeds.collectors import fetch_source
from xfeeds.models import SourceConfig


def get_mock_config(
    name: str = "test_source",
    url: str = "https://example.com",
    parser: str = "plain_text",
    **kwargs: Any,
) -> SourceConfig:
    return SourceConfig(
        name=name, url=url, parser=parser, independence_class="test_class", weight=1.0, **kwargs
    )


def test_fetch_success(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(content=b"test data")
    config = get_mock_config()
    result = fetch_source(config)
    assert result.success is True
    assert result.content == b"test data"
    assert result.cached is False


def test_fetch_html_rejection(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        content=b"<html></html>", headers={"Content-Type": "text/html; charset=utf-8"}
    )
    config = get_mock_config()
    result = fetch_source(config)
    assert result.success is False
    assert result.error == "Source returned text/html"


def test_fetch_4xx_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=404)
    config = get_mock_config()
    result = fetch_source(config)
    assert result.success is False
    assert result.error and "HTTP status error: 404" in result.error


def test_fetch_5xx_retry_and_fail(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=500)
    httpx_mock.add_response(status_code=500)
    httpx_mock.add_response(status_code=500)
    config = get_mock_config()
    result = fetch_source(config)
    assert result.success is False
    assert result.error and "HTTP status error: 500" in result.error
    assert len(httpx_mock.get_requests()) == 3


def test_fetch_429_retry_and_success(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=429)
    httpx_mock.add_response(status_code=200, content=b"success")
    config = get_mock_config()
    result = fetch_source(config)
    assert result.success is True
    assert result.content == b"success"
    assert len(httpx_mock.get_requests()) == 2


def test_fetch_caching_and_interval(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mock the cache directory to use tmp_path
    def mock_get_cache_path(config: Any) -> Path:
        return tmp_path / f"{config.name}.json"

    import xfeeds.collectors.base

    monkeypatch.setattr(xfeeds.collectors.base, "_get_cache_path", mock_get_cache_path)

    # First request
    httpx_mock.add_response(
        content=b"data1",
        headers={"ETag": '"etag1"', "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
    )
    config = get_mock_config(min_interval_seconds=60)
    result1 = fetch_source(config)
    assert result1.success is True
    assert result1.content == b"data1"

    # Second request immediately should be rate limited by interval
    result2 = fetch_source(config)
    assert result2.success is True
    assert result2.cached is True
    assert result2.error is None
    # No new requests sent
    assert len(httpx_mock.get_requests()) == 1

    # Fast forward time to bypass min_interval

    original_time = time.time

    def mock_time() -> float:
        return original_time() + 100

    monkeypatch.setattr(time, "time", mock_time)

    # Now it should request again, using ETag, and we mock a 304 response
    httpx_mock.add_response(status_code=304)
    result3 = fetch_source(config)
    assert result3.success is True
    assert result3.cached is True

    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    assert requests[1].headers.get("if-none-match") == '"etag1"'
    assert requests[1].headers.get("if-modified-since") == "Wed, 21 Oct 2015 07:28:00 GMT"


# Parser tests
from xfeeds.collectors.parsers import (
    bruteforceblocker,
    dshield,
    ipsum_levels,
    netset,
    plain_text,
    spamhaus_asn_json,
    spamhaus_json,
)


def test_plain_text_parser() -> None:
    content = b"""
# Some comment
1.2.3.4
5.6.7.8 # inline comment
10.0.0.1 # private IP should be skipped
invalid-ip
2001:4860:4860::8888
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))

    # 1.2.3.4, 5.6.7.8, 2001:4860:4860::8888 are global
    assert len(records) == 3
    assert str(records[0].ip_or_cidr) == "1.2.3.4"
    assert str(records[1].ip_or_cidr) == "5.6.7.8"
    assert str(records[2].ip_or_cidr) == "2001:4860:4860::8888"


def test_plain_text_with_crlf_and_semicolon() -> None:
    content = b"1.2.3.4\r\n; comment\r\n5.6.7.8"
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))
    assert len(records) == 2


def test_netset_parser() -> None:
    content = b"""
1.2.3.0/24
5.6.7.8
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(netset(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "1.2.3.0/24"


def test_spamhaus_json_parser_with_metadata() -> None:
    content = b"""{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}
{"type":"metadata","timestamp":123456,"records":1687,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(spamhaus_json(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "1.10.16.0/20"

    # Check that metadata was extracted to config
    assert config.license == "(c) 2026 The Spamhaus Project SLU"
    assert config.license_url == "https://www.spamhaus.org/drop/terms/"


def test_spamhaus_asn_json_parser_with_metadata() -> None:
    content = b"""{"asn":245,"rir":"arin","domain":"planningresearchcorp.com","cc":"US","asname":"PRC-AS"}
{"type":"metadata","timestamp":123456,"records":1687,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(spamhaus_asn_json(content, config, fetch_time))
    assert len(records) == 0
    assert config.license == "(c) 2026 The Spamhaus Project SLU"
    assert config.license_url == "https://www.spamhaus.org/drop/terms/"


def test_dshield_parser() -> None:
    content = b"""
# Some header
45.205.1.0	45.205.1.255	24	322	MULTA-ASN1	US	abuse@multacom.com
147.185.132.0	147.185.132.255	24	322	GOOGLE-CLOUD-PLATFORM	US	None
10.0.0.0 10.0.0.255 24 # private range should be skipped
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(dshield(content, config, fetch_time))

    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "45.205.1.0/24"
    assert str(records[1].ip_or_cidr) == "147.185.132.0/24"


def test_bruteforceblocker_parser() -> None:
    content = b"""# using cache
# Last-Modified: Wed, 12 Aug 2026 00:14:50 GMT
92.118.39.78\t\t# 2026-07-19 20:29:31\t\t25\t2839674
171.231.184.215\t\t# 2026-08-08 19:20:08\t\t23\t2844299
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(bruteforceblocker(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "92.118.39.78"
    assert str(records[1].ip_or_cidr) == "171.231.184.215"


def test_ipsum_levels_parser() -> None:
    content = b"""195.178.110.137
31.77.227.120
"""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(ipsum_levels(content, config, fetch_time))
    assert len(records) == 2
    assert str(records[0].ip_or_cidr) == "195.178.110.137"


def test_empty_source() -> None:
    content = b""
    config = get_mock_config()
    fetch_time = datetime.now(UTC)
    records = list(plain_text(content, config, fetch_time))
    assert len(records) == 0

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from xfeeds.models import SourceConfig


@dataclass
class CollectorResult:
    """The result of fetching a source."""

    success: bool
    """Whether the fetch was successful."""

    content: bytes = b""
    """The raw response content, if successful and not cached."""

    error: str | None = None
    """The error message, if unsuccessful."""

    cached: bool = False
    """Whether the response was a cache hit (304 Not Modified)."""

    status_code: int | None = None
    """The HTTP status code returned."""


def _is_retryable_error(e: BaseException) -> bool:
    """Return True if the exception should trigger a retry."""
    if isinstance(e, httpx.HTTPStatusError):
        # Retry on 429 Too Many Requests and 5xx Server Errors
        return e.response.status_code == 429 or e.response.status_code >= 500
    return isinstance(e, httpx.RequestError)


@retry(
    retry=retry_if_exception(_is_retryable_error),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
def _do_fetch(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    """Perform the HTTP request with retry logic."""
    response = client.request(method, url, **kwargs)

    # Do not raise for 304, it's a valid cache hit
    if response.status_code != 304:
        response.raise_for_status()

    return response


def _get_cache_path(config: SourceConfig) -> Path:
    """Return the path to the cache directory for a source."""
    cache_dir = Path("feeds/cache")
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{config.name}.json"


def fetch_source(config: SourceConfig) -> CollectorResult:
    """Fetch a source using its configuration."""
    timeout = httpx.Timeout(25.0)  # Default timeout
    headers = {"User-Agent": "xfeeds/2.0 (+https://github.com/neilweitzel/xfeeds)"}
    if config.require_user_agent:
        headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    method = config.method or "GET"

    # Enforce min_interval_seconds and load ETag / Last-Modified
    cache_path = _get_cache_path(config)
    cache_data: dict[str, Any] = {}
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    last_fetch_time = cache_data.get("last_fetch_time", 0)
    current_time = time.time()

    if config.min_interval_seconds and current_time - last_fetch_time < config.min_interval_seconds:
        return CollectorResult(
            success=True,
            cached=True,
            error=None,  # Do not set error for a successful cache skip
        )

    if cache_data.get("etag"):
        headers["If-None-Match"] = cache_data["etag"]
    if cache_data.get("last_modified"):
        headers["If-Modified-Since"] = cache_data["last_modified"]

    try:
        # We don't want httpx to follow redirects blindly if they break things,
        # but follow_redirects=True is often useful. In xfeeds, we'll follow redirects.
        with httpx.Client(timeout=timeout, verify=True, follow_redirects=True) as client:
            response = _do_fetch(client, method, config.url, headers=headers)

            # If server returned 304 Not Modified
            if response.status_code == 304:
                # Update last fetch time
                cache_data["last_fetch_time"] = current_time
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache_data, f)

                return CollectorResult(
                    success=True,
                    cached=True,
                    status_code=304,
                )

            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type.lower():
                return CollectorResult(
                    success=False,
                    error="Source returned text/html",
                    status_code=response.status_code,
                )

            # Update cache headers
            cache_data["last_fetch_time"] = current_time
            if response.headers.get("etag"):
                cache_data["etag"] = response.headers.get("etag")
            if response.headers.get("last-modified"):
                cache_data["last_modified"] = response.headers.get("last-modified")

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f)

            return CollectorResult(
                success=True,
                content=response.content,
                status_code=response.status_code,
            )

    except httpx.HTTPStatusError as e:
        return CollectorResult(
            success=False,
            error=f"HTTP status error: {e.response.status_code}",
            status_code=e.response.status_code,
        )
    except httpx.RequestError as e:
        return CollectorResult(
            success=False,
            error=f"Request error: {e}",
        )
    except Exception as e:
        return CollectorResult(
            success=False,
            error=f"Unexpected error: {e}",
        )

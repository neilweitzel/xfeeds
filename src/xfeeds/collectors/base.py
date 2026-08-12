"""HTTP fetching for sources.

Two independent caching mechanisms operate here and they solve different problems:

* ``min_interval_seconds`` protects the *upstream*. AbuseIPDB permits five
  blacklist calls per day and Spamhaus requires automated fetches to be at least
  an hour apart, so we must not hit them more often than configured.
* ``ETag`` / ``If-Modified-Since`` protects *bandwidth*. When the upstream says
  304 Not Modified there is no new body to download.

Both paths must still hand the caller a usable body, otherwise a cached run
silently drops every record for that source. That is why the response body is
persisted alongside the validators rather than only the headers.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import structlog
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from xfeeds.models import DefaultsConfig, SourceConfig

logger = structlog.get_logger(__name__)

CACHE_DIR = Path(".cache/sources")
"""Cache lives outside feeds/ because feeds/ is published output."""


@dataclass
class CollectorResult:
    """The result of fetching a source.

    ``content`` is populated on every successful result, including cache hits, so
    callers never have to distinguish a fresh fetch from a cached one in order to
    parse. ``success=True`` with empty ``content`` means the upstream genuinely
    returned nothing.
    """

    success: bool
    content: bytes = b""
    error: str | None = None
    skipped_no_credential: bool = False
    stale_fallback: bool = False
    """True when a fetch failed and the last cached copy was used instead."""
    """True when the source needs an API key that is not configured.

    Distinct from a failure: this is the expected state for keyed sources on a
    fresh clone, and must not be reported as a broken upstream.
    """
    cached: bool = False
    """True when content came from the local cache rather than a fresh download."""
    status_code: int | None = None
    not_modified: bool = False
    """True when the upstream answered 304."""
    skipped_by_interval: bool = False
    """True when min_interval_seconds suppressed the request."""
    last_modified_header: str | None = None
    """Upstream Last-Modified, used downstream for staleness warnings."""


def _is_retryable_error(e: BaseException) -> bool:
    """Retry transient failures only: 429, 5xx, and connection errors.

    4xx other than 429 are permanent for our purposes - retrying a 403 or a 404
    just wastes the upstream's time and ours.
    """
    if isinstance(e, httpx.HTTPStatusError):
        return e.response.status_code == 429 or e.response.status_code >= 500
    return isinstance(e, httpx.RequestError)


def _cache_paths(config: SourceConfig) -> tuple[Path, Path]:
    """Return (metadata path, body path) for a source.

    The name is hashed into the filename so a source name containing a path
    separator cannot escape the cache directory.
    """
    digest = hashlib.sha256(config.name.encode("utf-8")).hexdigest()[:12]
    stem = f"{config.name.replace('/', '_')}.{digest}"
    return CACHE_DIR / f"{stem}.meta.json", CACHE_DIR / f"{stem}.body"


def _read_cache(config: SourceConfig) -> tuple[dict[str, Any], bytes | None]:
    """Load cached metadata and body. Missing or corrupt cache is not an error."""
    meta_path, body_path = _cache_paths(config)
    meta: dict[str, Any] = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            meta = {}
    body: bytes | None = None
    if body_path.exists():
        try:
            body = body_path.read_bytes()
        except OSError:
            body = None
    return meta, body


def _write_cache(config: SourceConfig, meta: dict[str, Any], body: bytes | None) -> None:
    """Persist cache metadata and, when supplied, the response body."""
    meta_path, body_path = _cache_paths(config)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        if body is not None:
            body_path.write_bytes(body)
    except OSError as e:
        # A cache write failure must not fail the run - we simply lose the
        # optimisation on the next pass.
        logger.warning("cache_write_failed", source=config.name, error=str(e))


def fetch_source(config: SourceConfig, defaults: DefaultsConfig) -> CollectorResult:
    """Fetch one source.

    Never raises. Every failure path returns a CollectorResult with
    ``success=False``, because one dead upstream must not stop the other eleven.
    """
    meta, cached_body = _read_cache(config)
    now = time.time()

    # --- upstream protection: has the minimum interval elapsed? -------------
    interval = config.min_interval_seconds
    last_fetch = float(meta.get("last_fetch_time", 0.0))
    if interval and (now - last_fetch) < interval:
        if cached_body is not None:
            logger.info(
                "source_served_from_cache",
                source=config.name,
                seconds_until_refresh=int(interval - (now - last_fetch)),
            )
            return CollectorResult(
                success=True,
                content=cached_body,
                cached=True,
                skipped_by_interval=True,
                last_modified_header=meta.get("last_modified"),
            )
        # No cached body to fall back on, so the interval cannot be honoured
        # without losing the source entirely. Report it rather than pretend.
        return CollectorResult(
            success=False,
            error=(
                f"min_interval_seconds={interval} not yet elapsed and no cached body is available"
            ),
            skipped_by_interval=True,
        )

    headers = {"User-Agent": defaults.user_agent}
    if meta.get("etag"):
        headers["If-None-Match"] = str(meta["etag"])
    if meta.get("last_modified"):
        headers["If-Modified-Since"] = str(meta["last_modified"])

    if config.auth == "header" and config.auth_header:
        secret = config.resolved_auth_secret()
        if secret is None:
            return CollectorResult(
                success=False,
                skipped_no_credential=True,
                error=(
                    f"{config.auth_secret} is not set - source skipped. "
                    "This is expected until the key is configured."
                ),
            )
        headers[config.auth_header] = secret

    method = (config.method or "GET").upper()
    timeout = httpx.Timeout(float(config.timeout_seconds or defaults.timeout_seconds))

    @retry(
        retry=retry_if_exception(_is_retryable_error),
        stop=stop_after_attempt(max(1, defaults.retries)),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def _do_fetch(client: httpx.Client) -> httpx.Response:
        # POST sources send their parameters as a JSON body; GET sources use the
        # query string.
        if method == "POST":
            response = client.request(method, config.url, headers=headers, json=config.params)
        else:
            response = client.request(method, config.url, headers=headers, params=config.params)
        if response.status_code != 304:  # 304 is a valid answer, not an error
            response.raise_for_status()
        return response

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = _do_fetch(client)

            if response.status_code == 304:
                meta["last_fetch_time"] = now
                _write_cache(config, meta, None)
                if cached_body is None:
                    return CollectorResult(
                        success=False,
                        error="upstream returned 304 but no cached body is available",
                        status_code=304,
                        not_modified=True,
                    )
                return CollectorResult(
                    success=True,
                    content=cached_body,
                    cached=True,
                    not_modified=True,
                    status_code=304,
                    last_modified_header=meta.get("last_modified"),
                )

            # Several sources answer a missing/unacceptable User-Agent with a
            # redirect to an HTML page. Treat HTML as a failure rather than
            # feeding markup to a parser.
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type:
                return CollectorResult(
                    success=False,
                    error=f"source returned HTML (content-type: {content_type})",
                    status_code=response.status_code,
                )

            meta["last_fetch_time"] = now
            if response.headers.get("etag"):
                meta["etag"] = response.headers["etag"]
            if response.headers.get("last-modified"):
                meta["last_modified"] = response.headers["last-modified"]
            _write_cache(config, meta, response.content)

            return CollectorResult(
                success=True,
                content=response.content,
                status_code=response.status_code,
                last_modified_header=meta.get("last_modified"),
            )

    except httpx.HTTPStatusError as e:
        return _failure_or_stale(
            config, cached_body, meta, f"HTTP {e.response.status_code}", e.response.status_code
        )
    except httpx.RequestError as e:
        return _failure_or_stale(config, cached_body, meta, f"request error: {e}", None)
    except Exception as e:  # noqa: BLE001 - collectors must never raise
        return _failure_or_stale(config, cached_body, meta, f"unexpected error: {e}", None)


def _failure_or_stale(
    config: SourceConfig,
    cached_body: bytes | None,
    meta: dict[str, Any],
    error: str,
    status_code: int | None,
) -> CollectorResult:
    """Fall back to the last good copy when an upstream fails transiently.

    Only sources that opt in via ``allow_stale_fallback`` get this. It is correct
    for the allowlist - a slightly old list of Cloudflare ranges still protects
    those ranges, whereas failing the run entirely because GitHub returned a
    transient 403 is a worse outcome. It is NOT correct for threat feeds, where
    serving stale data silently is exactly what the staleness warning exists to
    catch.
    """
    if config.allow_stale_fallback and cached_body is not None:
        age_hours = (time.time() - float(meta.get("last_fetch_time", 0))) / 3600
        logger.warning(
            "source_failed_using_cached_copy",
            source=config.name,
            error=error,
            cached_age_hours=round(age_hours, 1),
        )
        return CollectorResult(
            success=True,
            content=cached_body,
            cached=True,
            stale_fallback=True,
            status_code=status_code,
            error=error,
        )
    return CollectorResult(success=False, error=error, status_code=status_code)

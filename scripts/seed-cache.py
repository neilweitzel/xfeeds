#!/usr/bin/env python3
"""Seed a source's response cache from a file on disk, for local runs only.

Why this exists
---------------
Two sources need API keys, and there are environments where the key is reachable
but ``httpx`` is not the thing holding it: a corporate egress proxy, a secrets
broker that injects auth into outbound requests, or any setup where ``curl``
succeeds and the pipeline's own client fails the TLS handshake to the proxy. In
that situation a local ``xfeeds run`` skips the keyed sources and reports a
smaller feed than production, which makes it useless for validating output.

Rather than teach the collector about proxies, fetch the body with whatever tool
does work and hand it to the cache. ``fetch_source`` already prefers a cached body
when ``min_interval_seconds`` has not elapsed, so a seeded cache is served exactly
as a fresh fetch would be, through the same parser and the same scoring path.

This is a development tool. It writes only into ``.cache/``, which is gitignored,
and it refuses to touch anything else.

Usage
-----
Fetch the body by hand, then seed it::

    curl -X POST https://threatfox-api.abuse.ch/api/v1/ \\
         -H 'Auth-Key: ...' -H 'Content-Type: application/json' \\
         -d '{"query":"get_iocs","days":7}' -o /tmp/tf.json

    python scripts/seed-cache.py threatfox /tmp/tf.json

The source must have ``min_interval_seconds`` set, or the collector will ignore
the cache and attempt a live fetch. ``--min-interval`` reports what is configured
so a missing value is obvious rather than silently defeating the seed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from xfeeds.collectors.base import CACHE_DIR, _cache_paths
from xfeeds.config import load_registry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", help="source name as it appears in sources.yaml")
    parser.add_argument("body", type=Path, help="file containing the raw response body")
    parser.add_argument(
        "--config", type=Path, default=Path("sources.yaml"), help="path to sources.yaml"
    )
    args = parser.parse_args()

    if not args.body.is_file():
        print(f"error: {args.body} is not a file", file=sys.stderr)
        return 1

    registry = load_registry(args.config)
    config = next((s for s in registry.sources if s.name == args.source), None)
    if config is None:
        names = ", ".join(sorted(s.name for s in registry.sources))
        print(f"error: no source named {args.source!r}. Known: {names}", file=sys.stderr)
        return 1

    meta_path, body_path = _cache_paths(config)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    body = args.body.read_bytes()
    body_path.write_bytes(body)
    # last_fetch_time is what suppresses the live request. No ETag or Last-Modified
    # is written: we did not capture the upstream's validators, and inventing them
    # would make a later conditional request lie about what we hold.
    meta_path.write_text(json.dumps({"last_fetch_time": time.time()}), encoding="utf-8")

    print(f"seeded {config.name}: {len(body)} bytes -> {body_path}")

    if not config.min_interval_seconds:
        print(
            f"WARNING: {config.name} has no min_interval_seconds, so the collector will "
            "ignore this cache and try a live fetch. Set one temporarily in a copy of "
            "sources.yaml and pass it with -c.",
            file=sys.stderr,
        )
        return 1

    print(f"  min_interval_seconds={config.min_interval_seconds}; the cache will be served")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

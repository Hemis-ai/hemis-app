"""Per-scan context — holds ALL mutable state for a single scan job.

Every Scanner instance creates its own ScanContext. It is passed to every
plugin call and destroyed when the scan completes. This eliminates all
module-level global state that previously leaked between concurrent scans.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ..config import settings


@dataclass
class ScanContext:
    """Isolated state for a single scan execution."""

    scan_id: str
    target_url: str

    # Per-scan domain dedup sets (replaces module-level globals in plugins)
    reported_domains: set[str] = field(default_factory=set)
    cors_reported_domains: set[str] = field(default_factory=set)

    # Per-scan HTTP client (replaces global _client_pool in base_plugin)
    _client: Optional[httpx.AsyncClient] = field(default=None, repr=False)

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the per-scan HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=settings.request_timeout,
                follow_redirects=False,
                verify=False,
                limits=httpx.Limits(
                    max_connections=settings.max_concurrent_requests * 2,
                    max_keepalive_connections=settings.max_concurrent_requests,
                ),
                headers={"User-Agent": settings.user_agent},
            )
        return self._client

    async def close(self):
        """Close the per-scan HTTP client. Call this in a finally block."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

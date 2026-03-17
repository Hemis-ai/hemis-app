"""Base class for all scanner plugins — Burp-Suite-grade request handling."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import httpx

from ..config import settings


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    form_fields: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_status: int = 200
    content_type: str = ""


@dataclass
class RawFinding:
    vuln_type: str
    title: str
    description: str
    affected_url: str
    severity: str  # will be overridden by CVSS
    affected_parameter: Optional[str] = None
    injection_point: Optional[str] = None
    payload: Optional[str] = None
    request_evidence: Optional[str] = None
    response_evidence: Optional[str] = None
    remediation: str = ""
    remediation_code: Optional[str] = None
    confidence: int = 80
    business_impact: Optional[str] = None
    verified: bool = False  # True = confirmed with verification request


# Shared client pool — reuse connections like Burp does
_client_pool: Optional[httpx.AsyncClient] = None


async def get_shared_client() -> httpx.AsyncClient:
    global _client_pool
    if _client_pool is None or _client_pool.is_closed:
        _client_pool = httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=False,
            verify=False,
            limits=httpx.Limits(
                max_connections=settings.max_concurrent_requests * 2,
                max_keepalive_connections=settings.max_concurrent_requests,
            ),
            headers={"User-Agent": settings.user_agent},
        )
    return _client_pool


async def close_shared_client():
    global _client_pool
    if _client_pool and not _client_pool.is_closed:
        await _client_pool.aclose()
        _client_pool = None


class BasePlugin(ABC):
    name: str = "base"
    vuln_type: str = "unknown"

    def __init__(self):
        self.payloads_sent = 0

    @abstractmethod
    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        ...

    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        timeout: float = 0,
        follow_redirects: bool = False,
    ) -> Optional[httpx.Response]:
        """Send an HTTP request using the shared connection pool."""
        self.payloads_sent += 1
        try:
            client = await get_shared_client()
            req_headers = dict(client.headers)
            if headers:
                req_headers.update(headers)

            if method.upper() == "POST":
                resp = await client.post(
                    url, data=data, params=params,
                    headers=req_headers, cookies=cookies,
                    timeout=timeout or settings.request_timeout,
                    follow_redirects=follow_redirects,
                )
            elif method.upper() == "PUT":
                resp = await client.put(
                    url, data=data, params=params,
                    headers=req_headers, cookies=cookies,
                    timeout=timeout or settings.request_timeout,
                    follow_redirects=follow_redirects,
                )
            else:
                resp = await client.get(
                    url, params=params,
                    headers=req_headers, cookies=cookies,
                    timeout=timeout or settings.request_timeout,
                    follow_redirects=follow_redirects,
                )
            return resp
        except Exception:
            return None

    @staticmethod
    def get_content_type(resp: httpx.Response) -> str:
        """Extract the content type from a response."""
        return resp.headers.get("content-type", "").lower().split(";")[0].strip()

    @staticmethod
    def is_html_response(resp: httpx.Response) -> bool:
        """Check if response is HTML (the only context where reflected XSS matters)."""
        ct = resp.headers.get("content-type", "").lower()
        return "text/html" in ct or "application/xhtml" in ct

    @staticmethod
    def is_json_response(resp: httpx.Response) -> bool:
        ct = resp.headers.get("content-type", "").lower()
        return "application/json" in ct or "text/json" in ct

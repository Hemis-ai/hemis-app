"""Base class for all scanner plugins — Burp-Suite-grade request handling."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

import httpx

from ..config import settings

if TYPE_CHECKING:
    from .scan_context import ScanContext


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


class BasePlugin(ABC):
    name: str = "base"
    vuln_type: str = "unknown"

    def __init__(self):
        self.payloads_sent = 0

    @abstractmethod
    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        ...

    async def _send_request(
        self,
        ctx: ScanContext,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        timeout: float = 0,
        follow_redirects: bool = False,
    ) -> Optional[httpx.Response]:
        """Send an HTTP request using the per-scan connection pool."""
        self.payloads_sent += 1
        try:
            client = await ctx.get_client()
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

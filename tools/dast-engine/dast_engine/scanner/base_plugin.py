"""Base class for all scanner plugins."""
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
        timeout: float = 10.0,
    ) -> Optional[httpx.Response]:
        self.payloads_sent += 1
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": settings.user_agent, **(headers or {})},
                cookies=cookies,
            ) as client:
                if method.upper() == "POST":
                    return await client.post(url, data=data, params=params)
                else:
                    return await client.get(url, params=params)
        except Exception:
            return None

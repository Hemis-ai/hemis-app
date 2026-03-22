"""
HTTP method tampering detection.

Tests endpoints with unexpected HTTP methods (OPTIONS, PUT, DELETE, PATCH, TRACE)
to identify method-based access control weaknesses and XST vulnerabilities.
Runs on all discovered endpoints.
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse
import httpx
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext
from ...config import settings


class MethodTamperingPlugin(BasePlugin):
    name = "HTTP Method Tampering Scanner"
    vuln_type = "method_tampering"

    async def _send_arbitrary_method(
        self,
        ctx: ScanContext,
        url: str,
        method: str,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """Send a request with an arbitrary HTTP method using httpx .request()."""
        self.payloads_sent += 1
        try:
            client = await ctx.get_client()
            req_headers = dict(client.headers)
            if headers:
                req_headers.update(headers)
            resp = await client.request(
                method.upper(),
                url,
                headers=req_headers,
                cookies=cookies,
                timeout=settings.request_timeout,
            )
            return resp
        except Exception:
            return None

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # --- OPTIONS discovery ---
        resp = await self._send_arbitrary_method(
            ctx,
            target.url,
            method="OPTIONS",
            headers=target.headers,
            cookies=target.cookies,
        )

        allowed_methods = set()
        if resp is not None and resp.status_code < 400:
            allow_header = resp.headers.get("allow", "")
            if allow_header:
                allowed_methods = {m.strip().upper() for m in allow_header.split(",")}

            # Also check Access-Control-Allow-Methods for CORS preflight
            acam = resp.headers.get("access-control-allow-methods", "")
            if acam:
                allowed_methods.update(m.strip().upper() for m in acam.split(","))

        # --- TRACE method check (XST vulnerability) ---
        trace_resp = await self._send_arbitrary_method(
            ctx,
            target.url,
            method="TRACE",
            headers=target.headers,
            cookies=target.cookies,
        )

        if trace_resp is not None and trace_resp.status_code < 400:
            body = trace_resp.text[:2000].lower()
            # TRACE should echo back the request; check if it does
            if "trace" in body or trace_resp.headers.get("content-type", "").startswith("message/http"):
                # Verify
                verify = await self._send_arbitrary_method(
                    ctx,
                    target.url,
                    method="TRACE",
                    headers=target.headers,
                    cookies=target.cookies,
                )
                if verify is not None and verify.status_code < 400:
                    findings.append(RawFinding(
                        vuln_type="trace_method_enabled",
                        title="TRACE Method Enabled (Cross-Site Tracing)",
                        description=(
                            "The server responds to TRACE requests, which can be exploited for "
                            "Cross-Site Tracing (XST) attacks to steal credentials from HTTP headers. "
                            "Verified with two independent requests."
                        ),
                        affected_url=target.url,
                        severity="MEDIUM",
                        payload="TRACE / HTTP/1.1",
                        request_evidence=f"TRACE {target.url}",
                        response_evidence=f"HTTP {trace_resp.status_code} | Content-Type: {trace_resp.headers.get('content-type', '')}",
                        remediation="Disable the TRACE method on the web server. In Apache: TraceEnable off",
                        confidence=85,
                        verified=True,
                        business_impact="TRACE can be used to steal HTTP-only cookies and authorization headers via XST.",
                    ))

        # --- Destructive methods on GET-only endpoints ---
        if target.method.upper() == "GET":
            dangerous_methods = ["PUT", "DELETE", "PATCH"]

            for method in dangerous_methods:
                # Skip if we already know from OPTIONS that the method is not allowed
                if allowed_methods and method not in allowed_methods:
                    continue

                resp = await self._send_arbitrary_method(
                    ctx,
                    target.url,
                    method=method,
                    headers=target.headers,
                    cookies=target.cookies,
                )

                if resp is None:
                    continue

                # Consider it a finding if the server responds with success (not 405/501)
                if resp.status_code < 400 and resp.status_code not in (405, 501):
                    # Verify
                    verify = await self._send_arbitrary_method(
                        ctx,
                        target.url,
                        method=method,
                        headers=target.headers,
                        cookies=target.cookies,
                    )
                    if verify is None or verify.status_code >= 400:
                        continue

                    findings.append(RawFinding(
                        vuln_type="dangerous_method_allowed",
                        title=f"Potentially Dangerous HTTP Method Accepted: {method}",
                        description=(
                            f"The endpoint accepts {method} requests without returning 405 Method Not Allowed. "
                            f"This GET-only endpoint responded with HTTP {resp.status_code} to a {method} request. "
                            f"This may indicate missing method-based access controls. Verified with two requests."
                        ),
                        affected_url=target.url,
                        severity="MEDIUM",
                        payload=f"{method} {target.url}",
                        request_evidence=f"{method} {target.url}",
                        response_evidence=f"HTTP {resp.status_code}",
                        remediation=(
                            f"Explicitly reject {method} requests on endpoints that only support GET. "
                            f"Return 405 Method Not Allowed with an appropriate Allow header."
                        ),
                        confidence=70,
                        verified=True,
                        business_impact=f"Accepting {method} without proper controls may allow unauthorized data modification or deletion.",
                    ))

        # --- Report allowed methods from OPTIONS if it reveals too much ---
        if allowed_methods:
            dangerous_in_options = allowed_methods & {"PUT", "DELETE", "PATCH", "TRACE"}
            if dangerous_in_options:
                findings.append(RawFinding(
                    vuln_type="verbose_options_response",
                    title="OPTIONS Response Reveals Dangerous Methods",
                    description=(
                        f"The OPTIONS response advertises potentially dangerous methods: "
                        f"{', '.join(sorted(dangerous_in_options))}. This information aids attackers "
                        f"in identifying attack surface."
                    ),
                    affected_url=target.url,
                    severity="INFO",
                    request_evidence=f"OPTIONS {target.url}",
                    response_evidence=f"Allow: {', '.join(sorted(allowed_methods))}",
                    remediation="Restrict OPTIONS responses to only necessary methods. Remove TRACE, PUT, DELETE if not needed.",
                    confidence=80,
                    verified=True,
                    business_impact="Method enumeration helps attackers map the application's attack surface.",
                ))

        return findings

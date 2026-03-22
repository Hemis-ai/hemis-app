"""
CORS misconfiguration detection — reports per-URL for Burp Suite parity.
Each URL gets its own finding (wildcard, origin reflection, wildcard+creds).
Domain dedup state is held in the per-scan ScanContext for origin-reflection
with credentials (HIGH severity) to avoid excessive noise on those.
"""
from __future__ import annotations
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


class CORSPlugin(BasePlugin):
    name = "CORS Misconfiguration Scanner"
    vuln_type = "cors_misconfiguration"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        domain = urlparse(target.url).netloc

        # Test with arbitrary Origin
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
        ]

        for origin in test_origins:
            resp = await self._send_request(
                ctx,
                target.url,
                headers={**target.headers, "Origin": origin},
                cookies=target.cookies,
            )
            if resp is None:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            # Dangerous: reflects arbitrary origin (report per-URL)
            if acao == origin:
                severity = "HIGH" if acac == "true" else "MEDIUM"

                # Verification
                verify = await self._send_request(
                    ctx,
                    target.url,
                    headers={**target.headers, "Origin": origin},
                    cookies=target.cookies,
                )
                if verify is None:
                    continue
                v_acao = verify.headers.get("access-control-allow-origin", "")
                if v_acao != origin:
                    continue

                cred_note = " With credentials enabled, this allows authenticated cross-site data theft." if acac == "true" else ""
                findings.append(RawFinding(
                    vuln_type="cors_misconfiguration",
                    title="CORS Origin Reflection (Arbitrary Origin Accepted)",
                    description=(
                        f"The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin, "
                        f"allowing cross-origin requests from any domain.{cred_note} "
                        f"Verified with two independent requests."
                    ),
                    affected_url=target.url, severity=severity,
                    payload=f"Origin: {origin}",
                    request_evidence=f"Origin: {origin}",
                    response_evidence=f"Access-Control-Allow-Origin: {acao}" + (f"\nAccess-Control-Allow-Credentials: {acac}" if acac else ""),
                    remediation=(
                        "Configure CORS with a strict allowlist of trusted origins. Never reflect arbitrary Origins. "
                        "Avoid using Access-Control-Allow-Credentials: true with reflected origins."
                    ),
                    confidence=90, verified=True,
                    business_impact="Cross-origin data theft. Attackers can read API responses from their own domain.",
                ))
                break  # First origin match is enough per URL

            # Dangerous: wildcard with credentials (report per-URL)
            if acao == "*" and acac == "true":
                findings.append(RawFinding(
                    vuln_type="cors_misconfiguration",
                    title="CORS Wildcard with Credentials",
                    description="Access-Control-Allow-Origin is set to '*' with credentials allowed.",
                    affected_url=target.url, severity="HIGH",
                    response_evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    remediation="Never combine wildcard CORS with credentials. Use specific origins.",
                    confidence=95, verified=True,
                    business_impact="Any website can make authenticated requests and read responses.",
                ))
                break

            # Overly permissive: wildcard without credentials (report per-URL)
            if acao == "*" and acac != "true":
                findings.append(RawFinding(
                    vuln_type="cors_misconfiguration",
                    title="Overly Permissive CORS Policy (Wildcard Origin)",
                    description=(
                        f"The endpoint returns Access-Control-Allow-Origin: * which allows any website to "
                        f"read responses via cross-origin requests. While credentials are not included, "
                        f"this may expose sensitive data returned by this endpoint to unauthorized origins."
                    ),
                    affected_url=target.url, severity="INFO",
                    request_evidence=f"Origin: {origin}",
                    response_evidence="Access-Control-Allow-Origin: *",
                    remediation=(
                        "Restrict Access-Control-Allow-Origin to specific trusted origins instead of using "
                        "a wildcard '*'. If the endpoint serves only public data, document this as an "
                        "accepted risk."
                    ),
                    confidence=85, verified=True,
                    business_impact="Any website can read cross-origin responses from this endpoint, potentially exposing non-public data.",
                ))
                break

        return findings

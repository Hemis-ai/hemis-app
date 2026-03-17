"""CORS misconfiguration detection."""
from __future__ import annotations
import json
from ..base_plugin import BasePlugin, ScanTarget, RawFinding


class CORSPlugin(BasePlugin):
    name = "CORS Misconfiguration Scanner"
    vuln_type = "cors_misconfiguration"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Test with arbitrary Origin
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://sub.{target.url.split('//')[1].split('/')[0] if '//' in target.url else 'example.com'}",  # subdomain
        ]

        for origin in test_origins:
            resp = await self._send_request(
                target.url,
                headers={**target.headers, "Origin": origin},
                cookies=target.cookies,
            )
            if resp is None:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            # Dangerous: reflects arbitrary origin
            if acao == origin:
                severity = "HIGH" if acac == "true" else "MEDIUM"
                findings.append(RawFinding(
                    vuln_type="cors_misconfiguration",
                    title="CORS Origin Reflection (Arbitrary Origin Accepted)",
                    description=f"The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin, "
                                f"allowing cross-origin requests from any domain."
                                + (" With credentials enabled, this allows authenticated cross-site data theft." if acac == "true" else ""),
                    affected_url=target.url, severity=severity,
                    payload=f"Origin: {origin}",
                    request_evidence=f"Origin: {origin}",
                    response_evidence=f"Access-Control-Allow-Origin: {acao}" + (f"\nAccess-Control-Allow-Credentials: {acac}" if acac else ""),
                    remediation="Configure CORS with a strict allowlist of trusted origins. Never reflect arbitrary Origins. "
                                "Avoid using Access-Control-Allow-Credentials: true with reflected origins.",
                    confidence=90,
                    business_impact="Cross-origin data theft. Attackers can read authenticated API responses from their own domain.",
                ))
                break

            # Dangerous: wildcard with credentials
            if acao == "*" and acac == "true":
                findings.append(RawFinding(
                    vuln_type="cors_misconfiguration",
                    title="CORS Wildcard with Credentials",
                    description="Access-Control-Allow-Origin is set to '*' with credentials allowed.",
                    affected_url=target.url, severity="HIGH",
                    response_evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    remediation="Never combine wildcard CORS with credentials. Use specific origins.",
                    confidence=95,
                    business_impact="Any website can make authenticated requests and read responses.",
                ))
                break

        return findings

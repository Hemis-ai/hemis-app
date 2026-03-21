"""Open Redirect detection."""
from __future__ import annotations
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

REDIRECT_PARAMS = {"url", "redirect", "next", "return", "goto", "to", "dest", "destination", "target", "redir", "return_to", "redirect_uri", "redirect_url", "continue", "forward"}
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/",
    "/\\evil.com",
    "//evil%2Ecom",
    "https:evil.com",
    "////evil.com",
]


class OpenRedirectPlugin(BasePlugin):
    name = "Open Redirect Scanner"
    vuln_type = "open_redirect"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        test_params = [(p, "query") for p in target.parameters if p.lower() in REDIRECT_PARAMS]
        test_params += [(f["name"], "form") for f in target.form_fields if f.get("name", "").lower() in REDIRECT_PARAMS]

        for param, source in test_params:
            for payload in REDIRECT_PAYLOADS:
                resp = await self._inject(ctx, target, param, payload, source)
                if resp is None:
                    continue
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    findings.append(RawFinding(
                        vuln_type="open_redirect",
                        title="Open Redirect",
                        description=f"The parameter '{param}' accepts arbitrary URLs for redirection. "
                                    f"An attacker can craft a link that redirects victims to a malicious site.",
                        affected_url=target.url, severity="MEDIUM",
                        affected_parameter=param, injection_point=source,
                        payload=payload,
                        request_evidence=f"{source.upper()} '{param}' = {payload}",
                        response_evidence=f"HTTP {resp.status_code} → Location: {location}",
                        remediation="Use an allowlist of permitted redirect destinations. Never redirect to user-supplied URLs without validation.",
                        remediation_code=json.dumps({
                            "vulnerableCode": f"redirect(request.args['{param}'])",
                            "remediatedCode": f"ALLOWED = ['/dashboard', '/home']\\nurl = request.args['{param}']\\nif url not in ALLOWED: url = '/'\\nredirect(url)",
                            "explanation": "Allowlist-based validation ensures redirects only go to known-safe destinations.",
                            "language": "Python",
                        }),
                        confidence=90,
                        business_impact="Phishing attacks using trusted domain, credential theft via look-alike pages.",
                    ))
                    break
        return findings

    async def _inject(self, ctx, target, param, payload, source):
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._send_request(ctx, url, headers=target.headers, cookies=target.cookies)
        else:
            data = {f["name"]: f.get("value", "") for f in target.form_fields}
            data[param] = payload
            return await self._send_request(ctx, target.url, method="POST", data=data, headers=target.headers, cookies=target.cookies)

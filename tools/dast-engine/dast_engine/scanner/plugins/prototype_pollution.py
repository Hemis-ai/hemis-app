"""
Prototype Pollution Scanner — detects server-side and client-side
prototype pollution via query parameters and JSON body injection.
"""
from __future__ import annotations
import json
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Query parameter payloads
QUERY_PAYLOADS = [
    "__proto__[hemisPolluted]=true",
    "constructor[prototype][hemisPolluted]=true",
    "__proto__.hemisPolluted=true",
    "__proto__[toString]=hemis_test",
]

# JSON body payloads
JSON_PAYLOADS = [
    {"__proto__": {"hemisPolluted": "true"}},
    {"constructor": {"prototype": {"hemisPolluted": "true"}}},
]


class PrototypePollutionPlugin(BasePlugin):
    name = "Prototype Pollution Scanner"
    vuln_type = "prototype_pollution"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Test via query parameters
        await self._test_query_params(target, ctx, findings)

        # Test via JSON body (only on POST endpoints)
        if target.method.upper() == "POST" or target.form_fields:
            await self._test_json_body(target, ctx, findings)

        return findings

    async def _test_query_params(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test prototype pollution via query parameters."""
        # Get baseline response
        baseline = await self._send_request(
            ctx, target.url, headers=target.headers, cookies=target.cookies
        )
        if baseline is None:
            return

        baseline_body = baseline.text
        baseline_status = baseline.status_code
        baseline_headers = dict(baseline.headers)

        for payload in QUERY_PAYLOADS:
            # Append payload to URL
            separator = "&" if "?" in target.url else "?"
            test_url = f"{target.url}{separator}{payload}"

            resp = await self._send_request(
                ctx, test_url, headers=target.headers, cookies=target.cookies
            )
            if resp is None:
                continue

            polluted = False
            evidence = ""

            # Check 1: Pollution marker appears in response
            if "hemisPolluted" in resp.text and "hemisPolluted" not in baseline_body:
                polluted = True
                evidence = "Pollution marker 'hemisPolluted' appeared in response body"

            # Check 2: Response structure changed (new keys in JSON)
            if self.is_json_response(resp) and self.is_json_response(baseline):
                try:
                    base_json = json.loads(baseline_body)
                    resp_json = json.loads(resp.text)
                    if isinstance(base_json, dict) and isinstance(resp_json, dict):
                        new_keys = set(resp_json.keys()) - set(base_json.keys())
                        if "hemisPolluted" in new_keys:
                            polluted = True
                            evidence = f"New key 'hemisPolluted' appeared in JSON response: {new_keys}"
                except (json.JSONDecodeError, TypeError):
                    pass

            # Check 3: Status code changed from success to error
            if baseline_status < 400 and resp.status_code >= 500:
                polluted = True
                evidence = f"Server error triggered (status changed from {baseline_status} to {resp.status_code})"

            if polluted:
                findings.append(RawFinding(
                    vuln_type="prototype_pollution",
                    title=f"Server-Side Prototype Pollution via Query Parameter",
                    description=(
                        f"The URL {target.url} is vulnerable to server-side prototype pollution. "
                        f"Injecting '{payload}' caused observable changes in the response. "
                        f"Evidence: {evidence}. "
                        "This can lead to property injection, authentication bypass, "
                        "or remote code execution depending on the application."
                    ),
                    affected_url=target.url,
                    affected_parameter="query string",
                    severity="HIGH",
                    payload=payload,
                    request_evidence=f"GET {test_url}",
                    response_evidence=resp.text[:300],
                    remediation=(
                        "Sanitize user input before merging into objects. "
                        "Use Object.create(null) for lookup maps. "
                        "Block __proto__ and constructor.prototype in input validation. "
                        "Use --frozen-intrinsics in Node.js."
                    ),
                    confidence=80 if "hemisPolluted" in resp.text else 60,
                    verified=True if "hemisPolluted" in resp.text else False,
                    business_impact=(
                        "Prototype pollution can escalate to RCE in Node.js applications "
                        "via gadgets like child_process.exec. It can also bypass "
                        "authentication, authorization, and input validation."
                    ),
                ))
                return  # One finding is sufficient

    async def _test_json_body(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test prototype pollution via JSON body."""
        for payload_obj in JSON_PAYLOADS:
            payload_str = json.dumps(payload_obj)

            resp = await self._send_request(
                ctx, target.url, method="POST",
                data=payload_str,
                headers={**target.headers, "Content-Type": "application/json"},
                cookies=target.cookies,
            )
            if resp is None:
                continue

            if "hemisPolluted" in resp.text:
                findings.append(RawFinding(
                    vuln_type="prototype_pollution",
                    title="Server-Side Prototype Pollution via JSON Body",
                    description=(
                        f"The endpoint {target.url} is vulnerable to prototype pollution "
                        f"via JSON body. Sending {payload_str} caused the pollution marker "
                        "to appear in the response."
                    ),
                    affected_url=target.url,
                    affected_parameter="JSON body",
                    severity="HIGH",
                    payload=payload_str,
                    request_evidence=f"POST {target.url}\n{payload_str}",
                    response_evidence=resp.text[:300],
                    remediation=(
                        "Sanitize JSON input before deep-merging. "
                        "Block __proto__ and constructor keys in all input."
                    ),
                    confidence=85,
                    verified=True,
                ))
                return

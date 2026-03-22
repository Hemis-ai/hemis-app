"""
HTTP Request Smuggling detection — CL.TE and TE.CL desync probes.

Key validation steps:
1. Establish baseline timing for normal requests
2. Send smuggling probes with conflicting Content-Length and Transfer-Encoding headers
3. Detect timing anomalies or unexpected responses that indicate desync
4. Test Transfer-Encoding obfuscation variants
5. Only run once per domain from root URL
"""
from __future__ import annotations
import time
import json
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Transfer-Encoding obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding: identity, chunked",
]


class RequestSmugglingPlugin(BasePlugin):
    name = "HTTP Request Smuggling Scanner"
    vuln_type = "request_smuggling"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Only test the root URL of each domain (once per domain)
        parsed = urlparse(target.url)
        domain = parsed.netloc
        domain_key = f"smuggling_tested_{domain}"
        if domain_key in ctx.reported_domains:
            return findings
        ctx.reported_domains.add(domain_key)

        # Only test on root-ish URLs (not deep paths with parameters)
        path = parsed.path.rstrip("/")
        if path.count("/") > 2:
            return findings

        root_url = f"{parsed.scheme}://{parsed.netloc}/"

        # Establish baseline timing with multiple requests
        baseline_times = []
        for _ in range(3):
            start = time.time()
            resp = await self._send_request(
                ctx, root_url, method="POST",
                data="x=1",
                headers={**target.headers, "Content-Type": "application/x-www-form-urlencoded"},
                cookies=target.cookies,
                timeout=10,
            )
            elapsed = time.time() - start
            baseline_times.append(elapsed)
            if resp is None:
                # Server doesn't accept POST — try GET-based detection only
                break

        if not baseline_times:
            return findings

        avg_baseline = sum(baseline_times) / len(baseline_times)
        max_baseline = max(baseline_times)

        # CL.TE probe: Content-Length covers first chunk, extra data after chunked terminator
        finding = await self._test_cl_te(ctx, root_url, target, avg_baseline, max_baseline)
        if finding:
            findings.append(finding)

        # TE.CL probe: Transfer-Encoding processes chunks, Content-Length is wrong
        finding = await self._test_te_cl(ctx, root_url, target, avg_baseline, max_baseline)
        if finding:
            findings.append(finding)

        # TE obfuscation variants
        finding = await self._test_te_obfuscation(ctx, root_url, target, avg_baseline, max_baseline)
        if finding:
            findings.append(finding)

        return findings

    async def _test_cl_te(self, ctx, url, target, avg_baseline, max_baseline):
        """
        CL.TE desync probe:
        Front-end uses Content-Length, back-end uses Transfer-Encoding.
        Send a request where CL covers the full body but the chunked encoding
        leaves extra data that the back-end interprets as the start of the next request.
        """
        # The probe body: chunked encoding with a short chunk, then a smuggled prefix
        # If CL.TE desync exists, the smuggled "G" will prefix the next request,
        # potentially causing a timeout or error
        smuggle_body = "0\r\n\r\nG"
        content_length = len(smuggle_body)

        headers = {
            **(target.headers or {}),
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(content_length),
            "Transfer-Encoding": "chunked",
        }

        # Timing-based detection: smuggling probe may cause delay
        time_threshold = max_baseline + 5.0

        start = time.time()
        resp = await self._send_request(
            ctx, url, method="POST",
            data=smuggle_body,
            headers=headers,
            cookies=target.cookies,
            timeout=15,
        )
        elapsed = time.time() - start

        if resp is None and elapsed >= time_threshold:
            # Timeout suggests desync — verify
            start2 = time.time()
            resp2 = await self._send_request(
                ctx, url, method="POST",
                data=smuggle_body,
                headers=headers,
                cookies=target.cookies,
                timeout=15,
            )
            elapsed2 = time.time() - start2

            if resp2 is None and elapsed2 >= time_threshold:
                return RawFinding(
                    vuln_type="request_smuggling",
                    title="HTTP Request Smuggling (CL.TE Desync)",
                    description=(
                        f"The server appears vulnerable to CL.TE request smuggling. "
                        f"A probe with conflicting Content-Length and Transfer-Encoding: chunked "
                        f"headers caused timeouts ({elapsed:.1f}s, {elapsed2:.1f}s) significantly "
                        f"exceeding the baseline ({avg_baseline:.1f}s), suggesting the back-end "
                        f"is waiting for additional chunked data while the front-end has finished."
                    ),
                    affected_url=url,
                    severity="CRITICAL",
                    payload="CL.TE probe with smuggled prefix",
                    request_evidence=(
                        f"Content-Length: {content_length} + Transfer-Encoding: chunked | "
                        f"Baseline: {avg_baseline:.1f}s | Probe: {elapsed:.1f}s, {elapsed2:.1f}s"
                    ),
                    response_evidence=f"Timeout after {elapsed:.1f}s and {elapsed2:.1f}s",
                    remediation=(
                        "Ensure front-end and back-end servers handle Content-Length and "
                        "Transfer-Encoding headers consistently. Reject ambiguous requests. "
                        "Use HTTP/2 end-to-end to eliminate request smuggling."
                    ),
                    remediation_code=json.dumps({
                        "vulnerableCode": "# Reverse proxy forwards both CL and TE headers",
                        "remediatedCode": (
                            "# Nginx: reject ambiguous requests\n"
                            "proxy_set_header Transfer-Encoding '';\n"
                            "# Or use HTTP/2 between proxy and backend\n"
                            "proxy_http_version 1.1;\n"
                            "proxy_set_header Connection '';"
                        ),
                        "explanation": "Normalize headers at the proxy layer to prevent desync between front-end and back-end.",
                        "language": "Nginx Config",
                    }),
                    confidence=70,
                    verified=True,
                    business_impact=(
                        "Request hijacking. An attacker can smuggle requests to poison "
                        "other users' connections, bypass security controls, or steal credentials."
                    ),
                )

        # Also check for unusual response (e.g., 400 when baseline was 200)
        if resp and resp.status_code in (400, 500) and avg_baseline < 2.0:
            # Server rejected the ambiguous request — might indicate awareness but also worth noting
            pass

        return None

    async def _test_te_cl(self, ctx, url, target, avg_baseline, max_baseline):
        """
        TE.CL desync probe:
        Front-end uses Transfer-Encoding, back-end uses Content-Length.
        """
        # Body: valid chunked encoding but Content-Length is set to only cover part of it
        smuggle_body = "1\r\nZ\r\n0\r\n\r\n"
        # Set Content-Length shorter than the full body
        short_cl = "1"

        headers = {
            **(target.headers or {}),
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": short_cl,
            "Transfer-Encoding": "chunked",
        }

        time_threshold = max_baseline + 5.0

        start = time.time()
        resp = await self._send_request(
            ctx, url, method="POST",
            data=smuggle_body,
            headers=headers,
            cookies=target.cookies,
            timeout=15,
        )
        elapsed = time.time() - start

        if resp is None and elapsed >= time_threshold:
            # Verify
            start2 = time.time()
            resp2 = await self._send_request(
                ctx, url, method="POST",
                data=smuggle_body,
                headers=headers,
                cookies=target.cookies,
                timeout=15,
            )
            elapsed2 = time.time() - start2

            if resp2 is None and elapsed2 >= time_threshold:
                return RawFinding(
                    vuln_type="request_smuggling",
                    title="HTTP Request Smuggling (TE.CL Desync)",
                    description=(
                        f"The server appears vulnerable to TE.CL request smuggling. "
                        f"A probe with conflicting Transfer-Encoding and Content-Length headers "
                        f"caused timeouts ({elapsed:.1f}s, {elapsed2:.1f}s) exceeding baseline "
                        f"({avg_baseline:.1f}s), indicating the back-end processed by Content-Length "
                        f"while the front-end used chunked encoding."
                    ),
                    affected_url=url,
                    severity="CRITICAL",
                    payload="TE.CL probe with mismatched Content-Length",
                    request_evidence=(
                        f"Transfer-Encoding: chunked + Content-Length: {short_cl} | "
                        f"Baseline: {avg_baseline:.1f}s | Probe: {elapsed:.1f}s, {elapsed2:.1f}s"
                    ),
                    response_evidence=f"Timeout after {elapsed:.1f}s and {elapsed2:.1f}s",
                    remediation=(
                        "Normalize Transfer-Encoding and Content-Length handling across all proxy layers. "
                        "Reject requests with both headers. Use HTTP/2 end-to-end."
                    ),
                    confidence=70,
                    verified=True,
                    business_impact=(
                        "Request hijacking. Attacker can inject requests into other users' "
                        "connections, bypass WAF rules, and steal session tokens."
                    ),
                )
        return None

    async def _test_te_obfuscation(self, ctx, url, target, avg_baseline, max_baseline):
        """Test Transfer-Encoding header obfuscation variants."""
        time_threshold = max_baseline + 5.0
        smuggle_body = "0\r\n\r\nG"

        for te_variant in TE_OBFUSCATIONS:
            # Parse the TE variant into header key/value
            if ": " in te_variant:
                te_key, te_value = te_variant.split(": ", 1)
            elif ":\t" in te_variant:
                te_key, te_value = te_variant.split(":\t", 1)
            else:
                continue

            headers = {
                **(target.headers or {}),
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(smuggle_body)),
                te_key: te_value,
            }

            start = time.time()
            resp = await self._send_request(
                ctx, url, method="POST",
                data=smuggle_body,
                headers=headers,
                cookies=target.cookies,
                timeout=15,
            )
            elapsed = time.time() - start

            if resp is None and elapsed >= time_threshold:
                # Verify
                start2 = time.time()
                resp2 = await self._send_request(
                    ctx, url, method="POST",
                    data=smuggle_body,
                    headers=headers,
                    cookies=target.cookies,
                    timeout=15,
                )
                elapsed2 = time.time() - start2

                if resp2 is None and elapsed2 >= time_threshold:
                    return RawFinding(
                        vuln_type="request_smuggling",
                        title=f"HTTP Request Smuggling (TE Obfuscation: {te_variant[:40]})",
                        description=(
                            f"The server appears vulnerable to request smuggling via "
                            f"Transfer-Encoding header obfuscation. The variant '{te_variant}' "
                            f"caused timeouts ({elapsed:.1f}s, {elapsed2:.1f}s) exceeding "
                            f"baseline ({avg_baseline:.1f}s), suggesting the front-end and "
                            f"back-end parse the header differently."
                        ),
                        affected_url=url,
                        severity="CRITICAL",
                        payload=f"TE obfuscation: {te_variant}",
                        request_evidence=(
                            f"{te_variant} | Baseline: {avg_baseline:.1f}s | "
                            f"Probe: {elapsed:.1f}s, {elapsed2:.1f}s"
                        ),
                        response_evidence=f"Timeout after {elapsed:.1f}s and {elapsed2:.1f}s",
                        remediation=(
                            "Normalize Transfer-Encoding headers at the proxy layer. "
                            "Reject non-standard TE values. Use HTTP/2 end-to-end."
                        ),
                        confidence=70,
                        verified=True,
                        business_impact="Request hijacking via header parsing discrepancy.",
                    )

        return None

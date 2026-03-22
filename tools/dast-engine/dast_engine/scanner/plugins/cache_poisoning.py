"""
Web Cache Poisoning & Cache Deception Scanner — detects unkeyed header
injection and cache deception via path confusion.
"""
from __future__ import annotations
import hashlib
import time
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Headers that are commonly unkeyed by caches
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil-cache-poison.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Host", "evil-cache-poison.com"),
    ("X-Forwarded-Server", "evil-cache-poison.com"),
]

# Extensions for cache deception
STATIC_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg"]

# Cache indicator headers
CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "x-varnish", "age",
    "x-cache-hits", "x-fastly-request-id", "x-proxy-cache",
    "surrogate-control", "cdn-cache-control",
]


class CachePoisoningPlugin(BasePlugin):
    name = "Web Cache Poisoning Scanner"
    vuln_type = "cache_poisoning"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Detect if caching is present
        has_cache = self._detect_caching(target)
        if not has_cache:
            return findings

        # Test 1: Unkeyed header injection (cache poisoning)
        await self._test_unkeyed_headers(target, ctx, findings)

        # Test 2: Cache deception via path confusion
        await self._test_cache_deception(target, ctx, findings)

        return findings

    def _detect_caching(self, target: ScanTarget) -> bool:
        """Check if the response indicates caching is active."""
        headers = {k.lower(): v for k, v in target.response_headers.items()}

        for ch in CACHE_HEADERS:
            if ch in headers:
                return True

        # Check Cache-Control for public or max-age
        cc = headers.get("cache-control", "")
        if "public" in cc or "max-age" in cc or "s-maxage" in cc:
            return True

        return False

    async def _test_unkeyed_headers(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test for cache poisoning via unkeyed headers."""
        # First, get a baseline response
        baseline = await self._send_request(
            ctx, target.url, headers=target.headers, cookies=target.cookies
        )
        if baseline is None:
            return

        baseline_body = baseline.text

        for header_name, header_value in UNKEYED_HEADERS:
            # Send request with potentially unkeyed header
            poisoned_headers = {**target.headers, header_name: header_value}
            resp = await self._send_request(
                ctx, target.url, headers=poisoned_headers, cookies=target.cookies
            )
            if resp is None:
                continue

            # Check if the injected value appears in the response
            if header_value in resp.text and header_value not in baseline_body:
                # Verify: send a clean request to see if poison stuck in cache
                time.sleep(0.5)  # Brief pause for cache propagation
                verify = await self._send_request(
                    ctx, target.url, headers=target.headers, cookies=target.cookies
                )
                if verify and header_value in verify.text:
                    findings.append(RawFinding(
                        vuln_type="cache_poisoning",
                        title=f"Web Cache Poisoning via {header_name}",
                        description=(
                            f"The response from {target.url} can be poisoned via the "
                            f"unkeyed header '{header_name}'. The injected value "
                            f"'{header_value}' was reflected in the cached response, "
                            "meaning all users will receive the poisoned content."
                        ),
                        affected_url=target.url,
                        affected_parameter=header_name,
                        severity="HIGH",
                        payload=f"{header_name}: {header_value}",
                        request_evidence=f"GET {target.url}\n{header_name}: {header_value}",
                        response_evidence=verify.text[:300],
                        remediation=(
                            "Include the header in the cache key, or strip it at the "
                            "edge/CDN before it reaches the application. "
                            "Configure the CDN to only vary on expected headers."
                        ),
                        confidence=90,
                        verified=True,
                        business_impact=(
                            "Cache poisoning allows attackers to serve malicious content "
                            "to all users of the site. This can be used for XSS, phishing, "
                            "or defacement at scale."
                        ),
                    ))
                    return  # One confirmed finding is enough

                # Not verified in cache, but reflected — still report as potential
                findings.append(RawFinding(
                    vuln_type="cache_poisoning",
                    title=f"Potential Cache Poisoning via {header_name} (Unverified)",
                    description=(
                        f"The header '{header_name}: {header_value}' is reflected in the "
                        f"response from {target.url} but was not confirmed in the cache. "
                        "If this header is unkeyed by the cache, poisoning may be possible."
                    ),
                    affected_url=target.url,
                    affected_parameter=header_name,
                    severity="MEDIUM",
                    payload=f"{header_name}: {header_value}",
                    response_evidence=resp.text[:200],
                    remediation="Investigate if the header is part of the cache key. Strip unneeded headers at the CDN.",
                    confidence=60,
                ))

    async def _test_cache_deception(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test for web cache deception by appending static extensions."""
        # Only test pages that appear to be dynamic (not already static files)
        parsed = urlparse(target.url)
        if any(parsed.path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return

        for ext in [".css", ".js", ".png"]:
            deception_url = target.url.rstrip("/") + f"/hemis-test{ext}"
            resp = await self._send_request(
                ctx, deception_url, headers=target.headers, cookies=target.cookies
            )
            if resp is None:
                continue

            # Check if the dynamic content is returned (same as original page)
            if resp.status_code == 200 and len(resp.text) > 100:
                # Check if the response has cache headers indicating it would be cached
                cache_status = ""
                for ch in CACHE_HEADERS:
                    val = resp.headers.get(ch)
                    if val:
                        cache_status += f"{ch}: {val}, "

                cc = resp.headers.get("cache-control", "")
                is_cacheable = (
                    "public" in cc or "max-age" in cc or "s-maxage" in cc
                ) and "no-store" not in cc and "private" not in cc

                if is_cacheable or cache_status:
                    # Verify content similarity
                    baseline = await self._send_request(
                        ctx, target.url, headers=target.headers, cookies=target.cookies
                    )
                    if baseline:
                        baseline_sig = hashlib.md5(baseline.text[:5000].encode()).hexdigest()
                        deception_sig = hashlib.md5(resp.text[:5000].encode()).hexdigest()

                        if baseline_sig == deception_sig:
                            findings.append(RawFinding(
                                vuln_type="cache_deception",
                                title=f"Web Cache Deception at {target.url}",
                                description=(
                                    f"Appending '{ext}' to {target.url} returns the same "
                                    "dynamic content, and the response appears cacheable. "
                                    "An attacker could trick a victim into visiting "
                                    f"{deception_url} — the CDN would cache the victim's "
                                    "personalized page and serve it to the attacker."
                                ),
                                affected_url=target.url,
                                severity="HIGH",
                                payload=deception_url,
                                request_evidence=f"GET {deception_url}",
                                response_evidence=f"Status: {resp.status_code}, Cache: {cache_status or cc}",
                                remediation=(
                                    "Configure the origin to return 404 for path extensions "
                                    "that don't match real resources. Set 'Cache-Control: "
                                    "no-store' on all dynamic/personalized pages."
                                ),
                                confidence=75,
                                business_impact=(
                                    "Cache deception allows attackers to steal user-specific "
                                    "content: account details, tokens, PII, and more."
                                ),
                            ))
                            return

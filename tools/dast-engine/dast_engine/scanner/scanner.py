"""
Main scanner orchestrator — runs all plugins against discovered endpoints.

Each Scanner instance creates its own ScanContext with:
  - Per-scan HTTP client (no shared global pool)
  - Per-scan domain dedup sets (no module-level globals)
  - Automatic cleanup in try/finally

This ensures 100% isolation between concurrent scan jobs.
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
from typing import Optional, Callable
from .base_plugin import BasePlugin, ScanTarget, RawFinding
from .scan_context import ScanContext
from .plugins.sqli import SQLiPlugin
from .plugins.xss import XSSPlugin
from .plugins.cmdi import CommandInjectionPlugin
from .plugins.path_traversal import PathTraversalPlugin
from .plugins.ssrf import SSRFPlugin
from .plugins.open_redirect import OpenRedirectPlugin
from .plugins.header_analysis import HeaderAnalysisPlugin
from .plugins.cookie_analysis import CookieAnalysisPlugin
from .plugins.cors import CORSPlugin
from .plugins.info_disclosure import InfoDisclosurePlugin
from .plugins.tls_check import TLSCheckPlugin
from .plugins.cache_analysis import CacheAnalysisPlugin
from .plugins.backup_discovery import BackupDiscoveryPlugin
from .plugins.method_tampering import MethodTamperingPlugin
from .plugins.host_header import HostHeaderPlugin
from .plugins.ssti import SSTIPlugin
from .plugins.nosql import NoSQLPlugin
from .plugins.jwt_check import JWTCheckPlugin
from .plugins.idor import IDORPlugin
from .plugins.request_smuggling import RequestSmugglingPlugin
from ..crawler.crawler import CrawlResult, FormTarget
from ..config import settings

logger = logging.getLogger(__name__)


def get_plugins(profile: str = "full") -> list[BasePlugin]:
    """Get plugins based on scan profile."""
    passive = [
        HeaderAnalysisPlugin(),
        CookieAnalysisPlugin(),
        CORSPlugin(),
        InfoDisclosurePlugin(),
        TLSCheckPlugin(),
        CacheAnalysisPlugin(),
        BackupDiscoveryPlugin(),
        JWTCheckPlugin(),
    ]
    active = [
        SQLiPlugin(),
        XSSPlugin(),
        CommandInjectionPlugin(),
        PathTraversalPlugin(),
        SSRFPlugin(),
        OpenRedirectPlugin(),
        MethodTamperingPlugin(),
        HostHeaderPlugin(),
        SSTIPlugin(),
        NoSQLPlugin(),
        IDORPlugin(),
        RequestSmugglingPlugin(),
    ]
    if profile == "quick":
        return passive + [SQLiPlugin(), XSSPlugin()]
    elif profile == "api_only":
        return [SQLiPlugin(), CommandInjectionPlugin(), SSRFPlugin(), HeaderAnalysisPlugin(), CORSPlugin()]
    elif profile == "deep":
        return passive + active
    else:
        return passive + active


class Scanner:
    def __init__(
        self,
        scan_id: str,
        target_url: str,
        crawl_result: CrawlResult,
        profile: str = "full",
        auth_headers: Optional[dict[str, str]] = None,
        auth_cookies: Optional[dict[str, str]] = None,
        on_progress: Optional[Callable[[int, int, int, str], None]] = None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.crawl_result = crawl_result
        self.plugins = get_plugins(profile)
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.on_progress = on_progress
        self.total_payloads = 0
        # Per-scan context — holds all mutable state for THIS scan only
        self.ctx = ScanContext(scan_id=scan_id, target_url=target_url)

        # Populate tech stack from crawler results
        if crawl_result.tech_stack:
            self.ctx.tech_stack = list(crawl_result.tech_stack)

        # Detect server type from response headers (use first available page)
        for _url, hdrs in crawl_result.response_headers.items():
            server_header = hdrs.get("server", hdrs.get("Server", ""))
            if server_header:
                self.ctx.server_type = server_header.lower().split("/")[0].strip()
                break

    async def scan(self) -> list[RawFinding]:
        """Run all plugins against all discovered endpoints."""
        findings: list[RawFinding] = []

        try:
            targets = self._build_targets()

            # Fetch response bodies for passive analysis targets
            await self._populate_response_bodies(targets)

            total = len(targets)
            tested = 0

            passive_plugins = [p for p in self.plugins if isinstance(p, (HeaderAnalysisPlugin, CookieAnalysisPlugin, CORSPlugin, InfoDisclosurePlugin, TLSCheckPlugin, CacheAnalysisPlugin, BackupDiscoveryPlugin, JWTCheckPlugin))]
            active_plugins = [p for p in self.plugins if p not in passive_plugins]

            # ── Static site detection ──
            is_static = self._detect_static_site(targets)
            if is_static:
                logger.warning(
                    "Target %s appears to be a static site — skipping active "
                    "injection plugins, running passive plugins only.",
                    self.target_url,
                )

            # ── Passive scan (no injection, uses stored response data) ──
            for target in targets:
                for plugin in passive_plugins:
                    try:
                        results = await plugin.scan(target, self.ctx)
                        findings.extend(results)
                        self.total_payloads += plugin.payloads_sent
                    except Exception:
                        pass

            # ── Active scan (injection-based, controlled concurrency) ──
            if not is_static:
                # Filter out targets marked as skip_active
                active_targets = [
                    t for t in targets
                    if not t.skip_active
                    and t.response_status not in (404, 405)
                    and t.response_status < 500
                ]
                skipped = len(targets) - len(active_targets)
                if skipped:
                    logger.info(
                        "Skipping active testing on %d/%d endpoints "
                        "(non-functional or non-injectable)",
                        skipped, len(targets),
                    )

                semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
                total_active = len(active_targets)

                async def scan_target(target: ScanTarget, idx: int):
                    nonlocal tested
                    target_findings = []
                    for plugin in active_plugins:
                        try:
                            async with semaphore:
                                results = await plugin.scan(target, self.ctx)
                                target_findings.extend(results)
                                self.total_payloads += plugin.payloads_sent
                        except Exception:
                            pass
                    tested += 1
                    if self.on_progress:
                        self.on_progress(tested, total, self.total_payloads, f"Testing endpoint {tested}/{total}")
                    return target_findings

                batch_size = settings.max_concurrent_requests
                for i in range(0, len(active_targets), batch_size):
                    batch = active_targets[i:i + batch_size]
                    tasks = [scan_target(t, i + j) for j, t in enumerate(batch)]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for result in batch_results:
                        if isinstance(result, list):
                            findings.extend(result)

        finally:
            # Clean up per-scan HTTP client — only affects THIS scan
            await self.ctx.close()

        # ── Deduplicate findings ──
        seen = set()
        unique_findings = []
        for f in findings:
            key = f"{f.vuln_type}|{f.affected_url}|{f.affected_parameter or ''}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    async def _populate_response_bodies(self, targets: list[ScanTarget]):
        """Fetch response bodies for targets that need passive analysis.
        This gives passive plugins (header analysis, DOM XSS) real response data.
        Also validates endpoints and marks non-functional ones as skip_active."""
        client = await self.ctx.get_client()

        # First pass: fetch a known-bad URL to fingerprint the site's custom 404
        try:
            notfound_resp = await client.get(
                self.target_url.rstrip("/") + "/hemisx-dast-nonexistent-page-404-check",
                headers={"User-Agent": settings.user_agent, **self.auth_headers},
                cookies={**self.crawl_result.cookies, **self.auth_cookies},
                timeout=settings.request_timeout,
                follow_redirects=True,
            )
            sig = self._body_signature(notfound_resp.text)
            self.ctx.custom_404_signatures.add(sig)
        except Exception:
            pass

        for target in targets:
            if target.response_body:
                continue  # Already populated
            try:
                resp = await client.get(
                    target.url,
                    headers={"User-Agent": settings.user_agent, **self.auth_headers},
                    cookies={**self.crawl_result.cookies, **self.auth_cookies},
                    timeout=settings.request_timeout,
                    follow_redirects=True,
                )
                target.response_body = resp.text[:500000]  # Cap at 500KB
                target.content_type = resp.headers.get("content-type", "").lower()
                target.response_status = resp.status_code
                # Update response headers if not already set
                if not target.response_headers:
                    target.response_headers = dict(resp.headers)

                # --- Endpoint validation: mark non-functional endpoints ---
                # Skip active testing for error status codes
                if target.response_status in (404, 405) or target.response_status >= 500:
                    target.skip_active = True
                    logger.debug(
                        "Skipping active scan for %s (status %d)",
                        target.url, target.response_status,
                    )
                    continue

                # Skip active testing if response matches a custom 404 page
                body_sig = self._body_signature(resp.text)
                if body_sig in self.ctx.custom_404_signatures:
                    target.skip_active = True
                    logger.debug(
                        "Skipping active scan for %s (matches custom 404 signature)",
                        target.url,
                    )
                    continue

                # Skip active injection testing for non-HTML/JSON content types
                ct = target.content_type.split(";")[0].strip()
                injectable_types = {
                    "text/html", "application/xhtml+xml",
                    "application/json", "text/json",
                    "application/x-www-form-urlencoded",
                    "",  # Allow empty content-type (unknown)
                }
                if ct and ct not in injectable_types:
                    target.skip_active = True
                    logger.debug(
                        "Skipping active scan for %s (content-type: %s)",
                        target.url, ct,
                    )

            except Exception:
                target.skip_active = True

    @staticmethod
    def _body_signature(body: str) -> str:
        """Create a normalized fingerprint of a response body for comparison.
        Strips whitespace variations to catch custom 404 pages that differ only
        in trivial formatting."""
        normalized = " ".join(body.split()).strip()
        return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()

    def _detect_static_site(self, targets: list[ScanTarget]) -> bool:
        """Detect if the target appears to be a static site.
        A site is considered static if:
          - All pages return the same body structure (identical signatures)
          - No forms accept POST submissions
          - No cookies are set by the server
        Returns True if the site appears static."""
        if not targets:
            return False

        # Check 1: Are there any forms that accept submissions?
        has_forms = any(t.form_fields for t in targets)
        if has_forms:
            return False

        # Check 2: Does the server set any cookies?
        has_cookies = bool(self.crawl_result.cookies)
        if has_cookies:
            return False

        # Check 3: Do all pages share the same body signature?
        signatures = set()
        for t in targets:
            if t.response_body:
                signatures.add(self._body_signature(t.response_body))
        # If there are very few unique signatures relative to pages, it's likely static
        populated = sum(1 for t in targets if t.response_body)
        if populated >= 3 and len(signatures) <= 1:
            return True

        return False

    def _build_targets(self) -> list[ScanTarget]:
        """Build ScanTarget objects from crawl results."""
        targets: list[ScanTarget] = []
        seen_urls = set()

        # Targets from discovered URLs with parameters (active scan candidates)
        for url, params in self.crawl_result.parameters.items():
            if url in seen_urls:
                continue
            seen_urls.add(url)
            headers_for_url = self.crawl_result.response_headers.get(url, {})
            targets.append(ScanTarget(
                url=url,
                method="GET",
                parameters=params,
                headers=self.auth_headers,
                cookies={**self.crawl_result.cookies, **self.auth_cookies},
                response_headers=headers_for_url,
            ))

        # Targets from discovered forms (active scan candidates)
        for form in self.crawl_result.forms:
            if form.action in seen_urls:
                continue
            seen_urls.add(form.action)
            headers_for_url = self.crawl_result.response_headers.get(form.url, {})
            targets.append(ScanTarget(
                url=form.action,
                method=form.method,
                form_fields=form.fields,
                headers=self.auth_headers,
                cookies={**self.crawl_result.cookies, **self.auth_cookies},
                response_headers=headers_for_url,
            ))

        # Add main pages for passive analysis (headers, cookies, info disclosure)
        # No cap — passive plugins need full URL coverage for Burp-parity findings
        for url in self.crawl_result.urls:
            if url not in seen_urls:
                headers_for_url = self.crawl_result.response_headers.get(url, {})
                targets.append(ScanTarget(
                    url=url,
                    method="GET",
                    headers=self.auth_headers,
                    cookies={**self.crawl_result.cookies, **self.auth_cookies},
                    response_headers=headers_for_url,
                ))
                seen_urls.add(url)

        return targets

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
from ..crawler.crawler import CrawlResult, FormTarget
from ..config import settings


def get_plugins(profile: str = "full") -> list[BasePlugin]:
    """Get plugins based on scan profile."""
    passive = [
        HeaderAnalysisPlugin(),
        CookieAnalysisPlugin(),
        CORSPlugin(),
        InfoDisclosurePlugin(),
    ]
    active = [
        SQLiPlugin(),
        XSSPlugin(),
        CommandInjectionPlugin(),
        PathTraversalPlugin(),
        SSRFPlugin(),
        OpenRedirectPlugin(),
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

    async def scan(self) -> list[RawFinding]:
        """Run all plugins against all discovered endpoints."""
        findings: list[RawFinding] = []

        try:
            targets = self._build_targets()

            # Fetch response bodies for passive analysis targets
            await self._populate_response_bodies(targets)

            total = len(targets)
            tested = 0

            passive_plugins = [p for p in self.plugins if isinstance(p, (HeaderAnalysisPlugin, CookieAnalysisPlugin, CORSPlugin, InfoDisclosurePlugin))]
            active_plugins = [p for p in self.plugins if p not in passive_plugins]

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
            semaphore = asyncio.Semaphore(settings.max_concurrent_requests)

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
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i + batch_size]
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
        This gives passive plugins (header analysis, DOM XSS) real response data."""
        client = await self.ctx.get_client()
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
            except Exception:
                pass

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
                if len(targets) > 200:
                    break

        return targets

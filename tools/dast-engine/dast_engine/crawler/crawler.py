"""Web crawler for discovering pages, forms, parameters, and API endpoints."""
from __future__ import annotations
import re
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional, Callable
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from ..config import settings


@dataclass
class FormTarget:
    url: str
    action: str
    method: str
    fields: list[dict]  # [{name, type, value}]


@dataclass
class CrawlResult:
    urls: list[str] = field(default_factory=list)
    forms: list[FormTarget] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)  # url -> [param names]
    tech_stack: list[str] = field(default_factory=list)
    response_headers: dict[str, dict[str, str]] = field(default_factory=dict)  # url -> headers
    cookies: dict[str, str] = field(default_factory=dict)


class Crawler:
    def __init__(
        self,
        target_url: str,
        max_depth: int = 10,
        max_pages: int = 500,
        scope_include: Optional[list[str]] = None,
        scope_exclude: Optional[list[str]] = None,
        auth_headers: Optional[dict[str, str]] = None,
        auth_cookies: Optional[dict[str, str]] = None,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.base_scheme = urlparse(target_url).scheme
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope_include = scope_include or []
        self.scope_exclude = scope_exclude or []
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.on_progress = on_progress

        self.visited: set[str] = set()
        self.result = CrawlResult()
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != self.base_domain:
            return False
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return False
        path = parsed.path
        for exc in self.scope_exclude:
            if re.search(exc.replace("*", ".*"), path):
                return False
        if self.scope_include:
            for inc in self.scope_include:
                if re.search(inc.replace("*", ".*"), path):
                    return True
            return False
        return True

    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        if url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None
        absolute = urljoin(base_url, url)
        parsed = urlparse(absolute)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    async def crawl(self) -> CrawlResult:
        """BFS crawl from target_url."""
        queue: list[tuple[str, int]] = [(self.target_url, 0)]
        self.visited.add(self.target_url)

        # Also try robots.txt and sitemap.xml
        await self._fetch_robots_sitemap()

        while queue and len(self.visited) < self.max_pages:
            # Process batch
            batch = []
            while queue and len(batch) < settings.max_concurrent_requests:
                batch.append(queue.pop(0))

            tasks = [self._fetch_page(url, depth) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception):
                    continue
                if res is None:
                    continue
                new_urls, depth = res
                for new_url in new_urls:
                    if new_url not in self.visited and len(self.visited) < self.max_pages:
                        if depth + 1 <= self.max_depth and self._in_scope(new_url):
                            self.visited.add(new_url)
                            queue.append((new_url, depth + 1))

            if self.on_progress:
                self.on_progress(len(self.visited), len(queue), f"Crawled {len(self.visited)} pages")

        self.result.urls = list(self.visited)
        return self.result

    async def _fetch_page(self, url: str, depth: int) -> Optional[tuple[list[str], int]]:
        async with self._semaphore:
            try:
                async with httpx.AsyncClient(
                    timeout=settings.request_timeout,
                    follow_redirects=True,
                    verify=False,
                    headers={
                        "User-Agent": settings.user_agent,
                        **self.auth_headers,
                    },
                    cookies=self.auth_cookies,
                ) as client:
                    resp = await client.get(url)

                    # Store response headers for passive analysis
                    self.result.response_headers[url] = dict(resp.headers)

                    # Store cookies
                    for name, value in resp.cookies.items():
                        self.result.cookies[name] = value

                    # Detect tech stack from headers
                    self._detect_tech(resp.headers, url)

                    content_type = resp.headers.get("content-type", "")
                    if "text/html" not in content_type and "application/xhtml" not in content_type:
                        return ([], depth)

                    body = resp.text
                    soup = BeautifulSoup(body, "lxml")
                    new_urls = []

                    # Extract links
                    for tag in soup.find_all("a", href=True):
                        normalized = self._normalize_url(tag["href"], url)
                        if normalized:
                            new_urls.append(normalized)

                    # Extract forms
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        method = (form.get("method", "GET")).upper()
                        abs_action = urljoin(url, action) if action else url
                        fields = []
                        for inp in form.find_all(["input", "textarea", "select"]):
                            name = inp.get("name")
                            if name:
                                fields.append({
                                    "name": name,
                                    "type": inp.get("type", "text"),
                                    "value": inp.get("value", ""),
                                })
                        if fields:
                            self.result.forms.append(FormTarget(
                                url=url,
                                action=abs_action,
                                method=method,
                                fields=fields,
                            ))

                    # Extract URL parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        params = list(parse_qs(parsed.query).keys())
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if params:
                            self.result.parameters[base] = params

                    # Extract JS endpoints (regex heuristic)
                    for script in soup.find_all("script"):
                        if script.string:
                            self._extract_js_endpoints(script.string, url, new_urls)

                    # Extract links from script src
                    for script in soup.find_all("script", src=True):
                        normalized = self._normalize_url(script["src"], url)
                        if normalized:
                            new_urls.append(normalized)

                    return (new_urls, depth)

            except Exception:
                return None

    def _extract_js_endpoints(self, js_text: str, base_url: str, new_urls: list[str]):
        """Extract API endpoints from inline JavaScript."""
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, js_text):
                endpoint = match.group(1)
                normalized = self._normalize_url(endpoint, base_url)
                if normalized and self._in_scope(normalized):
                    new_urls.append(normalized)

    def _detect_tech(self, headers: httpx.Headers, url: str):
        """Detect technology stack from response headers."""
        tech_map = {
            "x-powered-by": {
                "Express": "Express.js", "PHP": "PHP", "ASP.NET": "ASP.NET",
                "Next.js": "Next.js", "Nuxt": "Nuxt.js",
            },
            "server": {
                "nginx": "Nginx", "Apache": "Apache", "Microsoft-IIS": "IIS",
                "Cloudflare": "Cloudflare", "LiteSpeed": "LiteSpeed",
            },
        }
        for header_name, detections in tech_map.items():
            value = headers.get(header_name, "")
            for pattern, tech in detections.items():
                if pattern.lower() in value.lower() and tech not in self.result.tech_stack:
                    self.result.tech_stack.append(tech)

    async def _fetch_robots_sitemap(self):
        """Try to discover URLs from robots.txt and sitemap.xml."""
        try:
            async with httpx.AsyncClient(
                timeout=5, follow_redirects=True, verify=False,
                headers={"User-Agent": settings.user_agent},
            ) as client:
                # robots.txt
                resp = await client.get(f"{self.target_url}/robots.txt")
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and not path.startswith("*"):
                                url = urljoin(self.target_url, path)
                                if self._in_scope(url):
                                    self.visited.add(url)
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if "://" not in sitemap_url:
                                sitemap_url = "https:" + sitemap_url
                            await self._parse_sitemap(client, sitemap_url)

                # Default sitemap
                await self._parse_sitemap(client, f"{self.target_url}/sitemap.xml")
        except Exception:
            pass

    async def _parse_sitemap(self, client: httpx.AsyncClient, sitemap_url: str):
        try:
            resp = await client.get(sitemap_url)
            if resp.status_code == 200 and "<url>" in resp.text:
                soup = BeautifulSoup(resp.text, "lxml")
                for loc in soup.find_all("loc"):
                    url = loc.get_text().strip()
                    if self._in_scope(url) and len(self.visited) < self.max_pages:
                        self.visited.add(url)
        except Exception:
            pass

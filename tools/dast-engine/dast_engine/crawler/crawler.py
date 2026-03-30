"""Web crawler for discovering pages, forms, parameters, and API endpoints."""
from __future__ import annotations
import json
import re
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional, Callable
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from ..config import settings


# Common paths for hidden route fuzzing
COMMON_PATHS = [
    # Admin panels
    "/admin", "/admin/login", "/dashboard", "/wp-admin", "/administrator",
    "/manage", "/panel", "/control",
    # Config files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.yml", "/config.yaml", "/settings.json",
    # API docs
    "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/graphql", "/graphiql",
    # Version control
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/dirstate",
    # Debug/status
    "/debug", "/status", "/health", "/healthcheck", "/metrics",
    "/server-status", "/server-info",
    # Common frameworks
    "/wp-login.php", "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.well-known/security.txt", "/security.txt",
    # Backup & temp
    "/backup", "/backups", "/dump", "/export",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/humans.txt", "/.well-known/openid-configuration",
]

# Technology-specific paths to probe when a framework is detected
TECH_SPECIFIC_PATHS: dict[str, list[str]] = {
    "Next.js": ["/_next/data/", "/_next/static/", "/api/"],
    "WordPress": ["/wp-json/", "/wp-content/", "/xmlrpc.php"],
    "Express.js": ["/api/", "/.env", "/package.json"],
    "Django": ["/admin/", "/api/", "/__debug__/"],
    "Flask": ["/admin/", "/api/", "/__debug__/"],
    "Spring Boot": ["/actuator/", "/actuator/env", "/actuator/health"],
}

# OpenAPI / Swagger candidate locations
API_SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json",
]


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
    api_spec_url: Optional[str] = None
    api_spec_format: Optional[str] = None  # e.g., "openapi", "graphql"
    discovered_technologies: dict[str, list[str]] = field(default_factory=dict)  # tech category -> specific techs
    status_codes: dict[str, int] = field(default_factory=dict)  # url -> HTTP status code


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
        self._client: Optional[httpx.AsyncClient] = None

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

        # Phase 3: Hidden route fuzzing and API schema detection
        await self._fuzz_common_paths()
        await self._detect_api_schema()

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

                    # Store response headers and status code for passive analysis
                    self.result.response_headers[url] = dict(resp.headers)
                    self.result.status_codes[url] = resp.status_code

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

                    # Extract AJAX form submissions (data-action, data-url attributes)
                    for el in soup.find_all(attrs={"data-action": True}):
                        action_url = el.get("data-action", "")
                        if action_url:
                            normalized = self._normalize_url(action_url, url)
                            if normalized and self._in_scope(normalized):
                                new_urls.append(normalized)
                    for el in soup.find_all(attrs={"data-url": True}):
                        data_url = el.get("data-url", "")
                        if data_url:
                            normalized = self._normalize_url(data_url, url)
                            if normalized and self._in_scope(normalized):
                                new_urls.append(normalized)

                    # Extract button formaction attributes
                    for btn in soup.find_all("button", attrs={"formaction": True}):
                        formaction = btn.get("formaction", "")
                        if formaction:
                            normalized = self._normalize_url(formaction, url)
                            if normalized and self._in_scope(normalized):
                                new_urls.append(normalized)

                    # Extract hidden input fields that may reveal API endpoints
                    for hidden in soup.find_all("input", attrs={"type": "hidden"}):
                        val = hidden.get("value", "")
                        if val and (val.startswith("/") or val.startswith("http")):
                            normalized = self._normalize_url(val, url)
                            if normalized and self._in_scope(normalized):
                                new_urls.append(normalized)

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
            # Existing patterns
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            # Webpack chunk imports
            r'import\s*\(\s*["\']\.?(/[^"\']+)["\']',
            # React Router paths
            r'path:\s*["\'](/[^"\']+)["\']',
            r'<Route\s+[^>]*path=["\'](/[^"\']+)["\']',
            # Vue Router
            r'\{\s*path:\s*["\'](/[^"\']+)["\']',
            # Base URL concatenation: baseUrl + "/endpoint"
            r'[bB]ase[Uu]rl\s*\+\s*["\'](/[^"\']+)["\']',
            # Template literals: `${BASE}/api/endpoint`
            r'`\$\{[^}]+\}(/[^`]+)`',
            # .put and .delete HTTP methods
            r'\.put\s*\(\s*["\']([^"\']+)["\']',
            r'\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'\.patch\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, js_text):
                endpoint = match.group(1)
                normalized = self._normalize_url(endpoint, base_url)
                if normalized and self._in_scope(normalized):
                    new_urls.append(normalized)

        # Extract GraphQL operation names from gql template literals
        gql_pattern = r'gql\s*`([^`]+)`'
        for match in re.finditer(gql_pattern, js_text):
            gql_body = match.group(1)
            op_pattern = r'(?:query|mutation|subscription)\s+(\w+)'
            for op_match in re.finditer(op_pattern, gql_body):
                op_name = op_match.group(1)
                # Store GraphQL operations as parameters on the graphql endpoint
                graphql_url = urljoin(base_url, "/graphql")
                if graphql_url not in self.result.parameters:
                    self.result.parameters[graphql_url] = []
                if op_name not in self.result.parameters[graphql_url]:
                    self.result.parameters[graphql_url].append(op_name)

    def _detect_tech(self, headers: httpx.Headers, url: str):
        """Detect technology stack from response headers and populate discovered_technologies."""
        tech_map = {
            "x-powered-by": {
                "Express": ("Express.js", "backend"),
                "PHP": ("PHP", "backend"),
                "ASP.NET": ("ASP.NET", "backend"),
                "Next.js": ("Next.js", "frontend"),
                "Nuxt": ("Nuxt.js", "frontend"),
                "Django": ("Django", "backend"),
                "Flask": ("Flask", "backend"),
            },
            "server": {
                "nginx": ("Nginx", "server"),
                "Apache": ("Apache", "server"),
                "Microsoft-IIS": ("IIS", "server"),
                "Cloudflare": ("Cloudflare", "cdn"),
                "LiteSpeed": ("LiteSpeed", "server"),
            },
        }
        for header_name, detections in tech_map.items():
            value = headers.get(header_name, "")
            for pattern, (tech, category) in detections.items():
                if pattern.lower() in value.lower():
                    if tech not in self.result.tech_stack:
                        self.result.tech_stack.append(tech)
                    # Populate discovered_technologies
                    if category not in self.result.discovered_technologies:
                        self.result.discovered_technologies[category] = []
                    if tech not in self.result.discovered_technologies[category]:
                        self.result.discovered_technologies[category].append(tech)

        # Detect Spring Boot from specific headers
        if "x-application-context" in headers:
            if "Spring Boot" not in self.result.tech_stack:
                self.result.tech_stack.append("Spring Boot")
                if "backend" not in self.result.discovered_technologies:
                    self.result.discovered_technologies["backend"] = []
                if "Spring Boot" not in self.result.discovered_technologies.get("backend", []):
                    self.result.discovered_technologies["backend"].append("Spring Boot")

        # Detect WordPress from common WordPress headers/meta
        wp_indicators = ["x-pingback", "x-redirect-by"]
        for indicator in wp_indicators:
            if indicator in headers:
                if "WordPress" not in self.result.tech_stack:
                    self.result.tech_stack.append("WordPress")
                    if "cms" not in self.result.discovered_technologies:
                        self.result.discovered_technologies["cms"] = []
                    if "WordPress" not in self.result.discovered_technologies.get("cms", []):
                        self.result.discovered_technologies["cms"].append("WordPress")

    async def _fuzz_common_paths(self):
        """Probe common paths for hidden routes, config files, and admin panels."""
        # Combine COMMON_PATHS with technology-specific paths
        paths_to_probe = list(COMMON_PATHS)
        for tech in self.result.tech_stack:
            if tech in TECH_SPECIFIC_PATHS:
                for path in TECH_SPECIFIC_PATHS[tech]:
                    if path not in paths_to_probe:
                        paths_to_probe.append(path)

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
                # Process in batches to respect concurrency limits
                for i in range(0, len(paths_to_probe), settings.max_concurrent_requests):
                    if len(self.visited) >= self.max_pages:
                        break
                    batch = paths_to_probe[i:i + settings.max_concurrent_requests]
                    tasks = []
                    for path in batch:
                        full_url = f"{self.target_url}{path}"
                        if full_url not in self.visited:
                            tasks.append(self._probe_path(client, full_url))
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)

                    if self.on_progress:
                        self.on_progress(
                            len(self.visited), 0,
                            f"Fuzzing paths: {min(i + len(batch), len(paths_to_probe))}/{len(paths_to_probe)}",
                        )
        except Exception:
            pass

    async def _probe_path(self, client: httpx.AsyncClient, url: str):
        """Probe a single path and add to visited if it returns 200."""
        if len(self.visited) >= self.max_pages:
            return
        try:
            async with self._semaphore:
                resp = await client.get(url)
                self.result.status_codes[url] = resp.status_code
                if resp.status_code == 200:
                    self.visited.add(url)
                    self.result.response_headers[url] = dict(resp.headers)
                    # Store cookies from successful probes
                    for name, value in resp.cookies.items():
                        self.result.cookies[name] = value
        except Exception:
            pass

    async def _detect_api_schema(self):
        """Detect OpenAPI/Swagger schemas and extract API endpoints."""
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
                for path in API_SPEC_PATHS:
                    spec_url = f"{self.target_url}{path}"
                    try:
                        async with self._semaphore:
                            resp = await client.get(spec_url)
                            self.result.status_codes[spec_url] = resp.status_code
                            if resp.status_code != 200:
                                continue

                            content_type = resp.headers.get("content-type", "")
                            body = resp.text

                            # Try to parse as JSON (OpenAPI/Swagger)
                            spec = None
                            if "json" in content_type or body.strip().startswith("{"):
                                try:
                                    spec = json.loads(body)
                                except (json.JSONDecodeError, ValueError):
                                    continue

                            if spec and isinstance(spec, dict):
                                # Determine format
                                if "openapi" in spec:
                                    self.result.api_spec_url = spec_url
                                    self.result.api_spec_format = "openapi"
                                elif "swagger" in spec:
                                    self.result.api_spec_url = spec_url
                                    self.result.api_spec_format = "openapi"
                                else:
                                    continue

                                self.visited.add(spec_url)
                                self.result.response_headers[spec_url] = dict(resp.headers)

                                # Extract endpoints from the spec
                                self._parse_openapi_spec(spec)

                                # Found a valid spec; no need to check further
                                break
                    except Exception:
                        continue

                # Also check for GraphQL introspection
                graphql_url = f"{self.target_url}/graphql"
                try:
                    async with self._semaphore:
                        introspection_query = {
                            "query": '{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }'
                        }
                        resp = await client.post(
                            graphql_url,
                            json=introspection_query,
                            headers={"Content-Type": "application/json"},
                        )
                        self.result.status_codes[graphql_url] = resp.status_code
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                if "data" in data and "__schema" in data.get("data", {}):
                                    if not self.result.api_spec_url:
                                        self.result.api_spec_url = graphql_url
                                        self.result.api_spec_format = "graphql"
                                    self.visited.add(graphql_url)
                                    self.result.response_headers[graphql_url] = dict(resp.headers)
                                    self._parse_graphql_schema(data["data"]["__schema"])
                            except (json.JSONDecodeError, ValueError):
                                pass
                except Exception:
                    pass
        except Exception:
            pass

    def _parse_openapi_spec(self, spec: dict):
        """Extract endpoints and parameters from an OpenAPI/Swagger spec."""
        base_path = spec.get("basePath", "")
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_path = base_path + path if base_path else path
            endpoint_url = urljoin(self.target_url, full_path)

            if len(self.visited) < self.max_pages:
                self.visited.add(endpoint_url)

            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                    if not isinstance(details, dict):
                        continue
                    # Extract parameter names
                    params = details.get("parameters", [])
                    param_names = []
                    for param in params:
                        if isinstance(param, dict) and "name" in param:
                            param_names.append(param["name"])

                    # Also extract from requestBody (OpenAPI 3.x)
                    request_body = details.get("requestBody", {})
                    if isinstance(request_body, dict):
                        content = request_body.get("content", {})
                        for media_type, media_details in content.items():
                            if isinstance(media_details, dict):
                                schema = media_details.get("schema", {})
                                if isinstance(schema, dict):
                                    props = schema.get("properties", {})
                                    if isinstance(props, dict):
                                        param_names.extend(props.keys())

                    if param_names:
                        key = f"{endpoint_url}::{method.upper()}"
                        self.result.parameters[key] = param_names

    def _parse_graphql_schema(self, schema: dict):
        """Extract type and field names from a GraphQL introspection result."""
        types = schema.get("types", [])
        for gql_type in types:
            if not isinstance(gql_type, dict):
                continue
            type_name = gql_type.get("name", "")
            # Skip built-in types
            if type_name.startswith("__"):
                continue
            fields = gql_type.get("fields")
            if fields and isinstance(fields, list):
                field_names = [f.get("name", "") for f in fields if isinstance(f, dict) and f.get("name")]
                if field_names:
                    graphql_url = f"{self.target_url}/graphql"
                    key = f"{graphql_url}::{type_name}"
                    self.result.parameters[key] = field_names

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

"""
WebSocket Security Scanner — detects cross-origin hijacking,
authentication bypass, and WebSocket endpoint discovery.

Note: This plugin focuses on discovery and header-based checks since
full WebSocket protocol testing requires a WS client. It identifies
WebSocket endpoints from JavaScript source and tests the upgrade
handshake for security issues.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Patterns to find WebSocket URLs in JavaScript
WS_URL_PATTERNS = [
    re.compile(r'''(?:new\s+WebSocket|WebSocket)\s*\(\s*["'](wss?://[^"']+)["']''', re.IGNORECASE),
    re.compile(r'''["'](wss?://[^"']+)["']'''),
]

# Common WebSocket endpoint paths
WS_PATHS = [
    "/ws", "/websocket", "/socket", "/ws/", "/socket.io/",
    "/realtime", "/live", "/stream", "/events", "/push",
    "/api/ws", "/api/websocket", "/cable", "/hub",
]


class WebSocketPlugin(BasePlugin):
    name = "WebSocket Security Scanner"
    vuln_type = "websocket"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Step 1: Find WebSocket URLs in page source
        ws_urls = self._find_ws_urls(target)

        # Step 2: Probe common WS paths (only on base URL)
        if target.url == ctx.target_url or target.url == ctx.target_url.rstrip("/"):
            base = ctx.target_url.rstrip("/").replace("https://", "").replace("http://", "")
            scheme = "wss" if ctx.target_url.startswith("https") else "ws"
            for path in WS_PATHS:
                ws_urls.add(f"{scheme}://{base}{path}")

        # Step 3: Test each WebSocket URL
        tested = set()
        for ws_url in ws_urls:
            if ws_url in tested:
                continue
            tested.add(ws_url)
            await self._test_ws_endpoint(ws_url, target, ctx, findings)

        return findings

    def _find_ws_urls(self, target: ScanTarget) -> set[str]:
        """Extract WebSocket URLs from page source."""
        urls = set()
        body = target.response_body or ""

        for pattern in WS_URL_PATTERNS:
            for match in pattern.finditer(body):
                url = match.group(1) if match.lastindex else match.group()
                if url.startswith("ws://") or url.startswith("wss://"):
                    urls.add(url)

        return urls

    async def _test_ws_endpoint(
        self, ws_url: str, target: ScanTarget, ctx: ScanContext,
        findings: list[RawFinding]
    ) -> None:
        """Test a WebSocket endpoint via HTTP upgrade request."""
        # Convert ws:// to http:// for the upgrade request
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")

        # Test 1: Origin header check — can any origin connect?
        evil_origin = "https://evil-attacker.com"

        resp = await self._send_request(
            ctx, http_url,
            headers={
                **target.headers,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Origin": evil_origin,
            },
            cookies=target.cookies,
        )

        if resp is None:
            return

        # Check if the server accepted the WebSocket upgrade
        if resp.status_code == 101:
            findings.append(RawFinding(
                vuln_type="websocket_cors",
                title=f"WebSocket Cross-Origin Hijacking: {ws_url}",
                description=(
                    f"The WebSocket endpoint {ws_url} accepts upgrade requests from "
                    f"arbitrary origins (tested with: {evil_origin}). An attacker's "
                    "website can establish WebSocket connections to this endpoint, "
                    "potentially stealing data or performing actions as the victim."
                ),
                affected_url=ws_url,
                severity="HIGH",
                payload=f"Origin: {evil_origin}",
                request_evidence=f"GET {http_url}\nUpgrade: websocket\nOrigin: {evil_origin}",
                response_evidence=f"HTTP 101 Switching Protocols",
                remediation=(
                    "Validate the Origin header in WebSocket upgrade requests against "
                    "a whitelist of trusted domains. Reject connections from unknown origins."
                ),
                confidence=90,
                verified=True,
                business_impact=(
                    "Cross-origin WebSocket hijacking allows attackers to read real-time "
                    "data and send messages as the victim user."
                ),
            ))
        elif resp.status_code in (200, 400, 426):
            # Server responded but didn't upgrade — still report endpoint discovery
            findings.append(RawFinding(
                vuln_type="websocket_endpoint",
                title=f"WebSocket Endpoint Discovered: {ws_url}",
                description=(
                    f"A WebSocket endpoint was found at {ws_url}. The server responded "
                    f"with HTTP {resp.status_code} to an upgrade request."
                ),
                affected_url=ws_url,
                severity="INFO",
                response_evidence=f"HTTP {resp.status_code}",
                remediation="Ensure WebSocket endpoints require authentication and validate origins.",
                confidence=70,
            ))

        # Test 2: Authentication bypass — try without cookies
        resp_no_auth = await self._send_request(
            ctx, http_url,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Origin": ctx.target_url,
            },
            # No cookies/auth
        )

        if resp_no_auth and resp_no_auth.status_code == 101:
            findings.append(RawFinding(
                vuln_type="websocket_auth_bypass",
                title=f"WebSocket Endpoint Accepts Unauthenticated Connections: {ws_url}",
                description=(
                    f"The WebSocket endpoint {ws_url} accepts connections without "
                    "authentication cookies or tokens. Unauthenticated users can "
                    "connect and potentially access real-time data streams."
                ),
                affected_url=ws_url,
                severity="HIGH",
                request_evidence=f"GET {http_url}\nUpgrade: websocket\n(no cookies/auth)",
                response_evidence="HTTP 101 Switching Protocols",
                remediation=(
                    "Require authentication for WebSocket connections. Validate "
                    "session tokens during the upgrade handshake."
                ),
                confidence=80,
            ))

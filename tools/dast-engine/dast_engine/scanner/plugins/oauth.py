"""
OAuth 2.0 / OIDC Security Scanner — detects misconfigurations in
OAuth flows including open redirect, missing state, token leakage,
and CORS on token endpoints.
"""
from __future__ import annotations
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


class OAuthPlugin(BasePlugin):
    name = "OAuth/OIDC Security Scanner"
    vuln_type = "oauth"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Only run on the base URL to avoid repetition
        if target.url != ctx.target_url and target.url != ctx.target_url.rstrip("/"):
            return findings

        base = ctx.target_url.rstrip("/")

        # Step 1: Discover OIDC configuration
        oidc_config = await self._discover_oidc(base, ctx, findings)

        # Step 2: Test discovered endpoints
        if oidc_config:
            await self._test_authorization_endpoint(oidc_config, ctx, findings)
            await self._test_token_endpoint_cors(oidc_config, ctx, findings)

        # Step 3: Scan crawled pages for OAuth flow indicators
        await self._scan_page_for_oauth(target, ctx, findings)

        return findings

    async def _discover_oidc(
        self, base_url: str, ctx: ScanContext, findings: list[RawFinding]
    ) -> dict | None:
        """Discover OIDC configuration via well-known endpoints."""
        for path in OIDC_DISCOVERY_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = await self._send_request(ctx, url)
            if resp is None or resp.status_code != 200:
                continue

            try:
                config = json.loads(resp.text)
                if "authorization_endpoint" in config or "token_endpoint" in config:
                    # Informational finding
                    findings.append(RawFinding(
                        vuln_type="oauth_oidc_discovery",
                        title=f"OIDC Discovery Endpoint Accessible: {path}",
                        description=(
                            f"The OIDC discovery endpoint at {url} is accessible and reveals "
                            "OAuth/OIDC configuration including authorization, token, and "
                            "userinfo endpoints. This is expected behavior but reveals the "
                            "authentication architecture."
                        ),
                        affected_url=url,
                        severity="INFO",
                        response_evidence=resp.text[:500],
                        remediation="Ensure only necessary configuration is exposed. Review supported scopes and grant types.",
                        confidence=100,
                    ))
                    return config
            except (json.JSONDecodeError, TypeError):
                continue

        return None

    async def _test_authorization_endpoint(
        self, config: dict, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test the authorization endpoint for common OAuth vulnerabilities."""
        auth_endpoint = config.get("authorization_endpoint")
        if not auth_endpoint:
            return

        # Test 1: Open redirect via redirect_uri
        evil_redirect = "https://evil-attacker.com/callback"
        test_url = (
            f"{auth_endpoint}?response_type=code"
            f"&client_id=hemis_test_client"
            f"&redirect_uri={evil_redirect}"
            f"&scope=openid"
        )

        resp = await self._send_request(
            ctx, test_url, follow_redirects=False
        )
        if resp:
            location = resp.headers.get("location", "")

            # Check if it redirected to our evil URL
            if "evil-attacker.com" in location:
                findings.append(RawFinding(
                    vuln_type="oauth_open_redirect",
                    title="OAuth: Open Redirect via redirect_uri",
                    description=(
                        f"The authorization endpoint at {auth_endpoint} accepts arbitrary "
                        f"redirect_uri values. The server redirected to {evil_redirect}, "
                        "allowing attackers to steal authorization codes."
                    ),
                    affected_url=auth_endpoint,
                    affected_parameter="redirect_uri",
                    severity="HIGH",
                    payload=evil_redirect,
                    request_evidence=f"GET {test_url}",
                    response_evidence=f"Location: {location}",
                    remediation=(
                        "Validate redirect_uri against a strict whitelist of registered "
                        "callback URLs. Use exact string matching, not prefix matching."
                    ),
                    confidence=90,
                    verified=True,
                    business_impact=(
                        "Attackers can intercept authorization codes and exchange them "
                        "for access tokens, gaining unauthorized access to user accounts."
                    ),
                ))

            # Test 2: Missing state parameter
            # If the server responds without requiring state, it's vulnerable to CSRF
            if resp.status_code < 400 and "state" not in location.lower():
                # Try without state parameter and see if it proceeds
                test_url_no_state = (
                    f"{auth_endpoint}?response_type=code"
                    f"&client_id=hemis_test_client"
                    f"&redirect_uri={auth_endpoint}"
                    f"&scope=openid"
                )
                resp2 = await self._send_request(ctx, test_url_no_state, follow_redirects=False)
                if resp2 and resp2.status_code in (200, 302):
                    findings.append(RawFinding(
                        vuln_type="oauth_missing_state",
                        title="OAuth: State Parameter Not Required",
                        description=(
                            f"The authorization endpoint at {auth_endpoint} processes "
                            "authorization requests without a state parameter. This makes "
                            "the OAuth flow vulnerable to Cross-Site Request Forgery (CSRF)."
                        ),
                        affected_url=auth_endpoint,
                        affected_parameter="state",
                        severity="MEDIUM",
                        request_evidence=f"GET {test_url_no_state}",
                        remediation=(
                            "Require and validate the state parameter in all authorization "
                            "requests. Use a cryptographically random value tied to the user's session."
                        ),
                        confidence=70,
                        business_impact="CSRF on OAuth flows can force account linking or login to attacker-controlled accounts.",
                    ))

    async def _test_token_endpoint_cors(
        self, config: dict, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test if the token endpoint allows CORS from arbitrary origins."""
        token_endpoint = config.get("token_endpoint")
        if not token_endpoint:
            return

        resp = await self._send_request(
            ctx, token_endpoint,
            headers={"Origin": "https://evil-attacker.com"},
        )
        if resp is None:
            return

        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "https://evil-attacker.com" or acao == "*":
            findings.append(RawFinding(
                vuln_type="oauth_token_cors",
                title="OAuth Token Endpoint Allows Arbitrary CORS",
                description=(
                    f"The OAuth token endpoint at {token_endpoint} allows cross-origin "
                    f"requests from arbitrary origins (ACAO: {acao}). Malicious websites "
                    "can make direct token exchange requests."
                ),
                affected_url=token_endpoint,
                severity="HIGH",
                payload="Origin: https://evil-attacker.com",
                response_evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation=(
                    "Restrict CORS on the token endpoint to only registered client origins. "
                    "Most token exchanges should be server-to-server (no CORS needed)."
                ),
                confidence=90,
                verified=True,
            ))

    async def _scan_page_for_oauth(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Check if the page contains OAuth flow indicators with issues."""
        body = target.response_body
        if not body:
            return

        # Check for access tokens in URL fragments (token leakage)
        if "access_token=" in body and ("location.hash" in body or "#access_token" in body):
            findings.append(RawFinding(
                vuln_type="oauth_token_leakage",
                title="OAuth Access Token Exposed in URL Fragment",
                description=(
                    f"The page {target.url} handles access tokens via URL fragments "
                    "(implicit flow). Access tokens in URLs can leak via Referer headers, "
                    "browser history, and server logs."
                ),
                affected_url=target.url,
                severity="HIGH",
                response_evidence="Found access_token handling via URL fragments",
                remediation=(
                    "Migrate from implicit flow to authorization code flow with PKCE. "
                    "Never expose access tokens in URLs."
                ),
                confidence=75,
                business_impact="Leaked access tokens allow full account takeover.",
            ))

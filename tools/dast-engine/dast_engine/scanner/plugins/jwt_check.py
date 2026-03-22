"""
JWT Vulnerability Testing — passive + active hybrid plugin.

Checks:
1. Passively scans response headers and body for JWTs
2. Decodes JWT header to check algorithm and claims
3. Actively tests: alg:none bypass, empty signature validation
"""
from __future__ import annotations
import re
import json
import base64
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Regex to find JWTs in response bodies and headers
JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _b64_decode(segment: str) -> dict | None:
    """Decode a base64url-encoded JWT segment to a dict."""
    # Add padding if needed
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(segment)
        return json.loads(decoded)
    except Exception:
        return None


def _build_none_alg_token(original_jwt: str) -> str | None:
    """Build a JWT with alg:none and empty signature."""
    parts = original_jwt.split(".")
    if len(parts) < 2:
        return None
    # Decode header, set alg to none
    header = _b64_decode(parts[0])
    if header is None:
        return None
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    # Keep original payload, empty signature
    return f"{new_header}.{parts[1]}."


def _build_empty_sig_token(original_jwt: str) -> str | None:
    """Build a JWT with the original header/payload but empty signature."""
    parts = original_jwt.split(".")
    if len(parts) < 2:
        return None
    return f"{parts[0]}.{parts[1]}."


class JWTCheckPlugin(BasePlugin):
    name = "JWT Vulnerability Scanner"
    vuln_type = "jwt_none_alg"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Collect JWTs from various sources
        jwts = self._find_jwts(target)
        if not jwts:
            return findings

        for jwt_token, jwt_source in jwts:
            # Decode header
            parts = jwt_token.split(".")
            if len(parts) < 2:
                continue
            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            if header is None:
                continue

            alg = header.get("alg", "")

            # Check 1: alg already set to "none"
            if alg.lower() == "none":
                findings.append(self._make_finding(
                    vuln_type="jwt_none_alg",
                    title="JWT Algorithm None Accepted",
                    description=(
                        f"A JWT found in {jwt_source} uses the 'none' algorithm. "
                        "This means the token has no cryptographic signature and can be "
                        "trivially forged by any attacker."
                    ),
                    target=target, severity="HIGH",
                    payload=jwt_token[:80] + "...",
                    evidence=f"JWT header: {json.dumps(header)}",
                    confidence=95,
                ))

            # Check 2: Weak algorithm (HS256 with potentially brute-forceable secret)
            if alg in ("HS256", "HS384", "HS512"):
                findings.append(self._make_finding(
                    vuln_type="jwt_weak_alg",
                    title=f"JWT Uses Symmetric Algorithm ({alg})",
                    description=(
                        f"A JWT found in {jwt_source} uses the symmetric algorithm '{alg}'. "
                        "If the signing secret is weak or leaked, an attacker can forge tokens. "
                        "Symmetric algorithms are also vulnerable to key confusion attacks "
                        "if the server also accepts RS256."
                    ),
                    target=target, severity="MEDIUM",
                    payload=jwt_token[:80] + "...",
                    evidence=f"JWT header: {json.dumps(header)}",
                    confidence=70,
                ))

            # Check 3: Missing expiration claim
            if payload and "exp" not in payload:
                findings.append(self._make_finding(
                    vuln_type="jwt_missing_exp",
                    title="JWT Missing Expiration Claim",
                    description=(
                        f"A JWT found in {jwt_source} does not contain an 'exp' (expiration) claim. "
                        "This token never expires, meaning if stolen it can be used indefinitely."
                    ),
                    target=target, severity="LOW",
                    payload=jwt_token[:80] + "...",
                    evidence=f"JWT payload claims: {list(payload.keys()) if payload else 'N/A'}",
                    confidence=90,
                ))

            # Check 4: kid header injection potential
            kid = header.get("kid")
            if kid and ("/" in kid or ".." in kid or kid.startswith("http")):
                findings.append(self._make_finding(
                    vuln_type="jwt_none_alg",
                    title="JWT kid Header Injection Risk",
                    description=(
                        f"A JWT found in {jwt_source} has a 'kid' header value that contains "
                        f"path characters or URLs: '{kid}'. This may be vulnerable to key injection "
                        "attacks where an attacker controls the signing key location."
                    ),
                    target=target, severity="HIGH",
                    payload=jwt_token[:80] + "...",
                    evidence=f"JWT kid header: {kid}",
                    confidence=65,
                ))

            # Active test: Try alg:none bypass
            if alg.lower() != "none":
                none_token = _build_none_alg_token(jwt_token)
                if none_token:
                    finding = await self._test_none_alg(ctx, target, jwt_token, none_token, jwt_source)
                    if finding:
                        findings.append(finding)

            # Active test: Try empty signature
            empty_sig_token = _build_empty_sig_token(jwt_token)
            if empty_sig_token and empty_sig_token != jwt_token:
                finding = await self._test_empty_sig(ctx, target, jwt_token, empty_sig_token, jwt_source)
                if finding:
                    findings.append(finding)

        return findings

    def _find_jwts(self, target: ScanTarget) -> list[tuple[str, str]]:
        """Extract JWTs from response headers and body."""
        jwts = []
        seen = set()

        # Check Authorization header in response
        auth_header = target.response_headers.get("authorization", "")
        if not auth_header:
            auth_header = target.response_headers.get("Authorization", "")
        if auth_header:
            for match in JWT_PATTERN.finditer(auth_header):
                token = match.group()
                if token not in seen:
                    seen.add(token)
                    jwts.append((token, "Authorization header"))

        # Check Set-Cookie headers
        for key, value in target.response_headers.items():
            if key.lower() == "set-cookie":
                for match in JWT_PATTERN.finditer(value):
                    token = match.group()
                    if token not in seen:
                        seen.add(token)
                        jwts.append((token, "Set-Cookie header"))

        # Check response body
        if target.response_body:
            for match in JWT_PATTERN.finditer(target.response_body):
                token = match.group()
                if token not in seen:
                    seen.add(token)
                    jwts.append((token, "response body"))

        return jwts

    async def _test_none_alg(self, ctx, target, original_jwt, none_token, jwt_source):
        """Test if the server accepts a JWT with alg:none."""
        # Send request with original JWT to get baseline
        baseline = await self._send_request(
            ctx, target.url, method="GET",
            headers={**target.headers, "Authorization": f"Bearer {original_jwt}"},
            cookies=target.cookies,
        )
        if baseline is None:
            return None

        # Send request with none-alg JWT
        resp = await self._send_request(
            ctx, target.url, method="GET",
            headers={**target.headers, "Authorization": f"Bearer {none_token}"},
            cookies=target.cookies,
        )
        if resp is None:
            return None

        # If the none-alg token gets a similar successful response, it's vulnerable
        if resp.status_code == baseline.status_code and resp.status_code < 400:
            # Verify
            verify = await self._send_request(
                ctx, target.url, method="GET",
                headers={**target.headers, "Authorization": f"Bearer {none_token}"},
                cookies=target.cookies,
            )
            if verify and verify.status_code == baseline.status_code:
                return RawFinding(
                    vuln_type="jwt_none_alg",
                    title="JWT Algorithm None Bypass Confirmed",
                    description=(
                        f"The server accepts JWTs with alg:none (found via {jwt_source}). "
                        "An attacker can forge tokens without any cryptographic signature, "
                        "allowing complete authentication bypass."
                    ),
                    affected_url=target.url,
                    severity="HIGH",
                    payload=none_token[:80] + "...",
                    request_evidence=f"Authorization: Bearer {none_token[:60]}...",
                    response_evidence=f"Status: {resp.status_code} (same as valid JWT: {baseline.status_code})",
                    remediation=(
                        "Explicitly reject JWTs with alg:none. Use a JWT library that does not "
                        "support the none algorithm. Always validate the algorithm against an allowlist."
                    ),
                    remediation_code=json.dumps({
                        "vulnerableCode": "jwt.decode(token, algorithms=['HS256', 'none'])",
                        "remediatedCode": (
                            "# Explicitly specify allowed algorithms\n"
                            "jwt.decode(token, key=SECRET, algorithms=['RS256'])"
                        ),
                        "explanation": "Never include 'none' in the algorithms list. Use asymmetric algorithms (RS256) when possible.",
                        "language": "Python (PyJWT)",
                    }),
                    confidence=90,
                    verified=True,
                    business_impact="Complete authentication bypass. Any user can forge tokens for any account.",
                )
        return None

    async def _test_empty_sig(self, ctx, target, original_jwt, empty_sig_token, jwt_source):
        """Test if the server accepts a JWT with an empty signature."""
        baseline = await self._send_request(
            ctx, target.url, method="GET",
            headers={**target.headers, "Authorization": f"Bearer {original_jwt}"},
            cookies=target.cookies,
        )
        if baseline is None:
            return None

        resp = await self._send_request(
            ctx, target.url, method="GET",
            headers={**target.headers, "Authorization": f"Bearer {empty_sig_token}"},
            cookies=target.cookies,
        )
        if resp is None:
            return None

        if resp.status_code == baseline.status_code and resp.status_code < 400:
            # Verify
            verify = await self._send_request(
                ctx, target.url, method="GET",
                headers={**target.headers, "Authorization": f"Bearer {empty_sig_token}"},
                cookies=target.cookies,
            )
            if verify and verify.status_code == baseline.status_code:
                return RawFinding(
                    vuln_type="jwt_none_alg",
                    title="JWT Signature Not Validated",
                    description=(
                        f"The server accepts JWTs with an empty signature (found via {jwt_source}). "
                        "This indicates that signature validation is not enforced, allowing "
                        "token forgery."
                    ),
                    affected_url=target.url,
                    severity="HIGH",
                    payload=empty_sig_token[:80] + "...",
                    request_evidence=f"Authorization: Bearer {empty_sig_token[:60]}...",
                    response_evidence=f"Status: {resp.status_code} (same as valid JWT: {baseline.status_code})",
                    remediation=(
                        "Always verify JWT signatures. Ensure your JWT library is configured to "
                        "reject tokens with missing or invalid signatures."
                    ),
                    confidence=88,
                    verified=True,
                    business_impact="Token forgery. Attacker can modify JWT claims without detection.",
                )
        return None

    def _make_finding(
        self, vuln_type: str, title: str, description: str,
        target: ScanTarget, severity: str, payload: str,
        evidence: str, confidence: int,
    ) -> RawFinding:
        return RawFinding(
            vuln_type=vuln_type,
            title=title,
            description=description,
            affected_url=target.url,
            severity=severity,
            payload=payload,
            response_evidence=evidence,
            remediation=(
                "Use strong asymmetric algorithms (RS256, ES256). Set token expiration (exp claim). "
                "Validate all JWT claims server-side. Never accept alg:none."
            ),
            remediation_code=json.dumps({
                "vulnerableCode": "jwt.decode(token)  # No algorithm or key validation",
                "remediatedCode": (
                    "jwt.decode(\n"
                    "    token,\n"
                    "    key=PUBLIC_KEY,\n"
                    "    algorithms=['RS256'],  # Explicit allowlist\n"
                    "    options={'require': ['exp', 'iat', 'sub']}\n"
                    ")"
                ),
                "explanation": "Always specify allowed algorithms, require expiration, and validate with proper keys.",
                "language": "Python (PyJWT)",
            }),
            confidence=confidence,
            verified=False,
            business_impact="JWT vulnerabilities can lead to authentication bypass and privilege escalation.",
        )

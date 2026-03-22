"""
Mass Assignment / BOPLA Scanner — detects when APIs accept extra
privileged fields that weren't intended to be user-modifiable.
Also checks for excessive data exposure in API responses.
"""
from __future__ import annotations
import json
from urllib.parse import urljoin
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Privileged fields to inject
PRIVILEGED_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_staff": True,
    "is_superuser": True,
    "verified": True,
    "is_verified": True,
    "active": True,
    "is_active": True,
    "permissions": ["admin", "write", "delete"],
    "balance": 99999,
    "credits": 99999,
    "price": 0,
    "discount": 100,
    "group": "administrators",
}

# Sensitive fields that shouldn't appear in responses
SENSITIVE_RESPONSE_FIELDS = {
    "password", "password_hash", "passwordHash", "hashed_password",
    "secret", "secret_key", "secretKey", "api_key", "apiKey",
    "token", "access_token", "accessToken", "refresh_token", "refreshToken",
    "ssn", "social_security", "credit_card", "creditCard",
    "private_key", "privateKey",
}

# API documentation paths to discover endpoints
API_DOC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/swagger/v1/swagger.json", "/api/openapi.json",
]


class MassAssignmentPlugin(BasePlugin):
    name = "Mass Assignment / BOPLA Scanner"
    vuln_type = "mass_assignment"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Check for excessive data exposure in current response
        self._check_excessive_exposure(target, findings)

        # Only test mass assignment on API endpoints that return JSON
        ct = target.content_type.lower() if target.content_type else ""
        if "json" not in ct:
            return findings

        # Test mass assignment via PUT/PATCH with extra fields
        await self._test_mass_assignment(target, ctx, findings)

        # Discover API docs (only on base URL)
        if target.url == ctx.target_url or target.url == ctx.target_url.rstrip("/"):
            await self._discover_api_docs(ctx, findings)

        return findings

    def _check_excessive_exposure(
        self, target: ScanTarget, findings: list[RawFinding]
    ) -> None:
        """Check if API responses contain sensitive fields."""
        body = target.response_body
        if not body:
            return

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return

        exposed = self._find_sensitive_fields(data)
        if exposed:
            findings.append(RawFinding(
                vuln_type="bopla_excessive_exposure",
                title=f"Excessive Data Exposure: Sensitive Fields in API Response",
                description=(
                    f"The API endpoint {target.url} returns potentially sensitive "
                    f"fields in its response: {', '.join(exposed[:5])}. "
                    "These fields may expose internal data that should not be "
                    "visible to the requesting user."
                ),
                affected_url=target.url,
                severity="MEDIUM",
                response_evidence=f"Sensitive fields found: {', '.join(exposed[:10])}",
                remediation=(
                    "Implement response filtering to only return fields the client "
                    "actually needs. Use DTOs/serializers to control which fields "
                    "are exposed. Never return password hashes, tokens, or PII "
                    "unnecessarily."
                ),
                confidence=70,
                business_impact=(
                    "Excessive data exposure can leak credentials, tokens, PII, "
                    "or internal identifiers that enable further attacks."
                ),
            ))

    def _find_sensitive_fields(self, data, prefix: str = "") -> list[str]:
        """Recursively find sensitive field names in JSON data."""
        found = []
        if isinstance(data, dict):
            for key, val in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if key.lower() in SENSITIVE_RESPONSE_FIELDS:
                    found.append(full_key)
                if isinstance(val, (dict, list)):
                    found.extend(self._find_sensitive_fields(val, full_key))
        elif isinstance(data, list) and data:
            # Check first item
            found.extend(self._find_sensitive_fields(data[0], f"{prefix}[0]"))
        return found

    async def _test_mass_assignment(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test for mass assignment by sending extra privileged fields."""
        # Get baseline response
        baseline = await self._send_request(
            ctx, target.url, headers=target.headers, cookies=target.cookies
        )
        if baseline is None:
            return

        try:
            baseline_data = json.loads(baseline.text)
            if not isinstance(baseline_data, dict):
                return
        except (json.JSONDecodeError, TypeError):
            return

        # Build a payload with the original fields + privileged fields
        injected_payload = dict(baseline_data)
        injected_payload.update(PRIVILEGED_FIELDS)

        for method in ["PUT", "PATCH"]:
            resp = await self._send_request(
                ctx, target.url, method=method,
                data=json.dumps(injected_payload),
                headers={**target.headers, "Content-Type": "application/json"},
                cookies=target.cookies,
            )
            if resp is None:
                continue

            if resp.status_code < 400:
                try:
                    resp_data = json.loads(resp.text)
                    if not isinstance(resp_data, dict):
                        continue
                except (json.JSONDecodeError, TypeError):
                    continue

                # Check which privileged fields were accepted
                accepted = []
                for field, value in PRIVILEGED_FIELDS.items():
                    if field in resp_data:
                        if resp_data[field] == value and field not in baseline_data:
                            accepted.append(f"{field}={value}")
                        elif field in baseline_data and resp_data[field] != baseline_data.get(field):
                            accepted.append(f"{field}: {baseline_data.get(field)} → {resp_data[field]}")

                if accepted:
                    findings.append(RawFinding(
                        vuln_type="mass_assignment",
                        title=f"Mass Assignment: Privileged Fields Accepted via {method}",
                        description=(
                            f"The API endpoint {target.url} accepts privileged fields "
                            f"via {method} that should not be user-modifiable: "
                            f"{', '.join(accepted[:5])}. This allows attackers to "
                            "escalate privileges or modify protected data."
                        ),
                        affected_url=target.url,
                        affected_parameter=", ".join(f for f, _ in [a.split("=", 1) for a in accepted[:5]] if f),
                        severity="HIGH",
                        payload=json.dumps({k: v for k, v in PRIVILEGED_FIELDS.items() if any(k in a for a in accepted)})[:200],
                        request_evidence=f"{method} {target.url}",
                        response_evidence=resp.text[:300],
                        remediation=(
                            "Use allowlists for accepted fields in update operations. "
                            "Never blindly merge user input into database models. "
                            "Use DTOs/serializers that explicitly define writable fields."
                        ),
                        confidence=85,
                        verified=True,
                        business_impact=(
                            "Mass assignment can lead to privilege escalation (setting "
                            "is_admin=true), financial manipulation (setting price=0), "
                            "or data integrity violations."
                        ),
                    ))
                    return  # One finding is enough

    async def _discover_api_docs(
        self, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Discover API documentation that reveals endpoint structure."""
        base = ctx.target_url.rstrip("/")

        for path in API_DOC_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            resp = await self._send_request(ctx, url)
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    if "paths" in data or "openapi" in data or "swagger" in data:
                        endpoint_count = len(data.get("paths", {}))
                        findings.append(RawFinding(
                            vuln_type="api_documentation_exposed",
                            title=f"API Documentation Exposed: {path}",
                            description=(
                                f"OpenAPI/Swagger documentation at {url} is publicly accessible, "
                                f"revealing {endpoint_count} API endpoints, their parameters, "
                                "and data models. This aids attackers in mapping the attack surface."
                            ),
                            affected_url=url,
                            severity="MEDIUM",
                            response_evidence=f"Endpoints: {endpoint_count}, Version: {data.get('openapi', data.get('swagger', 'unknown'))}",
                            remediation=(
                                "Restrict API documentation access to authenticated users "
                                "or internal networks only."
                            ),
                            confidence=95,
                        ))
                        return
                except (json.JSONDecodeError, TypeError):
                    continue

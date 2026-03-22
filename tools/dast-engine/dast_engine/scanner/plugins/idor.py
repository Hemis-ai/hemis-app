"""
Insecure Direct Object Reference (IDOR) detection.

Key validation steps:
1. Identify numeric/UUID ID parameters in URLs
2. Send baseline request with original value
3. Increment/decrement ID and compare responses
4. If response is 200 with different content but same structure → potential IDOR
5. Verify with second request
"""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Parameter names commonly used for object references
IDOR_PARAM_NAMES = {
    "id", "userid", "user_id", "accountid", "account_id",
    "orderid", "order_id", "profileid", "profile_id",
    "doc_id", "record_id",
}

# Regex to detect numeric path segments (e.g., /users/1, /api/orders/42)
PATH_ID_PATTERN = re.compile(r'/(\w+)/(\d+)(?:/|$)')

# Test UUIDs for UUID parameter testing
TEST_UUIDS = [
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
]

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)


class IDORPlugin(BasePlugin):
    name = "IDOR Scanner"
    vuln_type = "idor"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Test query parameters
        for param in target.parameters:
            if not self._is_id_param(param):
                continue
            finding = await self._test_param_idor(ctx, target, param)
            if finding:
                findings.append(finding)

        # Test form fields
        for field in target.form_fields:
            param = field.get("name", "")
            if not param or not self._is_id_param(param):
                continue
            finding = await self._test_form_idor(ctx, target, param, field)
            if finding:
                findings.append(finding)

        # Test path-based IDs
        finding = await self._test_path_idor(ctx, target)
        if finding:
            findings.append(finding)

        return findings

    def _is_id_param(self, param: str) -> bool:
        """Check if a parameter name looks like an object ID reference."""
        return param.lower() in IDOR_PARAM_NAMES

    def _get_param_value(self, target: ScanTarget, param: str) -> str | None:
        """Extract the current value of a query parameter from the URL."""
        parsed = urlparse(target.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        values = qs.get(param)
        if values:
            return values[0]
        return None

    async def _inject_qs(self, ctx: ScanContext, target: ScanTarget, param: str, value: str):
        parsed = urlparse(target.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return await self._send_request(ctx, url, method="GET", headers=target.headers, cookies=target.cookies)

    async def _test_param_idor(self, ctx: ScanContext, target: ScanTarget, param: str):
        """Test a query parameter for IDOR by incrementing/decrementing numeric IDs."""
        original_value = self._get_param_value(target, param)
        if original_value is None:
            return None

        # Check if UUID
        if UUID_PATTERN.match(original_value):
            return await self._test_uuid_idor(ctx, target, param, original_value)

        # Check if numeric
        try:
            numeric_val = int(original_value)
        except (ValueError, TypeError):
            return None

        # Baseline request
        baseline = await self._inject_qs(ctx, target, param, original_value)
        if baseline is None or baseline.status_code >= 400:
            return None

        baseline_len = len(baseline.text)

        # Try adjacent IDs
        test_values = []
        if numeric_val > 0:
            test_values.append(str(numeric_val - 1))
        test_values.append(str(numeric_val + 1))
        if numeric_val > 1:
            test_values.append(str(numeric_val + 2))

        for test_val in test_values:
            resp = await self._inject_qs(ctx, target, param, test_val)
            if resp is None or resp.status_code >= 400:
                continue

            # Check: response is 200 and has different content
            if resp.status_code != 200:
                continue

            resp_len = len(resp.text)
            # Content should be different (different object) but similar length (same structure)
            if resp.text == baseline.text:
                continue  # Same content — not IDOR

            # Similar structure check: response length within 50% of baseline
            if baseline_len > 0:
                ratio = resp_len / baseline_len
                if ratio < 0.5 or ratio > 2.0:
                    continue  # Drastically different structure

            # Check for JSON structural similarity
            same_structure = self._check_structure_similarity(baseline.text, resp.text)
            if not same_structure:
                continue

            # Verification
            verify = await self._inject_qs(ctx, target, param, test_val)
            if verify is None or verify.status_code != 200:
                continue
            if verify.text == baseline.text:
                continue

            return RawFinding(
                vuln_type="idor",
                title=f"Insecure Direct Object Reference (Parameter: {param})",
                description=(
                    f"The parameter '{param}' appears to reference objects by sequential numeric ID. "
                    f"Changing the value from '{original_value}' to '{test_val}' returned a 200 response "
                    f"with different content but the same structure, indicating that access controls "
                    f"are not enforced and other users' data may be accessible. "
                    f"Verified with a second independent request."
                ),
                affected_url=target.url,
                severity="HIGH",
                affected_parameter=param,
                injection_point="query",
                payload=f"{param}={test_val} (original: {original_value})",
                request_evidence=f"GET {param}={test_val}",
                response_evidence=f"Original: {baseline_len}B | Modified: {resp_len}B | Status: 200",
                remediation=(
                    "Implement proper authorization checks on every object access. "
                    "Use indirect references (opaque tokens) instead of sequential IDs. "
                    "Verify that the authenticated user owns or has access to the requested resource."
                ),
                remediation_code=json.dumps({
                    "vulnerableCode": (
                        f"# No authorization check\n"
                        f"record = db.find_by_id(request.args['{param}'])\n"
                        f"return jsonify(record)"
                    ),
                    "remediatedCode": (
                        f"# Verify ownership before returning data\n"
                        f"record = db.find_by_id(request.args['{param}'])\n"
                        f"if record.owner_id != current_user.id:\n"
                        f"    abort(403)\n"
                        f"return jsonify(record)"
                    ),
                    "explanation": "Always verify that the authenticated user has permission to access the requested object.",
                    "language": "Python (Flask)",
                }),
                confidence=70,
                verified=True,
                business_impact="Unauthorized data access. An attacker can enumerate and view other users' records.",
            )

        return None

    async def _test_uuid_idor(self, ctx: ScanContext, target: ScanTarget, param: str, original_uuid: str):
        """Test UUID parameters with known test UUIDs."""
        baseline = await self._inject_qs(ctx, target, param, original_uuid)
        if baseline is None or baseline.status_code >= 400:
            return None

        for test_uuid in TEST_UUIDS:
            if test_uuid == original_uuid:
                continue

            resp = await self._inject_qs(ctx, target, param, test_uuid)
            if resp is None or resp.status_code >= 400:
                continue

            if resp.status_code == 200 and resp.text != baseline.text:
                # Verification
                verify = await self._inject_qs(ctx, target, param, test_uuid)
                if verify and verify.status_code == 200 and verify.text != baseline.text:
                    return RawFinding(
                        vuln_type="idor",
                        title=f"Insecure Direct Object Reference — UUID (Parameter: {param})",
                        description=(
                            f"The parameter '{param}' accepts arbitrary UUIDs. "
                            f"Replacing the original UUID with a test UUID returned different data, "
                            f"suggesting missing authorization checks."
                        ),
                        affected_url=target.url,
                        severity="HIGH",
                        affected_parameter=param,
                        injection_point="query",
                        payload=f"{param}={test_uuid}",
                        request_evidence=f"GET {param}={test_uuid}",
                        response_evidence=f"Status: 200 with different content",
                        remediation="Implement authorization checks. Use opaque tokens instead of predictable UUIDs.",
                        confidence=65,
                        verified=True,
                        business_impact="Unauthorized data access via UUID enumeration.",
                    )
        return None

    async def _test_path_idor(self, ctx: ScanContext, target: ScanTarget):
        """Test for path-based IDOR (e.g., /users/1 → /users/2)."""
        parsed = urlparse(target.url)
        path = parsed.path

        match = PATH_ID_PATTERN.search(path)
        if not match:
            return None

        resource = match.group(1)
        original_id = int(match.group(2))

        # Build test URLs with adjacent IDs
        test_ids = []
        if original_id > 0:
            test_ids.append(original_id - 1)
        test_ids.append(original_id + 1)

        # Baseline
        baseline = await self._send_request(
            ctx, target.url, method="GET",
            headers=target.headers, cookies=target.cookies,
        )
        if baseline is None or baseline.status_code >= 400:
            return None

        for test_id in test_ids:
            new_path = path[:match.start(2)] + str(test_id) + path[match.end(2):]
            test_url = urlunparse(parsed._replace(path=new_path))

            resp = await self._send_request(
                ctx, test_url, method="GET",
                headers=target.headers, cookies=target.cookies,
            )
            if resp is None or resp.status_code >= 400:
                continue

            if resp.status_code == 200 and resp.text != baseline.text:
                same_structure = self._check_structure_similarity(baseline.text, resp.text)
                if not same_structure:
                    continue

                # Verification
                verify = await self._send_request(
                    ctx, test_url, method="GET",
                    headers=target.headers, cookies=target.cookies,
                )
                if verify and verify.status_code == 200 and verify.text != baseline.text:
                    return RawFinding(
                        vuln_type="idor",
                        title=f"Insecure Direct Object Reference — Path (/{resource}/{original_id})",
                        description=(
                            f"The URL path contains a sequential ID for '{resource}'. "
                            f"Changing /{resource}/{original_id} to /{resource}/{test_id} "
                            f"returned a 200 response with different content, indicating "
                            f"that authorization is not enforced on this endpoint."
                        ),
                        affected_url=target.url,
                        severity="HIGH",
                        affected_parameter=f"path:/{resource}/{{id}}",
                        injection_point="path",
                        payload=test_url,
                        request_evidence=f"GET {new_path}",
                        response_evidence=f"Original: {len(baseline.text)}B | Modified: {len(resp.text)}B",
                        remediation="Implement authorization checks for path-based resource access.",
                        confidence=68,
                        verified=True,
                        business_impact=f"Unauthorized access to other users' {resource} records.",
                    )

        return None

    def _test_form_idor(self, ctx, target, param, field):
        """Placeholder — form-based IDOR testing uses same logic as query params."""
        # Form IDOR would require more complex testing; skipping for now
        return None

    @staticmethod
    def _check_structure_similarity(text_a: str, text_b: str) -> bool:
        """Check if two responses have similar JSON structure (same keys, different values)."""
        try:
            json_a = json.loads(text_a)
            json_b = json.loads(text_b)
            if isinstance(json_a, dict) and isinstance(json_b, dict):
                # Same top-level keys = same structure
                return set(json_a.keys()) == set(json_b.keys())
        except (json.JSONDecodeError, ValueError):
            pass

        # For HTML responses, check if they have similar length (rough heuristic)
        if len(text_a) > 0 and len(text_b) > 0:
            ratio = len(text_b) / len(text_a)
            return 0.5 < ratio < 2.0
        return False

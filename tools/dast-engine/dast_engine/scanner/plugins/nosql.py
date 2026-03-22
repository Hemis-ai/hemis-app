"""
NoSQL Injection detection — MongoDB-focused with baseline comparison.

Key validation steps:
1. Send benign baseline and record response length/content
2. Inject MongoDB operator payloads ($gt, $ne, $where) via query and JSON body
3. Compare response lengths — significant increase indicates data bypass
4. Verify with second request to confirm reproducibility
"""
from __future__ import annotations
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Query string parameter pollution payloads
QS_PAYLOADS = [
    ("[$gt]=", "MongoDB $gt operator (query)"),
    ("[$ne]=", "MongoDB $ne operator (query)"),
]

# String injection payloads for query/form params
STRING_PAYLOADS = [
    ("' || '1'=='1", "MongoDB string OR injection"),
    ("true, $where: '1 == 1'", "MongoDB $where auth bypass"),
]

# JSON body payloads (for API endpoints)
JSON_PAYLOADS = [
    ({"$gt": ""}, "MongoDB $gt operator (JSON)"),
    ({"$ne": None}, "MongoDB $ne operator (JSON)"),
    ("' || '1'=='1", "MongoDB string injection (JSON)"),
    ({"$where": "this.password.match(/.*/)"},  "MongoDB $where injection"),
]

# Parameters commonly targeted for auth bypass
AUTH_PARAMS = {"username", "user", "email", "password", "pass", "login", "token", "auth"}


class NoSQLPlugin(BasePlugin):
    name = "NoSQL Injection Scanner"
    vuln_type = "nosql_injection"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        test_params = self._get_params(target)
        if not test_params:
            return findings

        for param_name, param_source in test_params:
            finding = await self._test_nosql(ctx, target, param_name, param_source)
            if finding:
                findings.append(finding)

        return findings

    def _get_params(self, target: ScanTarget) -> list[tuple[str, str]]:
        params = []
        for p in target.parameters:
            params.append((p, "query"))
        for f in target.form_fields:
            params.append((f.get("name", ""), "form"))
        return [(n, s) for n, s in params if n]

    async def _inject_qs(self, ctx: ScanContext, target: ScanTarget, param: str, payload: str):
        """Inject via query string parameter."""
        parsed = urlparse(target.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return await self._send_request(ctx, url, method="GET", headers=target.headers, cookies=target.cookies)

    async def _inject_qs_operator(self, ctx: ScanContext, target: ScanTarget, param: str, operator_suffix: str):
        """Inject MongoDB operator via query string parameter pollution (e.g., param[$gt]=)."""
        parsed = urlparse(target.url)
        # Build raw query with operator syntax
        existing_qs = parsed.query
        operator_param = f"{param}{operator_suffix}"
        if existing_qs:
            new_query = f"{existing_qs}&{operator_param}"
        else:
            new_query = operator_param
        url = urlunparse(parsed._replace(query=new_query))
        return await self._send_request(ctx, url, method="GET", headers=target.headers, cookies=target.cookies)

    async def _inject_form(self, ctx: ScanContext, target: ScanTarget, param: str, payload: str):
        """Inject via POST form data."""
        form_data = {}
        for f in target.form_fields:
            form_data[f["name"]] = f.get("value", "test")
        form_data[param] = payload
        return await self._send_request(
            ctx, target.url, method="POST", data=form_data,
            headers=target.headers, cookies=target.cookies,
        )

    async def _inject_json(self, ctx: ScanContext, target: ScanTarget, param: str, payload_value):
        """Inject via JSON body (for API endpoints)."""
        json_body = {}
        for f in target.form_fields:
            json_body[f["name"]] = f.get("value", "test")
        json_body[param] = payload_value
        headers = dict(target.headers) if target.headers else {}
        headers["Content-Type"] = "application/json"
        return await self._send_request(
            ctx, target.url, method="POST",
            data=json.dumps(json_body).encode(),
            headers=headers, cookies=target.cookies,
        )

    async def _test_nosql(self, ctx: ScanContext, target: ScanTarget, param: str, source: str):
        """Test a parameter for NoSQL injection with baseline comparison."""
        is_auth_param = param.lower() in AUTH_PARAMS

        # Establish baseline with multiple requests for variance measurement
        baseline_lengths = []
        for _ in range(3):
            if source == "query":
                resp = await self._inject_qs(ctx, target, param, "hemisxtest123")
            else:
                resp = await self._inject_form(ctx, target, param, "hemisxtest123")
            if resp is None:
                return None
            baseline_lengths.append(len(resp.text))

        avg_baseline = sum(baseline_lengths) / len(baseline_lengths)
        baseline_variance = max(abs(ln - avg_baseline) for ln in baseline_lengths)
        # Threshold: response must be significantly larger than baseline
        min_threshold = max(baseline_variance * 3, 200)

        # Test query string operator payloads
        if source == "query":
            for operator_suffix, desc in QS_PAYLOADS:
                resp = await self._inject_qs_operator(ctx, target, param, operator_suffix)
                if resp is None:
                    continue

                resp_len = len(resp.text)
                diff = resp_len - avg_baseline

                if diff < min_threshold:
                    continue

                # Verification
                verify = await self._inject_qs_operator(ctx, target, param, operator_suffix)
                if verify is None:
                    continue
                verify_diff = len(verify.text) - avg_baseline
                if verify_diff < min_threshold:
                    continue

                vuln_type = "nosql_auth_bypass" if is_auth_param else "nosql_injection"
                severity = "CRITICAL" if is_auth_param else "HIGH"

                return self._make_finding(
                    vuln_type=vuln_type, param=param, source=source,
                    target=target, desc=desc,
                    payload=f"{param}{operator_suffix}",
                    avg_baseline=avg_baseline, resp_len=resp_len, diff=diff,
                    severity=severity, is_auth=is_auth_param,
                )

        # Test string injection payloads
        for payload, desc in STRING_PAYLOADS:
            if source == "query":
                resp = await self._inject_qs(ctx, target, param, payload)
            else:
                resp = await self._inject_form(ctx, target, param, payload)
            if resp is None:
                continue

            resp_len = len(resp.text)
            diff = resp_len - avg_baseline

            if diff < min_threshold:
                continue

            # Verification
            if source == "query":
                verify = await self._inject_qs(ctx, target, param, payload)
            else:
                verify = await self._inject_form(ctx, target, param, payload)
            if verify is None:
                continue
            if len(verify.text) - avg_baseline < min_threshold:
                continue

            vuln_type = "nosql_auth_bypass" if is_auth_param else "nosql_injection"
            severity = "CRITICAL" if is_auth_param else "HIGH"

            return self._make_finding(
                vuln_type=vuln_type, param=param, source=source,
                target=target, desc=desc, payload=payload,
                avg_baseline=avg_baseline, resp_len=resp_len, diff=diff,
                severity=severity, is_auth=is_auth_param,
            )

        # Test JSON body payloads (for form targets that might accept JSON)
        if source == "form":
            for payload_value, desc in JSON_PAYLOADS:
                resp = await self._inject_json(ctx, target, param, payload_value)
                if resp is None:
                    continue

                resp_len = len(resp.text)
                diff = resp_len - avg_baseline

                if diff < min_threshold:
                    continue

                # Verification
                verify = await self._inject_json(ctx, target, param, payload_value)
                if verify is None:
                    continue
                if len(verify.text) - avg_baseline < min_threshold:
                    continue

                vuln_type = "nosql_auth_bypass" if is_auth_param else "nosql_injection"
                severity = "CRITICAL" if is_auth_param else "HIGH"

                return self._make_finding(
                    vuln_type=vuln_type, param=param, source=source,
                    target=target, desc=desc,
                    payload=json.dumps(payload_value) if isinstance(payload_value, dict) else payload_value,
                    avg_baseline=avg_baseline, resp_len=resp_len, diff=diff,
                    severity=severity, is_auth=is_auth_param,
                )

        return None

    def _make_finding(
        self, vuln_type: str, param: str, source: str, target: ScanTarget,
        desc: str, payload: str, avg_baseline: float, resp_len: int, diff: float,
        severity: str, is_auth: bool,
    ) -> RawFinding:
        if is_auth:
            title = f"NoSQL Authentication Bypass ({desc})"
            impact = (
                "Authentication bypass. An attacker can log in as any user without "
                "knowing their password, gaining full access to the application."
            )
        else:
            title = f"NoSQL Injection ({desc})"
            impact = (
                "Data disclosure. An attacker can extract data from the NoSQL database "
                "by manipulating query operators to bypass filtering conditions."
            )

        return RawFinding(
            vuln_type=vuln_type,
            title=title,
            description=(
                f"The parameter '{param}' is vulnerable to NoSQL injection via {desc}. "
                f"Injecting the payload caused the response to grow by {diff:.0f} bytes "
                f"(baseline: {avg_baseline:.0f}B, injected: {resp_len}B), indicating "
                f"that the query returned additional data not normally accessible. "
                f"Verified with a second independent request."
            ),
            affected_url=target.url,
            severity=severity,
            affected_parameter=param,
            injection_point=source,
            payload=payload,
            request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
            response_evidence=f"Baseline: {avg_baseline:.0f}B | Injected: {resp_len}B | Delta: {diff:.0f}B",
            remediation=(
                "Never pass raw user input to NoSQL query operators. Use explicit field validation "
                "and cast inputs to expected types. Use a query builder or ORM that prevents operator injection. "
                "Sanitize JSON input to strip MongoDB operators ($gt, $ne, $where, etc.)."
            ),
            remediation_code=json.dumps({
                "vulnerableCode": (
                    f"db.users.find({{'{param}': req.body.{param}}})\n"
                    "# Attacker sends: {\"$ne\": null} to bypass"
                ),
                "remediatedCode": (
                    f"# Validate and cast input explicitly\n"
                    f"value = str(req.body.get('{param}', ''))\n"
                    f"if not value or '$' in value:\n"
                    f"    raise ValueError('Invalid input')\n"
                    f"db.users.find({{'{param}': value}})"
                ),
                "explanation": (
                    "Cast inputs to expected types (e.g., str) and reject values containing "
                    "MongoDB operators. Never pass raw request body fields into queries."
                ),
                "language": "Python (PyMongo)",
            }),
            confidence=82,
            verified=True,
            business_impact=impact,
        )

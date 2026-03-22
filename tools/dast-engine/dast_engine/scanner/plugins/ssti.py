"""
Server-Side Template Injection (SSTI) detection — multi-engine coverage.

Key validation steps:
1. Send benign baseline request for each parameter
2. Inject template syntax for multiple engines (Jinja2, Mako, ERB, Freemarker, etc.)
3. If mathematical evaluation result (49) appears in response but NOT in baseline → flag
4. Verify with second request to confirm reproducibility
"""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Template injection payloads: (payload, engine, detection_pattern)
SSTI_PAYLOADS = [
    ("{{7*7}}", "Jinja2/Twig", r"(?<!\{)49(?!\})"),
    ("{{config}}", "Jinja2", r"<Config|SECRET_KEY|DEBUG"),
    ("${7*7}", "Mako/Freemarker", r"(?<!\$)49(?!\})"),
    ("<#assign x=7*7>${x}", "Freemarker", r"49"),
    ("<%= 7*7 %>", "ERB", r"49"),
    ("{% set x = 7*7 %}{{x}}", "Pebble", r"49"),
    ("{php}echo 7*7;{/php}", "Smarty", r"49"),
]

# The marker value we look for in responses
EVAL_RESULT = "49"


class SSTIPlugin(BasePlugin):
    name = "SSTI Scanner"
    vuln_type = "ssti"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        test_params = self._get_params(target)
        if not test_params:
            return findings

        for param_name, param_source in test_params:
            finding = await self._test_ssti(ctx, target, param_name, param_source)
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

    async def _inject(self, ctx: ScanContext, target: ScanTarget, param: str, payload: str, source: str):
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._send_request(ctx, url, method="GET", headers=target.headers, cookies=target.cookies)
        else:
            form_data = {}
            for f in target.form_fields:
                form_data[f["name"]] = f.get("value", "test")
            form_data[param] = payload
            return await self._send_request(ctx, target.url, method="POST", data=form_data, headers=target.headers, cookies=target.cookies)

    async def _test_ssti(self, ctx: ScanContext, target: ScanTarget, param: str, source: str):
        """Test a parameter for SSTI across multiple template engines."""
        # Baseline: send a benign value
        baseline = await self._inject(ctx, target, param, "hemisxtest123", source)
        if baseline is None:
            return None
        baseline_text = baseline.text

        for payload, engine, detect_pattern in SSTI_PAYLOADS:
            resp = await self._inject(ctx, target, param, payload, source)
            if resp is None:
                continue

            # Check if the evaluation result appears in the response
            match = re.search(detect_pattern, resp.text)
            if not match:
                continue

            # For the "49" payloads, ensure it wasn't already in the baseline
            if EVAL_RESULT in detect_pattern:
                if re.search(detect_pattern, baseline_text):
                    continue

            # For config dump detection, ensure it wasn't in baseline
            if "config" in payload.lower():
                if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                    continue

            # Verification: send the same payload again
            verify = await self._inject(ctx, target, param, payload, source)
            if verify is None:
                continue
            if not re.search(detect_pattern, verify.text):
                continue

            evidence = resp.text[max(0, match.start() - 50):match.end() + 50]

            is_config_dump = "config" in payload.lower()
            title = f"Server-Side Template Injection ({engine})"
            if is_config_dump:
                title += " — Configuration Dump"

            return RawFinding(
                vuln_type="ssti",
                title=title,
                description=(
                    f"The parameter '{param}' is vulnerable to Server-Side Template Injection "
                    f"using {engine} template syntax. "
                    f"The payload '{payload}' was evaluated server-side and the result appeared "
                    f"in the response but was NOT present in the baseline. "
                    f"Verified: result reproduced across two independent requests. "
                    f"SSTI typically leads to Remote Code Execution (RCE)."
                ),
                affected_url=target.url,
                severity="CRITICAL",
                affected_parameter=param,
                injection_point=source,
                payload=payload,
                request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
                response_evidence=evidence.strip()[:200],
                remediation=(
                    "Never pass user input directly into template rendering. "
                    "Use a sandboxed template environment and disable dangerous features. "
                    "Validate and sanitize all user input before template processing."
                ),
                remediation_code=json.dumps({
                    "vulnerableCode": f"render_template_string(request.args.get('{param}'))",
                    "remediatedCode": (
                        f"# Pass user input as a variable, never as template source\n"
                        f"render_template('page.html', user_input=request.args.get('{param}'))"
                    ),
                    "explanation": (
                        "User input should be passed as template variables, not as template source code. "
                        "This prevents the template engine from evaluating attacker-controlled expressions."
                    ),
                    "language": "Python (Flask/Jinja2)",
                }),
                confidence=92,
                verified=True,
                business_impact=(
                    "Full server compromise. SSTI in most template engines allows "
                    "arbitrary code execution, enabling an attacker to read files, "
                    "execute system commands, and pivot to internal networks."
                ),
            )
        return None

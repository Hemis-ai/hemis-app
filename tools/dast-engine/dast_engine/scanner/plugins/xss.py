"""Cross-Site Scripting (XSS) detection: reflected, DOM-based heuristics."""
from __future__ import annotations
import re
import json
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

# Context-aware XSS payloads
XSS_PAYLOADS = [
    # HTML context
    {"payload": "<script>alert('HEMISX{canary}')</script>", "context": "html", "check": "<script>alert('HEMISX{canary}')</script>"},
    {"payload": "<img src=x onerror=alert('HEMISX{canary}')>", "context": "html", "check": "onerror=alert('HEMISX{canary}')"},
    {"payload": "<svg onload=alert('HEMISX{canary}')>", "context": "html", "check": "onload=alert('HEMISX{canary}')"},
    {"payload": "<body onload=alert('HEMISX{canary}')>", "context": "html", "check": "onload=alert('HEMISX{canary}')"},
    # Attribute context
    {"payload": "\" onmouseover=\"alert('HEMISX{canary}')\" x=\"", "context": "attribute", "check": "onmouseover=\"alert('HEMISX{canary}')\""},
    {"payload": "' onmouseover='alert(`HEMISX{canary}`)' x='", "context": "attribute", "check": "onmouseover='alert(`HEMISX{canary}`)"},
    # JavaScript context
    {"payload": "';alert('HEMISX{canary}');//", "context": "js", "check": "alert('HEMISX{canary}')"},
    {"payload": "\";alert('HEMISX{canary}');//", "context": "js", "check": "alert('HEMISX{canary}')"},
]

# DOM-based XSS source/sink patterns
DOM_SOURCES = [
    r"document\.location", r"document\.URL", r"document\.documentURI",
    r"document\.referrer", r"window\.location", r"location\.hash",
    r"location\.search", r"location\.href",
]
DOM_SINKS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
    r"document\.writeln\s*\(", r"eval\s*\(", r"setTimeout\s*\(",
    r"setInterval\s*\(", r"\.insertAdjacentHTML\s*\(",
]


class XSSPlugin(BasePlugin):
    name = "XSS Scanner"
    vuln_type = "xss_reflected"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Get testable parameters
        test_params = []
        for p in target.parameters:
            test_params.append((p, "query"))
        for f in target.form_fields:
            if f.get("name"):
                test_params.append((f["name"], "form"))

        # Test reflected XSS via parameter injection
        for param_name, param_source in test_params:
            finding = await self._test_reflected(target, param_name, param_source)
            if finding:
                findings.append(finding)

        # Test DOM-based XSS (heuristic: check JS source for dangerous patterns)
        dom_finding = self._test_dom_based(target)
        if dom_finding:
            findings.append(dom_finding)

        return findings

    async def _test_reflected(self, target: ScanTarget, param: str, source: str):
        """Test for reflected XSS by injecting canary strings."""
        canary = uuid.uuid4().hex[:8]

        for xss in XSS_PAYLOADS:
            payload = xss["payload"].replace("{canary}", canary)
            check_str = xss["check"].replace("{canary}", canary)

            resp = await self._inject(target, param, payload, source)
            if resp is None:
                continue

            # Check if the payload is reflected unencoded
            if check_str in resp.text:
                return RawFinding(
                    vuln_type="xss_reflected",
                    title=f"Reflected Cross-Site Scripting (XSS) - {xss['context'].upper()} Context",
                    description=f"The parameter '{param}' reflects user input without proper encoding in an {xss['context']} context. "
                                f"An attacker can inject arbitrary JavaScript that executes in the victim's browser session.",
                    affected_url=target.url,
                    severity="HIGH",
                    affected_parameter=param,
                    injection_point=source,
                    payload=payload,
                    request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
                    response_evidence=self._extract_context(resp.text, check_str),
                    remediation="Encode all user-supplied output using context-appropriate encoding: "
                                "HTML entity encoding for HTML context, JavaScript encoding for JS context, "
                                "URL encoding for URL context. Use Content-Security-Policy headers as defense in depth.",
                    remediation_code=json.dumps({
                        "vulnerableCode": f"<div>Results for: ${{{param}}}</div>",
                        "remediatedCode": f"<div>Results for: {{escapeHtml({param})}}</div>",
                        "explanation": "Context-appropriate output encoding prevents browsers from interpreting user input as executable code.",
                        "language": "JavaScript",
                        "framework": "React/Node.js",
                    }),
                    confidence=90,
                    business_impact="Session hijacking, credential theft via phishing, defacement of user-facing pages, "
                                   "and potential malware delivery to end users.",
                )

            # Check for partial reflection (canary reflected but payload sanitized)
            plain_canary = f"HEMISX{canary}"
            if plain_canary in resp.text:
                # Input is reflected but may be partially encoded - still noteworthy
                pass

        return None

    async def _inject(self, target: ScanTarget, param: str, payload: str, source: str):
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
            return await self._send_request(url, headers=target.headers, cookies=target.cookies)
        else:
            form_data = {}
            for f in target.form_fields:
                form_data[f["name"]] = f.get("value", "test")
            form_data[param] = payload
            return await self._send_request(
                target.url, method="POST", data=form_data,
                headers=target.headers, cookies=target.cookies,
            )

    def _test_dom_based(self, target: ScanTarget) -> RawFinding | None:
        """Heuristic check for DOM-based XSS by analyzing JavaScript in the page."""
        body = target.response_body
        if not body:
            return None

        found_sources = []
        found_sinks = []

        for pattern in DOM_SOURCES:
            if re.search(pattern, body):
                found_sources.append(pattern.replace("\\", ""))
        for pattern in DOM_SINKS:
            if re.search(pattern, body):
                found_sinks.append(pattern.replace("\\", "").replace(r"\s*", " ").replace(r"\(", "("))

        if found_sources and found_sinks:
            return RawFinding(
                vuln_type="xss_dom",
                title="Potential DOM-Based Cross-Site Scripting (XSS)",
                description=f"The page contains JavaScript that reads from user-controllable DOM sources "
                            f"({', '.join(found_sources[:3])}) and writes to dangerous sinks "
                            f"({', '.join(found_sinks[:3])}). This pattern may allow DOM-based XSS.",
                affected_url=target.url,
                severity="MEDIUM",
                payload=None,
                request_evidence=f"Sources found: {', '.join(found_sources)}",
                response_evidence=f"Sinks found: {', '.join(found_sinks)}",
                remediation="Avoid using dangerous DOM sinks like innerHTML. Use textContent or createElement instead. "
                            "Sanitize all user-controllable DOM sources before use.",
                confidence=60,
                business_impact="If exploitable, allows JavaScript execution in the user's browser context.",
            )
        return None

    def _extract_context(self, html: str, check_str: str) -> str:
        """Extract surrounding context around the reflected payload."""
        idx = html.find(check_str)
        if idx == -1:
            return check_str
        start = max(0, idx - 80)
        end = min(len(html), idx + len(check_str) + 80)
        return f"...{html[start:end]}..."

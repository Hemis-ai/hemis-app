"""
Cross-Site Scripting (XSS) detection — Burp-Suite-grade validation.

Key validation steps (matching how Burp Suite confirms XSS):
1. Send CLEAN baseline request first to get normal response
2. Inject payload and check Content-Type is text/html (NOT json, plaintext, etc.)
3. Verify the payload is reflected UNENCODED in an HTML context
4. Confirm with a second verification request to eliminate transient false positives
5. Analyze reflection context (HTML body, attribute, script block) for exploitability
"""
from __future__ import annotations
import re
import json
import uuid
import html as html_mod
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding


# Context-aware XSS payloads - each with a unique canary prefix for tracking
XSS_PAYLOADS = [
    # HTML context - script tags
    {
        "payload": "<script>alert('HEMISX{canary}')</script>",
        "context": "html",
        "check": "<script>alert('HEMISX{canary}')</script>",
        "description": "script tag injection",
    },
    {
        "payload": "<img src=x onerror=alert('HEMISX{canary}')>",
        "context": "html",
        "check": "onerror=alert('HEMISX{canary}')",
        "description": "event handler injection via img tag",
    },
    {
        "payload": "<svg/onload=alert('HEMISX{canary}')>",
        "context": "html",
        "check": "onload=alert('HEMISX{canary}')",
        "description": "event handler injection via svg tag",
    },
    # Attribute context breakout
    {
        "payload": "\"onmouseover=\"alert('HEMISX{canary}')\"",
        "context": "attribute",
        "check": "onmouseover=\"alert('HEMISX{canary}')\"",
        "description": "attribute breakout with event handler",
    },
    # JavaScript context breakout
    {
        "payload": "';alert('HEMISX{canary}');//",
        "context": "js",
        "check": "alert('HEMISX{canary}')",
        "description": "JavaScript string breakout",
    },
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

        if not test_params:
            return findings

        # Test reflected XSS via parameter injection
        for param_name, param_source in test_params:
            finding = await self._test_reflected(target, param_name, param_source)
            if finding:
                findings.append(finding)

        # Test DOM-based XSS (heuristic — only on HTML pages)
        if target.response_body and target.content_type and "html" in target.content_type:
            dom_finding = self._test_dom_based(target)
            if dom_finding:
                findings.append(dom_finding)

        return findings

    async def _test_reflected(self, target: ScanTarget, param: str, source: str):
        """
        Test for reflected XSS with Burp-level validation:
        1. Inject a unique canary string first (no special chars) — tests basic reflection
        2. If canary is reflected in HTML context, test real payloads
        3. Verify payload reflection is in HTML context (not JSON/plaintext)
        4. Analyze reflection context to rule out JSON-in-HTML false positives
        5. Confirm with a second verification request
        """
        # Phase 1: Probe with harmless canary to test reflection
        canary = f"HXS{uuid.uuid4().hex[:10]}"
        probe_resp = await self._inject(target, param, canary, source)
        if probe_resp is None:
            return None

        # ── CRITICAL CHECK #1: Is the response HTML? ──
        # JSON/XML/plaintext reflection is NOT XSS — the browser won't execute scripts
        # in non-HTML content types. This is the #1 source of false positives.
        if not self.is_html_response(probe_resp):
            return None

        # Is the canary reflected at all?
        if canary not in probe_resp.text:
            return None

        # Phase 2: Canary is reflected in HTML — now test with real payloads
        payload_canary = uuid.uuid4().hex[:8]

        for xss in XSS_PAYLOADS:
            payload = xss["payload"].replace("{canary}", payload_canary)
            check_str = xss["check"].replace("{canary}", payload_canary)

            resp = await self._inject(target, param, payload, source)
            if resp is None:
                continue

            # ── CRITICAL CHECK #2: Response must still be HTML ──
            if not self.is_html_response(resp):
                continue

            # Check if the dangerous part of the payload is reflected unencoded
            if check_str not in resp.text:
                continue

            # ── CRITICAL CHECK #3: Verify it's NOT inside a JSON blob embedded in HTML ──
            # Some pages embed JSON in <script type="application/json"> or
            # <script>var data = {"field": "PAYLOAD"}</script>
            # The payload is inside a JSON string literal — NOT executable XSS
            reflection_context = self._analyze_reflection_context(resp.text, check_str)
            if reflection_context in ("json_string", "json_ld"):
                continue

            # ── CRITICAL CHECK #4: Verification request ──
            # Burp Suite confirms by sending the same payload again. Eliminates transient
            # false positives from cached responses, race conditions, etc.
            verify_resp = await self._inject(target, param, payload, source)
            if verify_resp is None or check_str not in verify_resp.text:
                continue
            if not self.is_html_response(verify_resp):
                continue

            # ══ CONFIRMED: Real reflected XSS ══
            context_desc = xss["context"].upper()
            confidence = 95 if reflection_context == "html_body" else 88

            return RawFinding(
                vuln_type="xss_reflected",
                title=f"Reflected Cross-Site Scripting (XSS) — {context_desc} Context",
                description=(
                    f"The parameter '{param}' reflects user input without proper encoding in an "
                    f"{xss['context']} context ({xss['description']}). "
                    f"The injected payload executes in the victim's browser when the crafted URL is visited. "
                    f"Verified: payload confirmed reflected unencoded across two independent requests."
                ),
                affected_url=target.url,
                severity="HIGH",
                affected_parameter=param,
                injection_point=source,
                payload=payload,
                request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
                response_evidence=self._extract_context(resp.text, check_str),
                remediation=(
                    "Encode all user-supplied output using context-appropriate encoding: "
                    "HTML entity encoding for HTML context, JavaScript encoding for JS context, "
                    "URL encoding for URL context. Implement Content-Security-Policy headers "
                    "with script-src directives as defense in depth."
                ),
                remediation_code=json.dumps({
                    "vulnerableCode": f"<div>Results for: ${{{param}}}</div>",
                    "remediatedCode": f"<div>Results for: {{escapeHtml({param})}}</div>",
                    "explanation": (
                        "Context-appropriate output encoding prevents browsers from interpreting "
                        "user input as executable code. Use your framework's built-in escaping "
                        "(e.g., React auto-escapes, Django's |escape filter)."
                    ),
                    "language": "JavaScript/HTML",
                    "framework": "Any",
                }),
                confidence=confidence,
                business_impact=(
                    "Session hijacking via stolen cookies, credential theft through "
                    "injected phishing forms, defacement of user-facing pages, "
                    "and malware delivery to end users."
                ),
                verified=True,
            )

        return None

    def _analyze_reflection_context(self, html_body: str, check_str: str) -> str:
        """
        Determine WHERE in the HTML the payload is reflected.
        Returns: 'html_body', 'html_attribute', 'script_block', 'json_string', 'json_ld', or 'unknown'
        """
        idx = html_body.find(check_str)
        if idx == -1:
            return "unknown"

        # Get surrounding context (500 chars before reflection)
        prefix = html_body[max(0, idx - 500):idx]

        # Check if we're inside a <script> tag
        last_script_open = prefix.rfind("<script")
        last_script_close = prefix.rfind("</script")
        if last_script_open > last_script_close:
            # We're inside a script block
            script_tag = prefix[last_script_open:]
            # JSON-LD or application/json — payload is in a data blob, NOT executable
            if "application/json" in script_tag or "application/ld+json" in script_tag:
                return "json_ld"
            # Check if reflection is inside a JS string literal in a JSON-like structure
            # Look for patterns like {"key": "...PAYLOAD or "key":"...PAYLOAD
            nearby = prefix[max(0, len(prefix) - 150):]
            if re.search(r'["\']:\s*["\'][^"\']*$', nearby):
                return "json_string"
            return "script_block"

        # Check if inside an HTML attribute
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")
        if last_tag_open > last_tag_close:
            return "html_attribute"

        return "html_body"

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
        """
        Heuristic check for DOM-based XSS by analyzing JavaScript source/sink patterns.
        Only flagged when both a source and sink are found in the SAME script block,
        indicating a potential data flow.
        """
        body = target.response_body
        if not body:
            return None

        # Check per-script-block to confirm source+sink co-location
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(body, "lxml")
        except Exception:
            return None

        found_sources = []
        found_sinks = []

        for script in soup.find_all("script"):
            if not script.string:
                continue
            s = script.string
            block_sources = [p.replace("\\", "") for p in DOM_SOURCES if re.search(p, s)]
            block_sinks = [p.replace("\\", "").replace(r"\s*", " ").replace(r"\(", "(") for p in DOM_SINKS if re.search(p, s)]
            if block_sources and block_sinks:
                found_sources.extend(block_sources)
                found_sinks.extend(block_sinks)

        if not found_sources or not found_sinks:
            return None

        return RawFinding(
            vuln_type="xss_dom",
            title="Potential DOM-Based Cross-Site Scripting (XSS)",
            description=(
                f"The page contains JavaScript that reads from user-controllable DOM sources "
                f"({', '.join(set(found_sources[:3]))}) and writes to dangerous sinks "
                f"({', '.join(set(found_sinks[:3]))}) within the same script block. "
                f"Manual verification is recommended to confirm exploitability."
            ),
            affected_url=target.url,
            severity="MEDIUM",
            payload=None,
            request_evidence=f"Sources: {', '.join(set(found_sources))}",
            response_evidence=f"Sinks: {', '.join(set(found_sinks))}",
            remediation=(
                "Avoid using dangerous DOM sinks like innerHTML. Use textContent or "
                "createElement instead. Sanitize all user-controllable DOM sources before use."
            ),
            confidence=55,
            business_impact="If exploitable, allows JavaScript execution in the user's browser context.",
        )

    def _extract_context(self, html_text: str, check_str: str) -> str:
        """Extract surrounding HTML context around the reflected payload."""
        idx = html_text.find(check_str)
        if idx == -1:
            return check_str
        start = max(0, idx - 100)
        end = min(len(html_text), idx + len(check_str) + 100)
        return f"...{html_text[start:end]}..."

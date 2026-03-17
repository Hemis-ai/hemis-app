"""
Command Injection detection — with baseline comparison and verification.

Like Burp Suite, we first check if output patterns exist in baseline response
before attributing them to our payload.
"""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

UNIX_PAYLOADS = [
    ("; id", r"uid=\d+\(\w+\)\s+gid=\d+"),
    ("| id", r"uid=\d+\(\w+\)\s+gid=\d+"),
    ("`id`", r"uid=\d+\(\w+\)\s+gid=\d+"),
    ("$(id)", r"uid=\d+\(\w+\)\s+gid=\d+"),
    ("; cat /etc/passwd", r"root:x?:0:0:"),
    ("| cat /etc/passwd", r"root:x?:0:0:"),
    ("; uname -a", r"Linux\s+\S+\s+\d+\.\d+"),
]

WINDOWS_PAYLOADS = [
    ("& dir C:\\", r"Directory of C:\\"),
    ("| type C:\\Windows\\win.ini", r"\[fonts\]"),
    ("& whoami", r"\w+\\\w+"),
]


class CommandInjectionPlugin(BasePlugin):
    name = "Command Injection Scanner"
    vuln_type = "command_injection"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        test_params = [(p, "query") for p in target.parameters]
        test_params += [(f["name"], "form") for f in target.form_fields if f.get("name")]

        for param, source in test_params:
            # Get baseline to check for pre-existing matches
            baseline = await self._inject(target, param, "hemisxtest123", source)
            if baseline is None:
                continue
            baseline_text = baseline.text

            for payload, detect_pattern in UNIX_PAYLOADS + WINDOWS_PAYLOADS:
                # Check if pattern already exists in baseline
                if re.search(detect_pattern, baseline_text, re.IGNORECASE):
                    continue  # Pattern pre-exists — not caused by our injection

                resp = await self._inject(target, param, payload, source)
                if resp is None:
                    continue
                match = re.search(detect_pattern, resp.text, re.IGNORECASE)
                if not match:
                    continue

                # Verification request
                verify = await self._inject(target, param, payload, source)
                if verify is None or not re.search(detect_pattern, verify.text, re.IGNORECASE):
                    continue

                evidence = resp.text[max(0, match.start() - 30):match.end() + 30]
                findings.append(RawFinding(
                    vuln_type="command_injection",
                    title="OS Command Injection",
                    description=(
                        f"The parameter '{param}' is vulnerable to operating system command injection. "
                        f"The injected command produced output that was NOT present in the baseline response, "
                        f"confirming arbitrary command execution. Verified with repeated request."
                    ),
                    affected_url=target.url, severity="CRITICAL",
                    affected_parameter=param, injection_point=source, payload=payload,
                    request_evidence=f"{source.upper()} '{param}' = {payload}",
                    response_evidence=evidence.strip(),
                    remediation=(
                        "Never pass user input to shell commands. Use language-specific APIs instead of "
                        "system()/exec(). If shell execution is unavoidable, use strict allowlists."
                    ),
                    remediation_code=json.dumps({
                        "vulnerableCode": f"os.system(f'process {{request.{param}}}')",
                        "remediatedCode": f"subprocess.run(['process', request.{param}], shell=False)",
                        "explanation": "Using subprocess with shell=False prevents command injection.",
                        "language": "Python",
                    }),
                    confidence=95, verified=True,
                    business_impact="Complete server compromise. Attacker can execute arbitrary commands.",
                ))
                break  # One finding per param
        return findings

    async def _inject(self, target, param, payload, source):
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await self._send_request(url, headers=target.headers, cookies=target.cookies)
        else:
            data = {f["name"]: f.get("value", "") for f in target.form_fields}
            data[param] = payload
            return await self._send_request(target.url, method="POST", data=data, headers=target.headers, cookies=target.cookies)

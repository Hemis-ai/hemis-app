"""Command Injection detection via OS command payloads."""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

UNIX_PAYLOADS = [
    ("; id", r"uid=\d+"),
    ("| id", r"uid=\d+"),
    ("`id`", r"uid=\d+"),
    ("$(id)", r"uid=\d+"),
    ("; cat /etc/passwd", r"root:.*:0:0"),
    ("| cat /etc/passwd", r"root:.*:0:0"),
    ("; uname -a", r"Linux|Darwin|Unix"),
]

WINDOWS_PAYLOADS = [
    ("& dir C:\\", r"Directory of|Volume in drive"),
    ("| type C:\\Windows\\win.ini", r"\[fonts\]|\[extensions\]"),
    ("& whoami", r"\\\\[a-zA-Z0-9]+"),
]


class CommandInjectionPlugin(BasePlugin):
    name = "Command Injection Scanner"
    vuln_type = "command_injection"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        test_params = [(p, "query") for p in target.parameters]
        test_params += [(f["name"], "form") for f in target.form_fields if f.get("name")]

        for param, source in test_params:
            for payload, detect_pattern in UNIX_PAYLOADS + WINDOWS_PAYLOADS:
                resp = await self._inject(target, param, payload, source)
                if resp and re.search(detect_pattern, resp.text, re.IGNORECASE):
                    match = re.search(detect_pattern, resp.text, re.IGNORECASE)
                    evidence = resp.text[max(0, match.start()-30):match.end()+30] if match else ""
                    findings.append(RawFinding(
                        vuln_type="command_injection",
                        title=f"OS Command Injection",
                        description=f"The parameter '{param}' is vulnerable to operating system command injection. "
                                    f"The application executes user-supplied input as a shell command, allowing arbitrary command execution.",
                        affected_url=target.url, severity="CRITICAL",
                        affected_parameter=param, injection_point=source,
                        payload=payload,
                        request_evidence=f"{source.upper()} '{param}' = {payload}",
                        response_evidence=evidence.strip(),
                        remediation="Never pass user input to shell commands. Use language-specific APIs instead of system()/exec(). "
                                    "If shell execution is unavoidable, use strict allowlists for permitted values.",
                        remediation_code=json.dumps({
                            "vulnerableCode": f"os.system(f'process {{request.{param}}}')",
                            "remediatedCode": f"subprocess.run(['process', request.{param}], shell=False)",
                            "explanation": "Using subprocess with shell=False prevents command injection by not interpreting shell metacharacters.",
                            "language": "Python",
                        }),
                        confidence=95,
                        business_impact="Complete server compromise. Attacker can execute arbitrary commands, read/write files, install backdoors.",
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

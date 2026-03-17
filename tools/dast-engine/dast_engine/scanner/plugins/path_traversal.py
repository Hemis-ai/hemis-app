"""Path Traversal / Local File Inclusion (LFI) detection."""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", r"root:.*:0:0", "/etc/passwd"),
    ("....//....//....//etc/passwd", r"root:.*:0:0", "/etc/passwd"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", r"root:.*:0:0", "/etc/passwd"),
    ("..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "win.ini"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", r"\[fonts\]|\[extensions\]", "win.ini"),
    ("/etc/passwd", r"root:.*:0:0", "/etc/passwd"),
    ("../../../etc/shadow", r"root:.*:\d+:", "/etc/shadow"),
    ("../../../proc/self/environ", r"PATH=|HOME=|USER=", "/proc/self/environ"),
]


class PathTraversalPlugin(BasePlugin):
    name = "Path Traversal Scanner"
    vuln_type = "directory_traversal"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        test_params = [(p, "query") for p in target.parameters]
        test_params += [(f["name"], "form") for f in target.form_fields if f.get("name")]

        # Also test common file-inclusion parameter names in the URL
        parsed = urlparse(target.url)
        path_parts = parsed.path.split("/")
        file_params = {"file", "path", "page", "doc", "template", "include", "dir", "folder", "load"}
        for p in target.parameters:
            if p.lower() in file_params:
                test_params.insert(0, (p, "query"))  # Prioritize likely file params

        seen_params = set()
        for param, source in test_params:
            if param in seen_params:
                continue
            seen_params.add(param)

            for payload, detect_pattern, target_file in TRAVERSAL_PAYLOADS:
                resp = await self._inject(target, param, payload, source)
                if resp and re.search(detect_pattern, resp.text):
                    match = re.search(detect_pattern, resp.text)
                    evidence = resp.text[max(0, match.start()-30):match.end()+50] if match else ""
                    findings.append(RawFinding(
                        vuln_type="directory_traversal",
                        title=f"Path Traversal / Local File Inclusion",
                        description=f"The parameter '{param}' allows reading arbitrary files from the server filesystem. "
                                    f"The file '{target_file}' was successfully accessed via directory traversal sequences.",
                        affected_url=target.url, severity="HIGH",
                        affected_parameter=param, injection_point=source,
                        payload=payload,
                        request_evidence=f"{source.upper()} '{param}' = {payload}",
                        response_evidence=evidence.strip()[:200],
                        remediation="Never use user input to construct file paths. Use allowlists of permitted files. "
                                    "Canonicalize paths and verify they stay within the intended directory.",
                        remediation_code=json.dumps({
                            "vulnerableCode": f"open(f'templates/{{request.{param}}}')",
                            "remediatedCode": f"import os\\nbase = os.path.realpath('templates')\\npath = os.path.realpath(os.path.join(base, request.{param}))\\nif not path.startswith(base): raise ValueError('Invalid path')\\nopen(path)",
                            "explanation": "Path canonicalization + prefix check ensures the resolved path stays within the allowed directory.",
                            "language": "Python",
                        }),
                        confidence=95,
                        business_impact="Sensitive file disclosure including credentials, configuration files, and source code.",
                    ))
                    break
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

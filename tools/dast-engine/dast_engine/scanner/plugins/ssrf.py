"""Server-Side Request Forgery (SSRF) detection."""
from __future__ import annotations
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

SSRF_PAYLOADS = [
    # AWS metadata
    ("http://169.254.169.254/latest/meta-data/", [r"ami-id", r"instance-id", r"local-hostname", r"security-credentials"], "AWS EC2 Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", [r"AccessKeyId", r"SecretAccessKey", r"Token"], "AWS IAM Credentials"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", [r"project-id", r"zone"], "GCP Metadata"),
    # Azure metadata
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", [r"vmId", r"subscriptionId"], "Azure IMDS"),
    # Internal services
    ("http://127.0.0.1/", [r"<html", r"<title", r"localhost"], "Localhost Access"),
    ("http://[::1]/", [r"<html", r"<title"], "IPv6 Localhost"),
    ("http://127.0.0.1:22/", [r"SSH", r"OpenSSH"], "Internal SSH Service"),
    ("http://127.0.0.1:3306/", [r"mysql|MariaDB"], "Internal MySQL Service"),
    # Bypass attempts
    ("http://0177.0.0.1/", [r"<html", r"<title"], "Octal IP Bypass"),
    ("http://2130706433/", [r"<html", r"<title"], "Decimal IP Bypass"),
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
            for payload_url, detect_patterns, service_name in SSRF_PAYLOADS:
                resp = await self._inject(target, param, payload_url, source)
                if resp is None:
                    continue

                for pattern in detect_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        evidence = resp.text[max(0, match.start()-30):match.end()+50] if match else ""
                        findings.append(RawFinding(
                            vuln_type="ssrf",
                            title=f"Server-Side Request Forgery ({service_name})",
                            description=f"The parameter '{param}' allows making HTTP requests from the server to arbitrary destinations. "
                                        f"Successfully accessed {service_name} ({payload_url}), indicating the server fetches user-controlled URLs.",
                            affected_url=target.url, severity="HIGH",
                            affected_parameter=param, injection_point=source,
                            payload=payload_url,
                            request_evidence=f"{source.upper()} '{param}' = {payload_url}",
                            response_evidence=evidence.strip()[:200],
                            remediation="Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains/IPs. "
                                        "Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x). "
                                        "Use a dedicated HTTP client with SSRF protections.",
                            remediation_code=json.dumps({
                                "vulnerableCode": f"requests.get(user_input_url)",
                                "remediatedCode": "from urllib.parse import urlparse\\nimport ipaddress\\n\\ndef safe_fetch(url):\\n    parsed = urlparse(url)\\n    if parsed.hostname:\\n        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\\n        if ip.is_private or ip.is_loopback:\\n            raise ValueError('Blocked internal URL')\\n    return requests.get(url)",
                                "explanation": "DNS resolution + private IP check prevents SSRF to internal services and cloud metadata endpoints.",
                                "language": "Python",
                            }),
                            confidence=90,
                            business_impact=f"Access to {service_name}. May expose cloud credentials, internal services, or enable pivoting to internal infrastructure.",
                        ))
                        break
                else:
                    continue
                break  # Found SSRF on this param, move to next
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

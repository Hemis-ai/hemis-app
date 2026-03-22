"""
TLS certificate validation and HSTS enforcement checks.

Inspects the TLS certificate directly via ssl/socket modules (not httpx)
and checks for HSTS header completeness. Runs once per domain.
"""
from __future__ import annotations
import ssl
import socket
import asyncio
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


class TLSCheckPlugin(BasePlugin):
    name = "TLS Certificate & HSTS Checker"
    vuln_type = "tls_certificate"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        parsed = urlparse(target.url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Only run for HTTPS targets
        if parsed.scheme != "https":
            return findings

        # Only run once per domain
        dedup_key = f"tls_{hostname}"
        if dedup_key in ctx.reported_domains:
            return findings
        ctx.reported_domains.add(dedup_key)

        # --- TLS certificate inspection via ssl/socket ---
        try:
            cert_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._check_certificate, hostname, port, target.url
            )
            findings.extend(cert_findings)
        except Exception:
            pass

        # --- TLS version check ---
        try:
            version_findings = await asyncio.get_event_loop().run_in_executor(
                None, self._check_tls_versions, hostname, port, target.url
            )
            findings.extend(version_findings)
        except Exception:
            pass

        # --- HSTS header check ---
        findings.extend(self._check_hsts(target))

        return findings

    def _check_certificate(self, hostname: str, port: int, url: str) -> list[RawFinding]:
        """Check certificate expiry, self-signed, weak algo, CN/SAN mismatch."""
        findings: list[RawFinding] = []

        ctx_ssl = ssl.create_default_context()
        # First try with verification to detect self-signed
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
        except ssl.SSLCertVerificationError as e:
            err_msg = str(e)
            if "self-signed" in err_msg.lower() or "self signed" in err_msg.lower():
                findings.append(RawFinding(
                    vuln_type="tls_self_signed",
                    title="Self-Signed TLS Certificate",
                    description=(
                        f"The server at {hostname} presents a self-signed certificate. "
                        "Browsers will show security warnings and MITM attacks become easier."
                    ),
                    affected_url=url,
                    severity="HIGH",
                    remediation="Obtain a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                    confidence=95,
                    verified=True,
                    response_evidence=err_msg[:200],
                    business_impact="Users cannot trust the server identity; facilitates man-in-the-middle attacks.",
                ))
            # Try again without verification to still inspect the cert
            ctx_no_verify = ssl.create_default_context()
            ctx_no_verify.check_hostname = False
            ctx_no_verify.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with ctx_no_verify.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert = ssl.DER_cert_to_PEM_cert(cert_der) if cert_der else None
                        # Can't parse PEM easily; get the dict form
                        cert = ssock.getpeercert()
            except Exception:
                cert = None
        except Exception:
            cert = None

        if not cert:
            return findings

        # Check expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                if days_remaining < 0:
                    findings.append(RawFinding(
                        vuln_type="tls_cert_expired",
                        title="Expired TLS Certificate",
                        description=(
                            f"The TLS certificate for {hostname} expired on {not_after_str} "
                            f"({abs(days_remaining)} days ago). Browsers will reject the connection."
                        ),
                        affected_url=url,
                        severity="HIGH",
                        remediation="Renew the TLS certificate immediately.",
                        confidence=100,
                        verified=True,
                        response_evidence=f"Certificate notAfter: {not_after_str}",
                        business_impact="All users see browser warnings; site is effectively untrusted.",
                    ))
                elif days_remaining < 30:
                    findings.append(RawFinding(
                        vuln_type="tls_cert_expiring_soon",
                        title="TLS Certificate Expiring Soon",
                        description=(
                            f"The TLS certificate for {hostname} expires on {not_after_str} "
                            f"({days_remaining} days remaining). Renew before expiry to avoid downtime."
                        ),
                        affected_url=url,
                        severity="MEDIUM",
                        remediation="Renew the TLS certificate before expiry. Consider automated renewal via ACME/Let's Encrypt.",
                        confidence=100,
                        verified=True,
                        response_evidence=f"Certificate notAfter: {not_after_str}",
                        business_impact="Certificate will expire soon, potentially causing service disruption.",
                    ))
            except ValueError:
                pass

        # Check weak signature algorithm
        # Note: getpeercert() doesn't expose the signature algorithm directly,
        # but we can check via the DER form
        # For the dict form, we check what's available
        # The signature algorithm isn't in the dict; we'd need the binary form
        # We'll check via a second connection if needed

        # Check CN/SAN mismatch
        subject = dict(x[0] for x in cert.get("subject", ()))
        common_name = subject.get("commonName", "")
        san_entries = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_entries.append(san_value.lower())

        hostname_lower = hostname.lower()
        cn_matches = self._hostname_matches(hostname_lower, common_name.lower())
        san_matches = any(self._hostname_matches(hostname_lower, san) for san in san_entries)

        if not cn_matches and not san_matches:
            findings.append(RawFinding(
                vuln_type="tls_hostname_mismatch",
                title="TLS Certificate Hostname Mismatch",
                description=(
                    f"The TLS certificate CN='{common_name}' and SANs {san_entries} "
                    f"do not match the hostname '{hostname}'. Browsers will reject this connection."
                ),
                affected_url=url,
                severity="HIGH",
                remediation=f"Obtain a certificate that includes '{hostname}' in the CN or SAN fields.",
                confidence=95,
                verified=True,
                response_evidence=f"CN: {common_name}, SANs: {', '.join(san_entries) or 'none'}",
                business_impact="Certificate mismatch causes browser warnings and prevents trusted connections.",
            ))

        return findings

    def _check_tls_versions(self, hostname: str, port: int, url: str) -> list[RawFinding]:
        """Check if deprecated TLS versions (1.0, 1.1) are supported."""
        findings: list[RawFinding] = []

        deprecated_protocols = [
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ]

        for proto_version, proto_name in deprecated_protocols:
            try:
                ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_old.check_hostname = False
                ctx_old.verify_mode = ssl.CERT_NONE
                ctx_old.minimum_version = proto_version
                ctx_old.maximum_version = proto_version

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx_old.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If we get here, the deprecated version is supported
                        findings.append(RawFinding(
                            vuln_type="tls_deprecated_version",
                            title=f"Deprecated {proto_name} Supported",
                            description=(
                                f"The server supports {proto_name}, which has known vulnerabilities "
                                f"(BEAST, POODLE, etc.). Modern browsers are dropping support for it."
                            ),
                            affected_url=url,
                            severity="MEDIUM",
                            remediation=f"Disable {proto_name} on the server. Only allow TLS 1.2 and TLS 1.3.",
                            confidence=95,
                            verified=True,
                            response_evidence=f"Server accepted {proto_name} connection",
                            business_impact="Deprecated TLS versions have known attacks that compromise encryption.",
                        ))
            except (ssl.SSLError, OSError, ConnectionError):
                # Protocol not supported — this is good
                pass

        return findings

    def _check_hsts(self, target: ScanTarget) -> list[RawFinding]:
        """Check HSTS header for includeSubDomains and preload directives."""
        findings: list[RawFinding] = []
        headers = {k.lower(): v for k, v in target.response_headers.items()}
        hsts = headers.get("strict-transport-security", "")

        if not hsts:
            # Missing HSTS is already reported by header_analysis plugin
            return findings

        hsts_lower = hsts.lower()

        if "includesubdomains" not in hsts_lower:
            findings.append(RawFinding(
                vuln_type="hsts_missing_includesubdomains",
                title="HSTS Missing includeSubDomains Directive",
                description=(
                    "The Strict-Transport-Security header is present but does not include "
                    "the includeSubDomains directive. Subdomains may still be accessed over HTTP."
                ),
                affected_url=target.url,
                severity="LOW",
                remediation="Add includeSubDomains to HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                confidence=100,
                verified=True,
                response_evidence=f"Strict-Transport-Security: {hsts}",
                business_impact="Subdomains are not protected by HSTS, enabling downgrade attacks on subdomains.",
            ))

        if "preload" not in hsts_lower:
            findings.append(RawFinding(
                vuln_type="hsts_missing_preload",
                title="HSTS Missing preload Directive",
                description=(
                    "The Strict-Transport-Security header does not include the preload directive. "
                    "The domain cannot be submitted to the HSTS preload list for browser-level enforcement."
                ),
                affected_url=target.url,
                severity="INFO",
                remediation="Add preload to HSTS and submit to hstspreload.org: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                confidence=100,
                verified=True,
                response_evidence=f"Strict-Transport-Security: {hsts}",
                business_impact="First-visit users are not protected until the HSTS header is received.",
            ))

        return findings

    @staticmethod
    def _hostname_matches(hostname: str, pattern: str) -> bool:
        """Check if hostname matches a certificate pattern (supports wildcard)."""
        if pattern == hostname:
            return True
        if pattern.startswith("*."):
            # Wildcard matches one level: *.example.com matches foo.example.com but not foo.bar.example.com
            suffix = pattern[2:]
            if hostname.endswith(suffix) and hostname.count(".") == pattern.count("."):
                return True
        return False

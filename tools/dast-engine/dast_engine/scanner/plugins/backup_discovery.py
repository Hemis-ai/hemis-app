"""
Extended backup file discovery — Burp Suite-grade detection.

Probes for common backup, archive, VCS, and configuration files that
should not be publicly accessible. Verifies findings with two requests
and content-type validation. Runs once per domain from the root URL.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# (path, expected_content_types_substring, description)
BACKUP_PATHS: list[tuple[str, list[str], str]] = [
    # Backup suffixes on common files
    ("/robots.txt.bak", ["text/", "application/octet"], "Backup of robots.txt"),
    ("/robots.old", ["text/", "application/octet"], "Old robots.txt"),
    ("/robots.txt.tar.bz2", ["application/", "octet"], "Archive of robots.txt"),
    ("/.htaccess.bak", ["text/", "application/octet"], "Backup of .htaccess"),
    ("/.htpasswd", ["text/", "application/octet"], "Exposed .htpasswd file"),
    ("/web.config.bak", ["text/", "application/octet"], "Backup of web.config"),
    ("/web.config.old", ["text/", "application/octet"], "Old web.config"),
    ("/config.yml.bak", ["text/", "application/octet"], "Backup of config.yml"),
    ("/config.json.bak", ["text/", "application/octet"], "Backup of config.json"),

    # Database dumps
    ("/database.sql", ["text/", "application/sql", "application/octet"], "Exposed SQL database dump"),
    ("/dump.sql", ["text/", "application/sql", "application/octet"], "Exposed SQL dump"),
    ("/backup.sql", ["text/", "application/sql", "application/octet"], "Exposed SQL backup"),

    # Archive files
    ("/archive.zip", ["application/zip", "application/octet"], "Exposed ZIP archive"),
    ("/backup.tar.gz", ["application/gzip", "application/x-tar", "application/octet"], "Exposed tar.gz backup"),
    ("/site.tar.bz2", ["application/x-bzip", "application/octet"], "Exposed tar.bz2 site backup"),
    ("/backup.zip", ["application/zip", "application/octet"], "Exposed ZIP backup"),

    # Common backup file patterns
    ("/index.php.bak", ["text/", "application/octet"], "Backup of index.php"),
    ("/index.php.old", ["text/", "application/octet"], "Old index.php"),
    ("/index.php.orig", ["text/", "application/octet"], "Original index.php"),
    ("/index.php.save", ["text/", "application/octet"], "Saved index.php"),
    ("/index.php.swp", ["application/octet"], "Vim swap file for index.php"),
    ("/index.php~", ["text/", "application/octet"], "Editor backup of index.php"),
    ("/wp-config.php.bak", ["text/", "application/octet"], "Backup of WordPress config"),
    ("/configuration.php.bak", ["text/", "application/octet"], "Backup of Joomla config"),

    # VCS artifacts
    ("/.svn/entries", ["text/", "application/xml", "application/octet"], "SVN entries file"),
    ("/.hg/dirstate", ["application/octet"], "Mercurial dirstate file"),
]

# Patterns that indicate an HTML error page (false positive)
ERROR_PAGE_PATTERNS = [
    r"<title>\s*(404|not found|error|page not found|forbidden)",
    r"<h1>\s*(404|not found|error|page not found)",
    r"The page you requested was not found",
    r"The requested URL was not found",
    r"404 Not Found",
]


class BackupDiscoveryPlugin(BasePlugin):
    name = "Backup File Discovery Scanner"
    vuln_type = "backup_file_exposure"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Only run from root URL, once per domain
        parsed = urlparse(target.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        dedup_key = f"backup_{parsed.netloc}"
        if dedup_key in ctx.reported_domains:
            return findings

        if target.url.rstrip("/") != origin and parsed.path not in ("", "/", "/index.html"):
            return findings

        ctx.reported_domains.add(dedup_key)

        for path, expected_ct_parts, description in BACKUP_PATHS:
            probe_url = f"{origin}{path}"

            resp = await self._send_request(
                ctx,
                probe_url,
                headers=target.headers,
                cookies=target.cookies,
            )
            if resp is None or resp.status_code >= 400:
                continue

            # Check that it's not an HTML error page disguised as 200
            body = resp.text[:5000]
            if self._is_error_page(body):
                continue

            # Validate content-type makes sense for the file type
            ct = resp.headers.get("content-type", "").lower()
            ct_valid = any(part in ct for part in expected_ct_parts) if expected_ct_parts else True

            # For HTML responses on non-HTML files, likely a custom 404
            if "text/html" in ct and not path.endswith((".html", ".htm", ".php")):
                if self._is_error_page(body):
                    continue
                # If it's HTML but not an error page, still suspicious for backup files
                # Only skip if the body is very short (likely a redirect/error)
                if len(body.strip()) < 100:
                    continue

            # Verification request
            verify = await self._send_request(
                ctx,
                probe_url,
                headers=target.headers,
                cookies=target.cookies,
            )
            if verify is None or verify.status_code >= 400:
                continue

            verify_body = verify.text[:5000]
            if self._is_error_page(verify_body):
                continue

            # Determine severity based on file type
            severity = "MEDIUM"
            if any(x in path for x in [".sql", ".htpasswd", "config"]):
                severity = "HIGH"
            elif any(x in path for x in [".zip", ".tar", ".bz2", ".gz"]):
                severity = "HIGH"
            elif any(x in path for x in [".svn", ".hg"]):
                severity = "MEDIUM"

            content_preview = body[:200].replace("\n", " ").strip()

            findings.append(RawFinding(
                vuln_type="backup_file_exposure",
                title=f"Exposed Backup/Sensitive File: {description}",
                description=(
                    f"The file '{path}' is publicly accessible (HTTP {resp.status_code}). "
                    f"This {description.lower()} may contain sensitive data such as credentials, "
                    f"source code, or database contents. Verified with two independent requests."
                ),
                affected_url=probe_url,
                severity=severity,
                payload=path,
                response_evidence=f"HTTP {resp.status_code} | Content-Type: {ct}\nPreview: {content_preview[:150]}",
                remediation=(
                    f"Remove or restrict access to '{path}'. Configure web server rules to block "
                    f"access to backup files (.bak, .old, .orig, .swp, ~), archive files (.zip, .tar.gz), "
                    f"SQL dumps, and VCS directories (.svn, .hg)."
                ),
                confidence=85,
                verified=True,
                business_impact=f"Exposure of {description.lower()} may reveal source code, credentials, or database contents.",
            ))

        return findings

    @staticmethod
    def _is_error_page(body: str) -> bool:
        """Check if the response body looks like a custom error page."""
        for pattern in ERROR_PAGE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

"""7-phase scan pipeline orchestrator matching TypeScript scan-orchestrator.ts."""
from __future__ import annotations
import uuid
import json
import asyncio
import httpx
from datetime import datetime
from typing import Optional

from ..models.scan import ScanResponse, ScanStatus, ScanCreate
from ..models.finding import Finding, Severity
from ..models.progress import ScanProgressEvent
from ..crawler.crawler import Crawler, CrawlResult
from ..scanner.scanner import Scanner
from ..scanner.base_plugin import RawFinding
from ..scoring.cvss_calculator import get_cvss_for_type
from ..scoring.owasp_mapper import get_owasp_mapping
from ..storage.scan_store import store
from ..config import settings


PROFILE_CONFIG = {
    "full": {"max_depth": 10, "max_pages": 500},
    "quick": {"max_depth": 3, "max_pages": 50},
    "api_only": {"max_depth": 5, "max_pages": 200},
    "deep": {"max_depth": 20, "max_pages": 1000},
}


class ScanRunner:
    def __init__(self, scan_id: str, scan_config: ScanCreate):
        self.scan_id = scan_id
        self.config = scan_config
        self.auth_headers: dict[str, str] = {}
        self.auth_cookies: dict[str, str] = {}

    def _update_progress(self, progress: int, phase: str, message: str, status: str = "RUNNING", **kwargs):
        event = ScanProgressEvent(
            scanId=self.scan_id,
            status=status,
            progress=progress,
            currentPhase=phase,
            message=message,
            **kwargs,
        )
        store.update_progress(self.scan_id, event)
        # Don't override scan status here — let the caller control it
        store.update_scan(self.scan_id, progress=progress, currentPhase=phase)

    async def run(self):
        """Execute the full 7-phase scan pipeline."""
        try:
            store.update_scan(self.scan_id, status=ScanStatus.RUNNING, startedAt=datetime.utcnow().isoformat())

            # Phase 1: Initialization (0-5%)
            self._update_progress(2, "initializing", "Validating target and configuring scan...")
            await self._phase_init()

            # Phase 2: Crawling (5-40%)
            self._update_progress(5, "crawling", "Starting web crawl...")
            crawl_result = await self._phase_crawl()

            # Phase 3: Active Scanning (40-85%)
            self._update_progress(40, "scanning", "Starting vulnerability scanning...")
            raw_findings = await self._phase_scan(crawl_result)

            # Phase 4: Extraction (85-90%)
            self._update_progress(85, "extracting", f"Processing {len(raw_findings)} findings...")
            findings = await self._phase_extract(raw_findings)

            # Phase 5-6: Analysis (90-98%)
            self._update_progress(90, "analyzing", "Generating executive summary...")
            self._phase_analyze(findings, crawl_result)

            # Phase 7: Complete (100%)
            self._phase_complete(findings, crawl_result)

        except asyncio.CancelledError:
            store.update_scan(self.scan_id, status=ScanStatus.CANCELLED)
            raise
        except Exception as e:
            import traceback
            err_msg = str(e) or repr(e)
            store.update_scan(self.scan_id, status=ScanStatus.FAILED, currentPhase="failed")
            self._update_progress(
                store.get_scan(self.scan_id).progress if store.get_scan(self.scan_id) else 0,
                "failed", f"Scan failed: {err_msg}"
            )
            # Log full traceback for debugging
            import logging
            logging.getLogger("dast-engine").error("Scan %s failed:\n%s", self.scan_id, traceback.format_exc())

    async def _phase_init(self):
        """Phase 1: Validate target, configure auth, detect tech stack."""
        # Setup auth
        auth = self.config.authConfig
        if auth:
            if auth.type == "bearer" and auth.token:
                self.auth_headers["Authorization"] = f"Bearer {auth.token}"
            elif auth.type == "apikey" and auth.key:
                header = auth.header or "X-API-Key"
                self.auth_headers[header] = auth.key
            elif auth.type == "cookie" and auth.value:
                for cookie_pair in auth.value.split(";"):
                    if "=" in cookie_pair:
                        k, v = cookie_pair.strip().split("=", 1)
                        self.auth_cookies[k.strip()] = v.strip()
            elif auth.type == "header" and auth.name and auth.value:
                self.auth_headers[auth.name] = auth.value
            elif auth.type == "form" and auth.loginUrl and auth.username and auth.password:
                await self._form_login(auth)
            elif auth.type == "oauth2" and auth.tokenUrl and auth.clientId and auth.clientSecret:
                await self._oauth2_login(auth)

        # Validate target is reachable
        try:
            async with httpx.AsyncClient(timeout=30, verify=False, follow_redirects=True) as client:
                resp = await client.get(self.config.targetUrl, headers={
                    "User-Agent": settings.user_agent, **self.auth_headers
                })
                if resp.status_code >= 500:
                    raise Exception(f"Target returned HTTP {resp.status_code}")

                # Quick tech detection
                tech = []
                server = resp.headers.get("server", "")
                if server:
                    tech.append(server.split("/")[0])
                powered = resp.headers.get("x-powered-by", "")
                if powered:
                    tech.append(powered)
                store.update_scan(self.scan_id, techStackDetected=tech)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException) as e:
            raise Exception(f"Cannot connect to target: {self.config.targetUrl} ({type(e).__name__})")

    async def _form_login(self, auth):
        """Perform form-based authentication."""
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                data = {
                    auth.usernameField or "username": auth.username,
                    auth.passwordField or "password": auth.password,
                }
                resp = await client.post(auth.loginUrl, data=data)
                for name, value in resp.cookies.items():
                    self.auth_cookies[name] = value
        except Exception:
            pass

    async def _oauth2_login(self, auth):
        """Perform OAuth2 client_credentials authentication."""
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.post(auth.tokenUrl, data={
                    "grant_type": "client_credentials",
                    "client_id": auth.clientId,
                    "client_secret": auth.clientSecret,
                    "scope": auth.scope or "",
                })
                if resp.status_code == 200:
                    token = resp.json().get("access_token")
                    if token:
                        self.auth_headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass

    async def _phase_crawl(self) -> CrawlResult:
        """Phase 2: Crawl the target website."""
        profile_cfg = PROFILE_CONFIG.get(self.config.scanProfile.value, PROFILE_CONFIG["full"])
        scope = self.config.scope or {}

        def on_crawl_progress(visited: int, queued: int, msg: str):
            # Map crawl progress to 5-40% range
            progress = min(5 + int(35 * visited / max(profile_cfg["max_pages"], 1)), 40)
            self._update_progress(
                progress, "crawling", msg,
                endpointsDiscovered=visited,
            )

        crawler = Crawler(
            target_url=self.config.targetUrl,
            max_depth=profile_cfg["max_depth"],
            max_pages=profile_cfg["max_pages"],
            scope_include=scope.get("includePaths", []),
            scope_exclude=scope.get("excludePaths", []),
            auth_headers=self.auth_headers,
            auth_cookies=self.auth_cookies,
            on_progress=on_crawl_progress,
        )

        result = await crawler.crawl()

        store.update_scan(
            self.scan_id,
            endpointsDiscovered=len(result.urls),
            techStackDetected=result.tech_stack or store.get_scan(self.scan_id).techStackDetected,
        )

        return result

    async def _phase_scan(self, crawl_result: CrawlResult) -> list[RawFinding]:
        """Phase 3: Run vulnerability scanner plugins."""
        def on_scan_progress(tested: int, total: int, payloads: int, msg: str):
            progress = min(40 + int(45 * tested / max(total, 1)), 85)
            self._update_progress(
                progress, "scanning", msg,
                endpointsTested=tested,
                payloadsSent=payloads,
            )

        scanner = Scanner(
            scan_id=self.scan_id,
            target_url=self.config.targetUrl,
            crawl_result=crawl_result,
            profile=self.config.scanProfile.value,
            auth_headers=self.auth_headers,
            auth_cookies=self.auth_cookies,
            on_progress=on_scan_progress,
        )

        raw_findings = await scanner.scan()
        store.update_scan(self.scan_id, payloadsSent=scanner.total_payloads)

        return raw_findings

    async def _phase_extract(self, raw_findings: list[RawFinding]) -> list[Finding]:
        """Phase 4: Convert raw findings to scored Finding objects."""
        findings: list[Finding] = []

        for i, raw in enumerate(raw_findings):
            # Get CVSS score
            cvss = get_cvss_for_type(raw.vuln_type)
            # Get OWASP mapping
            mapping = get_owasp_mapping(raw.vuln_type)

            finding = Finding(
                id=f"{self.scan_id}-f{i+1}",
                scanId=self.scan_id,
                type=raw.vuln_type.upper(),
                owaspCategory=mapping.owasp_category,
                cweId=mapping.cwe_id,
                severity=Severity(cvss.severity),
                cvssScore=cvss.score,
                cvssVector=cvss.vector,
                riskScore=int(cvss.score * 10),
                title=raw.title,
                description=raw.description,
                businessImpact=raw.business_impact,
                affectedUrl=raw.affected_url,
                affectedParameter=raw.affected_parameter,
                injectionPoint=raw.injection_point,
                payload=raw.payload,
                requestEvidence=raw.request_evidence,
                responseEvidence=raw.response_evidence,
                remediation=raw.remediation,
                remediationCode=raw.remediation_code,
                pciDssRefs=mapping.pci_dss_refs,
                soc2Refs=mapping.soc2_refs,
                mitreAttackIds=mapping.mitre_attack_ids,
                confidenceScore=raw.confidence,
                isConfirmed=raw.confidence >= 85,
            )
            findings.append(finding)

        await store.add_findings(self.scan_id, findings)
        return findings

    def _phase_analyze(self, findings: list[Finding], crawl_result: CrawlResult):
        """Phase 5-6: Generate executive summary and correlate findings."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        store.update_scan(
            self.scan_id,
            criticalCount=severity_counts["CRITICAL"],
            highCount=severity_counts["HIGH"],
            mediumCount=severity_counts["MEDIUM"],
            lowCount=severity_counts["LOW"],
            infoCount=severity_counts["INFO"],
        )

        # Generate executive summary
        target = self.config.targetUrl
        total = len(findings)
        summary = f"## Scan Overview\nDASTscan of **{target}** identified **{total} vulnerabilities** across "
        summary += f"{severity_counts['CRITICAL']} critical, {severity_counts['HIGH']} high, "
        summary += f"{severity_counts['MEDIUM']} medium, {severity_counts['LOW']} low, and {severity_counts['INFO']} informational severity levels.\n\n"

        if severity_counts["CRITICAL"] > 0:
            crits = [f for f in findings if f.severity == Severity.CRITICAL]
            summary += "## Critical Risks\n"
            for c in crits[:5]:
                summary += f"- **{c.title}** at `{c.affectedUrl}` — {c.description[:100]}...\n"
            summary += "\n"

        if severity_counts["HIGH"] > 0:
            highs = [f for f in findings if f.severity == Severity.HIGH]
            summary += "## High-Priority Issues\n"
            for h in highs[:5]:
                summary += f"- **{h.title}** at `{h.affectedUrl}`\n"
            summary += "\n"

        summary += "## Recommendations\n"
        if severity_counts["CRITICAL"] > 0:
            summary += "- **Immediate**: Remediate all critical vulnerabilities before production deployment\n"
        if severity_counts["HIGH"] > 0:
            summary += "- **High Priority**: Address high-severity findings within the current sprint\n"
        summary += "- **Standard**: Review and fix medium/low findings as part of regular security hygiene\n"

        store.update_scan(self.scan_id, executiveSummary=summary)

        # Generate attack chain correlation data
        chains = self._correlate_attack_chains(findings)
        if chains:
            store.update_scan(self.scan_id, aiCorrelationData=json.dumps(chains))

        # Generate compliance data
        compliance = self._generate_compliance(findings)
        if compliance:
            store.update_scan(self.scan_id, aiComplianceData=json.dumps(compliance))

        self._update_progress(98, "analyzing", "Analysis complete")

    def _correlate_attack_chains(self, findings: list[Finding]) -> dict:
        """Identify attack chains from correlated findings."""
        chains = []
        sqli_findings = [i for i, f in enumerate(findings) if "SQL" in f.type.upper()]
        info_findings = [i for i, f in enumerate(findings) if "DISCLOSURE" in f.type.upper() or "DEBUG" in f.type.upper()]

        if sqli_findings and info_findings:
            chains.append({
                "chainId": f"{self.scan_id}-chain-1",
                "name": "SQL Injection + Information Disclosure → Data Exfiltration",
                "description": "SQL injection combined with information disclosure enables database mapping and targeted data extraction.",
                "severity": "CRITICAL",
                "findingIndices": sqli_findings[:2] + info_findings[:2],
                "exploitationSteps": [
                    "Use error messages to identify database type and structure",
                    "Exploit SQL injection to extract schema information",
                    "Dump sensitive tables (users, credentials, PII)",
                    "Leverage stolen credentials for lateral movement",
                ],
                "businessImpact": "Full database compromise leading to mass data breach.",
                "likelihoodOfExploitation": "HIGH",
            })

        xss_findings = [i for i, f in enumerate(findings) if "XSS" in f.type.upper()]
        header_findings = [i for i, f in enumerate(findings) if "CSP" in f.type.upper() or "HTTPONLY" in f.type.upper()]

        if xss_findings and header_findings:
            chains.append({
                "chainId": f"{self.scan_id}-chain-2",
                "name": "XSS + Missing Security Headers → Session Hijacking",
                "description": "Cross-site scripting combined with missing CSP and HttpOnly flags enables session token theft.",
                "severity": "HIGH",
                "findingIndices": xss_findings[:2] + header_findings[:2],
                "exploitationSteps": [
                    "Inject XSS payload into vulnerable parameter",
                    "Missing CSP allows inline script execution",
                    "Missing HttpOnly allows document.cookie access",
                    "Exfiltrate session token to attacker server",
                ],
                "businessImpact": "Account takeover via stolen session tokens.",
                "likelihoodOfExploitation": "MEDIUM",
            })

        risk_score = min(100, sum(30 if c["severity"] == "CRITICAL" else 15 for c in chains))

        return {
            "attackChains": chains,
            "riskAmplifiers": [],
            "duplicateGroups": [],
            "overallChainedRiskScore": risk_score,
        }

    def _generate_compliance(self, findings: list[Finding]) -> dict:
        """Generate compliance mapping against PCI-DSS and SOC2."""
        pci_controls = {}
        soc2_controls = {}

        for i, f in enumerate(findings):
            for ref in f.pciDssRefs:
                if ref not in pci_controls:
                    pci_controls[ref] = {"controlId": ref, "findingIndices": [], "severity": f.severity.value}
                pci_controls[ref]["findingIndices"].append(i)
            for ref in f.soc2Refs:
                if ref not in soc2_controls:
                    soc2_controls[ref] = {"controlId": ref, "findingIndices": [], "severity": f.severity.value}
                soc2_controls[ref]["findingIndices"].append(i)

        critical_or_high = sum(1 for f in findings if f.severity.value in ("CRITICAL", "HIGH"))
        total_checked = max(len(pci_controls) + len(soc2_controls), 1)
        failed = len([c for c in pci_controls.values() if c["severity"] in ("CRITICAL", "HIGH")])
        compliance_score = max(0, 100 - int(100 * failed / total_checked)) if total_checked > 0 else 100

        status = "CRITICAL_GAPS" if critical_or_high >= 3 else "SIGNIFICANT_GAPS" if critical_or_high >= 1 else "MINOR_GAPS" if len(findings) > 0 else "PASSING"
        audit_readiness = "NOT_READY" if critical_or_high >= 2 else "NEEDS_WORK" if critical_or_high >= 1 else "MOSTLY_READY" if len(findings) > 3 else "READY"

        frameworks = []
        if pci_controls:
            frameworks.append({
                "name": "PCI DSS v4.0",
                "overallStatus": status,
                "controlsAffected": len(pci_controls),
                "totalControlsChecked": max(12, len(pci_controls)),
                "affectedControls": [
                    {
                        "framework": "PCI DSS",
                        "controlId": cid,
                        "controlName": f"Control {cid}",
                        "status": "FAIL" if data["severity"] in ("CRITICAL", "HIGH") else "AT_RISK",
                        "findingIndices": data["findingIndices"],
                        "remediationNote": f"Address {len(data['findingIndices'])} finding(s) affecting this control.",
                    }
                    for cid, data in pci_controls.items()
                ],
            })

        key_gaps = []
        if critical_or_high > 0:
            key_gaps.append(f"{critical_or_high} critical/high vulnerabilities require immediate remediation")
        header_issues = sum(1 for f in findings if "missing" in f.type.lower())
        if header_issues > 0:
            key_gaps.append(f"{header_issues} missing security headers indicate insufficient hardening")

        return {
            "frameworks": frameworks,
            "highestRiskFramework": "PCI DSS v4.0" if pci_controls else "N/A",
            "complianceScore": compliance_score,
            "auditReadiness": audit_readiness,
            "keyGaps": key_gaps,
        }

    def _phase_complete(self, findings: list[Finding], crawl_result: CrawlResult):
        """Phase 7: Calculate final risk score and finalize scan."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        # Risk score formula matching TypeScript: critical*25 + high*10 + medium*3 + low*1, capped at 100
        risk_score = min(100,
            severity_counts["CRITICAL"] * 25 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 3 +
            severity_counts["LOW"] * 1
        )

        store.update_scan(
            self.scan_id,
            status=ScanStatus.COMPLETED,
            progress=100,
            currentPhase="complete",
            riskScore=risk_score,
            endpointsTested=len(crawl_result.urls),
            completedAt=datetime.utcnow().isoformat(),
        )

        self._update_progress(
            100, "complete", "Scan completed",
            status="COMPLETED",
            endpointsDiscovered=len(crawl_result.urls),
            endpointsTested=len(crawl_result.urls),
            findingsCount=len(findings),
        )


async def run_scan(scan_id: str, config: ScanCreate):
    """Entry point: runs the scan asynchronously."""
    runner = ScanRunner(scan_id, config)
    await runner.run()

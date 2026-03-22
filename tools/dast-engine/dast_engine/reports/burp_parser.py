"""
Burp Suite report parser -- extracts findings from Burp HTML/XML reports
for comparison against HemisX scan results.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BurpFinding:
    """A finding extracted from a Burp Suite report."""

    issue_id: str
    title: str
    severity: str  # High, Medium, Low, Information
    confidence: str  # Certain, Firm, Tentative
    host: str
    path: str
    url: str
    issue_detail: str = ""
    issue_background: str = ""
    remediation: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    cwe_ids: list[str] = field(default_factory=list)

    @property
    def normalized_severity(self) -> str:
        """Map Burp severity to HemisX severity."""
        return {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Information": "INFO",
        }.get(self.severity, "INFO")


# ---------------------------------------------------------------------------
# HTML parsing helpers
# ---------------------------------------------------------------------------

_TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    text = _TAG_STRIP_RE.sub(" ", text)
    return " ".join(text.split()).strip()


def _extract_between(html: str, start_marker: str, end_markers: list[str]) -> str:
    """Extract text between *start_marker* and the first occurrence of any
    string in *end_markers*.  Returns the raw HTML slice (caller should strip
    tags if needed)."""
    idx = html.find(start_marker)
    if idx == -1:
        return ""
    idx += len(start_marker)
    end_idx = len(html)
    for em in end_markers:
        pos = html.find(em, idx)
        if pos != -1 and pos < end_idx:
            end_idx = pos
    return html[idx:end_idx].strip()


def _extract_field(block: str, label: str) -> str:
    """Extract a Burp metadata field like ``Severity:.*<b>VALUE</b>``."""
    pattern = re.compile(rf"{label}:\s*.*?<b>(.*?)</b>", re.DOTALL | re.IGNORECASE)
    m = pattern.search(block)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------


def parse_burp_html(html_content: str) -> list[BurpFinding]:
    """Parse a Burp Suite HTML report and extract all findings.

    Burp HTML reports use the following conventions:
    - ``<span class="BODH0" id="N">`` for top-level issue headings
    - ``<span class="BODH1" id="N.M">`` for sub-instance headings
    - Metadata fields like Severity, Confidence, Host, Path appear as
      ``Label:&nbsp;...<b>Value</b>``
    - Sections such as *Issue detail*, *Issue background*, *Issue remediation*,
      *Request*, *Response* are introduced by ``<h2>`` headings followed by
      content spans or divs.
    """
    findings: list[BurpFinding] = []

    # Split into top-level issue blocks using the BODH0 markers.
    # Each BODH0 span starts a new issue; everything up to the next BODH0
    # (or end of file) belongs to that issue.
    issue_starts = [m.start() for m in re.finditer(r'<span\s+class="BODH0"', html_content)]
    if not issue_starts:
        return findings

    blocks: list[str] = []
    for i, start in enumerate(issue_starts):
        end = issue_starts[i + 1] if i + 1 < len(issue_starts) else len(html_content)
        blocks.append(html_content[start:end])

    for block in blocks:
        # --- Issue ID and title ---
        id_match = re.search(r'<span\s+class="BODH0"\s+id="(\d+)"[^>]*>', block)
        issue_id = id_match.group(1) if id_match else "0"

        # Title is the text content of the BODH0 span (up to the closing tag
        # or a line break).
        title_match = re.search(
            r'<span\s+class="BODH0"[^>]*>(.*?)</span>', block, re.DOTALL
        )
        title = _strip_html(title_match.group(1)) if title_match else "Unknown"

        # --- Metadata fields ---
        severity = _extract_field(block, "Severity")
        confidence = _extract_field(block, "Confidence")
        host = _extract_field(block, "Host")
        path = _extract_field(block, "Path")

        # Build URL from host + path
        url = host.rstrip("/") + "/" + path.lstrip("/") if host and path else host or path

        # --- Content sections ---
        section_end_markers = [
            "<h2>", '<span class="BODH0"', '<span class="BODH1"',
        ]

        issue_detail = _strip_html(
            _extract_between(block, "<h2>Issue detail</h2>", section_end_markers)
        )
        issue_background = _strip_html(
            _extract_between(block, "<h2>Issue background</h2>", section_end_markers)
        )
        remediation_text = _strip_html(
            _extract_between(block, "<h2>Issue remediation</h2>", section_end_markers)
        )
        # Also check for "Remediation detail"
        if not remediation_text:
            remediation_text = _strip_html(
                _extract_between(block, "<h2>Remediation detail</h2>", section_end_markers)
            )

        request_evidence = _strip_html(
            _extract_between(block, "<h2>Request</h2>", section_end_markers)
        )
        response_evidence = _strip_html(
            _extract_between(block, "<h2>Response</h2>", section_end_markers)
        )

        # --- CWE extraction (if present in detail/background) ---
        cwe_ids = re.findall(r"CWE-(\d+)", block)

        # --- Handle sub-instances (BODH1) ---
        # Each BODH1 block represents a specific URL/path instance of the
        # same top-level issue.  We emit one BurpFinding per sub-instance
        # when they exist; otherwise one finding for the top-level block.
        sub_starts = [m.start() for m in re.finditer(r'<span\s+class="BODH1"', block)]

        if sub_starts:
            for j, sstart in enumerate(sub_starts):
                send = sub_starts[j + 1] if j + 1 < len(sub_starts) else len(block)
                sub_block = block[sstart:send]

                sub_id_match = re.search(
                    r'<span\s+class="BODH1"\s+id="([\d.]+)"', sub_block
                )
                sub_id = sub_id_match.group(1) if sub_id_match else f"{issue_id}.{j+1}"

                sub_host = _extract_field(sub_block, "Host") or host
                sub_path = _extract_field(sub_block, "Path") or path
                sub_url = (
                    sub_host.rstrip("/") + "/" + sub_path.lstrip("/")
                    if sub_host and sub_path
                    else sub_host or sub_path
                )

                sub_detail = _strip_html(
                    _extract_between(sub_block, "<h2>Issue detail</h2>", section_end_markers)
                ) or issue_detail

                sub_request = _strip_html(
                    _extract_between(sub_block, "<h2>Request</h2>", section_end_markers)
                ) or request_evidence

                sub_response = _strip_html(
                    _extract_between(sub_block, "<h2>Response</h2>", section_end_markers)
                ) or response_evidence

                findings.append(
                    BurpFinding(
                        issue_id=sub_id,
                        title=title,
                        severity=severity or "Information",
                        confidence=confidence or "Tentative",
                        host=sub_host,
                        path=sub_path,
                        url=sub_url,
                        issue_detail=sub_detail,
                        issue_background=issue_background,
                        remediation=remediation_text,
                        request_evidence=sub_request,
                        response_evidence=sub_response,
                        cwe_ids=cwe_ids,
                    )
                )
        else:
            findings.append(
                BurpFinding(
                    issue_id=issue_id,
                    title=title,
                    severity=severity or "Information",
                    confidence=confidence or "Tentative",
                    host=host,
                    path=path,
                    url=url,
                    issue_detail=issue_detail,
                    issue_background=issue_background,
                    remediation=remediation_text,
                    request_evidence=request_evidence,
                    response_evidence=response_evidence,
                    cwe_ids=cwe_ids,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------


def parse_burp_xml(xml_content: str) -> list[BurpFinding]:
    """Parse a Burp Suite XML report and extract all findings.

    Burp XML exports use ``<issues>`` as the root element containing
    ``<issue>`` children.  Each ``<issue>`` has children like ``<name>``,
    ``<severity>``, ``<confidence>``, ``<host>``, ``<path>``,
    ``<issueDetail>``, ``<issueBackground>``, ``<remediationDetail>``,
    and optionally ``<requestresponse>`` elements with ``<request>``
    and ``<response>`` sub-elements.
    """
    findings: list[BurpFinding] = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return findings

    # The root might be <issues> directly, or it could wrap them.
    issues = root.findall(".//issue")

    for idx, issue_el in enumerate(issues):
        title = _xml_text(issue_el, "name")
        severity = _xml_text(issue_el, "severity") or "Information"
        confidence = _xml_text(issue_el, "confidence") or "Tentative"

        # Host may have an ``ip`` attribute
        host_el = issue_el.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""

        path = _xml_text(issue_el, "path")
        url = _xml_text(issue_el, "location") or (
            host.rstrip("/") + "/" + path.lstrip("/") if host and path else host or path
        )

        issue_detail = _strip_html(_xml_text(issue_el, "issueDetail"))
        issue_background = _strip_html(_xml_text(issue_el, "issueBackground"))
        remediation = _strip_html(
            _xml_text(issue_el, "remediationDetail")
            or _xml_text(issue_el, "remediationBackground")
        )

        # Serial number or index as ID
        serial = _xml_text(issue_el, "serialNumber") or str(idx + 1)
        type_index = _xml_text(issue_el, "type") or ""
        issue_id = serial if serial != str(idx + 1) else type_index or serial

        # Request / response evidence
        request_evidence = ""
        response_evidence = ""
        rr = issue_el.find("requestresponse")
        if rr is not None:
            req_el = rr.find("request")
            resp_el = rr.find("response")
            if req_el is not None and req_el.text:
                request_evidence = req_el.text.strip()
            if resp_el is not None and resp_el.text:
                response_evidence = resp_el.text.strip()

        # CWE extraction
        cwe_ids: list[str] = []
        vuln_classifications = issue_el.find("vulnerabilityClassifications")
        if vuln_classifications is not None and vuln_classifications.text:
            cwe_ids = re.findall(r"CWE-(\d+)", vuln_classifications.text)
        if not cwe_ids:
            # Try in detail/background text
            combined = issue_detail + " " + issue_background
            cwe_ids = re.findall(r"CWE-(\d+)", combined)

        findings.append(
            BurpFinding(
                issue_id=issue_id,
                title=title,
                severity=severity,
                confidence=confidence,
                host=host,
                path=path,
                url=url,
                issue_detail=issue_detail,
                issue_background=issue_background,
                remediation=remediation,
                request_evidence=request_evidence,
                response_evidence=response_evidence,
                cwe_ids=cwe_ids,
            )
        )

    return findings


def _xml_text(parent: ET.Element, tag: str) -> str:
    """Safely extract text from an XML child element."""
    el = parent.find(tag)
    if el is not None and el.text:
        return el.text.strip()
    return ""

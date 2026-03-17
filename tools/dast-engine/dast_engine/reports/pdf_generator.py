"""Professional PDF report generator using ReportLab with CVSS scoring and PoC details."""
from __future__ import annotations
import io
import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ..models.scan import ScanResponse
from ..models.finding import Finding

# Color palette
PURPLE = colors.HexColor("#7c3aed")
DARK_BG = colors.HexColor("#1a1a2e")
LIGHT_BG = colors.HexColor("#f8f7ff")
BORDER = colors.HexColor("#e5e0ff")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#ca8a04"),
    "LOW": colors.HexColor("#2563eb"),
    "INFO": colors.HexColor("#6b7280"),
}


def generate_pdf(scan: ScanResponse, findings: list[Finding]) -> bytes:
    """Generate a professional PDF security report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=25*mm, bottomMargin=20*mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=28, textColor=PURPLE, spaceAfter=6, fontName="Helvetica-Bold")
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=12, textColor=colors.gray, spaceAfter=20)
    heading_style = ParagraphStyle("SectionHeading", parent=styles["Heading2"], fontSize=14, textColor=PURPLE, spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold", borderWidth=0, borderPadding=0)
    body_style = ParagraphStyle("BodyText", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=6)
    small_style = ParagraphStyle("SmallText", parent=styles["Normal"], fontSize=8, textColor=colors.gray)
    code_style = ParagraphStyle("CodeText", parent=styles["Normal"], fontSize=8, fontName="Courier", leading=11, backColor=colors.HexColor("#f1f5f9"), spaceBefore=4, spaceAfter=4)
    sev_style = lambda color: ParagraphStyle("Sev", parent=styles["Normal"], fontSize=10, textColor=color, fontName="Helvetica-Bold")

    elements = []

    # ── Cover Page ──
    elements.append(Spacer(1, 60))
    elements.append(Paragraph("DAST Security Report", title_style))
    elements.append(HRFlowable(width="100%", thickness=3, color=PURPLE, spaceAfter=12))
    elements.append(Paragraph(f"Target: {scan.targetUrl}", subtitle_style))

    # Meta table
    meta_data = [
        ["Scan Name", scan.name, "Profile", scan.scanProfile],
        ["Status", scan.status.value, "Risk Score", str(scan.riskScore or 0)],
        ["Started", _fmt_date(scan.startedAt), "Completed", _fmt_date(scan.completedAt)],
        ["Endpoints Discovered", str(scan.endpointsDiscovered), "Endpoints Tested", str(scan.endpointsTested)],
        ["Payloads Sent", str(scan.payloadsSent), "Total Findings", str(len(findings))],
    ]
    meta_table = Table(meta_data, colWidths=[90, 140, 90, 140])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.gray),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.gray),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
    ]))
    elements.append(Spacer(1, 20))
    elements.append(meta_table)

    # Severity distribution
    elements.append(Spacer(1, 20))
    sev_data = [
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        [str(scan.criticalCount), str(scan.highCount), str(scan.mediumCount), str(scan.lowCount), str(scan.infoCount)],
    ]
    sev_table = Table(sev_data, colWidths=[85]*5)
    sev_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TEXTCOLOR", (0, 0), (0, -1), SEV_COLORS["CRITICAL"]),
        ("TEXTCOLOR", (1, 0), (1, -1), SEV_COLORS["HIGH"]),
        ("TEXTCOLOR", (2, 0), (2, -1), SEV_COLORS["MEDIUM"]),
        ("TEXTCOLOR", (3, 0), (3, -1), SEV_COLORS["LOW"]),
        ("TEXTCOLOR", (4, 0), (4, -1), SEV_COLORS["INFO"]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
    ]))
    elements.append(sev_table)

    # Tech stack
    if scan.techStackDetected:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"<b>Technology Stack:</b> {', '.join(scan.techStackDetected)}", body_style))

    elements.append(PageBreak())

    # ── Executive Summary ──
    if scan.executiveSummary:
        elements.append(Paragraph("Executive Summary", title_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=PURPLE, spaceAfter=12))
        for line in scan.executiveSummary.split("\n"):
            line = line.strip()
            if line.startswith("## "):
                elements.append(Paragraph(line.replace("## ", ""), heading_style))
            elif line.startswith("- **"):
                # Bold list items
                elements.append(Paragraph(f"  {_md_to_html(line)}", body_style))
            elif line.startswith("- "):
                elements.append(Paragraph(f"  {_md_to_html(line)}", body_style))
            elif line:
                elements.append(Paragraph(_md_to_html(line), body_style))
        elements.append(PageBreak())

    # ── Findings Summary Table ──
    elements.append(Paragraph("Findings Summary", title_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=PURPLE, spaceAfter=12))

    if findings:
        table_data = [["#", "Severity", "CVSS", "Title", "OWASP", "Confidence"]]
        for i, f in enumerate(findings):
            table_data.append([
                str(i + 1),
                f.severity.value,
                f"{f.cvssScore:.1f}" if f.cvssScore else "-",
                _truncate(f.title, 40),
                f.owaspCategory.split(" ")[0] if f.owaspCategory else "-",
                f"{f.confidenceScore}%",
            ])

        findings_table = Table(table_data, colWidths=[25, 60, 40, 200, 70, 55])
        findings_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), PURPLE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (2, 1), (2, -1), "CENTER"),
            ("ALIGN", (5, 1), (5, -1), "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ]))

        # Color severity cells
        for i, f in enumerate(findings):
            row = i + 1
            sev_color = SEV_COLORS.get(f.severity.value, colors.gray)
            findings_table.setStyle(TableStyle([("TEXTCOLOR", (1, row), (1, row), sev_color)]))

        elements.append(findings_table)
    elements.append(PageBreak())

    # ── Detailed Findings ──
    elements.append(Paragraph("Detailed Findings", title_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=PURPLE, spaceAfter=12))

    for i, f in enumerate(findings):
        sev_color = SEV_COLORS.get(f.severity.value, colors.gray)

        finding_elements = []
        finding_elements.append(Paragraph(
            f"<font color='{sev_color.hexval()}'>[{f.severity.value}]</font> "
            f"Finding #{i+1}: {_escape(f.title)}", heading_style
        ))

        # CVSS info
        cvss_text = f"<b>CVSS v3.1:</b> {f.cvssScore:.1f} ({f.severity.value})"
        if f.cvssVector:
            cvss_text += f" &nbsp;|&nbsp; <font size='7' color='gray'>{f.cvssVector}</font>"
        finding_elements.append(Paragraph(cvss_text, body_style))

        # Meta
        finding_elements.append(Paragraph(f"<b>OWASP:</b> {f.owaspCategory} &nbsp;|&nbsp; <b>CWE:</b> {f.cweId or 'N/A'} &nbsp;|&nbsp; <b>Confidence:</b> {f.confidenceScore}%", body_style))
        finding_elements.append(Paragraph(f"<b>URL:</b> <font color='{PURPLE.hexval()}'>{_escape(f.affectedUrl)}</font>", body_style))
        if f.affectedParameter:
            finding_elements.append(Paragraph(f"<b>Parameter:</b> <font name='Courier'>{_escape(f.affectedParameter)}</font>", body_style))

        # Description
        finding_elements.append(Spacer(1, 6))
        finding_elements.append(Paragraph("<b>Description</b>", body_style))
        finding_elements.append(Paragraph(_escape(f.description), body_style))

        # Business Impact
        if f.businessImpact:
            finding_elements.append(Paragraph("<b>Business Impact</b>", body_style))
            finding_elements.append(Paragraph(_escape(f.businessImpact), body_style))

        # Proof of Concept
        if f.payload or f.requestEvidence or f.responseEvidence:
            finding_elements.append(Spacer(1, 4))
            finding_elements.append(Paragraph("<b>Proof of Concept</b>", body_style))
            if f.payload:
                finding_elements.append(Paragraph(f"<b>Payload:</b>", small_style))
                finding_elements.append(Paragraph(_escape(f.payload), code_style))
            if f.requestEvidence:
                finding_elements.append(Paragraph(f"<b>Request:</b>", small_style))
                finding_elements.append(Paragraph(_escape(f.requestEvidence), code_style))
            if f.responseEvidence:
                finding_elements.append(Paragraph(f"<b>Response Evidence:</b>", small_style))
                finding_elements.append(Paragraph(_escape(f.responseEvidence[:500]), code_style))

        # Remediation
        finding_elements.append(Spacer(1, 4))
        finding_elements.append(Paragraph("<b>Remediation</b>", body_style))
        finding_elements.append(Paragraph(_escape(f.remediation), body_style))

        # Remediation Code
        if f.remediationCode:
            try:
                code_data = json.loads(f.remediationCode)
                if code_data.get("vulnerableCode"):
                    finding_elements.append(Paragraph("<b>Vulnerable Code:</b>", small_style))
                    finding_elements.append(Paragraph(_escape(code_data["vulnerableCode"]), code_style))
                if code_data.get("remediatedCode"):
                    finding_elements.append(Paragraph("<b>Fixed Code:</b>", small_style))
                    finding_elements.append(Paragraph(_escape(code_data["remediatedCode"]), code_style))
                if code_data.get("explanation"):
                    finding_elements.append(Paragraph(f"<i>{_escape(code_data['explanation'])}</i>", small_style))
            except (json.JSONDecodeError, KeyError):
                pass

        # Compliance References
        refs = []
        if f.pciDssRefs:
            refs.append(f"PCI DSS: {', '.join(f.pciDssRefs)}")
        if f.soc2Refs:
            refs.append(f"SOC 2: {', '.join(f.soc2Refs)}")
        if f.mitreAttackIds:
            refs.append(f"MITRE ATT&CK: {', '.join(f.mitreAttackIds)}")
        if refs:
            finding_elements.append(Spacer(1, 4))
            finding_elements.append(Paragraph(f"<b>Compliance:</b> {' | '.join(refs)}", small_style))

        finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceBefore=8, spaceAfter=8))

        elements.extend(finding_elements)

    # ── Footer ──
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=PURPLE))
    elements.append(Paragraph(
        f"Generated by HemisX DAST Engine on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.gray, alignment=TA_CENTER),
    ))

    doc.build(elements)
    return buffer.getvalue()


def generate_json_report(scan: ScanResponse, findings: list[Finding]) -> dict:
    """Generate structured JSON report."""
    return {
        "report": {
            "generatedAt": datetime.utcnow().isoformat(),
            "scan": {
                "id": scan.id, "name": scan.name, "targetUrl": scan.targetUrl,
                "scanProfile": scan.scanProfile, "status": scan.status.value,
                "riskScore": scan.riskScore,
                "severityCounts": {
                    "critical": scan.criticalCount, "high": scan.highCount,
                    "medium": scan.mediumCount, "low": scan.lowCount, "info": scan.infoCount,
                },
                "endpoints": {"discovered": scan.endpointsDiscovered, "tested": scan.endpointsTested},
                "payloadsSent": scan.payloadsSent,
                "techStack": scan.techStackDetected,
                "startedAt": scan.startedAt, "completedAt": scan.completedAt,
            },
            "executiveSummary": scan.executiveSummary,
            "findings": [f.model_dump() for f in findings],
        }
    }


def generate_csv_report(scan: ScanResponse, findings: list[Finding]) -> str:
    """Generate CSV report."""
    headers = ["ID", "Severity", "CVSS", "Title", "Type", "OWASP", "CWE", "URL", "Parameter", "Payload", "Confidence", "Status", "Remediation"]
    rows = [",".join(headers)]
    for f in findings:
        row = [
            f.id, f.severity.value, str(f.cvssScore or ""),
            _csv_escape(f.title), f.type, f.owaspCategory or "", f.cweId or "",
            _csv_escape(f.affectedUrl), f.affectedParameter or "",
            _csv_escape(f.payload or ""), str(f.confidenceScore),
            f.status.value, _csv_escape(f.remediation),
        ]
        rows.append(",".join(row))
    return "\ufeff" + "\n".join(rows)


def _fmt_date(dt_str: str | None) -> str:
    if not dt_str:
        return "N/A"
    try:
        return datetime.fromisoformat(dt_str).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return dt_str


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_to_html(text: str) -> str:
    import re
    text = _escape(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'`(.+?)`', r'<font name="Courier" size="8">\1</font>', text)
    return text


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[:max_len-3] + "..."


def _csv_escape(text: str) -> str:
    if not text:
        return ""
    text = text.replace('"', '""')
    if any(c in text for c in [",", '"', "\n"]):
        return f'"{text}"'
    return text

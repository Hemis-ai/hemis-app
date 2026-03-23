/**
 * HemisX DAST — Real PDF Report Generator using PDFKit
 * Generates professional security assessment PDFs with findings, charts, and compliance data.
 */

import PDFDocument from 'pdfkit'
import type { ReportData } from './html-template'

const SEV_HEX: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

function sevHex(severity: string): string {
  return SEV_HEX[severity] || '#6b7280'
}

export async function generatePdfReport(data: ReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `HemisX DAST Report — ${data.scan.name}`,
          Author: 'HemisX Security Platform',
          Subject: `DAST Security Assessment of ${data.scan.targetUrl}`,
          Creator: 'HemisX DAST Scanner',
        },
      })

      const chunks: Buffer[] = []
      doc.on('data', (chunk: Buffer) => chunks.push(chunk))
      doc.on('end', () => resolve(Buffer.concat(chunks)))
      doc.on('error', reject)

      const pageWidth = doc.page.width - 100

      // ── Cover Section ──
      doc.fontSize(8).fillColor('#6b7280').text('CONFIDENTIAL — SECURITY ASSESSMENT REPORT', { align: 'center' })
      doc.moveDown(3)
      doc.fontSize(28).fillColor('#111827').text('DAST Security', { align: 'center' })
      doc.fontSize(28).fillColor('#111827').text('Assessment Report', { align: 'center' })
      doc.moveDown(1)
      doc.fontSize(12).fillColor('#6b7280').text(data.scan.targetUrl, { align: 'center' })
      doc.moveDown(0.5)
      doc.fontSize(10).fillColor('#9ca3af').text(`Scan: ${data.scan.name}`, { align: 'center' })
      doc.fontSize(10).text(`Profile: ${data.scan.scanProfile.toUpperCase()}`, { align: 'center' })
      doc.fontSize(10).text(`Generated: ${new Date(data.generatedAt).toLocaleString()}`, { align: 'center' })

      doc.moveDown(3)

      // ── Risk Score Box ──
      const riskScore = data.scan.riskScore
      const riskHex = riskScore >= 75 ? '#ef4444' : riskScore >= 50 ? '#f97316' : riskScore >= 25 ? '#eab308' : '#22c55e'
      const grade = riskScore >= 75 ? 'F' : riskScore >= 50 ? 'D' : riskScore >= 25 ? 'C' : riskScore >= 10 ? 'B' : 'A'

      doc.rect(50, doc.y, pageWidth, 60).fillAndStroke('#f9fafb', '#e5e7eb')
      const boxY = doc.y + 10
      doc.fontSize(32).fillColor(riskHex).text(`${riskScore}`, 70, boxY, { width: 80 })
      doc.fontSize(10).fillColor('#6b7280').text('RISK SCORE', 70, boxY + 36, { width: 80 })

      doc.fontSize(28).fillColor(riskHex).text(grade, 170, boxY, { width: 50 })
      doc.fontSize(10).fillColor('#6b7280').text('GRADE', 170, boxY + 36, { width: 50 })

      // Severity counts
      const counts = [
        { label: 'CRITICAL', count: data.counts.critical, color: SEV_HEX.CRITICAL },
        { label: 'HIGH', count: data.counts.high, color: SEV_HEX.HIGH },
        { label: 'MEDIUM', count: data.counts.medium, color: SEV_HEX.MEDIUM },
        { label: 'LOW', count: data.counts.low, color: SEV_HEX.LOW },
        { label: 'INFO', count: data.counts.info, color: SEV_HEX.INFO },
      ]
      let countX = 260
      for (const c of counts) {
        doc.fontSize(16).fillColor(c.color).text(`${c.count}`, countX, boxY + 4, { width: 40 })
        doc.fontSize(7).fillColor('#6b7280').text(c.label, countX, boxY + 22, { width: 50 })
        countX += 50
      }

      doc.y = boxY + 70

      // ── Scan Details ──
      doc.moveDown(1)
      doc.fontSize(14).fillColor('#111827').text('Scan Details')
      doc.moveDown(0.5)
      const details = [
        ['Target URL', data.scan.targetUrl],
        ['Scan Profile', data.scan.scanProfile.toUpperCase()],
        ['Started', data.scan.startedAt ? new Date(data.scan.startedAt).toLocaleString() : 'N/A'],
        ['Completed', data.scan.completedAt ? new Date(data.scan.completedAt).toLocaleString() : 'N/A'],
        ['Endpoints Discovered', `${data.scan.endpointsDiscovered}`],
        ['Endpoints Tested', `${data.scan.endpointsTested}`],
        ['Payloads Sent', `${data.scan.payloadsSent}`],
        ['Technology Stack', data.scan.techStackDetected.join(', ') || 'Not detected'],
      ]
      for (const [label, value] of details) {
        doc.fontSize(9).fillColor('#6b7280').text(`${label}:`, 50, doc.y, { continued: true, width: 140 })
        doc.fillColor('#111827').text(` ${value}`)
      }

      // ── Executive Summary ──
      if (data.executiveSummary) {
        doc.moveDown(1.5)
        doc.fontSize(14).fillColor('#111827').text('Executive Summary')
        doc.moveDown(0.5)
        const plainSummary = data.executiveSummary.replace(/\*\*/g, '').replace(/##\s*/g, '').replace(/- /g, '• ')
        doc.fontSize(9).fillColor('#374151').text(plainSummary, { width: pageWidth, lineGap: 2 })
      }

      // ── Findings ──
      doc.addPage()
      doc.fontSize(18).fillColor('#111827').text('Detailed Findings')
      doc.moveDown(0.3)
      doc.fontSize(9).fillColor('#6b7280').text(`${data.counts.total} vulnerabilities identified`)
      doc.moveDown(1)

      for (let i = 0; i < data.findings.length; i++) {
        const f = data.findings[i]
        const color = sevHex(f.severity)

        // Check page space
        if (doc.y > 680) doc.addPage()

        // Finding header bar
        doc.rect(50, doc.y, pageWidth, 22).fill(color)
        doc.fontSize(9).fillColor('#ffffff')
          .text(`${f.severity} — ${f.title}`, 56, doc.y - 16, { width: pageWidth - 12 })

        doc.moveDown(0.3)

        // CVSS + confidence
        const meta: string[] = []
        if (f.cvssScore != null) meta.push(`CVSS: ${f.cvssScore}`)
        if (f.cvssVector) meta.push(`Vector: ${f.cvssVector}`)
        if (f.confidenceScore) meta.push(`Confidence: ${f.confidenceScore}%`)
        if (meta.length) doc.fontSize(8).fillColor('#6b7280').text(meta.join(' | '), 54)

        // Affected URL
        doc.fontSize(8).fillColor('#374151').text(`URL: ${f.affectedUrl}`, 54)
        if (f.affectedParameter) doc.text(`Parameter: ${f.affectedParameter}`, 54)

        // Description
        doc.moveDown(0.3)
        doc.fontSize(9).fillColor('#111827').text(f.description, 54, doc.y, { width: pageWidth - 10, lineGap: 1.5 })

        // Business Impact
        if (f.businessImpact) {
          doc.moveDown(0.3)
          doc.fontSize(8).fillColor('#b45309').text('Business Impact: ', 54, doc.y, { continued: true })
          doc.fillColor('#78350f').text(f.businessImpact, { width: pageWidth - 10 })
        }

        // Remediation
        doc.moveDown(0.3)
        doc.fontSize(8).fillColor('#059669').text('Remediation: ', 54, doc.y, { continued: true })
        doc.fillColor('#064e3b').text(f.remediation, { width: pageWidth - 10 })

        // Compliance refs
        const refs: string[] = []
        if (f.owaspCategory) refs.push(f.owaspCategory)
        if (f.cweId) refs.push(f.cweId)
        for (const mid of (f.mitreAttackIds || [])) refs.push(mid)
        for (const pci of (f.pciDssRefs || [])) refs.push(pci)
        for (const soc of (f.soc2Refs || [])) refs.push(soc)
        if (refs.length) {
          doc.moveDown(0.2)
          doc.fontSize(7).fillColor('#6b7280').text(`Refs: ${refs.join(' · ')}`, 54, doc.y, { width: pageWidth - 10 })
        }

        doc.moveDown(1)

        // Separator
        doc.strokeColor('#e5e7eb').lineWidth(0.5)
          .moveTo(50, doc.y).lineTo(50 + pageWidth, doc.y).stroke()
        doc.moveDown(0.5)
      }

      // ── Compliance Summary ──
      doc.addPage()
      doc.fontSize(18).fillColor('#111827').text('Compliance Mapping')
      doc.moveDown(1)

      // OWASP Top 10
      doc.fontSize(12).fillColor('#111827').text('OWASP Top 10 Coverage')
      doc.moveDown(0.5)
      const owaspCounts: Record<string, number> = {}
      for (const f of data.findings) {
        if (f.owaspCategory) owaspCounts[f.owaspCategory] = (owaspCounts[f.owaspCategory] || 0) + 1
      }
      if (Object.keys(owaspCounts).length > 0) {
        for (const [cat, count] of Object.entries(owaspCounts).sort((a, b) => b[1] - a[1])) {
          const barWidth = Math.min((count / Math.max(data.counts.total, 1)) * pageWidth * 2, pageWidth - 150)
          doc.rect(50, doc.y, barWidth, 12).fill('#eab308')
          doc.fontSize(8).fillColor('#111827').text(`${cat} (${count})`, 56, doc.y - 10)
          doc.moveDown(0.8)
        }
      } else {
        doc.fontSize(9).fillColor('#6b7280').text('No OWASP categories mapped')
      }

      // PCI-DSS
      doc.moveDown(1)
      doc.fontSize(12).fillColor('#111827').text('PCI-DSS References')
      doc.moveDown(0.5)
      const pciCounts: Record<string, number> = {}
      for (const f of data.findings) {
        for (const ref of (f.pciDssRefs || [])) pciCounts[ref] = (pciCounts[ref] || 0) + 1
      }
      if (Object.keys(pciCounts).length > 0) {
        for (const [ref, count] of Object.entries(pciCounts).sort((a, b) => b[1] - a[1])) {
          doc.fontSize(9).fillColor('#374151').text(`${ref}: ${count} finding${count > 1 ? 's' : ''}`, 54)
        }
      } else {
        doc.fontSize(9).fillColor('#6b7280').text('No PCI-DSS references')
      }

      // SOC2
      doc.moveDown(1)
      doc.fontSize(12).fillColor('#111827').text('SOC 2 References')
      doc.moveDown(0.5)
      const soc2Counts: Record<string, number> = {}
      for (const f of data.findings) {
        for (const ref of (f.soc2Refs || [])) soc2Counts[ref] = (soc2Counts[ref] || 0) + 1
      }
      if (Object.keys(soc2Counts).length > 0) {
        for (const [ref, count] of Object.entries(soc2Counts).sort((a, b) => b[1] - a[1])) {
          doc.fontSize(9).fillColor('#374151').text(`${ref}: ${count} finding${count > 1 ? 's' : ''}`, 54)
        }
      } else {
        doc.fontSize(9).fillColor('#6b7280').text('No SOC 2 references')
      }

      // MITRE ATT&CK
      doc.moveDown(1)
      doc.fontSize(12).fillColor('#111827').text('MITRE ATT&CK Techniques')
      doc.moveDown(0.5)
      const mitreCounts: Record<string, number> = {}
      for (const f of data.findings) {
        for (const id of (f.mitreAttackIds || [])) mitreCounts[id] = (mitreCounts[id] || 0) + 1
      }
      if (Object.keys(mitreCounts).length > 0) {
        for (const [id, count] of Object.entries(mitreCounts).sort((a, b) => b[1] - a[1])) {
          doc.fontSize(9).fillColor('#374151').text(`${id}: ${count} finding${count > 1 ? 's' : ''}`, 54)
        }
      } else {
        doc.fontSize(9).fillColor('#6b7280').text('No MITRE ATT&CK techniques mapped')
      }

      // ── Footer on each page ──
      const pageCount = doc.bufferedPageRange()
      for (let i = 0; i < pageCount.count; i++) {
        doc.switchToPage(i)
        doc.fontSize(7).fillColor('#9ca3af')
          .text(
            `HemisX DAST Security Report | ${data.scan.targetUrl} | Page ${i + 1} of ${pageCount.count} | ${new Date(data.generatedAt).toLocaleDateString()}`,
            50, doc.page.height - 35,
            { align: 'center', width: pageWidth }
          )
      }

      doc.end()
    } catch (err) {
      reject(err)
    }
  })
}

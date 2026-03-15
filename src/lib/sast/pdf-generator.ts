// HemisX SAST — PDF Report Generator
// Delegates to scripts/generate-pdf.cjs via child_process to avoid
// Turbopack's __dirname mangling that breaks pdfkit's font loading.

import { execFile } from 'child_process'
import path from 'path'
import type { ExecutiveReport } from '@/lib/sast/report-generator'

/**
 * Generate a PDF buffer from an ExecutiveReport.
 * Spawns a standalone Node.js script so pdfkit runs outside Turbopack's
 * bundle context, where __dirname resolves correctly.
 */
export function generatePdf(report: ExecutiveReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(process.cwd(), 'scripts', 'generate-pdf.cjs')
    const input = JSON.stringify({ report })

    const child = execFile(
      process.execPath,           // node binary
      [scriptPath],
      {
        encoding: 'buffer' as BufferEncoding,
        maxBuffer: 50 * 1024 * 1024,  // 50 MB
      },
      (error, stdout, stderr) => {
        if (error) {
          const stderrText = stderr ? Buffer.from(stderr).toString('utf8') : ''
          reject(new Error(`PDF generation failed: ${error.message}\n${stderrText}`))
          return
        }
        resolve(Buffer.from(stdout))
      }
    )

    // Pipe report JSON into the child's stdin
    if (child.stdin) {
      child.stdin.write(input)
      child.stdin.end()
    }
  })
}

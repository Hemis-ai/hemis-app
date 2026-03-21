import { NextRequest, NextResponse } from 'next/server'
import { MOCK_SAST_SCANS_FOR_IMPORT } from '@/lib/mock-data/wbrt'

/**
 * GET /api/wbrt/import-sast/[scanId] — Get SAST scan summary for import preview
 *
 * In demo mode (no DB / no real SAST data), returns mock scan metadata.
 * When a real SAST scan is available, fetches its summary from the SAST API.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  try {
    const { scanId } = await params

    // Try to fetch real SAST scan data
    try {
      const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:7777'
      const res = await fetch(`${baseUrl}/api/sast/scan/${scanId}`, {
        headers: { 'Content-Type': 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        return NextResponse.json({
          scan: {
            id: data.id || scanId,
            name: data.name || 'SAST Scan',
            date: data.completedAt || data.createdAt || new Date().toISOString(),
            findingsCount: data.summary?.total || data.findings?.length || 0,
            summary: data.summary || null,
            language: data.language || null,
            filesScanned: data.filesScanned || 0,
          },
        })
      }
    } catch {
      // SAST API not available — fall through to demo mode
    }

    // Demo mode: return mock data
    const mockScan = MOCK_SAST_SCANS_FOR_IMPORT.find(s => s.id === scanId)
    if (mockScan) {
      return NextResponse.json({ scan: mockScan })
    }

    // If scanId doesn't match any mock, return the first mock as a fallback
    if (MOCK_SAST_SCANS_FOR_IMPORT.length > 0) {
      return NextResponse.json({
        scan: { ...MOCK_SAST_SCANS_FOR_IMPORT[0], id: scanId },
        demo: true,
      })
    }

    return NextResponse.json({ error: 'SAST scan not found' }, { status: 404 })
  } catch (err) {
    console.error('[WBRT] GET /api/wbrt/import-sast/[scanId] error:', err)
    return NextResponse.json({ error: 'Failed to fetch SAST scan' }, { status: 500 })
  }
}

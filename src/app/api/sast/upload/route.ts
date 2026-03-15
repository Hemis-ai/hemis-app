import { NextRequest, NextResponse } from 'next/server'
import { getStorage } from '@/lib/sast/storage'
import { getScanQueue } from '@/lib/sast/job-queue'
import { randomUUID } from 'crypto'

/**
 * POST /api/sast/upload
 * Upload files for async scanning.
 * Accepts multipart/form-data with files, or JSON with file content.
 * Returns a job ID for polling scan status.
 *
 * Multipart: FormData with 'files' field (multiple)
 * JSON: { name: string, files: [{ path: string, content: string }], async?: boolean }
 */
export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get('content-type') || ''
    const scanId = randomUUID()
    const storage = getStorage()
    const queue = getScanQueue()

    let files: { path: string; content: string }[] = []
    let scanName = 'Uploaded Scan'

    if (contentType.includes('multipart/form-data')) {
      // Handle multipart file upload
      const formData = await req.formData()
      scanName = (formData.get('name') as string) || scanName

      const uploadedFiles = formData.getAll('files')
      for (const file of uploadedFiles) {
        if (file instanceof File) {
          const content = await file.text()
          const filePath = file.name
          files.push({ path: filePath, content })

          // Store file
          await storage.putFile(scanId, filePath, content)
        }
      }
    } else {
      // Handle JSON upload
      const body = await req.json()
      files = body.files || []
      scanName = body.name || scanName

      // Store files
      for (const file of files) {
        await storage.putFile(scanId, file.path, file.content)
      }
    }

    if (files.length === 0) {
      return NextResponse.json({ error: 'No files provided' }, { status: 400 })
    }

    // Submit to job queue
    const jobId = await queue.enqueue({
      id:        `job-${scanId}`,
      scanId,
      name:      scanName,
      files,
      orgId:     'demo-org',
      userId:    'demo-user',
      priority:  'normal',
      createdAt: new Date().toISOString(),
    })

    return NextResponse.json({
      jobId,
      scanId,
      status: 'queued',
      filesUploaded: files.length,
      totalSize: files.reduce((sum, f) => sum + f.content.length, 0),
      message: 'Files uploaded and scan queued. Poll /api/sast/jobs/:jobId for status.',
    }, { status: 202 })

  } catch (err) {
    console.error('[SAST Upload] Error:', err)
    return NextResponse.json({ error: 'Upload failed' }, { status: 500 })
  }
}

import { NextRequest, NextResponse } from 'next/server'
import { getScanQueue } from '@/lib/sast/job-queue'

/**
 * GET /api/sast/jobs/:id
 * Poll async scan job status.
 * Returns: { jobId, scanId, status, progress, result?, error? }
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const queue = getScanQueue()

  const status = await queue.getStatus(id)
  if (!status) {
    return NextResponse.json({ error: 'Job not found' }, { status: 404 })
  }

  return NextResponse.json(status)
}

/**
 * DELETE /api/sast/jobs/:id
 * Cancel a queued scan job.
 */
export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const queue = getScanQueue()

  const cancelled = await queue.cancel(id)
  if (!cancelled) {
    return NextResponse.json({ error: 'Job cannot be cancelled (already processing or not found)' }, { status: 400 })
  }

  return NextResponse.json({ success: true, message: 'Job cancelled' })
}

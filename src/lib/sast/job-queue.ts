// HemisX SAST — Job Queue Abstraction
// Provides async scan processing with pluggable backends:
// - In-memory queue (development / serverless)
// - BullMQ + Redis (production / self-hosted)
//
// Scans are submitted as jobs and processed asynchronously by workers.

import { Queue, Worker, Job as BullJob } from 'bullmq'
import type IORedis from 'ioredis'

// ─── Job Types ──────────────────────────────────────────────────────────────

export interface ScanJob {
  id:        string
  scanId:    string
  name:      string
  files:     { path: string; content: string }[]
  language?: string
  orgId:     string
  userId:    string
  priority:  'low' | 'normal' | 'high'
  createdAt: string
}

export type JobStatus = 'queued' | 'processing' | 'completed' | 'failed'

export interface JobResult {
  jobId:     string
  scanId:    string
  status:    JobStatus
  progress:  number  // 0-100
  result?:   unknown
  error?:    string
  startedAt?: string
  completedAt?: string
}

export type ScanWorkerFn = (job: ScanJob) => Promise<unknown>

// ─── Queue Interface ────────────────────────────────────────────────────────

export interface ScanQueue {
  enqueue(job: ScanJob): Promise<string>
  getStatus(jobId: string): Promise<JobResult | null>
  cancel(jobId: string): Promise<boolean>
  registerWorker(fn: ScanWorkerFn): void
  getQueueStats(): Promise<{ queued: number; processing: number; completed: number; failed: number }>
}

// ─── In-Memory Queue (Development / Serverless) ─────────────────────────────

export class InMemoryQueue implements ScanQueue {
  private jobs: Map<string, { job: ScanJob; result: JobResult }> = new Map()
  private workerFn: ScanWorkerFn | null = null
  private processing: Set<string> = new Set()

  async enqueue(job: ScanJob): Promise<string> {
    const jobId = job.id || `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

    this.jobs.set(jobId, {
      job: { ...job, id: jobId },
      result: {
        jobId,
        scanId: job.scanId,
        status: 'queued',
        progress: 0,
      },
    })

    // Process immediately in background (non-blocking)
    if (this.workerFn) {
      this.processJob(jobId).catch(err => {
        console.error(`[Queue] Job ${jobId} failed:`, err)
      })
    }

    return jobId
  }

  private async processJob(jobId: string): Promise<void> {
    const entry = this.jobs.get(jobId)
    if (!entry || !this.workerFn) return

    this.processing.add(jobId)
    entry.result.status = 'processing'
    entry.result.progress = 10
    entry.result.startedAt = new Date().toISOString()

    try {
      const result = await this.workerFn(entry.job)
      entry.result.status = 'completed'
      entry.result.progress = 100
      entry.result.result = result
      entry.result.completedAt = new Date().toISOString()
    } catch (err) {
      entry.result.status = 'failed'
      entry.result.error = err instanceof Error ? err.message : 'Unknown error'
      entry.result.completedAt = new Date().toISOString()
    } finally {
      this.processing.delete(jobId)
    }
  }

  async getStatus(jobId: string): Promise<JobResult | null> {
    return this.jobs.get(jobId)?.result ?? null
  }

  async cancel(jobId: string): Promise<boolean> {
    const entry = this.jobs.get(jobId)
    if (!entry || entry.result.status !== 'queued') return false
    entry.result.status = 'failed'
    entry.result.error = 'Cancelled by user'
    return true
  }

  registerWorker(fn: ScanWorkerFn): void {
    this.workerFn = fn
  }

  async getQueueStats(): Promise<{ queued: number; processing: number; completed: number; failed: number }> {
    let queued = 0, processing = 0, completed = 0, failed = 0
    for (const entry of Array.from(this.jobs.values())) {
      switch (entry.result.status) {
        case 'queued': queued++; break
        case 'processing': processing++; break
        case 'completed': completed++; break
        case 'failed': failed++; break
      }
    }
    return { queued, processing, completed, failed }
  }
}

// ─── BullMQ + Redis Queue (Production) ──────────────────────────────────────

export class BullMQQueue implements ScanQueue {
  private queue: Queue
  private worker: Worker | null = null

  constructor(redisConnection: IORedis) {
    this.queue = new Queue('hemisx-sast-scans', {
      connection: redisConnection as unknown as import('bullmq').ConnectionOptions,
      defaultJobOptions: {
        removeOnComplete: { age: 86400, count: 1000 }, // Keep 24h or 1000 jobs
        removeOnFail: { age: 604800, count: 5000 },    // Keep 7 days
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 1000,
        },
      },
    })
  }

  async enqueue(job: ScanJob): Promise<string> {
    const priorityMap = { high: 1, normal: 5, low: 10 }
    const bullJob = await this.queue.add('scan', job, {
      jobId: job.id,
      priority: priorityMap[job.priority] || 5,
    })
    return bullJob.id || job.id
  }

  async getStatus(jobId: string): Promise<JobResult | null> {
    const job = await BullJob.fromId(this.queue, jobId)
    if (!job) return null

    const state = await job.getState()
    const statusMap: Record<string, JobStatus> = {
      waiting: 'queued',
      delayed: 'queued',
      active: 'processing',
      completed: 'completed',
      failed: 'failed',
    }

    return {
      jobId: job.id || jobId,
      scanId: (job.data as ScanJob).scanId,
      status: statusMap[state] || 'queued',
      progress: typeof job.progress === 'number' ? job.progress : 0,
      result: job.returnvalue,
      error: job.failedReason,
      startedAt: job.processedOn ? new Date(job.processedOn).toISOString() : undefined,
      completedAt: job.finishedOn ? new Date(job.finishedOn).toISOString() : undefined,
    }
  }

  async cancel(jobId: string): Promise<boolean> {
    const job = await BullJob.fromId(this.queue, jobId)
    if (!job) return false
    const state = await job.getState()
    if (state === 'waiting' || state === 'delayed') {
      await job.remove()
      return true
    }
    return false
  }

  registerWorker(fn: ScanWorkerFn): void {
    this.worker = new Worker('hemisx-sast-scans', async (job) => {
      return fn(job.data as ScanJob)
    }, {
      connection: this.queue.opts.connection as unknown as import('bullmq').ConnectionOptions,
      concurrency: 5,
      limiter: {
        max: 10,
        duration: 60000, // Max 10 jobs per minute
      },
    })

    this.worker.on('completed', (job) => {
      console.log(`[Worker] Job ${job.id} completed`)
    })

    this.worker.on('failed', (job, err) => {
      console.error(`[Worker] Job ${job?.id} failed:`, err.message)
    })
  }

  async getQueueStats(): Promise<{ queued: number; processing: number; completed: number; failed: number }> {
    const [waiting, active, completed, failed] = await Promise.all([
      this.queue.getWaitingCount(),
      this.queue.getActiveCount(),
      this.queue.getCompletedCount(),
      this.queue.getFailedCount(),
    ])
    return { queued: waiting, processing: active, completed, failed }
  }

  async close(): Promise<void> {
    await this.worker?.close()
    await this.queue.close()
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────

let _queue: ScanQueue | null = null

export function getScanQueue(): ScanQueue {
  if (_queue) return _queue

  const redisUrl = process.env.REDIS_URL

  if (redisUrl) {
    try {
      // Dynamic import to avoid bundling ioredis when not needed
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const IORedis = require('ioredis')
      const redis = new IORedis(redisUrl)
      _queue = new BullMQQueue(redis)
      console.log('[Queue] Using BullMQ + Redis backend')
    } catch {
      console.warn('[Queue] Redis connection failed, falling back to in-memory')
      _queue = new InMemoryQueue()
    }
  } else {
    _queue = new InMemoryQueue()
    console.log('[Queue] Using in-memory queue (set REDIS_URL for production)')
  }

  return _queue
}

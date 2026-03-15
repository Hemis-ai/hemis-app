// HemisX SAST — File Storage Abstraction
// Provides a unified interface for file storage with pluggable backends:
// - Local filesystem (development)
// - AWS S3 (production)
// Files are stored by scan ID for isolation and cleanup.

import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { writeFile, readFile, mkdir, rm, readdir } from 'fs/promises'
import { join } from 'path'
import { existsSync } from 'fs'

// ─── Storage Interface ──────────────────────────────────────────────────────

export interface StorageBackend {
  putFile(scanId: string, filePath: string, content: string | Buffer): Promise<string>
  getFile(scanId: string, filePath: string): Promise<string>
  listFiles(scanId: string): Promise<string[]>
  deleteScan(scanId: string): Promise<void>
  getDownloadUrl?(scanId: string, filePath: string): Promise<string>
}

// ─── Local Filesystem Backend ───────────────────────────────────────────────

export class LocalStorage implements StorageBackend {
  private baseDir: string

  constructor(baseDir?: string) {
    this.baseDir = baseDir || join(process.cwd(), '.hemisx-storage')
  }

  private scanDir(scanId: string): string {
    return join(this.baseDir, 'scans', scanId)
  }

  async putFile(scanId: string, filePath: string, content: string | Buffer): Promise<string> {
    const dir = this.scanDir(scanId)
    const fullPath = join(dir, filePath)
    const parentDir = fullPath.substring(0, fullPath.lastIndexOf('/'))

    await mkdir(parentDir, { recursive: true })
    await writeFile(fullPath, content, 'utf-8')

    return fullPath
  }

  async getFile(scanId: string, filePath: string): Promise<string> {
    const fullPath = join(this.scanDir(scanId), filePath)
    return readFile(fullPath, 'utf-8')
  }

  async listFiles(scanId: string): Promise<string[]> {
    const dir = this.scanDir(scanId)
    if (!existsSync(dir)) return []

    const results: string[] = []
    const walkDir = async (currentDir: string, prefix: string = '') => {
      const entries = await readdir(currentDir, { withFileTypes: true })
      for (const entry of entries) {
        const relPath = prefix ? `${prefix}/${entry.name}` : entry.name
        if (entry.isDirectory()) {
          await walkDir(join(currentDir, entry.name), relPath)
        } else {
          results.push(relPath)
        }
      }
    }
    await walkDir(dir)
    return results
  }

  async deleteScan(scanId: string): Promise<void> {
    const dir = this.scanDir(scanId)
    if (existsSync(dir)) {
      await rm(dir, { recursive: true, force: true })
    }
  }
}

// ─── AWS S3 Backend ─────────────────────────────────────────────────────────

export class S3Storage implements StorageBackend {
  private client: S3Client
  private bucket: string
  private prefix: string

  constructor(config?: {
    region?: string
    bucket?: string
    prefix?: string
    accessKeyId?: string
    secretAccessKey?: string
  }) {
    this.bucket = config?.bucket || process.env.HEMISX_S3_BUCKET || 'hemisx-sast-scans'
    this.prefix = config?.prefix || process.env.HEMISX_S3_PREFIX || 'scans/'

    this.client = new S3Client({
      region: config?.region || process.env.AWS_REGION || 'us-east-1',
      ...(config?.accessKeyId ? {
        credentials: {
          accessKeyId: config.accessKeyId,
          secretAccessKey: config.secretAccessKey || '',
        },
      } : {}),
    })
  }

  private key(scanId: string, filePath: string): string {
    return `${this.prefix}${scanId}/${filePath}`
  }

  async putFile(scanId: string, filePath: string, content: string | Buffer): Promise<string> {
    const key = this.key(scanId, filePath)
    await this.client.send(new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: typeof content === 'string' ? Buffer.from(content, 'utf-8') : content,
      ContentType: 'text/plain',
      ServerSideEncryption: 'AES256',
    }))
    return `s3://${this.bucket}/${key}`
  }

  async getFile(scanId: string, filePath: string): Promise<string> {
    const result = await this.client.send(new GetObjectCommand({
      Bucket: this.bucket,
      Key: this.key(scanId, filePath),
    }))
    return await result.Body?.transformToString('utf-8') ?? ''
  }

  async listFiles(scanId: string): Promise<string[]> {
    const prefix = `${this.prefix}${scanId}/`
    const result = await this.client.send(new ListObjectsV2Command({
      Bucket: this.bucket,
      Prefix: prefix,
    }))
    return (result.Contents ?? [])
      .map(obj => obj.Key?.replace(prefix, '') ?? '')
      .filter(Boolean)
  }

  async deleteScan(scanId: string): Promise<void> {
    const files = await this.listFiles(scanId)
    for (const file of files) {
      await this.client.send(new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: this.key(scanId, file),
      }))
    }
  }

  async getDownloadUrl(scanId: string, filePath: string): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: this.key(scanId, filePath),
    })
    return getSignedUrl(this.client, command, { expiresIn: 3600 })
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────

let _storage: StorageBackend | null = null

export function getStorage(): StorageBackend {
  if (_storage) return _storage

  if (process.env.HEMISX_S3_BUCKET) {
    _storage = new S3Storage()
    console.log('[Storage] Using S3 backend:', process.env.HEMISX_S3_BUCKET)
  } else {
    _storage = new LocalStorage()
    console.log('[Storage] Using local filesystem backend')
  }

  return _storage
}

// src/app/api/cloud/connect/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { saveConnection, testConnection, generateCloudFormationTemplate, generateTerraformTemplate } from '@/lib/cloud-scanner/aws-connector'
import { randomUUID } from 'crypto'

export async function GET() {
  const externalId = `hemisx-${randomUUID().slice(0, 8)}`
  return NextResponse.json({
    externalId,
    hemisxAccountId: '123456789012',
    cloudformation: generateCloudFormationTemplate(externalId),
    terraform: generateTerraformTemplate(externalId),
  })
}

export async function POST(req: NextRequest) {
  try {
    const { roleArn, externalId } = await req.json()
    if (!roleArn?.trim()) return NextResponse.json({ error: 'roleArn is required' }, { status: 400 })
    const conn = saveConnection(roleArn.trim(), externalId)
    const result = await testConnection(conn)
    if (!result.success) return NextResponse.json({ error: result.error }, { status: 400 })
    return NextResponse.json({ connection: { ...conn, status: 'CONNECTED', regions: result.regions } }, { status: 201 })
  } catch (err) {
    console.error('[Cloud] POST /api/cloud/connect error:', err)
    return NextResponse.json({ error: 'Connection failed' }, { status: 500 })
  }
}

import { NextRequest, NextResponse } from 'next/server'
import { DEFAULT_CUSTOM_RULES, validatePattern, testPattern } from '@/lib/sast/custom-rules'
import type { CustomRuleDefinition } from '@/lib/sast/custom-rules'

// In-memory store for demo (would be DB-backed in production)
let customRules: CustomRuleDefinition[] = [...DEFAULT_CUSTOM_RULES]

/**
 * GET /api/sast/rules
 * List all custom rules
 */
export async function GET() {
  return NextResponse.json({ rules: customRules })
}

/**
 * POST /api/sast/rules
 * Create a new custom rule or test a pattern
 * Body: { action: 'create' | 'test', ...ruleData }
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()

    if (body.action === 'test') {
      // Test a pattern against sample code
      const { pattern, code } = body
      if (!pattern || !code) {
        return NextResponse.json({ error: 'pattern and code are required' }, { status: 400 })
      }
      const validation = validatePattern(pattern)
      if (!validation.valid) {
        return NextResponse.json({ error: `Invalid regex: ${validation.error}` }, { status: 400 })
      }
      const result = testPattern(pattern, code)
      return NextResponse.json(result)
    }

    // Create a new rule
    const { name, description, pattern, languages, severity, confidence, owasp, cwe, category, remediation } = body

    if (!name || !pattern) {
      return NextResponse.json({ error: 'name and pattern are required' }, { status: 400 })
    }

    const validation = validatePattern(pattern)
    if (!validation.valid) {
      return NextResponse.json({ error: `Invalid regex: ${validation.error}` }, { status: 400 })
    }

    const newRule: CustomRuleDefinition = {
      id: `CUSTOM-${String(customRules.length + 1).padStart(3, '0')}`,
      name,
      description: description || '',
      pattern,
      languages: languages || ['all'],
      severity: severity || 'MEDIUM',
      confidence: confidence || 'MEDIUM',
      owasp: owasp || 'A03:2021 – Injection',
      cwe: cwe || 'CWE-79',
      category: category || 'Injection',
      remediation: remediation || '',
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      testCases: body.testCases || [],
    }

    customRules.push(newRule)
    return NextResponse.json({ rule: newRule }, { status: 201 })
  } catch (err) {
    console.error('[SAST] Custom rules error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * PATCH /api/sast/rules
 * Toggle rule enabled/disabled
 * Body: { id: string, enabled: boolean }
 */
export async function PATCH(req: NextRequest) {
  try {
    const { id, enabled } = await req.json()
    const rule = customRules.find(r => r.id === id)
    if (!rule) {
      return NextResponse.json({ error: 'Rule not found' }, { status: 404 })
    }
    rule.enabled = enabled
    rule.updatedAt = new Date().toISOString()
    return NextResponse.json({ rule })
  } catch (err) {
    console.error('[SAST] Rule toggle error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * DELETE /api/sast/rules
 * Delete a custom rule
 * Body: { id: string }
 */
export async function DELETE(req: NextRequest) {
  try {
    const { id } = await req.json()
    const idx = customRules.findIndex(r => r.id === id)
    if (idx === -1) {
      return NextResponse.json({ error: 'Rule not found' }, { status: 404 })
    }
    customRules.splice(idx, 1)
    return NextResponse.json({ success: true })
  } catch (err) {
    console.error('[SAST] Rule delete error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

import { NextRequest, NextResponse } from 'next/server'
import { verifyWebhookSignature, handleWebhookEvent } from '@/lib/github/webhook-handler'

/**
 * POST /api/github/webhook
 * Receives GitHub App webhook events.
 * Verifies the signature, routes to the appropriate handler.
 */
export async function POST(req: NextRequest) {
  try {
    const rawBody = await req.text()
    const signature = req.headers.get('x-hub-signature-256')
    const event = req.headers.get('x-github-event')

    // Verify webhook signature
    if (!verifyWebhookSignature(rawBody, signature)) {
      console.error('[GitHub Webhook] Invalid signature')
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 })
    }

    if (!event) {
      return NextResponse.json({ error: 'Missing x-github-event header' }, { status: 400 })
    }

    const payload = JSON.parse(rawBody)

    console.log(`[GitHub Webhook] Received event: ${event} (action: ${payload.action || 'N/A'})`)

    // Handle the event
    const result = await handleWebhookEvent(event, payload)

    console.log(`[GitHub Webhook] Result: ${result.action} — ${result.message}`)

    return NextResponse.json(result)
  } catch (err) {
    console.error('[GitHub Webhook] Error:', err)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

import Anthropic from '@anthropic-ai/sdk'

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY || '' })

export class ClaudeClient {
  private readonly model: string
  private readonly maxRetries = 3
  private readonly baseDelayMs = 1000

  constructor(model: string = process.env.CLAUDE_MODEL || 'claude-sonnet-4-6') {
    this.model = model
  }

  async callClaude<T>(
    systemPrompt: string,
    userPrompt: string,
    validator: (response: string) => { valid: boolean; data?: T; error?: string },
  ): Promise<T | null> {
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await client.messages.create({
          model: this.model,
          max_tokens: 2000,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }],
        })
        const content = response.content[0]
        if (content.type !== 'text') return null
        const result = validator(content.text)
        if (!result.valid) return null
        return result.data ?? null
      } catch (err: unknown) {
        const error = err as { status?: number; message?: string }
        const isTransient = error.status === 429 || error.status === 500 || (error.message?.includes('timeout'))
        if (isTransient && attempt < this.maxRetries - 1) {
          await new Promise((resolve) => setTimeout(resolve, this.baseDelayMs * Math.pow(2, attempt)))
          continue
        }
        console.error('Claude API error', { error: error.message, status: error.status, attempt: attempt + 1 })
        return null
      }
    }
    return null
  }
}

export const claudeClient = new ClaudeClient()

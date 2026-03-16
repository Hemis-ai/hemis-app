import Anthropic from '@anthropic-ai/sdk'

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY || '' })

export interface ClaudeCallOptions {
  maxTokens?: number
  temperature?: number
}

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
    options?: ClaudeCallOptions,
  ): Promise<T | null> {
    const maxTokens = options?.maxTokens ?? 2000
    const temperature = options?.temperature ?? undefined

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        const response = await client.messages.create({
          model: this.model,
          max_tokens: maxTokens,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }],
          ...(temperature !== undefined ? { temperature } : {}),
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

  /**
   * Batch multiple prompts in parallel with concurrency control.
   * Returns results in the same order as inputs.
   */
  async callClaudeBatch<T>(
    calls: Array<{
      systemPrompt: string
      userPrompt: string
      validator: (response: string) => { valid: boolean; data?: T; error?: string }
      options?: ClaudeCallOptions
    }>,
    concurrency = 3,
  ): Promise<Array<T | null>> {
    const results: Array<T | null> = new Array(calls.length).fill(null)
    const queue = calls.map((call, index) => ({ ...call, index }))

    const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length > 0) {
        const item = queue.shift()
        if (!item) break
        results[item.index] = await this.callClaude<T>(
          item.systemPrompt,
          item.userPrompt,
          item.validator,
          item.options,
        )
      }
    })

    await Promise.all(workers)
    return results
  }
}

export const claudeClient = new ClaudeClient()

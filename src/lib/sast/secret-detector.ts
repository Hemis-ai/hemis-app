/**
 * HemisX SAST — High-confidence secret detection patterns.
 * These patterns target specific credential formats with low false-positive rates.
 */

export interface SecretPattern {
  id:      string
  name:    string
  pattern: RegExp
  entropy?: number    // min Shannon entropy threshold (optional future use)
  remediation: string
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'SECRET-AWS-001',
    name: 'AWS Access Key ID',
    pattern: /(?<![A-Z0-9])(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Z0-9])/g,
    remediation: 'Revoke immediately in AWS IAM. Use IAM roles or AWS Secrets Manager.',
  },
  {
    id: 'SECRET-AWS-002',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*["']?([a-zA-Z0-9/+=]{40})["']?/gi,
    remediation: 'Revoke immediately. Rotate credentials and audit CloudTrail for unauthorized usage.',
  },
  {
    id: 'SECRET-GCP-001',
    name: 'Google Cloud Service Account Key',
    pattern: /"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}"/gi,
    remediation: 'Delete the service account key in GCP Console. Create a new key and store in Secret Manager.',
  },
  {
    id: 'SECRET-AZURE-001',
    name: 'Azure Storage Account Key',
    pattern: /AccountKey=[a-zA-Z0-9+/]{88}==/g,
    remediation: 'Regenerate the storage account key in Azure Portal. Use managed identities instead.',
  },
  {
    id: 'SECRET-GITHUB-001',
    name: 'GitHub Personal Access Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    remediation: 'Revoke the token at github.com/settings/tokens. Use GitHub Actions secrets for CI/CD.',
  },
  {
    id: 'SECRET-GITHUB-002',
    name: 'GitHub OAuth App Secret',
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    remediation: 'Regenerate the OAuth app secret in GitHub settings. Store in environment variables.',
  },
  {
    id: 'SECRET-STRIPE-001',
    name: 'Stripe API Key',
    pattern: /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}/g,
    remediation: 'Roll the key immediately in Stripe Dashboard. Use restricted keys with minimal permissions.',
  },
  {
    id: 'SECRET-SLACK-001',
    name: 'Slack Bot/App Token',
    pattern: /xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g,
    remediation: 'Revoke the token in Slack App settings. Use environment variables and rotate regularly.',
  },
  {
    id: 'SECRET-JWT-001',
    name: 'JSON Web Token (JWT)',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    remediation: 'Do not commit JWTs to source. Expire and rotate the token. Store in httpOnly cookies or secure storage.',
  },
  {
    id: 'SECRET-PRIVATE-KEY-001',
    name: 'PEM Private Key',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    remediation: 'Remove from source immediately. Revoke and reissue the certificate/key pair.',
  },
  {
    id: 'SECRET-SENDGRID-001',
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    remediation: 'Revoke in SendGrid settings. Store API keys in environment variables.',
  },
  {
    id: 'SECRET-TWILIO-001',
    name: 'Twilio Auth Token',
    pattern: /SK[a-f0-9]{32}/g,
    remediation: 'Rotate the auth token in Twilio Console. Store in environment variables only.',
  },
  {
    id: 'SECRET-MAILGUN-001',
    name: 'Mailgun API Key',
    pattern: /key-[a-f0-9]{32}/g,
    remediation: 'Regenerate in Mailgun settings. Do not hardcode API keys.',
  },
  {
    id: 'SECRET-NPM-001',
    name: 'npm Auth Token',
    pattern: /\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[a-zA-Z0-9_-]{36,}/g,
    remediation: 'Revoke the npm token. Never commit .npmrc with auth tokens to source control.',
  },
  {
    id: 'SECRET-HEROKU-001',
    name: 'Heroku API Key',
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    remediation: 'Regenerate in Heroku account settings. Use config vars for storing API keys.',
  },
  {
    id: 'SECRET-DISCORD-001',
    name: 'Discord Bot Token',
    pattern: /[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/g,
    remediation: 'Regenerate the bot token in Discord Developer Portal. Store in environment variables.',
  },
  {
    id: 'SECRET-OPENAI-001',
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{48}/g,
    remediation: 'Revoke at platform.openai.com/api-keys. Store in environment variables, never in source.',
  },
  {
    id: 'SECRET-ANTHROPIC-001',
    name: 'Anthropic API Key',
    pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{93}/g,
    remediation: 'Revoke at console.anthropic.com. Store in environment variables only.',
  },
]

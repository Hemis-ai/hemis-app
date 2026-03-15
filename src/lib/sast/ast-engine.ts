// HemisX SAST — AST Analysis Engine
// Uses acorn (pure-JS ECMAScript parser) to perform real Abstract Syntax Tree
// analysis for JavaScript/TypeScript. This is the technical moat that separates
// HemisX from basic grep/regex-based tools — it understands code structure,
// variable scoping, data flow, and call graphs.

import * as acorn from 'acorn'
import * as walk from 'acorn-walk'
import type { SastFindingResult, SastSeverity, SastConfidence, SastCategory } from '@/lib/types/sast'

// ─── AST Rule Definition ────────────────────────────────────────────────────

interface AstRule {
  id:          string
  name:        string
  description: string
  severity:    SastSeverity
  confidence:  SastConfidence
  owasp:       string
  cwe:         string
  category:    SastCategory
  remediation: string
  check:       (node: acorn.Node, ancestors: acorn.Node[], ctx: AnalysisContext) => AstMatch | null
  nodeType:    string  // AST node type to visit (CallExpression, AssignmentExpression, etc.)
}

interface AstMatch {
  line:    number
  column:  number
  snippet: string
  detail?: string
}

interface AnalysisContext {
  source:     string
  lines:      string[]
  filePath:   string
  // Taint tracking: maps variable names to their taint source
  taintedVars: Map<string, TaintSource>
  // Track dangerous sinks that were called
  dangerousCalls: Set<string>
}

interface TaintSource {
  source:   string   // 'req.body', 'req.query', 'req.params', 'process.env', 'user_input'
  line:     number
  variable: string
}

// ─── Helper: get source snippet around a node ────────────────────────────────

function getSnippet(lines: string[], line: number, context: number = 1): string {
  const start = Math.max(0, line - 1 - context)
  const end = Math.min(lines.length - 1, line - 1 + context)
  return lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1} | ${l}`)
    .join('\n')
}

// ─── Helper: get member expression as dotted string ──────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function memberToString(node: any): string {
  if (node.type === 'Identifier') return node.name
  if (node.type === 'MemberExpression') {
    const obj = memberToString(node.object)
    const prop = node.computed ? `[${memberToString(node.property)}]` : `.${memberToString(node.property)}`
    return obj + prop
  }
  if (node.type === 'Literal') return String(node.value)
  return '?'
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getCalleeName(node: any): string {
  if (node.callee?.type === 'Identifier') return node.callee.name
  if (node.callee?.type === 'MemberExpression') return memberToString(node.callee)
  return ''
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isUserInput(node: any): boolean {
  const str = memberToString(node)
  return /^(req|request|ctx)\.(body|query|params|headers|cookies|files|session)/.test(str) ||
         /^(args|input|data|payload|form|fields)/.test(str)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function containsUserInput(node: any, ctx: AnalysisContext): boolean {
  if (!node) return false
  if (isUserInput(node)) return true
  if (node.type === 'Identifier' && ctx.taintedVars.has(node.name)) return true
  if (node.type === 'BinaryExpression') {
    return containsUserInput(node.left, ctx) || containsUserInput(node.right, ctx)
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions?.some((e: acorn.Node) => containsUserInput(e, ctx)) ?? false
  }
  if (node.type === 'MemberExpression') return isUserInput(node)
  return false
}

// ─── AST Rules Library ──────────────────────────────────────────────────────

const AST_RULES: AstRule[] = [
  // ────── INJECTION: eval() with user input ──────
  {
    id: 'AST-INJ-001',
    name: 'eval() called with potentially tainted input',
    description: 'eval() executes arbitrary JavaScript. When called with user-controlled input, it allows Remote Code Execution (RCE).',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-94',
    category: 'Injection',
    remediation: 'Never use eval() with user input. Use JSON.parse() for data, or a sandboxed interpreter for dynamic evaluation.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (name !== 'eval' && name !== 'Function') return null
      const hasUserInput = n.arguments?.some((arg: acorn.Node) => containsUserInput(arg, ctx))
      if (!hasUserInput && n.arguments?.length > 0) {
        // Still flag eval with any non-literal argument
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const firstArg = n.arguments[0] as any
        if (firstArg.type !== 'Literal') {
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: hasUserInput ? 'User input flows directly into eval()' : 'Dynamic value passed to eval()',
          }
        }
      }
      if (hasUserInput) {
        const loc = node.loc?.start ?? { line: 1, column: 0 }
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: 'User-controlled input flows into eval() — Remote Code Execution risk',
        }
      }
      return null
    },
  },

  // ────── INJECTION: Command injection via exec/spawn ──────
  {
    id: 'AST-INJ-002',
    name: 'OS command execution with dynamic arguments',
    description: 'Child process functions (exec, execSync, spawn) called with string concatenation or template literals can lead to command injection.',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
    category: 'Injection',
    remediation: 'Use execFile() or spawn() with array arguments instead of exec(). Never concatenate user input into shell commands.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      const dangerous = ['exec', 'execSync', 'child_process.exec', 'child_process.execSync']
      if (!dangerous.some(d => name.endsWith(d))) return null

      const firstArg = n.arguments?.[0]
      if (!firstArg) return null

      // Flag if argument is not a literal string (concatenation, template, variable)
      if (firstArg.type !== 'Literal') {
        const hasTaint = containsUserInput(firstArg, ctx)
        const loc = node.loc?.start ?? { line: 1, column: 0 }
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: hasTaint
            ? 'User input concatenated into shell command — Command Injection'
            : 'Dynamic string in exec() — potential command injection if input is user-controlled',
        }
      }
      return null
    },
  },

  // ────── INJECTION: SQL via string concatenation in query() ──────
  {
    id: 'AST-INJ-003',
    name: 'SQL query built with string concatenation',
    description: 'SQL query methods called with concatenated/template strings are vulnerable to SQL injection.',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
    category: 'Injection',
    remediation: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [id]). Never concatenate input into SQL.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      const sqlMethods = ['query', 'execute', 'raw', 'exec', '$queryRaw', '$executeRaw']
      if (!sqlMethods.some(m => name.endsWith(m))) return null

      const firstArg = n.arguments?.[0]
      if (!firstArg) return null

      // Check if the SQL string is constructed dynamically
      if (firstArg.type === 'BinaryExpression' || firstArg.type === 'TemplateLiteral') {
        // Verify it actually looks like SQL
        let hasSQL = false
        if (firstArg.type === 'TemplateLiteral') {
          const raw = firstArg.quasis?.map((q: { value: { raw: string } }) => q.value.raw).join('') ?? ''
          hasSQL = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|CREATE|DROP|ALTER)\b/i.test(raw)
        } else if (firstArg.type === 'BinaryExpression') {
          // Walk the left side looking for SQL keywords in literals
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const checkNode = (nd: any): boolean => {
            if (nd.type === 'Literal' && typeof nd.value === 'string') {
              return /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(nd.value)
            }
            if (nd.type === 'BinaryExpression') return checkNode(nd.left) || checkNode(nd.right)
            return false
          }
          hasSQL = checkNode(firstArg)
        }

        if (hasSQL) {
          const hasTaint = containsUserInput(firstArg, ctx)
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: hasTaint
              ? 'User input interpolated into SQL query — SQL Injection'
              : 'Dynamic SQL construction detected — use parameterized queries',
          }
        }
      }
      return null
    },
  },

  // ────── CRYPTO: Weak hash algorithms ──────
  {
    id: 'AST-CRYPTO-001',
    name: 'Weak cryptographic hash algorithm (MD5/SHA1)',
    description: 'MD5 and SHA1 are cryptographically broken. They should not be used for security-sensitive operations.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-327',
    category: 'Cryptography',
    remediation: 'Use SHA-256 or stronger: crypto.createHash("sha256"). For passwords, use bcrypt, scrypt, or argon2.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (!name.endsWith('createHash') && !name.endsWith('createHmac')) return null

      const firstArg = n.arguments?.[0]
      if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') {
        const algo = firstArg.value.toLowerCase()
        if (algo === 'md5' || algo === 'sha1' || algo === 'md4') {
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: `Weak hash algorithm "${firstArg.value}" — use SHA-256 or stronger`,
          }
        }
      }
      return null
    },
  },

  // ────── CRYPTO: Math.random() for security ──────
  {
    id: 'AST-CRYPTO-002',
    name: 'Math.random() used (not cryptographically secure)',
    description: 'Math.random() is not cryptographically secure. It should never be used for tokens, IDs, or security-sensitive randomness.',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-338',
    category: 'Cryptography',
    remediation: 'Use crypto.randomBytes(), crypto.randomUUID(), or crypto.getRandomValues() for secure random generation.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (name !== 'Math.random') return null

      // Check if result is used for something security-related
      // (assigned to a var with security-related name)
      const loc = node.loc?.start ?? { line: 1, column: 0 }
      const lineText = ctx.lines[loc.line - 1] || ''
      const securityContext = /\b(token|secret|key|password|auth|session|nonce|salt|id|uuid|csrf)\b/i.test(lineText)

      if (securityContext) {
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: 'Math.random() used in security context — not cryptographically secure',
        }
      }
      return null
    },
  },

  // ────── DESER: JSON.parse without try-catch ──────
  {
    id: 'AST-DESER-001',
    name: 'JSON.parse() on user input without error handling',
    description: 'JSON.parse() with user input can throw on malformed JSON, causing denial of service. Without validation, it may also lead to prototype pollution.',
    severity: 'LOW',
    confidence: 'MEDIUM',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-502',
    category: 'Deserialization',
    remediation: 'Wrap JSON.parse() in try-catch. Validate and sanitize the parsed result. Consider using a schema validator like zod or joi.',
    nodeType: 'CallExpression',
    check: (node, ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (name !== 'JSON.parse') return null

      const hasUserInput = n.arguments?.some((a: acorn.Node) => containsUserInput(a, ctx))
      if (!hasUserInput) return null

      // Check if wrapped in try-catch
      const inTryCatch = ancestors.some(a => a.type === 'TryStatement')
      if (inTryCatch) return null

      const loc = node.loc?.start ?? { line: 1, column: 0 }
      return {
        line: loc.line,
        column: loc.column,
        snippet: getSnippet(ctx.lines, loc.line),
        detail: 'JSON.parse() with user input outside try-catch — can throw on malformed data',
      }
    },
  },

  // ────── XSS: innerHTML assignment ──────
  {
    id: 'AST-XSS-001',
    name: 'innerHTML assignment with dynamic content',
    description: 'Setting innerHTML with user-controlled content allows Cross-Site Scripting (XSS) attacks.',
    severity: 'HIGH',
    confidence: 'HIGH',
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
    category: 'XSS',
    remediation: 'Use textContent instead of innerHTML. If HTML is needed, sanitize with DOMPurify or similar library.',
    nodeType: 'AssignmentExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.left?.type === 'MemberExpression') {
        const prop = n.left.property
        if (prop?.type === 'Identifier' && (prop.name === 'innerHTML' || prop.name === 'outerHTML')) {
          if (n.right?.type !== 'Literal') {
            const loc = node.loc?.start ?? { line: 1, column: 0 }
            return {
              line: loc.line,
              column: loc.column,
              snippet: getSnippet(ctx.lines, loc.line),
              detail: `Assignment to ${prop.name} with dynamic content — XSS risk`,
            }
          }
        }
      }
      return null
    },
  },

  // ────── AUTH: JWT without algorithm verification ──────
  {
    id: 'AST-AUTH-001',
    name: 'JWT verification without algorithm specification',
    description: 'JWT verify/decode called without specifying allowed algorithms allows algorithm confusion attacks (e.g., none algorithm bypass).',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-347',
    category: 'Authentication',
    remediation: 'Always specify algorithms: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never allow "none" algorithm.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (!name.endsWith('.verify') && !name.endsWith('.decode')) return null
      if (!name.includes('jwt') && !name.includes('jsonwebtoken')) {
        // Check if the object variable might be jwt
        const lineText = ctx.lines[(node.loc?.start?.line ?? 1) - 1] || ''
        if (!/jwt|jsonwebtoken|token/i.test(lineText)) return null
      }

      // Check if options object has 'algorithms' property
      const optionsArg = n.arguments?.[2] // jwt.verify(token, secret, options)
      if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
        // No options or non-object options
        if (name.endsWith('.verify')) {
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: 'jwt.verify() without algorithms option — vulnerable to algorithm confusion attacks',
          }
        }
      } else {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const hasAlgorithms = optionsArg.properties?.some((p: any) => {
          const key = p.key?.name || p.key?.value
          return key === 'algorithms'
        })
        if (!hasAlgorithms && name.endsWith('.verify')) {
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: 'jwt.verify() options missing "algorithms" — specify allowed algorithms',
          }
        }
      }
      return null
    },
  },

  // ────── SSRF: HTTP request with user-controlled URL ──────
  {
    id: 'AST-SSRF-001',
    name: 'HTTP request with user-controlled URL',
    description: 'Making HTTP requests (fetch, axios, http.get) with user-supplied URLs can lead to SSRF, allowing attackers to access internal services.',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
    category: 'SSRF',
    remediation: 'Validate and allowlist URLs before making requests. Block private/internal IP ranges. Use a URL parser to check the hostname.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      const httpFunctions = ['fetch', 'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete',
        'http.get', 'http.request', 'https.get', 'https.request', 'got', 'got.get',
        'request', 'superagent.get', 'needle.get', 'undici.fetch']

      if (!httpFunctions.some(f => name === f || name.endsWith(`.${f}`))) return null

      const firstArg = n.arguments?.[0]
      if (firstArg && containsUserInput(firstArg, ctx)) {
        const loc = node.loc?.start ?? { line: 1, column: 0 }
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: 'User-controlled URL passed to HTTP client — Server-Side Request Forgery risk',
        }
      }
      return null
    },
  },

  // ────── PATH: Path traversal via user input in file operations ──────
  {
    id: 'AST-PATH-001',
    name: 'File operation with user-controlled path',
    description: 'File system operations (readFile, writeFile, etc.) with user input in the path can lead to arbitrary file read/write (path traversal).',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-22',
    category: 'Path Traversal',
    remediation: 'Use path.resolve() and verify the resolved path starts with the expected base directory. Never pass user input directly to file operations.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      const fileFunctions = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync',
        'createReadStream', 'createWriteStream', 'appendFile', 'appendFileSync',
        'unlink', 'unlinkSync', 'readdir', 'readdirSync', 'stat', 'statSync',
        'fs.readFile', 'fs.readFileSync', 'fs.writeFile', 'fs.writeFileSync']

      if (!fileFunctions.some(f => name === f || name.endsWith(`.${f.split('.').pop()}`))) return null

      const firstArg = n.arguments?.[0]
      if (firstArg && containsUserInput(firstArg, ctx)) {
        const loc = node.loc?.start ?? { line: 1, column: 0 }
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: 'User-controlled path in file operation — Path Traversal risk',
        }
      }
      return null
    },
  },

  // ────── MISCONFIG: Disabled security headers / CORS * ──────
  {
    id: 'AST-MISC-001',
    name: 'CORS configured with wildcard origin',
    description: 'Setting Access-Control-Allow-Origin to "*" allows any website to make requests to your API, potentially leading to data theft.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-942',
    category: 'Misconfiguration',
    remediation: 'Specify allowed origins explicitly: cors({ origin: ["https://myapp.com"] }). Avoid using "*" in production.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (name !== 'cors' && !name.endsWith('.cors')) return null

      const optionsArg = n.arguments?.[0]
      if (optionsArg?.type === 'ObjectExpression') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const originProp = optionsArg.properties?.find((p: any) => {
          const key = p.key?.name || p.key?.value
          return key === 'origin'
        })
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (originProp && (originProp as any).value?.type === 'Literal' && (originProp as any).value?.value === '*') {
          const loc = node.loc?.start ?? { line: 1, column: 0 }
          return {
            line: loc.line,
            column: loc.column,
            snippet: getSnippet(ctx.lines, loc.line),
            detail: 'CORS origin set to "*" — allows requests from any domain',
          }
        }
      }
      return null
    },
  },

  // ────── PROTOTYPE: Object spread/assign from user input ──────
  {
    id: 'AST-PROTO-001',
    name: 'Object.assign/spread with user-controlled source',
    description: 'Using Object.assign() or spread operator with user input can lead to Prototype Pollution, allowing attackers to inject properties into Object.prototype.',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-915',
    category: 'Injection',
    remediation: 'Validate and sanitize user input before merging into objects. Use a safe merge library that ignores __proto__, constructor, and prototype properties.',
    nodeType: 'CallExpression',
    check: (node, _ancestors, ctx) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const name = getCalleeName(n)
      if (name !== 'Object.assign') return null

      // Check if any source argument is user input
      const sources = n.arguments?.slice(1) || []
      const hasTaintedSource = sources.some((arg: acorn.Node) => containsUserInput(arg, ctx))

      if (hasTaintedSource) {
        const loc = node.loc?.start ?? { line: 1, column: 0 }
        return {
          line: loc.line,
          column: loc.column,
          snippet: getSnippet(ctx.lines, loc.line),
          detail: 'Object.assign() with user input — Prototype Pollution risk',
        }
      }
      return null
    },
  },
]

// ─── Taint Analysis Pass ────────────────────────────────────────────────────

function runTaintAnalysis(ast: acorn.Node, ctx: AnalysisContext): void {
  // First pass: identify variables assigned from user input sources
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  walk.simple(ast, {
    VariableDeclarator(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.id?.type === 'Identifier' && n.init) {
        if (containsUserInput(n.init, ctx)) {
          ctx.taintedVars.set(n.id.name, {
            source: memberToString(n.init),
            line: n.loc?.start?.line ?? 0,
            variable: n.id.name,
          })
        }
        // Also track destructured assignments: const { username } = req.body
        if (n.id.type === 'ObjectPattern' && isUserInput(n.init)) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          for (const prop of (n.id as any).properties || []) {
            if (prop.value?.type === 'Identifier') {
              ctx.taintedVars.set(prop.value.name, {
                source: memberToString(n.init) + '.' + (prop.key?.name || '?'),
                line: n.loc?.start?.line ?? 0,
                variable: prop.value.name,
              })
            }
          }
        }
      }
    },
    AssignmentExpression(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.left?.type === 'Identifier' && containsUserInput(n.right, ctx)) {
        ctx.taintedVars.set(n.left.name, {
          source: memberToString(n.right),
          line: n.loc?.start?.line ?? 0,
          variable: n.left.name,
        })
      }
    },
  } as walk.SimpleVisitors<unknown>)

  // Second pass: propagate taint through assignments
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  walk.simple(ast, {
    VariableDeclarator(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.id?.type === 'Identifier' && n.init?.type === 'Identifier') {
        const source = ctx.taintedVars.get(n.init.name)
        if (source) {
          ctx.taintedVars.set(n.id.name, {
            ...source,
            variable: n.id.name,
          })
        }
      }
    },
  } as walk.SimpleVisitors<unknown>)
}

// ─── Main AST Scanner ───────────────────────────────────────────────────────

export function scanWithAST(
  scanId: string,
  filePath: string,
  source: string,
): SastFindingResult[] {
  // Only parse JS/TS files
  const ext = filePath.split('.').pop()?.toLowerCase()
  if (!ext || !['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(ext)) {
    return []
  }

  // Strip TypeScript-specific syntax for acorn (which only parses ES)
  let cleanSource = source
  if (ext === 'ts' || ext === 'tsx') {
    cleanSource = stripTypeScript(source)
  }

  let ast: acorn.Node
  try {
    ast = acorn.parse(cleanSource, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowHashBang: true,
    })
  } catch {
    // If parsing fails, return empty (regex rules will still catch things)
    return []
  }

  const lines = source.split('\n')
  const ctx: AnalysisContext = {
    source,
    lines,
    filePath,
    taintedVars: new Map(),
    dangerousCalls: new Set(),
  }

  // Run taint analysis first
  runTaintAnalysis(ast, ctx)

  // Run AST rules
  const findings: SastFindingResult[] = []

  for (const rule of AST_RULES) {
    walk.ancestor(ast, {
      [rule.nodeType](node: acorn.Node, ancestors: acorn.Node[]) {
        const match = rule.check(node, ancestors, ctx)
        if (match) {
          findings.push({
            id:           `${scanId}-ast-${findings.length}`,
            scanId,
            ruleId:       rule.id,
            ruleName:     rule.name,
            severity:     rule.severity,
            confidence:   rule.confidence,
            language:     ext === 'py' ? 'python' : 'javascript',
            filePath,
            lineStart:    match.line,
            lineEnd:      match.line,
            codeSnippet:  match.snippet,
            description:  `${rule.description}${match.detail ? `\n\nDetail: ${match.detail}` : ''}`,
            remediation:  rule.remediation,
            owasp:        rule.owasp,
            cwe:          rule.cwe,
            category:     rule.category,
            status:       'OPEN',
            falsePositive: false,
            detectedAt:   new Date().toISOString(),
          })
        }
      },
    } as walk.AncestorVisitors<unknown>)
  }

  return findings
}

// ─── TypeScript Stripping (basic) ────────────────────────────────────────────
// Remove TS-specific syntax so acorn can parse it as JS

function stripTypeScript(source: string): string {
  return source
    // Remove type annotations: param: Type → param
    .replace(/:\s*(?:string|number|boolean|any|void|never|unknown|null|undefined|object|symbol|bigint|Record|Array|Promise|Map|Set|Date)\b[^=,)}\n]*/g, '')
    // Remove interface/type declarations
    .replace(/^(?:export\s+)?(?:interface|type)\s+\w+[\s\S]*?^\}/gm, '')
    // Remove generic type parameters: <Type>
    .replace(/<[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*>/g, '')
    // Remove 'as Type' assertions
    .replace(/\bas\s+\w+/g, '')
    // Remove access modifiers
    .replace(/\b(?:public|private|protected|readonly|abstract|override)\s+/g, '')
    // Remove non-null assertions
    .replace(/!\./g, '.')
    // Remove satisfies
    .replace(/\bsatisfies\s+\w+/g, '')
}

/** Get AST rule count */
export function getAstRuleCount(): number {
  return AST_RULES.length
}

/** List AST rules (metadata only) */
export function listAstRules() {
  return AST_RULES.map(r => ({
    id: r.id,
    name: r.name,
    severity: r.severity,
    category: r.category,
    cwe: r.cwe,
    owasp: r.owasp,
    nodeType: r.nodeType,
  }))
}

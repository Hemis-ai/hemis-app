// HemisX SAST — Deep Taint Analysis Engine
// Inter-procedural data-flow analysis with source-sink mapping, sanitizer
// recognition, and path-sensitive tracking. Builds on the basic taint pass
// in ast-engine.ts to provide full data-flow paths from user-controlled
// sources to dangerous sinks.

import * as acorn from 'acorn'
import * as walk from 'acorn-walk'
import type { SastFindingResult, SastSeverity, SastCategory } from '@/lib/types/sast'

// ─── Core Data Structures ──────────────────────────────────────────────────

export interface TaintNode {
  id:        string
  type:      'source' | 'sink' | 'transform' | 'sanitizer'
  name:      string
  location:  { file: string; line: number; column: number }
  taintLabel: string
}

export interface TaintPath {
  source:         TaintNode
  sink:           TaintNode
  hops:           TaintNode[]
  sanitized:      boolean
  sanitizerName?: string
  confidence:     'HIGH' | 'MEDIUM' | 'LOW'
}

interface FunctionSummary {
  name:             string
  file:             string
  line:             number
  params:           string[]
  taintedParams:    Set<number>   // indices of params that reach a sink
  returnsTaint:     boolean       // does the function return tainted data?
  sanitizes:        boolean       // does the function sanitize input?
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body:             any           // AST node for the function body
}

interface TaintState {
  tainted:   Map<string, TaintEntry>   // variable → taint info
  functions: Map<string, FunctionSummary>
  sources:   TaintNode[]
  sinks:     TaintNode[]
  paths:     TaintPath[]
  file:      string
  lines:     string[]
  nodeId:    number
}

interface TaintEntry {
  source:    TaintNode
  hops:      TaintNode[]
  sanitized: boolean
  sanitizerName?: string
}

// ─── Known Sources ────────────────────────────────────────────────────────

const SOURCE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^(req|request|ctx)\.(body|query|params|headers|cookies|files|session)/, label: 'http_input' },
  { pattern: /^(args|input|data|payload|form|fields)$/,                               label: 'user_input' },
  { pattern: /^process\.env/,                                                          label: 'environment' },
  { pattern: /^(document\.(location|cookie|URL|referrer))/,                            label: 'dom_input' },
  { pattern: /^(window\.location|location\.(hash|search|href))/,                       label: 'url_input' },
]

// ─── Known Sinks ──────────────────────────────────────────────────────────

const SINK_PATTERNS: Array<{
  pattern: RegExp
  category: SastCategory
  severity: SastSeverity
  cwe: string
  owasp: string
  description: string
}> = [
  { pattern: /^eval$/,                       category: 'Injection',      severity: 'CRITICAL', cwe: 'CWE-94',  owasp: 'A03:2021 – Injection', description: 'Code injection via eval()' },
  { pattern: /^Function$/,                   category: 'Injection',      severity: 'CRITICAL', cwe: 'CWE-94',  owasp: 'A03:2021 – Injection', description: 'Code injection via Function constructor' },
  { pattern: /^(exec|execSync|spawn)$/,      category: 'Injection',      severity: 'CRITICAL', cwe: 'CWE-78',  owasp: 'A03:2021 – Injection', description: 'OS command injection' },
  { pattern: /\.(query|execute|raw|\$queryRaw|\$executeRaw)$/, category: 'Injection', severity: 'CRITICAL', cwe: 'CWE-89', owasp: 'A03:2021 – Injection', description: 'SQL injection' },
  { pattern: /\.innerHTML$/,                 category: 'XSS',            severity: 'HIGH',     cwe: 'CWE-79',  owasp: 'A03:2021 – Injection', description: 'DOM-based XSS via innerHTML' },
  { pattern: /^document\.write$/,            category: 'XSS',            severity: 'HIGH',     cwe: 'CWE-79',  owasp: 'A03:2021 – Injection', description: 'DOM-based XSS via document.write' },
  { pattern: /^(fetch|axios|http\.get|https\.get|got|request|undici\.fetch)/, category: 'SSRF', severity: 'HIGH', cwe: 'CWE-918', owasp: 'A10:2021 – SSRF', description: 'Server-Side Request Forgery' },
  { pattern: /^(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)/, category: 'Path Traversal', severity: 'HIGH', cwe: 'CWE-22', owasp: 'A01:2021 – Broken Access Control', description: 'Path traversal' },
  { pattern: /^(res|response)\.(send|json|write|end)$/, category: 'XSS', severity: 'MEDIUM', cwe: 'CWE-79', owasp: 'A03:2021 – Injection', description: 'Unsanitized data in HTTP response' },
  { pattern: /^(setInterval|setTimeout)$/,   category: 'Injection',      severity: 'HIGH',     cwe: 'CWE-94',  owasp: 'A03:2021 – Injection', description: 'Code injection via timer with string argument' },
]

// ─── Known Sanitizers ─────────────────────────────────────────────────────

const KNOWN_SANITIZERS = new Set([
  'parseInt', 'parseFloat', 'Number', 'Boolean', 'String',
  'encodeURIComponent', 'encodeURI', 'decodeURIComponent',
  'escapeHtml', 'escape', 'sanitize', 'purify',
  'DOMPurify.sanitize', 'xss', 'sanitizeHtml',
  'validator.escape', 'validator.isEmail', 'validator.isInt',
  'sqlstring.escape', 'mysql.escape', 'pg.escapeLiteral',
  'path.normalize', 'path.resolve', 'path.join', 'path.basename',
  'JSON.stringify',
  'zod.parse', 'schema.parse', 'schema.safeParse',
  'joi.validate',
])

// ─── Helpers ──────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function memberToStr(node: any): string {
  if (!node) return '?'
  if (node.type === 'Identifier') return node.name
  if (node.type === 'MemberExpression') {
    const obj = memberToStr(node.object)
    const prop = node.computed ? `[${memberToStr(node.property)}]` : `.${memberToStr(node.property)}`
    return obj + prop
  }
  if (node.type === 'Literal') return String(node.value)
  if (node.type === 'ThisExpression') return 'this'
  return '?'
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getCallee(node: any): string {
  if (node.callee?.type === 'Identifier') return node.callee.name
  if (node.callee?.type === 'MemberExpression') return memberToStr(node.callee)
  return ''
}

function makeNodeId(state: TaintState): string {
  return `tn-${state.nodeId++}`
}

function isSource(name: string): string | null {
  for (const sp of SOURCE_PATTERNS) {
    if (sp.pattern.test(name)) return sp.label
  }
  return null
}

function isSanitizer(name: string): boolean {
  if (KNOWN_SANITIZERS.has(name)) return true
  // Also match method calls like obj.sanitize(), obj.escape()
  const method = name.split('.').pop() || ''
  if (/^(sanitize|escape|purify|validate|clean|filter|encode|normalize)$/i.test(method)) return true
  return false
}

function findSink(name: string) {
  for (const sp of SINK_PATTERNS) {
    if (sp.pattern.test(name)) return sp
  }
  return null
}

function getSnippet(lines: string[], line: number, context: number = 1): string {
  const start = Math.max(0, line - 1 - context)
  const end = Math.min(lines.length - 1, line - 1 + context)
  return lines.slice(start, end + 1).map((l, i) => `${start + i + 1} | ${l}`).join('\n')
}

// ─── Phase 1: Build function summaries ────────────────────────────────────

function buildFunctionMap(ast: acorn.Node, state: TaintState): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  walk.simple(ast, {
    FunctionDeclaration(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.id?.name) {
        state.functions.set(n.id.name, {
          name: n.id.name,
          file: state.file,
          line: n.loc?.start?.line ?? 0,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          params: (n.params || []).map((p: any) => p.name || '?'),
          taintedParams: new Set(),
          returnsTaint: false,
          sanitizes: false,
          body: n.body,
        })
      }
    },
    VariableDeclarator(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.id?.type === 'Identifier' && n.init &&
          (n.init.type === 'FunctionExpression' || n.init.type === 'ArrowFunctionExpression')) {
        state.functions.set(n.id.name, {
          name: n.id.name,
          file: state.file,
          line: n.loc?.start?.line ?? 0,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          params: (n.init.params || []).map((p: any) => p.name || '?'),
          taintedParams: new Set(),
          returnsTaint: false,
          sanitizes: false,
          body: n.init.body,
        })
      }
    },
  } as walk.SimpleVisitors<unknown>)
}

// ─── Phase 2: Intra-procedural taint propagation ──────────────────────────

function propagateTaint(ast: acorn.Node, state: TaintState): void {
  // Pass 1: identify direct sources
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  walk.simple(ast, {
    VariableDeclarator(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (!n.id || !n.init) return

      if (n.id.type === 'Identifier') {
        const initStr = memberToStr(n.init)
        const label = isSource(initStr)
        if (label) {
          const loc = n.loc?.start ?? { line: 1, column: 0 }
          const srcNode: TaintNode = {
            id: makeNodeId(state),
            type: 'source',
            name: initStr,
            location: { file: state.file, line: loc.line, column: loc.column },
            taintLabel: label,
          }
          state.sources.push(srcNode)
          state.tainted.set(n.id.name, { source: srcNode, hops: [], sanitized: false })
        }
      }

      // Destructured: const { username, password } = req.body
      if (n.id.type === 'ObjectPattern' && n.init) {
        const initStr = memberToStr(n.init)
        const label = isSource(initStr)
        if (label) {
          const loc = n.loc?.start ?? { line: 1, column: 0 }
          const srcNode: TaintNode = {
            id: makeNodeId(state),
            type: 'source',
            name: initStr,
            location: { file: state.file, line: loc.line, column: loc.column },
            taintLabel: label,
          }
          state.sources.push(srcNode)
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          for (const prop of (n.id.properties || []) as any[]) {
            const varName = prop.value?.name || prop.key?.name
            if (varName) {
              state.tainted.set(varName, { source: srcNode, hops: [], sanitized: false })
            }
          }
        }
      }
    },

    AssignmentExpression(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.left?.type !== 'Identifier') return
      const rhsStr = memberToStr(n.right)
      const label = isSource(rhsStr)
      if (label) {
        const loc = n.loc?.start ?? { line: 1, column: 0 }
        const srcNode: TaintNode = {
          id: makeNodeId(state),
          type: 'source',
          name: rhsStr,
          location: { file: state.file, line: loc.line, column: loc.column },
          taintLabel: label,
        }
        state.sources.push(srcNode)
        state.tainted.set(n.left.name, { source: srcNode, hops: [], sanitized: false })
      }
    },
  } as walk.SimpleVisitors<unknown>)

  // Pass 2: propagate taint through variable assignments, binary expressions,
  // template literals, function calls (with sanitizer detection)
  for (let pass = 0; pass < 3; pass++) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    walk.simple(ast, {
      VariableDeclarator(node: acorn.Node) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const n = node as any
        if (!n.id || n.id.type !== 'Identifier' || !n.init) return
        if (state.tainted.has(n.id.name)) return // already tainted

        const entry = resolveNodeTaint(n.init, state)
        if (entry) {
          const loc = n.loc?.start ?? { line: 1, column: 0 }
          const hop: TaintNode = {
            id: makeNodeId(state),
            type: entry.sanitized ? 'sanitizer' : 'transform',
            name: n.id.name,
            location: { file: state.file, line: loc.line, column: loc.column },
            taintLabel: 'propagation',
          }
          state.tainted.set(n.id.name, {
            source: entry.source,
            hops: [...entry.hops, hop],
            sanitized: entry.sanitized,
            sanitizerName: entry.sanitizerName,
          })
        }
      },

      AssignmentExpression(node: acorn.Node) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const n = node as any
        if (n.left?.type !== 'Identifier') return
        if (state.tainted.has(n.left.name)) return

        const entry = resolveNodeTaint(n.right, state)
        if (entry) {
          const loc = n.loc?.start ?? { line: 1, column: 0 }
          const hop: TaintNode = {
            id: makeNodeId(state),
            type: entry.sanitized ? 'sanitizer' : 'transform',
            name: n.left.name,
            location: { file: state.file, line: loc.line, column: loc.column },
            taintLabel: 'propagation',
          }
          state.tainted.set(n.left.name, {
            source: entry.source,
            hops: [...entry.hops, hop],
            sanitized: entry.sanitized,
            sanitizerName: entry.sanitizerName,
          })
        }
      },
    } as walk.SimpleVisitors<unknown>)
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolveNodeTaint(node: any, state: TaintState): TaintEntry | null {
  if (!node) return null

  // Direct variable reference
  if (node.type === 'Identifier') {
    return state.tainted.get(node.name) || null
  }

  // Member expression (req.body.x, etc.)
  if (node.type === 'MemberExpression') {
    const str = memberToStr(node)
    const label = isSource(str)
    if (label) {
      const srcNode: TaintNode = {
        id: makeNodeId(state),
        type: 'source',
        name: str,
        location: { file: state.file, line: node.loc?.start?.line ?? 0, column: node.loc?.start?.column ?? 0 },
        taintLabel: label,
      }
      return { source: srcNode, hops: [], sanitized: false }
    }
    // Check if the object part is tainted
    return resolveNodeTaint(node.object, state)
  }

  // Binary expression: "SELECT * FROM " + username
  if (node.type === 'BinaryExpression') {
    return resolveNodeTaint(node.left, state) || resolveNodeTaint(node.right, state)
  }

  // Template literal: `SELECT * FROM ${username}`
  if (node.type === 'TemplateLiteral') {
    for (const expr of (node.expressions || [])) {
      const entry = resolveNodeTaint(expr, state)
      if (entry) return entry
    }
    return null
  }

  // Function call — check for sanitizers and taint propagation
  if (node.type === 'CallExpression') {
    const calleeName = getCallee(node)

    // Check if this is a sanitizer
    if (isSanitizer(calleeName)) {
      // Check if any argument is tainted
      for (const arg of (node.arguments || [])) {
        const entry = resolveNodeTaint(arg, state)
        if (entry) {
          return { ...entry, sanitized: true, sanitizerName: calleeName }
        }
      }
      return null
    }

    // Check if a known function propagates taint
    const fnSummary = state.functions.get(calleeName)
    if (fnSummary && fnSummary.returnsTaint) {
      // Check if tainted arguments are passed
      for (let i = 0; i < (node.arguments || []).length; i++) {
        if (fnSummary.taintedParams.has(i)) {
          const entry = resolveNodeTaint(node.arguments[i], state)
          if (entry) return entry
        }
      }
    }

    // Check if any argument to the call is tainted (conservative)
    for (const arg of (node.arguments || [])) {
      const entry = resolveNodeTaint(arg, state)
      if (entry) return entry
    }
    return null
  }

  // Conditional (ternary): cond ? a : b
  if (node.type === 'ConditionalExpression') {
    return resolveNodeTaint(node.consequent, state) || resolveNodeTaint(node.alternate, state)
  }

  // Logical expression: a || b, a && b
  if (node.type === 'LogicalExpression') {
    return resolveNodeTaint(node.left, state) || resolveNodeTaint(node.right, state)
  }

  // Await expression
  if (node.type === 'AwaitExpression') {
    return resolveNodeTaint(node.argument, state)
  }

  return null
}

// ─── Phase 3: Inter-procedural analysis ───────────────────────────────────

function analyzeInterProcedural(ast: acorn.Node, state: TaintState): void {
  // For each function, check if any parameter flows to a return statement
  for (const [, fnSummary] of Array.from(state.functions.entries())) {
    if (!fnSummary.body) continue

    // Build a local taint map for this function
    const localTainted = new Map<string, number>()
    fnSummary.params.forEach((p, i) => localTainted.set(p, i))

    // Check if sanitizer patterns exist in function name
    if (isSanitizer(fnSummary.name)) {
      fnSummary.sanitizes = true
    }

    // Walk the function body looking for return statements
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      walk.simple(fnSummary.body, {
        ReturnStatement(node: acorn.Node) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const n = node as any
          if (!n.argument) return
          const returned = findTaintedParam(n.argument, localTainted)
          if (returned !== null) {
            fnSummary.returnsTaint = true
            fnSummary.taintedParams.add(returned)
          }
        },
      } as walk.SimpleVisitors<unknown>)
    } catch {
      // Walking may fail on some AST shapes
    }
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findTaintedParam(node: any, paramMap: Map<string, number>): number | null {
  if (!node) return null
  if (node.type === 'Identifier') {
    return paramMap.get(node.name) ?? null
  }
  if (node.type === 'BinaryExpression') {
    return findTaintedParam(node.left, paramMap) ?? findTaintedParam(node.right, paramMap)
  }
  if (node.type === 'TemplateLiteral') {
    for (const expr of (node.expressions || [])) {
      const r = findTaintedParam(expr, paramMap)
      if (r !== null) return r
    }
  }
  if (node.type === 'MemberExpression') {
    return findTaintedParam(node.object, paramMap)
  }
  if (node.type === 'CallExpression') {
    for (const arg of (node.arguments || [])) {
      const r = findTaintedParam(arg, paramMap)
      if (r !== null) return r
    }
  }
  return null
}

// ─── Phase 4: Sink detection and path construction ────────────────────────

function detectSinks(ast: acorn.Node, state: TaintState): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  walk.simple(ast, {
    CallExpression(node: acorn.Node) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      const calleeName = getCallee(n)
      const sinkDef = findSink(calleeName)
      if (!sinkDef) return

      // Check if any argument is tainted
      for (const arg of (n.arguments || [])) {
        const entry = resolveNodeTaint(arg, state)
        if (entry) {
          const loc = n.loc?.start ?? { line: 1, column: 0 }
          const sinkNode: TaintNode = {
            id: makeNodeId(state),
            type: 'sink',
            name: calleeName,
            location: { file: state.file, line: loc.line, column: loc.column },
            taintLabel: sinkDef.category,
          }
          state.sinks.push(sinkNode)

          // Build the path
          const confidence = entry.sanitized ? 'LOW' : (
            entry.source.taintLabel === 'http_input' ? 'HIGH' : 'MEDIUM'
          )

          state.paths.push({
            source: entry.source,
            sink: sinkNode,
            hops: entry.hops,
            sanitized: entry.sanitized,
            sanitizerName: entry.sanitizerName,
            confidence,
          })
        }
      }
    },

    AssignmentExpression(node: acorn.Node) {
      // Check for innerHTML assignments: el.innerHTML = tainted
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any
      if (n.left?.type === 'MemberExpression') {
        const leftStr = memberToStr(n.left)
        const sinkDef = findSink(leftStr)
        if (sinkDef) {
          const entry = resolveNodeTaint(n.right, state)
          if (entry) {
            const loc = n.loc?.start ?? { line: 1, column: 0 }
            const sinkNode: TaintNode = {
              id: makeNodeId(state),
              type: 'sink',
              name: leftStr,
              location: { file: state.file, line: loc.line, column: loc.column },
              taintLabel: sinkDef.category,
            }
            state.sinks.push(sinkNode)
            state.paths.push({
              source: entry.source,
              sink: sinkNode,
              hops: entry.hops,
              sanitized: entry.sanitized,
              sanitizerName: entry.sanitizerName,
              confidence: entry.sanitized ? 'LOW' : 'HIGH',
            })
          }
        }
      }
    },
  } as walk.SimpleVisitors<unknown>)
}

// ─── Main entry: Run deep taint analysis ──────────────────────────────────

export function runDeepTaintAnalysis(
  scanId: string,
  filePath: string,
  source: string,
): SastFindingResult[] {
  // Only parse JS/TS
  const ext = filePath.split('.').pop()?.toLowerCase()
  if (!ext || !['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(ext)) return []

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
    return []
  }

  const lines = source.split('\n')
  const state: TaintState = {
    tainted:   new Map(),
    functions: new Map(),
    sources:   [],
    sinks:     [],
    paths:     [],
    file:      filePath,
    lines,
    nodeId:    0,
  }

  // Phase 1: Build function map
  buildFunctionMap(ast, state)

  // Phase 2: Inter-procedural analysis (before propagation so we know which functions propagate)
  analyzeInterProcedural(ast, state)

  // Phase 3: Intra-procedural taint propagation
  propagateTaint(ast, state)

  // Phase 4: Detect sinks and build paths
  detectSinks(ast, state)

  // Convert paths to findings
  return pathsToFindings(scanId, filePath, state)
}

// ─── Convert taint paths to SAST findings ─────────────────────────────────

function pathsToFindings(
  scanId: string,
  filePath: string,
  state: TaintState,
): SastFindingResult[] {
  const findings: SastFindingResult[] = []
  const seen = new Set<string>() // dedup by sink location

  for (const path of state.paths) {
    // Skip sanitized paths (they're handled, not vulnerable)
    if (path.sanitized) continue

    const dedupKey = `${path.sink.location.line}:${path.sink.name}`
    if (seen.has(dedupKey)) continue
    seen.add(dedupKey)

    // Find the sink definition for metadata
    const sinkDef = findSink(path.sink.name)
    if (!sinkDef) continue

    // Build the flow description
    const flowSteps = [
      `${path.source.name} (line ${path.source.location.line})`,
      ...path.hops.map(h => `→ ${h.name} (line ${h.location.line})`),
      `→ ${path.sink.name} (line ${path.sink.location.line})`,
    ].join(' ')

    findings.push({
      id:           `${scanId}-taint-${findings.length}`,
      scanId,
      ruleId:       `TAINT-${sinkDef.cwe.replace('CWE-', '')}`,
      ruleName:     `Data flow: ${sinkDef.description}`,
      severity:     sinkDef.severity,
      confidence:   path.confidence,
      language:     'javascript',
      filePath,
      lineStart:    path.sink.location.line,
      lineEnd:      path.sink.location.line,
      codeSnippet:  getSnippet(state.lines, path.sink.location.line),
      description:  `Taint analysis detected user-controlled data flowing to a dangerous sink.\n\nFlow: ${flowSteps}\n\nSource: ${path.source.name} (${path.source.taintLabel})\nSink: ${path.sink.name} (${sinkDef.description})`,
      remediation:  getRemediation(sinkDef.category),
      owasp:        sinkDef.owasp,
      cwe:          sinkDef.cwe,
      category:     sinkDef.category,
      status:       'OPEN',
      falsePositive: false,
      detectedAt:   new Date().toISOString(),
    })
  }

  return findings
}

function getRemediation(category: SastCategory): string {
  const remediation: Record<string, string> = {
    'Injection':       'Use parameterized queries for SQL. Use execFile() with array args for OS commands. Never pass user input to eval().',
    'XSS':             'Sanitize output with DOMPurify or use textContent. Apply Content-Security-Policy headers.',
    'SSRF':            'Validate and allowlist URLs. Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x). Use a URL parser.',
    'Path Traversal':  'Use path.resolve() and verify the result starts with the expected base directory. Reject paths containing "..".',
  }
  return remediation[category] || 'Validate and sanitize all user input before passing to security-sensitive functions.'
}

// ─── TypeScript stripping (same as ast-engine) ────────────────────────────

function stripTypeScript(source: string): string {
  return source
    .replace(/:\s*(?:string|number|boolean|any|void|never|unknown|null|undefined|object|symbol|bigint|Record|Array|Promise|Map|Set|Date)\b[^=,)}\n]*/g, '')
    .replace(/^(?:export\s+)?(?:interface|type)\s+\w+[\s\S]*?^\}/gm, '')
    .replace(/<[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*>/g, '')
    .replace(/\bas\s+\w+/g, '')
    .replace(/\b(?:public|private|protected|readonly|abstract|override)\s+/g, '')
    .replace(/!\./g, '.')
    .replace(/\bsatisfies\s+\w+/g, '')
}

/** Get count of taint analysis sink patterns */
export function getTaintRuleCount(): number {
  return SINK_PATTERNS.length
}

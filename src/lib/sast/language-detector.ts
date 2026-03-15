import type { SupportedLanguage } from '@/lib/types/sast'

const EXT_MAP: Record<string, SupportedLanguage> = {
  js:   'javascript',
  mjs:  'javascript',
  cjs:  'javascript',
  jsx:  'javascript',
  ts:   'typescript',
  tsx:  'typescript',
  py:   'python',
  php:  'php',
  phtml:'php',
  java: 'java',
  go:   'go',
  rb:   'ruby',
  cs:   'csharp',
}

// Shebang / import signature heuristics for files without extensions
const CONTENT_HINTS: Array<{ pattern: RegExp; lang: SupportedLanguage }> = [
  { pattern: /^#!.*python|^from\s+\w+\s+import|^import\s+\w+\s*$/m,   lang: 'python' },
  { pattern: /^<\?php/,                                                  lang: 'php' },
  { pattern: /^package\s+main|^import\s+"fmt"/m,                         lang: 'go' },
  { pattern: /^import\s+(?:java\.|org\.|com\.)|public\s+class\s+\w+/m,  lang: 'java' },
  { pattern: /require\s*\(|module\.exports|const\s+\w+\s*=\s*require/,  lang: 'javascript' },
  { pattern: /import\s+type\s+|interface\s+\w+\s*\{|:\s*string\s*[;,]/, lang: 'typescript' },
  { pattern: /^#!.*ruby|require\s+'[a-z]/m,                              lang: 'ruby' },
  { pattern: /using\s+System;|namespace\s+\w+/,                          lang: 'csharp' },
]

/**
 * Detect language from file path extension, with content-based fallback.
 */
export function detectLanguage(filePath: string, content: string): SupportedLanguage {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? ''
  if (EXT_MAP[ext]) return EXT_MAP[ext]

  for (const { pattern, lang } of CONTENT_HINTS) {
    if (pattern.test(content)) return lang
  }
  return 'unknown'
}

/**
 * Return true if rule language list includes the given language or 'all'.
 */
export function languageMatches(
  ruleLangs: string[],
  fileLang: SupportedLanguage
): boolean {
  return (ruleLangs as string[]).includes('all') || ruleLangs.includes(fileLang)
}

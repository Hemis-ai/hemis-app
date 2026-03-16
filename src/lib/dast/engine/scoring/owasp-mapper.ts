import type { OwaspMapping } from '../../types'

const PLUGIN_MAP = new Map<string, OwaspMapping>([
  ['10010', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-1004', type: 'missing_httponly', mitreAttackIds: [], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10011', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-614', type: 'missing_secure_flag', mitreAttackIds: [], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10054', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-1275', type: 'missing_samesite', mitreAttackIds: [], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10056', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-200', type: 'x_debug_token', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10202', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-22', type: 'directory_traversal', mitreAttackIds: ['T1083'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.1'] }],
  ['10041', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-319', type: 'http_to_https_insecure', mitreAttackIds: [], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],
  ['10042', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-319', type: 'https_to_http_insecure', mitreAttackIds: [], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],
  ['10096', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-200', type: 'timestamp_disclosure', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10098', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-264', type: 'cross_domain_misconfig', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['40012', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-79', type: 'xss_reflected', mitreAttackIds: ['T1059.007'], pciDssRefs: ['6.5.7'], soc2Refs: ['CC6.6'] }],
  ['40014', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-79', type: 'xss_stored', mitreAttackIds: ['T1059.007'], pciDssRefs: ['6.5.7'], soc2Refs: ['CC6.6'] }],
  ['40018', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40019', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_mysql', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40020', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_hypersonic', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40021', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_oracle', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40022', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_postgres', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40024', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_sqlite', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40026', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-79', type: 'xss_dom', mitreAttackIds: ['T1059.007'], pciDssRefs: ['6.5.7'], soc2Refs: ['CC6.6'] }],
  ['40027', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_mssql', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40003', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-113', type: 'crlf_injection', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40008', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-472', type: 'parameter_tampering', mitreAttackIds: [], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40009', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-97', type: 'server_side_include', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40028', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-215', type: 'elmah_info_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['40032', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-215', type: 'htaccess_info_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['40034', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-215', type: 'env_info_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['90018', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-89', type: 'sql_injection_advanced', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['90019', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-94', type: 'server_side_code_injection', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['90020', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-78', type: 'command_injection', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['90021', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-643', type: 'xpath_injection', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['90023', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-611', type: 'xxe', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['10020', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-1021', type: 'missing_anti_clickjacking', mitreAttackIds: [], pciDssRefs: ['6.5.9'], soc2Refs: ['CC6.1'] }],
  ['10021', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-693', type: 'missing_x_content_type_options', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10035', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-319', type: 'missing_hsts', mitreAttackIds: [], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],
  ['10036', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-200', type: 'server_version_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10037', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-200', type: 'server_x_powered_by_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10038', { owaspCategory: 'A04:2021-Insecure Design', cweId: 'CWE-693', type: 'missing_csp', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10009', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'in_page_banner_info_leak', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10015', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-525', type: 'incomplete_cache_control', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10017', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-829', type: 'cross_domain_js', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10019', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-345', type: 'missing_content_type', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10023', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'debug_error_messages', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10024', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'sensitive_data_in_url', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10025', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'sensitive_data_in_referrer', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10027', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'suspicious_comments', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10032', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-642', type: 'viewstate', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10040', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-311', type: 'mixed_content', mitreAttackIds: [], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],
  ['10043', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-20', type: 'user_controllable_js_event', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10048', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-78', type: 'shellshock', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['10050', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-524', type: 'retrieved_from_cache', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10052', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'chrome_logger_data', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10055', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-693', type: 'csp_scanner', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10057', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-284', type: 'username_hash_found', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10062', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-359', type: 'pii_disclosure', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['90001', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-642', type: 'insecure_jsf_viewstate', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['90011', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-436', type: 'charset_mismatch', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['90022', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'application_error_disclosure', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['90033', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-565', type: 'loosely_scoped_cookie', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10003', { owaspCategory: 'A06:2021-Vulnerable and Outdated Components', cweId: 'CWE-829', type: 'vulnerable_js_library', mitreAttackIds: ['T1189'], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10044', { owaspCategory: 'A06:2021-Vulnerable and Outdated Components', cweId: 'CWE-201', type: 'big_redirect', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10058', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-16', type: 'get_for_post', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10105', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-326', type: 'weak_authentication', mitreAttackIds: [], pciDssRefs: ['2.1'], soc2Refs: ['CC6.1'] }],
  ['10026', { owaspCategory: 'A08:2021-Software and Data Integrity Failures', cweId: 'CWE-235', type: 'http_parameter_override', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.6'] }],
  ['90017', { owaspCategory: 'A08:2021-Software and Data Integrity Failures', cweId: 'CWE-91', type: 'xslt_injection', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['40046', { owaspCategory: 'A10:2021-Server-Side Request Forgery', cweId: 'CWE-918', type: 'ssrf', mitreAttackIds: ['T1190'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],

  // ─── Expanded Coverage: Additional ZAP Plugin Mappings ─────────────────

  // A01: Broken Access Control — Additional checks
  ['40016', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-352', type: 'cross_site_method_tampering', mitreAttackIds: ['T1185'], pciDssRefs: ['6.5.9'], soc2Refs: ['CC6.1'] }],
  ['40038', { owaspCategory: 'A01:2021-Broken Access Control', cweId: 'CWE-284', type: 'bypassing_403', mitreAttackIds: ['T1190'], pciDssRefs: ['7.1'], soc2Refs: ['CC6.1', 'CC6.3'] }],

  // A02: Cryptographic Failures — Additional checks
  ['10047', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-311', type: 'https_content_via_http', mitreAttackIds: ['T1557'], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],
  ['10106', { owaspCategory: 'A02:2021-Cryptographic Failures', cweId: 'CWE-319', type: 'http_only_site', mitreAttackIds: ['T1557'], pciDssRefs: ['4.1'], soc2Refs: ['CC6.7'] }],

  // A03: Injection — Advanced injection types
  ['40017', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-79', type: 'xss_persistent', mitreAttackIds: ['T1059.007'], pciDssRefs: ['6.5.7'], soc2Refs: ['CC6.6'] }],
  ['90025', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-917', type: 'expression_language_injection', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],
  ['90035', { owaspCategory: 'A03:2021-Injection', cweId: 'CWE-1336', type: 'ssti', mitreAttackIds: ['T1059'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],

  // A05: Security Misconfiguration — Extended coverage
  ['10045', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-540', type: 'source_code_disclosure', mitreAttackIds: ['T1083'], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['10049', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-524', type: 'content_cacheability', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['10095', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-530', type: 'backup_file_disclosure', mitreAttackIds: ['T1083'], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['40029', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-693', type: 'trace_method', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['40035', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-538', type: 'hidden_file', mitreAttackIds: ['T1083'], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['40042', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-215', type: 'spring_actuator', mitreAttackIds: ['T1190'], pciDssRefs: [], soc2Refs: ['CC7.1'] }],
  ['90028', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-200', type: 'insecure_http_method', mitreAttackIds: [], pciDssRefs: [], soc2Refs: ['CC6.1'] }],
  ['90034', { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: 'CWE-918', type: 'cloud_metadata', mitreAttackIds: ['T1552.005'], pciDssRefs: ['6.5.1'], soc2Refs: ['CC6.6'] }],

  // A06: Vulnerable and Outdated Components — Log4Shell
  ['40043', { owaspCategory: 'A06:2021-Vulnerable and Outdated Components', cweId: 'CWE-117', type: 'log4shell', mitreAttackIds: ['T1190', 'T1059'], pciDssRefs: ['6.5.1', '6.2'], soc2Refs: ['CC6.6', 'CC7.1'] }],

  // A07: Identification and Authentication Failures — Session & Auth
  ['40013', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-384', type: 'session_fixation', mitreAttackIds: ['T1563'], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10012', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-613', type: 'session_timeout', mitreAttackIds: ['T1550'], pciDssRefs: ['6.5.10', '8.1.8'], soc2Refs: ['CC6.1'] }],
  ['10029', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-614', type: 'insecure_session_cookie', mitreAttackIds: ['T1539'], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10053', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-1004', type: 'cookie_without_expiry', mitreAttackIds: [], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1'] }],
  ['10108', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-352', type: 'csrf_on_auth', mitreAttackIds: ['T1185'], pciDssRefs: ['6.5.9'], soc2Refs: ['CC6.1'] }],
  ['10109', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-307', type: 'brute_force', mitreAttackIds: ['T1110'], pciDssRefs: ['6.5.10', '8.1.6'], soc2Refs: ['CC6.1'] }],
  ['10110', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-287', type: 'auth_bypass', mitreAttackIds: ['T1548'], pciDssRefs: ['6.5.10'], soc2Refs: ['CC6.1', 'CC6.3'] }],
  ['10111', { owaspCategory: 'A07:2021-Identification and Authentication Failures', cweId: 'CWE-613', type: 'insufficient_session_expiry', mitreAttackIds: ['T1550'], pciDssRefs: ['6.5.10', '8.1.8'], soc2Refs: ['CC6.1'] }],
])

export function getOwaspMapping(pluginId: string): OwaspMapping | undefined {
  return PLUGIN_MAP.get(pluginId)
}

export function getOwaspMappingOrDefault(pluginId: string, riskLevel: string): OwaspMapping {
  return PLUGIN_MAP.get(pluginId) ?? buildDefaultMapping(riskLevel)
}

function buildDefaultMapping(riskLevel: string): OwaspMapping {
  const base = { owaspCategory: 'A05:2021-Security Misconfiguration', cweId: '', mitreAttackIds: [] as string[], pciDssRefs: [] as string[] }
  switch (riskLevel.toLowerCase()) {
    case 'high': return { ...base, type: 'unknown_high', soc2Refs: ['CC6.6'] }
    case 'medium': return { ...base, type: 'unknown_medium', soc2Refs: ['CC6.1'] }
    case 'low': return { ...base, type: 'unknown_low', soc2Refs: [] }
    default: return { ...base, type: 'unknown_info', soc2Refs: [] }
  }
}

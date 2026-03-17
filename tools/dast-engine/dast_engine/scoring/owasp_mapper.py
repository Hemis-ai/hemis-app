"""OWASP Top 10 2021 + CWE + MITRE ATT&CK + PCI-DSS + SOC2 mapping for vulnerability types."""

from dataclasses import dataclass, field


@dataclass
class OwaspMapping:
    owasp_category: str
    cwe_id: str
    type: str
    mitre_attack_ids: list[str] = field(default_factory=list)
    pci_dss_refs: list[str] = field(default_factory=list)
    soc2_refs: list[str] = field(default_factory=list)


VULN_TYPE_MAP: dict[str, OwaspMapping] = {
    # A03:2021 Injection
    "sql_injection": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_mysql": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection_mysql", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_postgres": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection_postgres", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_mssql": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection_mssql", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_sqlite": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection_sqlite", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_oracle": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection_oracle", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_blind": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "sql_injection_time": OwaspMapping("A03:2021 Injection", "CWE-89", "sql_injection", ["T1190"], ["6.5.1"], ["CC6.6"]),
    "xss_reflected": OwaspMapping("A03:2021 Injection", "CWE-79", "xss_reflected", ["T1059.007"], ["6.5.7"], ["CC6.6"]),
    "xss_stored": OwaspMapping("A03:2021 Injection", "CWE-79", "xss_stored", ["T1059.007"], ["6.5.7"], ["CC6.6"]),
    "xss_dom": OwaspMapping("A03:2021 Injection", "CWE-79", "xss_dom", ["T1059.007"], ["6.5.7"], ["CC6.6"]),
    "command_injection": OwaspMapping("A03:2021 Injection", "CWE-78", "command_injection", ["T1059"], ["6.5.1"], ["CC6.6"]),
    "ssti": OwaspMapping("A03:2021 Injection", "CWE-1336", "ssti", ["T1059"], ["6.5.1"], ["CC6.6"]),

    # A01:2021 Broken Access Control
    "directory_traversal": OwaspMapping("A01:2021 Broken Access Control", "CWE-22", "directory_traversal", ["T1083"], ["6.5.1"], ["CC6.1"]),
    "open_redirect": OwaspMapping("A01:2021 Broken Access Control", "CWE-601", "open_redirect", ["T1566"], ["6.5.10"], ["CC6.1"]),
    "cors_misconfiguration": OwaspMapping("A01:2021 Broken Access Control", "CWE-942", "cors_misconfiguration", [], ["6.5.10"], ["CC6.1"]),
    "missing_httponly": OwaspMapping("A01:2021 Broken Access Control", "CWE-1004", "missing_httponly", [], ["6.5.10"], ["CC6.1"]),
    "missing_secure_flag": OwaspMapping("A01:2021 Broken Access Control", "CWE-614", "missing_secure_flag", [], ["6.5.10"], ["CC6.1"]),
    "missing_samesite": OwaspMapping("A01:2021 Broken Access Control", "CWE-1275", "missing_samesite", [], ["6.5.10"], ["CC6.1"]),
    "insecure_cookie": OwaspMapping("A01:2021 Broken Access Control", "CWE-614", "insecure_cookie", [], ["6.5.10"], ["CC6.1"]),

    # A05:2021 Security Misconfiguration
    "missing_csp": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-693", "missing_csp", [], [], ["CC6.1"]),
    "missing_hsts": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-319", "missing_hsts", [], ["4.1"], ["CC6.7"]),
    "missing_anti_clickjacking": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-1021", "missing_anti_clickjacking", [], ["6.5.9"], ["CC6.1"]),
    "missing_x_content_type_options": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-693", "missing_x_content_type_options", [], [], ["CC6.1"]),
    "server_version_leak": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-200", "server_version_leak", [], [], ["CC7.1"]),
    "debug_error_messages": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-215", "debug_error_messages", [], [], ["CC7.1"]),
    "information_disclosure": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-200", "information_disclosure", [], [], ["CC7.1"]),
    "exposed_sensitive_file": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-538", "hidden_file", ["T1083"], [], ["CC7.1"]),
    "missing_referrer_policy": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-116", "missing_referrer_policy", [], [], ["CC6.1"]),
    "missing_permissions_policy": OwaspMapping("A05:2021 Security Misconfiguration", "CWE-693", "missing_permissions_policy", [], [], ["CC6.1"]),

    # A10:2021 SSRF
    "ssrf": OwaspMapping("A10:2021 Server-Side Request Forgery", "CWE-918", "ssrf", ["T1190"], ["6.5.1"], ["CC6.6"]),
}


def get_owasp_mapping(vuln_type: str) -> OwaspMapping:
    return VULN_TYPE_MAP.get(vuln_type, OwaspMapping(
        owasp_category="A05:2021 Security Misconfiguration",
        cwe_id="CWE-200",
        type=vuln_type,
    ))

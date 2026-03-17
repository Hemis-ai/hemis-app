"""CVSS v3.1 Calculator - Direct port from TypeScript cvss-calculator.ts"""
import math
from ..models.cvss import CvssInput, CvssResult

AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.00}


def round_up(value: float) -> float:
    return math.ceil(value * 10) / 10


def cvss_to_severity(score: float) -> str:
    if score == 0.0:
        return "INFO"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def format_vector(inp: CvssInput) -> str:
    return f"CVSS:3.1/AV:{inp.AV}/AC:{inp.AC}/PR:{inp.PR}/UI:{inp.UI}/S:{inp.S}/C:{inp.C}/I:{inp.I}/A:{inp.A}"


def calculate_cvss(inp: CvssInput) -> CvssResult:
    iss = 1 - (1 - IMPACT_WEIGHTS[inp.C]) * (1 - IMPACT_WEIGHTS[inp.I]) * (1 - IMPACT_WEIGHTS[inp.A])

    if inp.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return CvssResult(score=0.0, vector=format_vector(inp), severity="INFO")

    pr_weight = PR_WEIGHTS_UNCHANGED[inp.PR] if inp.S == "U" else PR_WEIGHTS_CHANGED[inp.PR]
    exploitability = 8.22 * AV_WEIGHTS[inp.AV] * AC_WEIGHTS[inp.AC] * pr_weight * UI_WEIGHTS[inp.UI]

    if inp.S == "U":
        score = round_up(min(impact + exploitability, 10))
    else:
        score = round_up(min(1.08 * (impact + exploitability), 10))

    return CvssResult(score=score, vector=format_vector(inp), severity=cvss_to_severity(score))


# All preset vectors ported from TypeScript
PRESET_VECTORS: dict[str, dict] = {
    # Critical: Remote Code Execution / Full Compromise
    "sql_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "sql_injection_mysql": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "sql_injection_postgres": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "sql_injection_mssql": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "sql_injection_sqlite": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "sql_injection_oracle": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "command_injection": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "ssti": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    # High: Data Exfiltration / Significant Impact
    "ssrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N"},
    "directory_traversal": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "xxe": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "session_fixation": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "H", "I": "H", "A": "N"},
    "broken_access_control": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    # Medium: Client-Side / Conditional Impact
    "xss_reflected": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "xss_stored": {"AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "xss_dom": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "open_redirect": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "cors_misconfiguration": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    # Low: Informational / Hardening
    "information_disclosure": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    "missing_csp": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
    "missing_hsts": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "missing_anti_clickjacking": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
    "missing_x_content_type_options": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
    "insecure_cookie": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "missing_httponly": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "missing_secure_flag": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "missing_samesite": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "server_version_leak": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    "debug_error_messages": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
}


def get_cvss_for_type(vuln_type: str) -> CvssResult:
    """Get pre-calculated CVSS for a known vulnerability type."""
    preset = PRESET_VECTORS.get(vuln_type)
    if preset:
        return calculate_cvss(CvssInput(**preset))
    # Default: low severity info disclosure
    return calculate_cvss(CvssInput(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"))

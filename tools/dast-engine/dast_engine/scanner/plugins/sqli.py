"""
SQL Injection detection — Burp-Suite-grade validation.

Key validation steps:
1. Error-based: Get BASELINE response first, check error patterns don't pre-exist,
   then inject and confirm NEW error patterns appear
2. Boolean-blind: Use statistical analysis with multiple request pairs to eliminate noise
3. Time-based: Confirm with TWO time-delayed requests (Burp's approach to eliminate network jitter)
"""
from __future__ import annotations
import re
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext

# Database error signatures for error-based SQLi detection
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark after the character string",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"MySqlException",
        r"com\.mysql\.jdbc",
        r"SQLSTATE\[HY000\]",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"PSQLException",
        r"org\.postgresql",
        r"ERROR:\s+syntax error at or near",
        r"unterminated quoted string",
        r"invalid input syntax for type",
    ],
    "MSSQL": [
        r"microsoft.*odbc.*driver",
        r"microsoft.*sql.*server",
        r"Unclosed quotation mark",
        r"SqlException",
        r"Incorrect syntax near",
        r"\[Microsoft\]\[ODBC",
    ],
    "Oracle": [
        r"ORA-\d{5}",
        r"oracle.*driver",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"unrecognized token",
        r'near ".*": syntax error',
    ],
}

# Error-based injection payloads
ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1' --", "' OR 1=1 --", '" OR 1=1 --', "' UNION SELECT NULL --"]

# Boolean-blind payloads (pairs: true condition, false condition)
BLIND_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1 --", "' AND 1=2 --"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
]

# Time-based payloads (should cause >4s delay)
TIME_PAYLOADS = [
    ("' OR SLEEP(5) --", "MySQL"),
    ("'; WAITFOR DELAY '0:0:5' --", "MSSQL"),
    ("' OR pg_sleep(5) --", "PostgreSQL"),
]


class SQLiPlugin(BasePlugin):
    name = "SQL Injection Scanner"
    vuln_type = "sql_injection"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        test_params = self._get_params(target)
        if not test_params:
            return findings

        for param_name, param_source in test_params:
            # Phase 1: Error-based detection (with baseline comparison)
            finding = await self._test_error_based(ctx, target, param_name, param_source)
            if finding:
                findings.append(finding)
                continue

            # Phase 2: Boolean-blind detection (statistical)
            finding = await self._test_blind(ctx, target, param_name, param_source)
            if finding:
                findings.append(finding)
                continue

            # Phase 3: Time-based detection (with confirmation)
            finding = await self._test_time_based(ctx, target, param_name, param_source)
            if finding:
                findings.append(finding)

        return findings

    def _get_params(self, target: ScanTarget) -> list[tuple[str, str]]:
        params = []
        for p in target.parameters:
            params.append((p, "query"))
        for f in target.form_fields:
            params.append((f.get("name", ""), "form"))
        return [(n, s) for n, s in params if n]

    async def _inject(self, ctx: ScanContext, target: ScanTarget, param: str, payload: str, source: str):
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
            return await self._send_request(ctx, url, method="GET", headers=target.headers, cookies=target.cookies)
        else:
            form_data = {}
            for f in target.form_fields:
                form_data[f["name"]] = f.get("value", "test")
            form_data[param] = payload
            return await self._send_request(ctx, target.url, method="POST", data=form_data, headers=target.headers, cookies=target.cookies)

    def _find_db_errors(self, text: str) -> list[tuple[str, str, re.Match]]:
        """Scan text for database error patterns. Returns [(db_type, pattern, match)]."""
        results = []
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    results.append((db_type, pattern, match))
        return results

    async def _test_error_based(self, ctx: ScanContext, target: ScanTarget, param: str, source: str):
        """
        Error-based SQLi with baseline comparison:
        1. Send clean value → record which error patterns exist in baseline
        2. Send SQL metacharacter → check for NEW error patterns not in baseline
        """
        # Baseline: send a normal, non-malicious value
        baseline = await self._inject(ctx, target, param, "hemisxtest123", source)
        if baseline is None:
            return None

        # Record error patterns already present in the baseline
        baseline_errors = set()
        for db_type, pattern, _ in self._find_db_errors(baseline.text):
            baseline_errors.add(pattern)

        for payload in ERROR_PAYLOADS:
            resp = await self._inject(ctx, target, param, payload, source)
            if resp is None:
                continue

            for db_type, pattern, match in self._find_db_errors(resp.text):
                if pattern in baseline_errors:
                    continue  # Already there before injection

                evidence = resp.text[max(0, match.start() - 50):match.end() + 50]

                # Verification: inject again to confirm reproducibility
                verify = await self._inject(ctx, target, param, payload, source)
                if verify is None:
                    continue
                verify_match = re.search(pattern, verify.text, re.IGNORECASE)
                if not verify_match:
                    continue

                vuln_type = {
                    "MySQL": "sql_injection_mysql", "PostgreSQL": "sql_injection_postgres",
                    "MSSQL": "sql_injection_mssql", "Oracle": "sql_injection_oracle",
                    "SQLite": "sql_injection_sqlite",
                }.get(db_type, "sql_injection")

                return RawFinding(
                    vuln_type=vuln_type,
                    title=f"SQL Injection ({db_type} — Error Based)",
                    description=(
                        f"The parameter '{param}' is vulnerable to SQL injection. "
                        f"Injecting SQL metacharacters triggered a {db_type} database error "
                        f"that was NOT present in the baseline response, confirming that user "
                        f"input is directly interpolated into SQL queries. "
                        f"Verified: error reproduced across two independent requests."
                    ),
                    affected_url=target.url, severity="CRITICAL",
                    affected_parameter=param, injection_point=source, payload=payload,
                    request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
                    response_evidence=evidence.strip(),
                    remediation=(
                        "Use parameterized queries (prepared statements) instead of string concatenation. "
                        "Never interpolate user input directly into SQL queries."
                    ),
                    remediation_code=json.dumps({
                        "vulnerableCode": f"db.query(f\"SELECT * FROM users WHERE {param}='{{req.{param}}}'\")",
                        "remediatedCode": f"db.query(\"SELECT * FROM users WHERE {param} = $1\", [req.{param}])",
                        "explanation": "Parameterized queries separate SQL logic from data, preventing injection.",
                        "language": "Python/JavaScript",
                    }),
                    confidence=95, verified=True,
                    business_impact=f"Full database compromise. An attacker can read, modify, or delete all data in the {db_type} database.",
                )
        return None

    async def _test_blind(self, ctx: ScanContext, target: ScanTarget, param: str, source: str):
        """Boolean-blind SQLi with statistical validation and repeated confirmation."""
        # Establish baseline variance with 3 requests
        baseline_lengths = []
        for _ in range(3):
            resp = await self._inject(ctx, target, param, "hemisxtest123", source)
            if resp is None:
                return None
            baseline_lengths.append(len(resp.text))

        avg_baseline = sum(baseline_lengths) / len(baseline_lengths)
        baseline_variance = max(abs(l - avg_baseline) for l in baseline_lengths)
        min_threshold = max(baseline_variance * 3, 200)

        for true_payload, false_payload in BLIND_PAIRS:
            true_resp = await self._inject(ctx, target, param, f"hemisxtest123{true_payload}", source)
            false_resp = await self._inject(ctx, target, param, f"hemisxtest123{false_payload}", source)
            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)
            diff = abs(true_len - false_len)

            if diff < min_threshold:
                continue
            # True should be closer to baseline
            if abs(true_len - avg_baseline) >= abs(false_len - avg_baseline):
                continue

            # Verification
            v_true = await self._inject(ctx, target, param, f"hemisxtest123{true_payload}", source)
            v_false = await self._inject(ctx, target, param, f"hemisxtest123{false_payload}", source)
            if v_true is None or v_false is None:
                continue
            if abs(len(v_true.text) - len(v_false.text)) < min_threshold:
                continue

            return RawFinding(
                vuln_type="sql_injection",
                title="SQL Injection (Boolean-Based Blind)",
                description=(
                    f"The parameter '{param}' is vulnerable to boolean-based blind SQL injection. "
                    f"True conditions: ~{true_len}B, false: ~{false_len}B (delta: {diff}B, "
                    f"baseline variance: {baseline_variance:.0f}B). Verified with repeated pairs."
                ),
                affected_url=target.url, severity="CRITICAL",
                affected_parameter=param, injection_point=source,
                payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                request_evidence=f"True: {true_len}B, False: {false_len}B, Baseline: {avg_baseline:.0f}B",
                response_evidence=f"Delta: {diff}B (threshold: {min_threshold:.0f}B)",
                remediation="Use parameterized queries. Implement WAF rules for SQL injection patterns.",
                confidence=82, verified=True,
                business_impact="Database content can be extracted one bit at a time through boolean queries.",
            )
        return None

    async def _test_time_based(self, ctx: ScanContext, target: ScanTarget, param: str, source: str):
        """Time-based blind SQLi with double-confirmation."""
        baseline_times = []
        for _ in range(3):
            start = time.time()
            resp = await self._inject(ctx, target, param, "hemisxtest123", source)
            baseline_times.append(time.time() - start)
            if resp is None:
                return None

        avg_baseline = sum(baseline_times) / len(baseline_times)
        max_baseline = max(baseline_times)
        time_threshold = max_baseline + 4.0

        for payload, db_type in TIME_PAYLOADS:
            start = time.time()
            resp = await self._inject(ctx, target, param, f"hemisxtest123{payload}", source)
            elapsed = time.time() - start
            if resp is None or elapsed < time_threshold:
                continue

            # Confirmation
            start2 = time.time()
            resp2 = await self._inject(ctx, target, param, f"hemisxtest123{payload}", source)
            elapsed2 = time.time() - start2
            if resp2 is None or elapsed2 < time_threshold:
                continue

            vuln_type = f"sql_injection_{db_type.lower()}" if db_type != "MySQL" else "sql_injection_mysql"
            return RawFinding(
                vuln_type=vuln_type,
                title=f"SQL Injection (Time-Based Blind — {db_type})",
                description=(
                    f"The parameter '{param}' is vulnerable to time-based blind SQL injection. "
                    f"SLEEP payload caused {elapsed:.1f}s and {elapsed2:.1f}s delays "
                    f"(baseline: avg {avg_baseline:.1f}s, max {max_baseline:.1f}s). "
                    f"Confirmed with two independent requests."
                ),
                affected_url=target.url, severity="CRITICAL",
                affected_parameter=param, injection_point=source, payload=payload,
                request_evidence=f"Baseline: avg {avg_baseline:.1f}s | Injected: {elapsed:.1f}s, {elapsed2:.1f}s",
                response_evidence=f"Time delta: {elapsed - avg_baseline:.1f}s, {elapsed2 - avg_baseline:.1f}s",
                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                confidence=88, verified=True,
                business_impact=f"Complete {db_type} database compromise through time-based data extraction.",
            )
        return None

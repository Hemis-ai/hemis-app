"""SQL Injection detection: error-based, boolean-blind, and time-based."""
from __future__ import annotations
import re
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding

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
        r"near \".*\": syntax error",
    ],
}

# Error-based injection payloads
ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1' --", "' OR 1=1 --", '" OR 1=1 --', "1; DROP TABLE test --", "' UNION SELECT NULL --"]

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
    ("' AND (SELECT CASE WHEN (1=1) THEN RANDOMBLOB(500000000) ELSE 1 END) --", "SQLite"),
]


class SQLiPlugin(BasePlugin):
    name = "SQL Injection Scanner"
    vuln_type = "sql_injection"

    async def scan(self, target: ScanTarget) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Get all testable parameters
        test_params = self._get_params(target)
        if not test_params:
            return findings

        for param_name, param_source in test_params:
            # Phase 1: Error-based detection
            finding = await self._test_error_based(target, param_name, param_source)
            if finding:
                findings.append(finding)
                continue  # Skip further tests for this param

            # Phase 2: Boolean-blind detection
            finding = await self._test_blind(target, param_name, param_source)
            if finding:
                findings.append(finding)
                continue

            # Phase 3: Time-based detection
            finding = await self._test_time_based(target, param_name, param_source)
            if finding:
                findings.append(finding)

        return findings

    def _get_params(self, target: ScanTarget) -> list[tuple[str, str]]:
        """Get all testable parameters from URL query and form fields."""
        params = []
        for p in target.parameters:
            params.append((p, "query"))
        for f in target.form_fields:
            params.append((f.get("name", ""), "form"))
        return [(n, s) for n, s in params if n]

    async def _inject(self, target: ScanTarget, param: str, payload: str, source: str):
        """Inject payload into a specific parameter."""
        if source == "query":
            parsed = urlparse(target.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
            return await self._send_request(
                url, method="GET",
                headers=target.headers, cookies=target.cookies,
            )
        else:
            form_data = {}
            for f in target.form_fields:
                form_data[f["name"]] = f.get("value", "test")
            form_data[param] = payload
            return await self._send_request(
                target.url, method="POST", data=form_data,
                headers=target.headers, cookies=target.cookies,
            )

    async def _test_error_based(self, target: ScanTarget, param: str, source: str):
        """Test for error-based SQL injection by looking for DB error messages."""
        for payload in ERROR_PAYLOADS:
            resp = await self._inject(target, param, payload, source)
            if resp is None:
                continue

            body = resp.text.lower()
            for db_type, patterns in DB_ERROR_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        vuln_type = {
                            "MySQL": "sql_injection_mysql",
                            "PostgreSQL": "sql_injection_postgres",
                            "MSSQL": "sql_injection_mssql",
                            "Oracle": "sql_injection_oracle",
                            "SQLite": "sql_injection_sqlite",
                        }.get(db_type, "sql_injection")

                        # Extract the matched error snippet
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        evidence = resp.text[max(0, match.start() - 50):match.end() + 50] if match else ""

                        return RawFinding(
                            vuln_type=vuln_type,
                            title=f"SQL Injection ({db_type} - Error Based)",
                            description=f"The parameter '{param}' is vulnerable to SQL injection. "
                                        f"The application returns {db_type} database error messages when injected with SQL metacharacters, "
                                        f"confirming that user input is directly interpolated into SQL queries without sanitization.",
                            affected_url=target.url,
                            severity="CRITICAL",
                            affected_parameter=param,
                            injection_point=source,
                            payload=payload,
                            request_evidence=f"{source.upper()} parameter '{param}' = {payload}",
                            response_evidence=evidence.strip(),
                            remediation="Use parameterized queries (prepared statements) instead of string concatenation. "
                                        "Never interpolate user input directly into SQL queries. Apply input validation as defense in depth.",
                            remediation_code=json.dumps({
                                "vulnerableCode": f"db.query(f\"SELECT * FROM users WHERE {param}='{{req.{param}}}'\")",
                                "remediatedCode": f"db.query(\"SELECT * FROM users WHERE {param} = $1\", [req.{param}])",
                                "explanation": "Parameterized queries separate SQL logic from data, preventing injection.",
                                "language": "Python/JavaScript",
                            }),
                            confidence=95,
                            business_impact=f"Full database compromise. An attacker can read, modify, or delete all data in the {db_type} database. "
                                           "This includes user credentials, PII, and business-critical records.",
                        )
        return None

    async def _test_blind(self, target: ScanTarget, param: str, source: str):
        """Test for boolean-blind SQLi by comparing response lengths."""
        # First get baseline response
        baseline = await self._inject(target, param, "normalvalue123", source)
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        for true_payload, false_payload in BLIND_PAIRS:
            true_resp = await self._inject(target, param, f"normalvalue123{true_payload}", source)
            false_resp = await self._inject(target, param, f"normalvalue123{false_payload}", source)

            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # If true and false conditions produce significantly different responses
            # AND the true condition matches baseline more closely
            if abs(true_len - false_len) > 50 and abs(true_len - baseline_len) < abs(false_len - baseline_len):
                return RawFinding(
                    vuln_type="sql_injection",
                    title="SQL Injection (Boolean-Based Blind)",
                    description=f"The parameter '{param}' is vulnerable to boolean-based blind SQL injection. "
                                f"The application responds differently to logically true vs false SQL conditions "
                                f"(response length diff: {abs(true_len - false_len)} bytes), indicating that "
                                f"injected SQL is being executed by the database.",
                    affected_url=target.url,
                    severity="CRITICAL",
                    affected_parameter=param,
                    injection_point=source,
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    request_evidence=f"True condition response: {true_len} bytes, False condition response: {false_len} bytes",
                    response_evidence=f"Response length differential: {abs(true_len - false_len)} bytes",
                    remediation="Use parameterized queries. Implement WAF rules for SQL injection patterns.",
                    confidence=80,
                    business_impact="Database content can be extracted one bit at a time through boolean queries.",
                )
        return None

    async def _test_time_based(self, target: ScanTarget, param: str, source: str):
        """Test for time-based blind SQLi using SLEEP/WAITFOR/pg_sleep."""
        # Get baseline timing
        start = time.time()
        baseline = await self._inject(target, param, "normalvalue123", source)
        baseline_time = time.time() - start
        if baseline is None:
            return None

        for payload, db_type in TIME_PAYLOADS:
            start = time.time()
            resp = await self._inject(target, param, f"normalvalue123{payload}", source)
            elapsed = time.time() - start

            if resp is not None and elapsed > baseline_time + 4.0:
                return RawFinding(
                    vuln_type=f"sql_injection_{db_type.lower()}" if db_type != "MySQL" else "sql_injection_mysql",
                    title=f"SQL Injection (Time-Based Blind - {db_type})",
                    description=f"The parameter '{param}' is vulnerable to time-based blind SQL injection. "
                                f"A sleep payload caused a {elapsed:.1f}s response delay (baseline: {baseline_time:.1f}s), "
                                f"confirming server-side SQL execution.",
                    affected_url=target.url,
                    severity="CRITICAL",
                    affected_parameter=param,
                    injection_point=source,
                    payload=payload,
                    request_evidence=f"Baseline response time: {baseline_time:.1f}s, Injected response time: {elapsed:.1f}s",
                    response_evidence=f"Time differential: {elapsed - baseline_time:.1f}s (threshold: 4.0s)",
                    remediation="Use parameterized queries. Never concatenate user input into SQL.",
                    confidence=85,
                    business_impact=f"Complete {db_type} database compromise through time-based data extraction.",
                )
        return None

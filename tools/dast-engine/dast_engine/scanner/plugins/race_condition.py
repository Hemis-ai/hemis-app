"""
Race Condition (TOCTOU) Scanner — detects time-of-check to time-of-use
vulnerabilities by sending concurrent identical requests and checking
for duplicate processing.

This is a novel scan not available in most DAST tools including Burp Suite
(Burp added Turbo Intruder but it's manual, not automated detection).
"""
from __future__ import annotations
import asyncio
import json
from urllib.parse import urlparse
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


# Endpoint patterns likely to have race conditions
RACE_PRONE_PATTERNS = [
    "redeem", "coupon", "voucher", "claim", "activate",
    "transfer", "withdraw", "payment", "checkout", "purchase",
    "reset", "password", "verify", "confirm", "submit",
    "create", "register", "signup", "invite", "like", "vote",
    "follow", "subscribe", "unsubscribe", "delete",
]

# Number of concurrent requests
RACE_CONCURRENCY = 15


class RaceConditionPlugin(BasePlugin):
    name = "Race Condition (TOCTOU) Scanner"
    vuln_type = "race_condition"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Only test endpoints that are likely to have race conditions
        path = urlparse(target.url).path.lower()
        is_race_prone = any(pattern in path for pattern in RACE_PRONE_PATTERNS)

        # Also check POST endpoints (state-changing operations)
        has_forms = bool(target.form_fields)
        is_post = target.method.upper() == "POST"

        if not (is_race_prone or has_forms or is_post):
            return findings

        # Test 1: Send concurrent GET requests and compare responses
        await self._test_race_get(target, ctx, findings)

        # Test 2: If it has forms, test concurrent POST submissions
        if has_forms or is_post:
            await self._test_race_post(target, ctx, findings)

        return findings

    async def _test_race_get(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Send concurrent GET requests to detect inconsistent state."""
        client = await ctx.get_client()

        async def single_request():
            try:
                resp = await client.get(
                    target.url,
                    headers={"User-Agent": "HemisX-DAST-Scanner/1.0", **target.headers},
                    cookies=target.cookies,
                    timeout=10.0,
                )
                return resp.status_code, len(resp.text), resp.text[:200]
            except Exception:
                return None, None, None

        # Fire concurrent requests
        tasks = [single_request() for _ in range(RACE_CONCURRENCY)]
        results = await asyncio.gather(*tasks)

        # Analyze results for inconsistencies
        valid_results = [(s, l, b) for s, l, b in results if s is not None]
        if len(valid_results) < 5:
            return

        statuses = [r[0] for r in valid_results]
        lengths = [r[1] for r in valid_results]

        unique_statuses = set(statuses)
        unique_lengths = len(set(lengths))

        # Inconsistent responses under concurrent load may indicate race conditions
        if len(unique_statuses) > 1 and any(s >= 500 for s in statuses):
            error_count = sum(1 for s in statuses if s >= 500)
            findings.append(RawFinding(
                vuln_type="race_condition",
                title=f"Potential Race Condition: Inconsistent Responses Under Load",
                description=(
                    f"Sending {RACE_CONCURRENCY} concurrent requests to {target.url} "
                    f"produced {len(unique_statuses)} different status codes: "
                    f"{dict((s, statuses.count(s)) for s in unique_statuses)}. "
                    f"{error_count} requests returned server errors, suggesting the "
                    "endpoint may not handle concurrent access safely."
                ),
                affected_url=target.url,
                severity="MEDIUM",
                request_evidence=f"{RACE_CONCURRENCY}x concurrent GET {target.url}",
                response_evidence=f"Status distribution: {dict((s, statuses.count(s)) for s in unique_statuses)}",
                remediation=(
                    "Implement proper locking/synchronization for state-changing operations. "
                    "Use database-level locks, optimistic concurrency control, or atomic operations."
                ),
                confidence=55,
                business_impact=(
                    "Race conditions can allow: double-spending, duplicate resource creation, "
                    "bypassing one-time-use tokens, and inventory manipulation."
                ),
            ))

    async def _test_race_post(
        self, target: ScanTarget, ctx: ScanContext, findings: list[RawFinding]
    ) -> None:
        """Send concurrent POST requests to detect TOCTOU vulnerabilities."""
        client = await ctx.get_client()

        # Build form data from available fields
        form_data = {}
        for field in target.form_fields:
            name = field.get("name", "")
            value = field.get("value", "test")
            if name:
                form_data[name] = value

        if not form_data:
            form_data = {"test": "hemis_race_test"}

        async def single_post():
            try:
                resp = await client.post(
                    target.url,
                    data=form_data,
                    headers={"User-Agent": "HemisX-DAST-Scanner/1.0", **target.headers},
                    cookies=target.cookies,
                    timeout=10.0,
                    follow_redirects=True,
                )
                return resp.status_code, resp.text[:500]
            except Exception:
                return None, None

        # Fire concurrent POST requests
        tasks = [single_post() for _ in range(RACE_CONCURRENCY)]
        results = await asyncio.gather(*tasks)

        valid_results = [(s, b) for s, b in results if s is not None]
        if len(valid_results) < 5:
            return

        # Count successful responses (2xx)
        success_count = sum(1 for s, _ in valid_results if 200 <= s < 300)
        error_count = sum(1 for s, _ in valid_results if s >= 500)

        # If many concurrent POSTs succeed, the endpoint may not have proper locking
        if success_count > 1:
            # Check if responses contain indicators of duplicate processing
            bodies = [b for _, b in valid_results if b]
            has_ids = any('"id"' in b or '"ID"' in b for b in bodies)

            if has_ids:
                # Extract IDs to see if duplicates were created
                ids = set()
                for body in bodies:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and "id" in data:
                            ids.add(str(data["id"]))
                    except (json.JSONDecodeError, TypeError):
                        pass

                if len(ids) > 1:
                    findings.append(RawFinding(
                        vuln_type="race_condition",
                        title=f"Race Condition: Duplicate Resource Creation",
                        description=(
                            f"Sending {RACE_CONCURRENCY} concurrent POST requests to "
                            f"{target.url} created {len(ids)} separate resources "
                            f"(IDs: {', '.join(list(ids)[:5])}). The endpoint does not "
                            "properly serialize write operations, allowing race conditions."
                        ),
                        affected_url=target.url,
                        severity="HIGH",
                        payload=json.dumps(form_data)[:200],
                        request_evidence=f"{RACE_CONCURRENCY}x concurrent POST {target.url}",
                        response_evidence=f"Created {len(ids)} resources with IDs: {', '.join(list(ids)[:5])}",
                        remediation=(
                            "Use database-level unique constraints and optimistic locking. "
                            "Implement idempotency keys for state-changing operations. "
                            "Use SELECT ... FOR UPDATE or advisory locks."
                        ),
                        confidence=80,
                        verified=True,
                        business_impact=(
                            "Duplicate resource creation can lead to: double-spending, "
                            "multiple account registrations, inventory depletion, "
                            "and bypassing rate limits."
                        ),
                    ))

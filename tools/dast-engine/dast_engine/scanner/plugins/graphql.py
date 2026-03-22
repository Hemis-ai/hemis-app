"""
GraphQL Security Scanner — detects introspection, query depth abuse,
batch queries, field suggestions, and injection via arguments.
"""
from __future__ import annotations
import json
from urllib.parse import urljoin
from ..base_plugin import BasePlugin, ScanTarget, RawFinding
from ..scan_context import ScanContext


GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
    "/gql", "/query", "/api/gql", "/graphql/api",
]

INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}types{name fields{name}}}}"}'
INTROSPECTION_BYPASS = '{"query":"query IntrospectionQuery{__schema{queryType{name}}}"}'
INTROSPECTION_NEWLINE = '{"query":"{__schema\\n{queryType{name}}}"}'

DEPTH_QUERY_TEMPLATE = '{"query":"{' + "a{" * 15 + "b" + "}" * 15 + '}"}'

BATCH_QUERY = '[{"query":"{__typename}"},{"query":"{__typename}"}]'

FIELD_SUGGESTION_QUERY = '{"query":"{__typenameXYZ}"}'

SQLI_PAYLOADS = [
    '{"query":"{ user(id: \\"1\' OR 1=1--\\") { name } }"}',
    '{"query":"{ user(id: \\"1\\") { name } }"}',
]


class GraphQLPlugin(BasePlugin):
    name = "GraphQL Security Scanner"
    vuln_type = "graphql"

    async def scan(self, target: ScanTarget, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []

        # Only run on the base URL (avoid per-page repetition)
        if target.url != ctx.target_url and target.url != ctx.target_url.rstrip("/"):
            return findings

        base_url = ctx.target_url.rstrip("/")

        for path in GRAPHQL_PATHS:
            endpoint = urljoin(base_url + "/", path.lstrip("/"))
            found = await self._test_endpoint(endpoint, ctx, findings)
            if found:
                break  # Found a working GraphQL endpoint

        return findings

    async def _test_endpoint(
        self, endpoint: str, ctx: ScanContext, findings: list[RawFinding]
    ) -> bool:
        """Test a single endpoint for GraphQL. Returns True if GraphQL detected."""

        # 1. Introspection check
        resp = await self._send_request(
            ctx, endpoint, method="POST",
            data=INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp is None:
            return False

        body = resp.text
        is_graphql = any(k in body for k in ('"data"', '"errors"', '__schema', 'queryType'))
        if not is_graphql:
            return False

        # GraphQL endpoint confirmed
        if "__schema" in body or "queryType" in body:
            findings.append(RawFinding(
                vuln_type="graphql_introspection",
                title=f"GraphQL Introspection Enabled at {endpoint}",
                description=(
                    f"The GraphQL endpoint at {endpoint} allows introspection queries, "
                    "exposing the entire API schema including types, fields, mutations, "
                    "and relationships. Attackers can use this to map the full API surface."
                ),
                affected_url=endpoint,
                severity="MEDIUM",
                payload=INTROSPECTION_QUERY[:100],
                request_evidence=f"POST {endpoint}\n{INTROSPECTION_QUERY[:200]}",
                response_evidence=body[:300],
                remediation=(
                    "Disable introspection in production: "
                    "Apollo Server: introspection: false. "
                    "Express GraphQL: graphiql: false. "
                    "If needed for dev, restrict by IP or auth."
                ),
                confidence=95,
                verified=True,
            ))
        else:
            # Try bypass techniques
            for bypass_query, desc in [
                (INTROSPECTION_BYPASS, "named query bypass"),
                (INTROSPECTION_NEWLINE, "newline bypass"),
            ]:
                resp2 = await self._send_request(
                    ctx, endpoint, method="POST",
                    data=bypass_query,
                    headers={"Content-Type": "application/json"},
                )
                if resp2 and ("__schema" in resp2.text or "queryType" in resp2.text):
                    findings.append(RawFinding(
                        vuln_type="graphql_introspection",
                        title=f"GraphQL Introspection Bypass at {endpoint} ({desc})",
                        description=(
                            f"Introspection is partially blocked at {endpoint} but can be bypassed "
                            f"using {desc}. The full schema is still accessible."
                        ),
                        affected_url=endpoint,
                        severity="MEDIUM",
                        payload=bypass_query[:100],
                        response_evidence=resp2.text[:300],
                        remediation="Ensure introspection is fully disabled, not just regex-filtered.",
                        confidence=90,
                        verified=True,
                    ))
                    break

        # 2. Query depth limit check
        resp3 = await self._send_request(
            ctx, endpoint, method="POST",
            data=DEPTH_QUERY_TEMPLATE,
            headers={"Content-Type": "application/json"},
        )
        if resp3 and resp3.status_code == 200:
            if '"errors"' not in resp3.text or "depth" not in resp3.text.lower():
                findings.append(RawFinding(
                    vuln_type="graphql_depth_limit",
                    title=f"GraphQL Query Depth Limit Not Enforced at {endpoint}",
                    description=(
                        f"The GraphQL endpoint at {endpoint} does not enforce query depth limits. "
                        "An attacker can craft deeply nested queries to cause Denial of Service "
                        "by exhausting server resources."
                    ),
                    affected_url=endpoint,
                    severity="MEDIUM",
                    payload=DEPTH_QUERY_TEMPLATE[:80],
                    response_evidence=resp3.text[:200],
                    remediation=(
                        "Implement query depth limiting: "
                        "graphql-depth-limit (npm), or custom validation rule. "
                        "Recommended max depth: 7-10."
                    ),
                    confidence=80,
                ))

        # 3. Batch query abuse
        resp4 = await self._send_request(
            ctx, endpoint, method="POST",
            data=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp4 and resp4.status_code == 200:
            try:
                parsed = json.loads(resp4.text)
                if isinstance(parsed, list) and len(parsed) >= 2:
                    findings.append(RawFinding(
                        vuln_type="graphql_batch_abuse",
                        title=f"GraphQL Batch Query Abuse Possible at {endpoint}",
                        description=(
                            f"The GraphQL endpoint at {endpoint} accepts batched queries. "
                            "Attackers can send hundreds of queries in a single request to "
                            "bypass rate limiting, brute-force authentication, or cause DoS."
                        ),
                        affected_url=endpoint,
                        severity="LOW",
                        payload=BATCH_QUERY,
                        response_evidence=resp4.text[:200],
                        remediation=(
                            "Limit batch query size to a maximum of 5-10 operations. "
                            "Implement query cost analysis to prevent resource exhaustion."
                        ),
                        confidence=85,
                    ))
            except (json.JSONDecodeError, TypeError):
                pass

        # 4. Field suggestion leak
        resp5 = await self._send_request(
            ctx, endpoint, method="POST",
            data=FIELD_SUGGESTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp5 and ("Did you mean" in resp5.text or "did you mean" in resp5.text):
            findings.append(RawFinding(
                vuln_type="graphql_field_suggestion",
                title=f"GraphQL Field Suggestions Enabled at {endpoint}",
                description=(
                    f"The GraphQL endpoint at {endpoint} suggests valid field names when "
                    "an invalid field is queried. Attackers can enumerate the schema "
                    "even when introspection is disabled."
                ),
                affected_url=endpoint,
                severity="INFO",
                payload=FIELD_SUGGESTION_QUERY,
                response_evidence=resp5.text[:300],
                remediation=(
                    "Disable field suggestions in production to prevent schema enumeration."
                ),
                confidence=90,
            ))

        # 5. Injection via arguments
        for payload in SQLI_PAYLOADS:
            resp6 = await self._send_request(
                ctx, endpoint, method="POST",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp6 and any(err in resp6.text.lower() for err in [
                "sql syntax", "mysql", "postgresql", "sqlite",
                "unterminated", "syntax error",
            ]):
                findings.append(RawFinding(
                    vuln_type="graphql_injection",
                    title=f"SQL Injection via GraphQL Argument at {endpoint}",
                    description=(
                        f"The GraphQL endpoint at {endpoint} appears vulnerable to SQL injection "
                        "through query arguments. Database error messages are exposed in the response."
                    ),
                    affected_url=endpoint,
                    severity="CRITICAL",
                    payload=payload[:150],
                    response_evidence=resp6.text[:300],
                    remediation=(
                        "Use parameterized queries in all GraphQL resolvers. "
                        "Never concatenate user input into SQL statements."
                    ),
                    confidence=85,
                    verified=True,
                ))
                break

        return True

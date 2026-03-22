"""
Scan time estimation engine.

Provides ETA based on:
- Number of discovered endpoints
- Scan profile (quick/standard/full/deep)
- Number of parameters per endpoint
- Detected technology complexity
- Historical scan data

Updates ETA continuously during the scan as more information becomes available.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import time


@dataclass
class ScanEstimate:
    """Estimated scan timing information."""
    estimated_total_seconds: float
    estimated_remaining_seconds: float
    endpoints_per_second: float
    payloads_per_second: float
    started_at: float
    phase_estimates: dict[str, float]  # phase_name -> estimated_seconds
    confidence: str  # "low", "medium", "high"

    @property
    def eta_display(self) -> str:
        """Human-readable ETA string."""
        remaining = max(0, self.estimated_remaining_seconds)
        if remaining < 60:
            return f"{int(remaining)}s remaining"
        elif remaining < 3600:
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            return f"{minutes}m {seconds}s remaining"
        else:
            hours = int(remaining // 3600)
            minutes = int((remaining % 3600) // 60)
            return f"{hours}h {minutes}m remaining"

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.started_at


class ScanEstimator:
    """Estimates and tracks scan duration."""

    # Average time per operation (calibrated from real scans)
    CRAWL_TIME_PER_PAGE = 0.5  # seconds per page crawled
    PASSIVE_SCAN_PER_TARGET = 0.3  # seconds per target for passive plugins
    ACTIVE_SCAN_PER_PARAM = 2.0  # seconds per parameter for active plugins
    EXTRACTION_PER_FINDING = 0.1
    ANALYSIS_BASE_TIME = 5.0  # seconds for AI enrichment

    # Profile multipliers
    PROFILE_MULTIPLIERS = {
        "quick": 0.3,
        "full": 1.0,
        "api_only": 0.6,
        "deep": 2.5,
    }

    # Default assumptions for initial estimate
    DEFAULT_ENDPOINTS = 50
    DEFAULT_PARAMS_PER_ENDPOINT = 3
    DEFAULT_FINDINGS = 10

    def __init__(self, profile: str = "full"):
        self.profile = profile
        self.multiplier = self.PROFILE_MULTIPLIERS.get(profile, 1.0)
        self.started_at = time.time()
        self._phase_start_times: dict[str, float] = {}
        self._phase_actual_durations: dict[str, float] = {}
        self._endpoints_discovered = 0
        self._endpoints_tested = 0
        self._total_params = 0
        self._payloads_sent = 0

    def estimate_initial(self, target_url: str) -> ScanEstimate:
        """Initial rough estimate before crawling begins."""
        endpoints = self.DEFAULT_ENDPOINTS
        params = endpoints * self.DEFAULT_PARAMS_PER_ENDPOINT
        findings = self.DEFAULT_FINDINGS

        phase_estimates = self._compute_phase_estimates(endpoints, params, findings)
        total = sum(phase_estimates.values()) * self.multiplier
        remaining = total - (time.time() - self.started_at)

        return self._build_estimate(max(0, remaining), "low")

    def update_after_crawl(self, endpoints: int, params: int, forms: int) -> ScanEstimate:
        """Refine estimate after crawling completes."""
        self._endpoints_discovered = endpoints
        self._total_params = params

        # Estimated findings based on endpoint count (rough heuristic: ~20% of endpoints yield a finding)
        estimated_findings = max(1, int(endpoints * 0.2))

        phase_estimates = self._compute_phase_estimates(endpoints, params, estimated_findings)

        # Replace crawl estimate with actual crawl duration if available
        if "crawling" in self._phase_actual_durations:
            phase_estimates["crawling"] = self._phase_actual_durations["crawling"]

        # Replace init estimate with actual if available
        if "initializing" in self._phase_actual_durations:
            phase_estimates["initializing"] = self._phase_actual_durations["initializing"]

        total = sum(phase_estimates.values()) * self.multiplier
        # For phases already completed, use actual durations (not multiplied)
        completed_actual = sum(
            self._phase_actual_durations.get(p, 0)
            for p in ("initializing", "crawling")
        )
        # Remaining = total estimate minus elapsed time
        elapsed = time.time() - self.started_at
        remaining = max(0, total - elapsed)

        return self._build_estimate(remaining, "medium")

    def update_during_scan(self, tested: int, total: int, payloads: int) -> ScanEstimate:
        """Update ETA during active scanning."""
        self._endpoints_tested = tested
        self._payloads_sent = payloads
        elapsed = time.time() - self.started_at

        # Calculate actual scan speed from observed data
        scan_phase_elapsed = 0.0
        if "scanning" in self._phase_start_times:
            scan_phase_elapsed = time.time() - self._phase_start_times["scanning"]

        if tested > 0 and scan_phase_elapsed > 0:
            endpoints_per_second = tested / scan_phase_elapsed
            remaining_endpoints = max(0, total - tested)
            estimated_scan_remaining = remaining_endpoints / endpoints_per_second if endpoints_per_second > 0 else 0
        else:
            # Fall back to parameter-based estimate
            estimated_scan_remaining = (
                max(0, total - tested) * self.DEFAULT_PARAMS_PER_ENDPOINT * self.ACTIVE_SCAN_PER_PARAM * self.multiplier
            )

        # Add estimates for remaining phases (extraction, analysis, complete)
        estimated_findings = max(1, int(self._endpoints_discovered * 0.2))
        extraction_time = estimated_findings * self.EXTRACTION_PER_FINDING * self.multiplier
        analysis_time = self.ANALYSIS_BASE_TIME * self.multiplier
        completion_time = 1.0

        remaining = estimated_scan_remaining + extraction_time + analysis_time + completion_time

        return self._build_estimate(max(0, remaining), "high")

    def phase_start(self, phase: str) -> None:
        """Mark the start of a scan phase."""
        self._phase_start_times[phase] = time.time()

    def phase_end(self, phase: str) -> None:
        """Mark the end of a scan phase and record actual duration."""
        if phase in self._phase_start_times:
            self._phase_actual_durations[phase] = time.time() - self._phase_start_times[phase]

    def _compute_phase_estimates(self, endpoints: int, params: int, findings: int) -> dict[str, float]:
        """Compute per-phase time estimates based on workload."""
        return {
            "initializing": 3.0,
            "crawling": endpoints * self.CRAWL_TIME_PER_PAGE,
            "scanning": params * self.ACTIVE_SCAN_PER_PARAM,
            "extracting": findings * self.EXTRACTION_PER_FINDING,
            "analyzing": self.ANALYSIS_BASE_TIME,
            "complete": 1.0,
        }

    def _build_estimate(self, remaining_seconds: float, confidence: str) -> ScanEstimate:
        """Build a ScanEstimate from current state."""
        elapsed = time.time() - self.started_at
        total = elapsed + remaining_seconds

        # Calculate throughput rates
        scan_phase_elapsed = 0.0
        if "scanning" in self._phase_start_times:
            scan_phase_elapsed = time.time() - self._phase_start_times["scanning"]

        endpoints_per_second = (
            self._endpoints_tested / scan_phase_elapsed
            if scan_phase_elapsed > 0 and self._endpoints_tested > 0
            else 0.0
        )
        payloads_per_second = (
            self._payloads_sent / scan_phase_elapsed
            if scan_phase_elapsed > 0 and self._payloads_sent > 0
            else 0.0
        )

        # Build phase estimates dict combining actuals and predictions
        phase_estimates: dict[str, float] = {}
        base_estimates = self._compute_phase_estimates(
            self._endpoints_discovered or self.DEFAULT_ENDPOINTS,
            self._total_params or self.DEFAULT_ENDPOINTS * self.DEFAULT_PARAMS_PER_ENDPOINT,
            max(1, int((self._endpoints_discovered or self.DEFAULT_ENDPOINTS) * 0.2)),
        )
        for phase_name, est in base_estimates.items():
            if phase_name in self._phase_actual_durations:
                phase_estimates[phase_name] = self._phase_actual_durations[phase_name]
            else:
                phase_estimates[phase_name] = est * self.multiplier

        return ScanEstimate(
            estimated_total_seconds=total,
            estimated_remaining_seconds=remaining_seconds,
            endpoints_per_second=endpoints_per_second,
            payloads_per_second=payloads_per_second,
            started_at=self.started_at,
            phase_estimates=phase_estimates,
            confidence=confidence,
        )

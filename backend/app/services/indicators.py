"""Shared structured indicator model used across all detection rule modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
DetectionStatus = Literal[
    "Detected",
    "Not detected",
    "Check unavailable",
    "Informational",
    "Blocked for safety",
]
IndicatorCategory = Literal[
    "url_structure",
    "tracker",
    "phishing",
    "malware",
    "redirect",
    "domain_intel",
    "file_download",
]


@dataclass(frozen=True)
class RuleFinding:
    """Structured finding produced by any centralized detection rule."""

    rule_id: str
    rule_name: str
    category: IndicatorCategory
    severity: SeverityLevel
    evidence: str
    explanation: str
    recommendation: str
    score_contribution: int
    detection_status: DetectionStatus = "Detected"
    dedup_group: str | None = None
    # Optional tracker & inspection metadata
    detection_source: str = "url"  # "url" | "html_script" | "tracking_pixel" | "cookie" | "html_page" | "provider"
    tracker_domain: str | None = None
    confidence: str | None = None

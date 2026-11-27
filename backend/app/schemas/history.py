"""Pydantic schemas for Scan History API responses."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class HistorySummary(BaseModel):
    """Summary item returned in GET /api/history."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_type: Literal["url", "message", "message-image"]
    input_text: str
    risk_score: int
    risk_level: Literal[
        "Safe",
        "Suspicious",
        "Dangerous",
        "No strong indicators detected",
        "Inspection unavailable",
    ]
    created_at: datetime


class HistoryListResponse(BaseModel):
    """Paginated list of scan history records."""

    success: bool = True
    total: int
    limit: int
    offset: int
    items: list[HistorySummary]


class HistoryDetailResponse(BaseModel):
    """Complete details for a single scan history record."""

    model_config = ConfigDict(from_attributes=True)

    success: bool = True
    id: int
    scan_type: Literal["url", "message", "message-image"]
    input_text: str
    risk_score: int
    risk_level: Literal[
        "Safe",
        "Suspicious",
        "Dangerous",
        "No strong indicators detected",
        "Inspection unavailable",
    ]
    detected_indicators: list[str]
    explanations: list[str]
    recommendations: list[str]
    created_at: datetime
    disclaimer: str = (
        "Automated analysis can make mistakes and a Safe result never guarantees "
        "a URL or message is 100% safe."
    )


class HistoryDeleteResponse(BaseModel):
    """Response for deleting a single history record."""

    success: bool = True
    message: str
    deleted_id: int


class HistoryClearResponse(BaseModel):
    """Response for clearing all history records."""

    success: bool = True
    message: str
    deleted_count: int


class ReportRuleFindingSchema(BaseModel):
    """Rule finding summary inside a scan report."""

    rule_id: str
    rule_name: str
    severity: str
    evidence: str
    explanation: str
    score_contribution: int = 0
    detection_status: str = "Detected"
    detection_source: str = "url"


class ReportRuleAnalysisSchema(BaseModel):
    """Rule-based analysis section of a detailed scan report."""

    status: Literal["completed", "unavailable"] = "completed"
    rule_score: int
    inspection_status: str = "Check unavailable"
    inspection_note: str = "URL-only analysis — website content was not inspected."
    detected_rules: list[ReportRuleFindingSchema] = []


class ReportMLAnalysisSchema(BaseModel):
    """ML prediction section of a detailed scan report."""

    status: Literal["available", "unavailable"] = "unavailable"
    available: bool = False
    prediction: str = "Analysis unavailable"
    confidence: float | None = None
    calibrated: bool = False
    model_version: str | None = None
    score_contribution: int = 0
    note: str = "ML analysis was not recorded for this scan."


class ReportThreatIntelSchema(BaseModel):
    """Threat intelligence section of a detailed scan report."""

    status: Literal["matched", "no_match", "unavailable"] = "unavailable"
    reputation_status: str = "Check unavailable"
    provider_name: str = "unconfigured"
    domain_age_status: str = "Check unavailable"
    domain_age_days: int | None = None
    checked_at: str | None = None
    cached: bool = False
    provider_results: list[dict] = []
    note: str | None = None


class ScanReportResponse(BaseModel):
    """Comprehensive, validated scan report for display and JSON/PDF export."""

    success: bool = True
    scan_id: int
    created_at: datetime
    scan_type: Literal["url", "message", "message-image"]
    input_preview: str
    risk_score: int
    risk_level: Literal[
        "Safe",
        "Suspicious",
        "Dangerous",
        "No strong indicators detected",
        "Inspection unavailable",
    ]
    classification_summary: str
    detected_indicators: list[str]
    detected_urls: list[str] = []
    rule_analysis: ReportRuleAnalysisSchema
    ml_analysis: ReportMLAnalysisSchema
    threat_intelligence: ReportThreatIntelSchema
    explanations: list[str]
    recommendations: list[str]
    analysis_sources: list[str]
    privacy_notice: str = (
        "Sensitive tokens, passwords, and session credentials are redacted before storage and export."
    )
    disclaimer: str = (
        "Automated analysis can make mistakes and a Safe result never guarantees "
        "a URL or message is 100% safe."
    )


class AnalyticsClassificationsSchema(BaseModel):
    """Counts of stored scans grouped by final classification."""

    safe: int = 0
    suspicious: int = 0
    dangerous: int = 0
    no_strong_indicators: int = 0
    inspection_unavailable: int = 0


class RiskBucketSchema(BaseModel):
    """Risk score distribution bucket."""

    label: str
    min_score: int
    max_score: int
    count: int
    percentage: float


class TrendPointSchema(BaseModel):
    """Daily or weekly scan volume and classification breakdown."""

    period: str
    total: int
    safe: int
    suspicious: int
    dangerous: int


class IndicatorFrequencySchema(BaseModel):
    """Frequency count for a detected indicator."""

    indicator: str
    count: int


class MLStatsSchema(BaseModel):
    """Recorded ML availability and prediction statistics."""

    recorded_scans: int = 0
    available_scans: int = 0
    unavailable_scans: int = 0
    flagged_predictions: int = 0
    average_confidence: float | None = None


class ThreatIntelStatsSchema(BaseModel):
    """Recorded threat intelligence lookup statistics."""

    recorded_scans: int = 0
    malicious_matches: int = 0
    clean_checks: int = 0
    unavailable_checks: int = 0


class AnalyticsResponse(BaseModel):
    """Real-database analytics summary for the ScamShield AI dashboard."""

    success: bool = True
    has_data: bool = False
    total_scans: int = 0
    url_scans: int = 0
    message_scans: int = 0
    message_image_scans: int = 0
    average_risk_score: float | None = None
    high_risk_rate: float = 0.0
    classifications: AnalyticsClassificationsSchema
    risk_distribution: list[RiskBucketSchema]
    daily_trends: list[TrendPointSchema]
    weekly_trends: list[TrendPointSchema]
    top_indicators: list[IndicatorFrequencySchema]
    ml_stats: MLStatsSchema
    threat_intel_stats: ThreatIntelStatsSchema

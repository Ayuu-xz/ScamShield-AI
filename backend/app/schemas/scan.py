"""Pydantic request and response schemas for scan endpoints."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.core.config import settings

AssessmentLevel = Literal[
    "Safe",
    "Suspicious",
    "Dangerous",
    "No strong indicators detected",
    "Inspection unavailable",
    "Unavailable",
]


class UrlScanRequest(BaseModel):
    """Request body for POST /api/scan/url."""

    url: str = Field(..., description="Plain-text URL to inspect without visiting it.")
    inspect_website: bool = Field(
        default=False,
        description="Optionally run isolated read-only website inspection with SSRF protections.",
    )

    @field_validator("url")
    @classmethod
    def validate_non_empty_url(cls, value: str) -> str:
        """Trim whitespace and enforce basic length limits."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("URL cannot be empty.")
        if len(cleaned) > settings.url_config.max_url_length:
            raise ValueError(
                f"URL exceeds maximum allowed length of {settings.url_config.max_url_length} characters."
            )
        return cleaned


class MessageScanRequest(BaseModel):
    """Request body for POST /api/scan/message."""

    message: str = Field(..., description="Plain-text SMS, email, or chat message to inspect.")
    inspect_website: bool = Field(
        default=False,
        description="Optionally run isolated read-only inspection on extracted URLs.",
    )

    @field_validator("message")
    @classmethod
    def validate_non_empty_message(cls, value: str) -> str:
        """Trim whitespace and enforce message length limits."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Message cannot be empty.")
        if len(cleaned) > settings.message_config.max_message_length:
            raise ValueError(
                f"Message exceeds maximum allowed length of {settings.message_config.max_message_length} characters."
            )
        return cleaned


class RuleFindingSchema(BaseModel):
    """Structured finding schema for API responses."""

    rule_id: str
    rule_name: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    evidence: str
    explanation: str
    score_contribution: int = Field(0, ge=0, le=100)
    detection_status: Literal[
        "Detected",
        "Not detected",
        "Check unavailable",
        "Informational",
        "Blocked for safety",
    ]
    detection_source: str = "url"
    tracker_domain: str | None = None
    confidence: str | None = None


class ProviderLookupSchema(BaseModel):
    """Per-provider threat-intelligence lookup status."""

    provider_name: str
    lookup_status: str
    threat_category: str = "Unavailable"
    checked_at: str = ""
    cached: bool = False
    error: str | None = None


class DomainIntelligenceSchema(BaseModel):
    """Domain reputation and age status schema."""

    provider_name: str = "unconfigured"
    reputation_status: Literal["Detected", "Not detected", "Check unavailable"] = "Check unavailable"
    domain_age_status: str = "Check unavailable"
    domain_age_days: int | None = None
    confidence: str | None = None
    checked_at: str | None = None
    cached: bool = False
    provider_results: list[ProviderLookupSchema] = []
    note: str | None = None


class MLAnalysisSchema(BaseModel):
    """Structured ML prediction payload kept separate from rule-based scoring."""

    available: bool = False
    prediction: str = "Model unavailable"
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    calibrated: bool = False
    probabilities: dict[str, float] = {}
    model_version: str | None = None
    score_contribution: int = Field(0, ge=0, le=100)
    disclaimer: str = "ML predictions are probabilistic and may be incorrect."
    error: str | None = None


class UrlScanItem(BaseModel):
    """Individual URL scan result returned inside message and image-OCR scans."""

    url: str
    normalized_url: str | None = None
    risk_score: int = Field(0, ge=0, le=100)
    risk_level: AssessmentLevel
    inspection_status: str = "Check unavailable"
    inspection_note: str = "URL-only analysis — website content was not inspected."
    blocked_destinations: list[str] = []
    completed_checks: list[str] = []
    detected_indicators: list[str] = []
    explanations: list[str] = []
    recommendations: list[str] = []
    detected_rules: list[RuleFindingSchema] = []
    rule_explanations: list[str] = []
    tracker_indicators: list[RuleFindingSchema] = []
    phishing_indicators: list[RuleFindingSchema] = []
    malware_indicators: list[RuleFindingSchema] = []
    redirect_indicators: list[RuleFindingSchema] = []
    domain_intelligence: DomainIntelligenceSchema | None = None
    file_download_indicators: list[RuleFindingSchema] = []
    reputation_status: str = "Check unavailable"
    limitations: list[str] = []
    error: str | None = None


class SuggestedUrlCandidateSchema(BaseModel):
    """Conservative OCR ambiguity candidate shown separately for user review."""

    original: str
    suggested: str
    reason: str


class LocalizedExplanationSchema(BaseModel):
    """Localized explanation bundle for a single language (en, hi, hinglish)."""

    summary: str
    explanations: list[str] = []
    recommendations: list[str] = []


class ScanResponse(BaseModel):
    """Unified structured response payload for URL, message, and image-OCR scans."""

    success: bool = True
    scan_id: int | None = None
    scan_type: Literal["url", "message", "message-image"]
    risk_score: int | None = Field(default=None, ge=0, le=100)
    risk_level: AssessmentLevel | None = None
    rule_score: int | None = Field(default=None, ge=0, le=100)
    combined_risk_score: int | None = Field(default=None, ge=0, le=100)
    ml_analysis: MLAnalysisSchema | None = None
    inspection_status: str = "Check unavailable"
    inspection_note: str = "URL-only analysis — website content was not inspected."
    blocked_destinations: list[str] = []
    completed_checks: list[str] = []
    detected_rules: list[RuleFindingSchema] = []
    rule_explanations: list[str] = []
    tracker_indicators: list[RuleFindingSchema] = []
    phishing_indicators: list[RuleFindingSchema] = []
    malware_indicators: list[RuleFindingSchema] = []
    redirect_indicators: list[RuleFindingSchema] = []
    domain_intelligence: DomainIntelligenceSchema | None = None
    file_download_indicators: list[RuleFindingSchema] = []
    reputation_status: str = "Check unavailable"
    detected_indicators: list[str] = []
    explanations: list[str] = []
    recommendations: list[str] = []
    multilingual_explanations: dict[str, LocalizedExplanationSchema] = {}
    limitations: list[str] = []
    disclaimer: str = "A low-risk result does not guarantee that a URL is safe."
    extracted_text: str | None = None
    detected_urls: list[str] = []
    url_results: list[UrlScanItem] = []
    overall_risk_score: int | None = Field(default=None, ge=0, le=100)
    overall_risk_level: AssessmentLevel | None = None
    ocr_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    low_ocr_confidence_warning: str | None = None
    ocr_status: str | None = None
    ocr_warnings: list[str] = []
    suggested_url_candidates: list[SuggestedUrlCandidateSchema] = []
    status: str = "completed"
    explanation: str | None = None

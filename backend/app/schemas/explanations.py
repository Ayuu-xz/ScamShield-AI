"""Pydantic schemas for Gemini-powered explainable AI text and TTS audio endpoints."""

from typing import Literal

from pydantic import BaseModel, Field

LanguageCode = Literal["en", "hi", "hinglish"]


class IndicatorExplanationItem(BaseModel):
    """Per-indicator structured explanation distinguishing confirmed vs potential warnings."""

    indicator: str
    status: Literal["Confirmed", "Potential Warning"] = "Potential Warning"
    what_detected: str
    why_suspicious: str
    safety_impact: str


class GeminiExplanationPayload(BaseModel):
    """Validated structured JSON output expected from Gemini."""

    title: str
    short_summary: str
    overall_explanation: str
    detected_indicators: list[str] = []
    indicator_explanations: list[IndicatorExplanationItem] = []
    potential_risks: list[str] = []
    recommended_actions: list[str] = []
    confidence_limitations: str


class GeminiExplanationRequest(BaseModel):
    """Structured scan evidence passed to Gemini (detection remains source of truth)."""

    scan_type: Literal["url", "message", "message-image"] = "url"
    risk_level: str = Field(..., min_length=1, max_length=60)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    detected_indicators: list[str] = []
    rule_explanations: list[str] = []
    ml_analysis: dict | None = None
    detected_urls: list[str] = []
    reputation_status: str = "Check unavailable"
    domain_intelligence: dict | None = None
    inspection_status: str = "Check unavailable"
    inspection_note: str = ""
    ocr_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    language: LanguageCode = "en"


class GeminiExplanationResponse(BaseModel):
    """API response for POST /api/explanations/generate."""

    success: bool = True
    available: bool
    explanation_id: str | None = None
    language: LanguageCode = "en"
    model: str | None = None
    cached: bool = False
    explanation: GeminiExplanationPayload | None = None
    fallback_explanations: list[str] = []
    error: str | None = None
    privacy_notice: str = (
        "Sanitized scan evidence (excluding passwords, tokens, and full private messages) "
        "may be sent to Google's Gemini API to generate explanations."
    )


class GeminiAudioRequest(BaseModel):
    """Request body for POST /api/explanations/audio using a server-validated explanation ID."""

    explanation_id: str = Field(..., min_length=8, max_length=64)
    language: LanguageCode = "en"

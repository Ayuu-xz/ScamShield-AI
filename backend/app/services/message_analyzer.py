"""URL-first message analysis module using the centralized URL & inspection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.core.config import MessageAnalyzerConfig, ThreatIntelConfig, settings
from app.ml.predictor import predict_url_ml
from app.schemas.scan import (
    DomainIntelligenceSchema,
    RuleFindingSchema,
    SuggestedUrlCandidateSchema,
    UrlScanItem,
)
from app.services.indicators import RuleFinding
from app.services.risk_scorer import classify_risk_score, score_indicators
from app.services.rules.threat_intel_service import ThreatIntelResult
from app.services.url_analyzer import analyze_url_full
from app.services.url_extractor import extract_urls_from_text
from app.services.website_inspector import InspectionOutcome


def to_rule_schema(finding: RuleFinding) -> RuleFindingSchema:
    """Convert internal RuleFinding dataclass into Pydantic RuleFindingSchema."""
    return RuleFindingSchema(
        rule_id=finding.rule_id,
        rule_name=finding.rule_name,
        severity=finding.severity,
        evidence=finding.evidence,
        explanation=finding.explanation,
        score_contribution=finding.score_contribution,
        detection_status=finding.detection_status,
        detection_source=finding.detection_source,
        tracker_domain=finding.tracker_domain,
        confidence=finding.confidence,
    )


def _dedup_rule_schemas(items: list[RuleFindingSchema]) -> list[RuleFindingSchema]:
    """Deduplicate RuleFindingSchema entries across multiple URLs by (rule_id, evidence)."""
    seen: set[tuple[str, str]] = set()
    result: list[RuleFindingSchema] = []
    for item in items:
        key = (item.rule_id, item.evidence)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


@dataclass(frozen=True)
class MessageUrlAnalysisResult:
    """Aggregated URL-first analysis result for a message or OCR-extracted text."""

    status: str
    explanation: str
    detected_urls: list[str]
    url_results: list[UrlScanItem]
    overall_risk_score: int | None
    overall_risk_level: str
    inspection_status: str
    inspection_note: str
    blocked_destinations: list[str]
    completed_checks: list[str]
    detected_rules: list[RuleFindingSchema]
    rule_explanations: list[str]
    tracker_indicators: list[RuleFindingSchema]
    phishing_indicators: list[RuleFindingSchema]
    malware_indicators: list[RuleFindingSchema]
    redirect_indicators: list[RuleFindingSchema]
    domain_intelligence: DomainIntelligenceSchema | None
    file_download_indicators: list[RuleFindingSchema]
    reputation_status: str
    detected_indicators: list[str]
    explanations: list[str]
    recommendations: list[str]
    limitations: list[str]
    suggested_url_candidates: list[SuggestedUrlCandidateSchema] = field(default_factory=list)


def extract_urls_from_message(raw_message: str) -> list[str]:
    """Extract and deduplicate URLs from message text while preserving order."""
    return extract_urls_from_text(raw_message, source="message").detected_urls


def analyze_message_urls(
    raw_message: str,
    *,
    inspect_website: bool = False,
    source: str = "message",
    config: MessageAnalyzerConfig = settings.message_config,
    provider_fn: Callable[[str, str, ThreatIntelConfig], ThreatIntelResult] | None = None,
    inspector_fn: Callable[[str], InspectionOutcome] | None = None,
) -> MessageUrlAnalysisResult:
    """Extract URLs from a message and score ONLY those URLs via the centralized engine."""
    if not isinstance(raw_message, str):
        raise ValueError("Message must be a text string.")

    cleaned = raw_message.strip()
    if not cleaned:
        raise ValueError("Message cannot be empty.")

    if len(cleaned) > config.max_message_length:
        raise ValueError(
            f"Message exceeds maximum allowed length of {config.max_message_length} characters."
        )

    extraction = extract_urls_from_text(cleaned, source=source)
    detected_urls = extraction.detected_urls
    suggested_candidates = [
        SuggestedUrlCandidateSchema(
            original=c.original,
            suggested=c.suggested,
            reason=c.reason,
        )
        for c in extraction.suggested_candidates
    ]

    if not detected_urls:
        return MessageUrlAnalysisResult(
            status="no_url_detected",
            explanation=(
                "No URL detected. URL-based risk assessment is unavailable. "
                "Please review the extracted text or enter the URL manually."
            ),
            detected_urls=[],
            url_results=[],
            overall_risk_score=None,
            overall_risk_level="Unavailable",
            inspection_status="Check unavailable",
            inspection_note="No URL detected — website inspection was not performed.",
            blocked_destinations=[],
            completed_checks=[],
            detected_rules=[],
            rule_explanations=[],
            tracker_indicators=[],
            phishing_indicators=[],
            malware_indicators=[],
            redirect_indicators=[],
            domain_intelligence=None,
            file_download_indicators=[],
            reputation_status="Check unavailable",
            detected_indicators=[],
            explanations=[],
            recommendations=[
                "No URL was found to inspect. If this message came from an unknown sender, "
                "verify it independently through official channels before taking action."
            ],
            limitations=[
                "No URL was detected in the message; non-URL text analysis is not included in URL-first mode."
            ],
        )

    url_results: list[UrlScanItem] = []
    valid_scores: list[int] = []
    highest_assessment = None
    any_inspection_completed = False

    all_blocked: list[str] = []
    all_checks: list[str] = []
    all_rules: list[RuleFindingSchema] = []
    all_rule_explanations: list[str] = []
    all_trackers: list[RuleFindingSchema] = []
    all_phishing: list[RuleFindingSchema] = []
    all_malware: list[RuleFindingSchema] = []
    all_redirects: list[RuleFindingSchema] = []
    all_downloads: list[RuleFindingSchema] = []
    all_indicators: list[str] = []
    all_explanations: list[str] = []
    all_recommendations: list[str] = []
    all_limitations: list[str] = []

    for url in detected_urls:
        try:
            normalized, findings, domain_summary, outcome = analyze_url_full(
                url,
                inspect_website=inspect_website,
                provider_fn=provider_fn,
                inspector_fn=inspector_fn,
            )
            ml_url_pred = predict_url_ml(normalized.normalized)
            assessment = score_indicators(
                findings,
                domain_intelligence=domain_summary,
                inspection_outcome=outcome,
                ml_prediction=ml_url_pred,
            )
            if outcome.status == "completed":
                any_inspection_completed = True

            rules_schema = [to_rule_schema(f) for f in assessment.detected_rules]
            trackers_schema = [to_rule_schema(f) for f in assessment.tracker_indicators]
            phishing_schema = [to_rule_schema(f) for f in assessment.phishing_indicators]
            malware_schema = [to_rule_schema(f) for f in assessment.malware_indicators]
            redirects_schema = [to_rule_schema(f) for f in assessment.redirect_indicators]
            downloads_schema = [to_rule_schema(f) for f in assessment.file_download_indicators]
            domain_schema = DomainIntelligenceSchema(**assessment.domain_intelligence)

            url_results.append(
                UrlScanItem(
                    url=url,
                    normalized_url=normalized.normalized,
                    risk_score=assessment.risk_score,
                    risk_level=assessment.risk_level,
                    inspection_status=assessment.inspection_status,
                    inspection_note=assessment.inspection_note,
                    blocked_destinations=assessment.blocked_destinations,
                    completed_checks=assessment.completed_checks,
                    detected_indicators=assessment.detected_indicators,
                    explanations=assessment.explanations,
                    recommendations=assessment.recommendations,
                    detected_rules=rules_schema,
                    rule_explanations=assessment.rule_explanations,
                    tracker_indicators=trackers_schema,
                    phishing_indicators=phishing_schema,
                    malware_indicators=malware_schema,
                    redirect_indicators=redirects_schema,
                    domain_intelligence=domain_schema,
                    file_download_indicators=downloads_schema,
                    reputation_status=assessment.reputation_status,
                    limitations=assessment.limitations,
                )
            )
            valid_scores.append(assessment.risk_score)
            if highest_assessment is None or assessment.risk_score > highest_assessment.risk_score:
                highest_assessment = assessment

            all_blocked.extend(assessment.blocked_destinations)
            all_checks.extend(assessment.completed_checks)
            all_rules.extend(rules_schema)
            all_rule_explanations.extend(assessment.rule_explanations)
            all_trackers.extend(trackers_schema)
            all_phishing.extend(phishing_schema)
            all_malware.extend(malware_schema)
            all_redirects.extend(redirects_schema)
            all_downloads.extend(downloads_schema)
            all_indicators.extend(assessment.detected_indicators)
            all_explanations.extend(assessment.explanations)
            all_recommendations.extend(assessment.recommendations)
            all_limitations.extend(assessment.limitations)
        except ValueError as exc:
            url_results.append(
                UrlScanItem(
                    url=url,
                    normalized_url=None,
                    risk_score=0,
                    risk_level="Unavailable",
                    error=str(exc),
                )
            )

    if not valid_scores or highest_assessment is None:
        return MessageUrlAnalysisResult(
            status="no_valid_url_detected",
            explanation=(
                "Extracted link(s) could not be parsed as valid HTTP/HTTPS URLs. "
                "URL-based risk assessment is unavailable."
            ),
            detected_urls=detected_urls,
            url_results=url_results,
            overall_risk_score=None,
            overall_risk_level="Unavailable",
            inspection_status="Check unavailable",
            inspection_note="Extracted links could not be parsed.",
            blocked_destinations=[],
            completed_checks=[],
            detected_rules=[],
            rule_explanations=[],
            tracker_indicators=[],
            phishing_indicators=[],
            malware_indicators=[],
            redirect_indicators=[],
            domain_intelligence=None,
            file_download_indicators=[],
            reputation_status="Check unavailable",
            detected_indicators=[],
            explanations=[],
            recommendations=[
                "Do not click malformed or obfuscated links; verify with the official source."
            ],
            limitations=["Extracted URLs could not be parsed as valid HTTP/HTTPS links."],
        )

    overall_score = max(valid_scores)
    overall_level = classify_risk_score(
        overall_score,
        inspection_completed=any_inspection_completed,
    )

    if len(valid_scores) == 1:
        summary = (
            f"Analyzed 1 detected URL using the centralized URL engine "
            f"(score: {overall_score}/100, {overall_level})."
        )
    else:
        summary = (
            f"Analyzed {len(valid_scores)} unique URLs using the centralized URL engine. "
            f"Overall risk ({overall_score}/100, {overall_level}) reflects the highest-risk URL detected."
        )

    return MessageUrlAnalysisResult(
        status="completed",
        explanation=summary,
        detected_urls=detected_urls,
        url_results=url_results,
        overall_risk_score=overall_score,
        overall_risk_level=overall_level,
        inspection_status=highest_assessment.inspection_status,
        inspection_note=highest_assessment.inspection_note,
        blocked_destinations=list(dict.fromkeys(all_blocked)),
        completed_checks=list(dict.fromkeys(all_checks)),
        detected_rules=_dedup_rule_schemas(all_rules),
        rule_explanations=list(dict.fromkeys(all_rule_explanations)),
        tracker_indicators=_dedup_rule_schemas(all_trackers),
        phishing_indicators=_dedup_rule_schemas(all_phishing),
        malware_indicators=_dedup_rule_schemas(all_malware),
        redirect_indicators=_dedup_rule_schemas(all_redirects),
        domain_intelligence=DomainIntelligenceSchema(**highest_assessment.domain_intelligence),
        file_download_indicators=_dedup_rule_schemas(all_downloads),
        reputation_status=highest_assessment.reputation_status,
        detected_indicators=list(dict.fromkeys(all_indicators)),
        explanations=list(dict.fromkeys(all_explanations)),
        recommendations=list(dict.fromkeys(all_recommendations)),
        limitations=list(dict.fromkeys(all_limitations)),
        suggested_url_candidates=suggested_candidates,
    )

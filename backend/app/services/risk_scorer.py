"""Centralized risk scoring, 4-state assessment classification, and explainability engine."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import MLConfig, RiskThresholds, settings
from app.ml.predictor import MLPredictionResult
from app.services.indicators import RuleFinding
from app.services.website_inspector import InspectionOutcome


@dataclass(frozen=True)
class RiskAssessment:
    """Aggregated risk score, 4-state classification, categorized findings, and limitations."""

    risk_score: int
    rule_score: int
    ml_score_contribution: int
    risk_level: str
    inspection_status: str
    inspection_note: str
    blocked_destinations: list[str]
    completed_checks: list[str]
    detected_rules: list[RuleFinding]
    rule_explanations: list[str]
    tracker_indicators: list[RuleFinding]
    phishing_indicators: list[RuleFinding]
    malware_indicators: list[RuleFinding]
    redirect_indicators: list[RuleFinding]
    domain_intelligence: dict
    file_download_indicators: list[RuleFinding]
    reputation_status: str
    detected_indicators: list[str]
    explanations: list[str]
    recommendations: list[str]
    limitations: list[str]


def classify_risk_score(
    score: int,
    *,
    inspection_completed: bool = True,
    thresholds: RiskThresholds = settings.risk_thresholds,
) -> str:
    """Map a 0-100 score to the 4-state assessment model.

    - 50-100: Dangerous
    - 25-49:  Suspicious
    - 0-24:   'No strong indicators detected' (when website was inspected)
              or 'Inspection unavailable' (when URL-only or inspection failed/blocked)
    """
    if score > thresholds.suspicious_max:
        return "Dangerous"
    if score > thresholds.safe_max:
        return "Suspicious"
    if inspection_completed:
        return "No strong indicators detected"
    return "Inspection unavailable"


def deduplicate_findings(findings: list[RuleFinding]) -> list[RuleFinding]:
    """Prevent double-counting by deduplicating on rule_id and dedup_group."""
    by_rule_id: dict[str, RuleFinding] = {}
    for item in findings:
        if item.rule_id not in by_rule_id:
            by_rule_id[item.rule_id] = item

    deduped: list[RuleFinding] = []
    group_winners: dict[str, RuleFinding] = {}

    for item in by_rule_id.values():
        if item.dedup_group is None:
            deduped.append(item)
            continue
        existing = group_winners.get(item.dedup_group)
        if existing is None or item.score_contribution > existing.score_contribution:
            group_winners[item.dedup_group] = item

    deduped.extend(group_winners.values())
    return deduped


def compute_ml_score_contribution(
    rule_score: int,
    ml_prediction: MLPredictionResult | None,
    ml_config: MLConfig = settings.ml_config,
) -> int:
    """Compute a bounded, non-overlapping ML score contribution.

    - Never adds points if ML is unavailable or predicts Legitimate.
    - Never adds points if rule_score is already Dangerous (>= 50).
    - If rule_score == 0 and high-confidence Phishing: +25 (Suspicious).
    - If 0 < rule_score < 50 and high-confidence Phishing: capped boost (+15 max).
    """
    if (
        ml_prediction is None
        or not ml_prediction.available
        or ml_prediction.prediction != "Phishing"
        or ml_prediction.confidence is None
        or ml_prediction.confidence < ml_config.high_confidence_threshold
    ):
        return 0

    if rule_score >= 50:
        return 0
    if rule_score == 0:
        return ml_config.standalone_ml_boost

    boost = round((ml_prediction.confidence - 0.5) * 30)
    return min(ml_config.combined_ml_boost_cap, max(0, boost))


def score_indicators(
    findings: list[RuleFinding],
    *,
    domain_intelligence: dict | None = None,
    inspection_outcome: InspectionOutcome | None = None,
    ml_prediction: MLPredictionResult | None = None,
    thresholds: RiskThresholds = settings.risk_thresholds,
    ml_config: MLConfig = settings.ml_config,
) -> RiskAssessment:
    """Deduplicate findings, combine rule + ML safely, and categorize results."""
    unique_findings = deduplicate_findings(findings)

    raw_rule_score = sum(
        f.score_contribution
        for f in unique_findings
        if f.detection_status == "Detected" and f.score_contribution > 0
    )
    bounded_rule_score = min(100, max(0, raw_rule_score))
    ml_boost = compute_ml_score_contribution(bounded_rule_score, ml_prediction, ml_config=ml_config)
    bounded_score = min(100, max(0, bounded_rule_score + ml_boost))

    outcome = inspection_outcome or InspectionOutcome(
        status="not_requested",
        reason="URL-only analysis — website content was not inspected.",
    )
    inspection_completed = outcome.status == "completed"
    risk_level = classify_risk_score(
        bounded_score,
        inspection_completed=inspection_completed,
        thresholds=thresholds,
    )

    if outcome.status == "completed":
        inspection_status = "Detected" if bounded_score >= 25 else "Completed"
        inspection_note = "Isolated read-only website inspection completed."
    elif outcome.status == "blocked":
        inspection_status = "Blocked for safety"
        inspection_note = outcome.reason or "Website inspection was blocked for safety."
    elif outcome.status == "unavailable":
        inspection_status = "Check unavailable"
        inspection_note = outcome.reason or "Website inspection was unavailable."
    else:
        inspection_status = "Check unavailable"
        inspection_note = "URL-only analysis — website content was not inspected."

    completed_checks = ["URL structure & obfuscation", "URL-based redirect & file rules"]
    if outcome.status == "completed":
        completed_checks.append("Isolated read-only HTML, script, form & cookie inspection")

    detected_rules = [
        f for f in unique_findings if f.detection_status == "Detected" and f.score_contribution > 0
    ]
    rule_explanations = [
        f"{f.rule_name} (+{f.score_contribution}): {f.explanation}"
        for f in detected_rules
    ]

    tracker_indicators = [f for f in unique_findings if f.category == "tracker"]
    phishing_indicators = [f for f in unique_findings if f.category == "phishing"]
    malware_indicators = [f for f in unique_findings if f.category == "malware"]
    redirect_indicators = [f for f in unique_findings if f.category == "redirect"]
    file_download_indicators = [f for f in unique_findings if f.category == "file_download"]

    domain_intel = domain_intelligence or {
        "provider_name": "unconfigured",
        "reputation_status": "Check unavailable",
        "domain_age_status": "Check unavailable",
        "domain_age_days": None,
        "confidence": None,
        "note": "No external threat-intelligence provider is configured.",
    }
    reputation_status = str(domain_intel.get("reputation_status", "Check unavailable"))
    if reputation_status != "Check unavailable":
        completed_checks.append("External threat-intelligence reputation check")

    recommendations: list[str] = []
    seen_recs: set[str] = set()
    for f in detected_rules:
        if f.recommendation not in seen_recs:
            seen_recs.add(f.recommendation)
            recommendations.append(f.recommendation)

    if not recommendations:
        recommendations.append(
            "No strong malicious indicators were detected, but safety is not verified. "
            "Always double-check the domain and sender before entering sensitive information."
        )

    limitations: list[str] = []
    if not inspection_completed:
        limitations.append(inspection_note)
    else:
        limitations.append(
            "Read-only HTML inspection does not execute JavaScript, click buttons, or submit forms."
        )
    if reputation_status == "Check unavailable":
        limitations.append(
            "External malware and domain-reputation checks were unavailable; a low score does not guarantee safety."
        )

    return RiskAssessment(
        risk_score=bounded_score,
        rule_score=bounded_rule_score,
        ml_score_contribution=ml_boost,
        risk_level=risk_level,
        inspection_status=inspection_status,
        inspection_note=inspection_note,
        blocked_destinations=list(outcome.blocked_destinations),
        completed_checks=completed_checks,
        detected_rules=detected_rules,
        rule_explanations=rule_explanations,
        tracker_indicators=tracker_indicators,
        phishing_indicators=phishing_indicators,
        malware_indicators=malware_indicators,
        redirect_indicators=redirect_indicators,
        domain_intelligence=domain_intel,
        file_download_indicators=file_download_indicators,
        reputation_status=reputation_status,
        detected_indicators=[f.rule_name for f in detected_rules],
        explanations=[f.explanation for f in detected_rules],
        recommendations=recommendations,
        limitations=limitations,
    )

"""Privacy sanitization, detailed scan report builder, and JSON/PDF export service."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fpdf import FPDF

from app.db.models import ScanHistory
from app.schemas.history import (
    ReportMLAnalysisSchema,
    ReportRuleAnalysisSchema,
    ReportRuleFindingSchema,
    ReportThreatIntelSchema,
    ScanReportResponse,
)

SENSITIVE_PARAM_KEYS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "api_key",
    "apikey",
    "secret",
    "session",
    "sessionid",
    "cookie",
    "otp",
    "pin",
    "code",
}

_INLINE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|api_key|apikey|secret|session|cookie|otp|pin)"
    r"\s*([:=])\s*([^\s&;,\"']+)"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*")
MAX_STORED_MESSAGE_CHARS = 240


def redact_sensitive_text(text: str) -> tuple[str, bool]:
    """Mask inline secrets, credentials, cookies, and auth tokens in text."""
    redacted = False

    def _replace_kv(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f"{match.group(1)}{match.group(2)}[REDACTED]"

    cleaned = _INLINE_SECRET_RE.sub(_replace_kv, text)
    if _BEARER_RE.search(cleaned):
        redacted = True
        cleaned = _BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", cleaned)
    return cleaned, redacted


def sanitize_url_for_storage(url: str) -> tuple[str, bool]:
    """Redact sensitive query parameter values in URLs while preserving domain/path."""
    cleaned, inline_redacted = redact_sensitive_text(url.strip())
    redacted = inline_redacted
    try:
        parts = urlsplit(cleaned)
        if parts.query:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            new_pairs: list[tuple[str, str]] = []
            for key, val in pairs:
                if key.lower() in SENSITIVE_PARAM_KEYS and val:
                    new_pairs.append((key, "REDACTED"))
                    redacted = True
                else:
                    new_pairs.append((key, val))
            cleaned = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urlencode(new_pairs), parts.fragment)
            )
    except ValueError:
        pass
    return cleaned, redacted


def sanitize_input_for_storage(scan_type: str, raw_input: str) -> tuple[str, bool]:
    """Sanitize URL or message input for privacy-safe persistence."""
    if scan_type == "url":
        return sanitize_url_for_storage(raw_input)

    cleaned, redacted = redact_sensitive_text(raw_input.strip())
    if len(cleaned) > MAX_STORED_MESSAGE_CHARS:
        cleaned = f"{cleaned[:MAX_STORED_MESSAGE_CHARS].rstrip()}... [truncated for privacy]"
    return cleaned, redacted


def build_sanitized_report_payload(
    *,
    rule_score: int,
    inspection_status: str,
    inspection_note: str,
    detected_rules: list[Any],
    ml_analysis: Any | None,
    domain_intelligence: Any | None,
    reputation_status: str,
    detected_urls: list[str] | None = None,
    redacted: bool = False,
) -> dict[str, Any]:
    """Create a sanitized, secret-free JSON snapshot for detailed reports and analytics."""
    serialized_rules: list[dict[str, Any]] = []
    for item in detected_rules or []:
        if hasattr(item, "model_dump"):
            d = item.model_dump()
        elif isinstance(item, dict):
            d = dict(item)
        else:
            d = {
                "rule_id": getattr(item, "rule_id", "unknown"),
                "rule_name": getattr(item, "rule_name", "Rule check"),
                "severity": getattr(item, "severity", "info"),
                "evidence": getattr(item, "evidence", ""),
                "explanation": getattr(item, "explanation", ""),
                "score_contribution": getattr(item, "score_contribution", 0),
                "detection_status": getattr(item, "detection_status", "Detected"),
                "detection_source": getattr(item, "detection_source", "url"),
            }
        evidence_clean, _ = redact_sensitive_text(str(d.get("evidence", "")))
        serialized_rules.append(
            {
                "rule_id": str(d.get("rule_id", "unknown")),
                "rule_name": str(d.get("rule_name", "Rule check")),
                "severity": str(d.get("severity", "info")),
                "evidence": evidence_clean,
                "explanation": str(d.get("explanation", "")),
                "score_contribution": int(d.get("score_contribution", 0) or 0),
                "detection_status": str(d.get("detection_status", "Detected")),
                "detection_source": str(d.get("detection_source", "url")),
            }
        )

    ml_dict: dict[str, Any]
    if ml_analysis is None:
        ml_dict = {"available": False, "prediction": "Analysis unavailable"}
    elif hasattr(ml_analysis, "model_dump"):
        ml_dict = ml_analysis.model_dump()
    else:
        ml_dict = dict(ml_analysis)

    if domain_intelligence is None:
        intel_dict: dict[str, Any] = {
            "provider_name": "unconfigured",
            "reputation_status": reputation_status or "Check unavailable",
            "domain_age_status": "Check unavailable",
            "provider_results": [],
        }
    elif hasattr(domain_intelligence, "model_dump"):
        intel_dict = domain_intelligence.model_dump()
    else:
        intel_dict = dict(domain_intelligence)

    # Never persist credentials or raw error strings that could carry sensitive tokens
    safe_providers = []
    for p in intel_dict.get("provider_results") or []:
        safe_providers.append(
            {
                "provider_name": str(p.get("provider_name", "unknown")),
                "lookup_status": str(p.get("lookup_status", "Check unavailable")),
                "threat_category": str(p.get("threat_category", "Unavailable")),
                "checked_at": str(p.get("checked_at", "")),
                "cached": bool(p.get("cached", False)),
            }
        )

    safe_urls = [sanitize_url_for_storage(u)[0] for u in (detected_urls or [])]

    return {
        "rule_analysis": {
            "rule_score": int(rule_score),
            "inspection_status": inspection_status,
            "inspection_note": inspection_note,
            "detected_rules": serialized_rules,
        },
        "ml_analysis": {
            "available": bool(ml_dict.get("available", False)),
            "prediction": str(ml_dict.get("prediction", "Analysis unavailable")),
            "confidence": ml_dict.get("confidence"),
            "calibrated": bool(ml_dict.get("calibrated", False)),
            "model_version": ml_dict.get("model_version"),
            "score_contribution": int(ml_dict.get("score_contribution", 0) or 0),
        },
        "threat_intelligence": {
            "reputation_status": str(
                intel_dict.get("reputation_status") or reputation_status or "Check unavailable"
            ),
            "provider_name": str(intel_dict.get("provider_name", "unconfigured")),
            "domain_age_status": str(intel_dict.get("domain_age_status", "Check unavailable")),
            "domain_age_days": intel_dict.get("domain_age_days"),
            "checked_at": intel_dict.get("checked_at"),
            "cached": bool(intel_dict.get("cached", False)),
            "provider_results": safe_providers,
            "note": intel_dict.get("note"),
        },
        "detected_urls": safe_urls,
        "privacy_redacted": redacted,
    }


def _classification_summary(risk_level: str, risk_score: int) -> str:
    if risk_level == "Dangerous":
        return f"High-risk indicators detected (score {risk_score}/100). Avoid interacting with this target."
    if risk_level == "Suspicious":
        return f"Moderate risk indicators detected (score {risk_score}/100). Verify independently before proceeding."
    if risk_level == "Safe":
        return f"Low risk score ({risk_score}/100) with no high-risk indicators detected."
    if risk_level == "No strong indicators detected":
        return (
            f"No strong phishing or malware indicators were detected in static checks "
            f"(score {risk_score}/100), but website content or external reputation may be unverified."
        )
    return (
        f"Inspection was incomplete or unavailable (score {risk_score}/100). "
        "Treat unverified links with caution."
    )


def build_scan_report(record: ScanHistory) -> ScanReportResponse:
    """Build and validate a complete ScanReportResponse from a ScanHistory database record."""
    payload = record.report_payload if isinstance(record.report_payload, dict) else {}
    rule_raw = payload.get("rule_analysis") or {}
    ml_raw = payload.get("ml_analysis") or {}
    intel_raw = payload.get("threat_intelligence") or {}

    detected_rules = [
        ReportRuleFindingSchema(**r)
        for r in (rule_raw.get("detected_rules") or [])
        if isinstance(r, dict)
    ]

    rule_analysis = ReportRuleAnalysisSchema(
        status="completed",
        rule_score=int(rule_raw.get("rule_score", record.risk_score)),
        inspection_status=str(rule_raw.get("inspection_status", "Check unavailable")),
        inspection_note=str(
            rule_raw.get(
                "inspection_note",
                "URL-only analysis — website content was not inspected.",
            )
        ),
        detected_rules=detected_rules,
    )

    ml_available = bool(ml_raw.get("available", False))
    if ml_raw:
        ml_note = (
            "ML model prediction recorded during scan."
            if ml_available
            else "ML model was unavailable during this scan."
        )
    else:
        ml_note = "ML analysis was not recorded for this historical scan."

    ml_analysis = ReportMLAnalysisSchema(
        status="available" if ml_available else "unavailable",
        available=ml_available,
        prediction=str(
            ml_raw.get("prediction", "Analysis unavailable" if not ml_available else "Unknown")
        ),
        confidence=ml_raw.get("confidence"),
        calibrated=bool(ml_raw.get("calibrated", False)),
        model_version=ml_raw.get("model_version"),
        score_contribution=int(ml_raw.get("score_contribution", 0) or 0),
        note=ml_note,
    )

    rep_status = str(intel_raw.get("reputation_status", "Check unavailable"))
    if rep_status == "Detected":
        intel_status = "matched"
    elif rep_status == "Not detected":
        intel_status = "no_match"
    else:
        intel_status = "unavailable"

    threat_intel = ReportThreatIntelSchema(
        status=intel_status,
        reputation_status=rep_status,
        provider_name=str(intel_raw.get("provider_name", "unconfigured")),
        domain_age_status=str(intel_raw.get("domain_age_status", "Check unavailable")),
        domain_age_days=intel_raw.get("domain_age_days"),
        checked_at=intel_raw.get("checked_at"),
        cached=bool(intel_raw.get("cached", False)),
        provider_results=list(intel_raw.get("provider_results") or []),
        note=intel_raw.get("note")
        or (
            "Threat intelligence lookup was unavailable or not recorded for this scan."
            if intel_status == "unavailable"
            else None
        ),
    )

    sources = ["Rule-Based Security Engine"]
    if ml_available:
        sources.append("ScamShield ML Classifier")
    if intel_status != "unavailable":
        sources.append(f"Threat Intelligence ({threat_intel.provider_name})")

    sanitized_preview, _ = redact_sensitive_text(record.input_text)

    return ScanReportResponse(
        success=True,
        scan_id=record.id,
        created_at=record.created_at,
        scan_type=record.scan_type,
        input_preview=sanitized_preview,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        classification_summary=_classification_summary(record.risk_level, record.risk_score),
        detected_indicators=list(record.detected_indicators or []),
        detected_urls=list(payload.get("detected_urls") or []),
        rule_analysis=rule_analysis,
        ml_analysis=ml_analysis,
        threat_intelligence=threat_intel,
        explanations=list(record.explanations or []),
        recommendations=list(record.recommendations or []),
        analysis_sources=sources,
    )


def export_report_json(report: ScanReportResponse) -> bytes:
    """Validate and serialize a ScanReportResponse as clean, machine-readable JSON."""
    validated = ScanReportResponse.model_validate(report.model_dump())
    return validated.model_dump_json(indent=2).encode("utf-8")


def _pdf_safe(text: str) -> str:
    """Ensure text renders safely in standard PDF Helvetica fonts without encoding errors."""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


class _ReportPDF(FPDF):
    def header(self) -> None:
        self.set_fill_color(12, 18, 30)
        self.rect(0, 0, 210, 22, "F")
        self.set_xy(12, 6)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.cell(100, 6, "ScamShield AI  |  Security Scan Report")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(148, 163, 184)
        self.set_xy(12, 13)
        self.cell(186, 4, "Defensive Read-Only URL & Message Threat Analysis")
        self.ln(14)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            6,
            _pdf_safe(f"ScamShield AI Automated Security Report  |  Page {self.page_no()}"),
            align="C",
        )


def export_report_pdf(report: ScanReportResponse) -> bytes:
    """Generate a formatted, branded PDF cybersecurity report for a validated scan report."""
    validated = ScanReportResponse.model_validate(report.model_dump())
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_left_margin(12)
    pdf.set_right_margin(12)

    def section_title(title: str) -> None:
        pdf.ln(3)
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(30, 64, 175)
        pdf.cell(186, 7, _pdf_safe(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(203, 213, 225)
        pdf.line(12, pdf.get_y(), 198, pdf.get_y())
        pdf.ln(2)

    def body_line(label: str, value: str) -> None:
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(46, 5.5, _pdf_safe(label))
        pdf.set_x(58)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)
        pdf.multi_cell(140, 5.5, _pdf_safe(value), new_x="LMARGIN", new_y="NEXT")

    section_title("1. Scan Summary")
    body_line("Scan ID:", f"#{validated.scan_id}")
    body_line("Timestamp (UTC):", validated.created_at.isoformat())
    body_line("Scan Type:", validated.scan_type.upper())
    body_line("Final Classification:", validated.risk_level)
    body_line("Risk Score:", f"{validated.risk_score} / 100")
    body_line("Analysis Sources:", ", ".join(validated.analysis_sources))
    body_line("Inspected Input:", validated.input_preview)
    body_line("Summary:", validated.classification_summary)

    section_title("2. Detection Evidence & Rule-Based Analysis")
    body_line("Rule Score:", f"{validated.rule_analysis.rule_score} / 100")
    body_line("Website Inspection:", validated.rule_analysis.inspection_status)
    body_line("Inspection Note:", validated.rule_analysis.inspection_note)

    if validated.detected_indicators:
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(186, 5.5, "Detected Indicators:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)
        for ind in validated.detected_indicators:
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _pdf_safe(f"  - {ind}"), new_x="LMARGIN", new_y="NEXT")
    else:
        body_line("Detected Indicators:", "None detected in static rule checks.")

    if validated.rule_analysis.detected_rules:
        pdf.ln(1)
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(186, 5.5, "Detailed Rule Breakdown:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8.5)
        for rule in validated.rule_analysis.detected_rules[:12]:
            pdf.set_x(12)
            pdf.set_text_color(15, 23, 42)
            pdf.multi_cell(
                186,
                4.8,
                _pdf_safe(
                    f"  * [{rule.severity.upper()}] {rule.rule_name} (+{rule.score_contribution}): {rule.explanation}"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )

    section_title("3. Machine Learning & Threat Intelligence")
    if validated.ml_analysis.available:
        conf_pct = (
            f"{round(validated.ml_analysis.confidence * 100, 1)}%"
            if validated.ml_analysis.confidence is not None
            else "N/A"
        )
        body_line(
            "ML Prediction:",
            f"{validated.ml_analysis.prediction} (Confidence: {conf_pct}, Score Contribution: +{validated.ml_analysis.score_contribution})",
        )
    else:
        body_line("ML Prediction:", f"Unavailable — {validated.ml_analysis.note}")

    body_line("Threat Reputation:", validated.threat_intelligence.reputation_status)
    body_line("Threat Provider:", validated.threat_intelligence.provider_name)
    if validated.threat_intelligence.provider_results:
        for pr in validated.threat_intelligence.provider_results:
            body_line(
                f"  Provider ({pr.get('provider_name', 'unknown')}):",
                f"{pr.get('lookup_status', 'Check unavailable')} — {pr.get('threat_category', 'Unavailable')}",
            )
    elif validated.threat_intelligence.note:
        body_line("Threat Intel Note:", validated.threat_intelligence.note)

    section_title("4. Explanations & Recommended Next Steps")
    if validated.explanations:
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(186, 5.5, "Result Explanations:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)
        for exp in validated.explanations:
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _pdf_safe(f"  - {exp}"), new_x="LMARGIN", new_y="NEXT")

    if validated.recommendations:
        pdf.ln(1)
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(186, 5.5, "Recommended Next Steps:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)
        for rec in validated.recommendations:
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _pdf_safe(f"  - {rec}"), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_x(12)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(
        186,
        4.8,
        _pdf_safe(f"DISCLAIMER: {validated.disclaimer} {validated.privacy_notice}"),
        border=1,
        fill=True,
        new_x="LMARGIN",
        new_y="NEXT",
    )

    return bytes(pdf.output())

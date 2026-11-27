"""API route definitions for ScamShield AI."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Path, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.ml.predictor import MLPredictionResult, predict_message_ml, predict_url_ml
from app.schemas.health import HealthResponse
from app.schemas.history import (
    AnalyticsResponse,
    HistoryClearResponse,
    HistoryDeleteResponse,
    HistoryDetailResponse,
    HistoryListResponse,
    HistorySummary,
    ScanReportResponse,
)
from app.schemas.scan import (
    DomainIntelligenceSchema,
    LocalizedExplanationSchema,
    MLAnalysisSchema,
    MessageScanRequest,
    ScanResponse,
    UrlScanItem,
    UrlScanRequest,
)
from app.services.analytics_service import compute_analytics
from app.services.explanation_service import generate_multilingual_explanations
from app.services.history_service import (
    clear_scan_history,
    delete_scan_history_by_id,
    get_scan_history_by_id,
    list_scan_history,
    save_scan_history,
)
from app.services.message_analyzer import analyze_message_urls, to_rule_schema
from app.services.ocr_service import (
    ImageValidationError,
    OcrUnavailableError,
    extract_text_from_image,
    validate_and_load_image,
)
from app.services.report_service import (
    build_sanitized_report_payload,
    build_scan_report,
    export_report_json,
    export_report_pdf,
    sanitize_input_for_storage,
)
from app.services.risk_scorer import score_indicators
from app.services.url_analyzer import analyze_url_full, normalize_and_validate_url

router = APIRouter(prefix="/api", tags=["system"])

SAVABLE_RISK_LEVELS = {
    "Safe",
    "Suspicious",
    "Dangerous",
    "No strong indicators detected",
    "Inspection unavailable",
}


def _to_ml_schema(pred: MLPredictionResult, score_contribution: int = 0) -> MLAnalysisSchema:
    return MLAnalysisSchema(
        available=pred.available,
        prediction=pred.prediction,
        confidence=pred.confidence,
        calibrated=pred.calibrated,
        probabilities=pred.probabilities,
        model_version=pred.model_version,
        score_contribution=score_contribution,
        disclaimer=pred.disclaimer,
        error=pred.error,
    )


def _build_message_multi_exp(analysis) -> dict[str, LocalizedExplanationSchema]:
    """Convert MessageUrlAnalysisResult rules into localized English/Hindi/Hinglish bundles."""
    from app.services.indicators import RuleFinding as _RF

    rf_list = [
        _RF(
            rule_id=r.rule_id,
            rule_name=r.rule_name,
            category="url_structure",
            severity=r.severity,
            evidence=r.evidence,
            explanation=r.explanation,
            recommendation="",
            score_contribution=r.score_contribution,
            detection_status=r.detection_status,
        )
        for r in analysis.detected_rules
    ]
    return {
        lang: LocalizedExplanationSchema(
            summary=bundle.summary,
            explanations=bundle.explanations,
            recommendations=bundle.recommendations,
        )
        for lang, bundle in generate_multilingual_explanations(
            risk_score=analysis.overall_risk_score,
            risk_level=analysis.overall_risk_level,
            detected_rules=rf_list,
            fallback_recommendations=analysis.recommendations,
        ).items()
    }


@router.get("/health", response_model=HealthResponse, summary="Backend health check")
def health_check() -> HealthResponse:
    """Return service status so the frontend can verify backend connectivity."""
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/scan/url", response_model=ScanResponse, summary="Scan a URL as plain text")
def scan_url(
    payload: UrlScanRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Analyze a submitted URL using URL-text rules and optional isolated inspection."""
    try:
        normalized, findings, domain_summary, outcome = analyze_url_full(
            payload.url,
            inspect_website=payload.inspect_website,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    ml_pred = predict_url_ml(normalized.normalized)
    assessment = score_indicators(
        findings,
        domain_intelligence=domain_summary,
        inspection_outcome=outcome,
        ml_prediction=ml_pred,
    )
    multi_exp = {
        lang: LocalizedExplanationSchema(
            summary=bundle.summary,
            explanations=bundle.explanations,
            recommendations=bundle.recommendations,
        )
        for lang, bundle in generate_multilingual_explanations(
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            detected_rules=assessment.detected_rules,
            fallback_recommendations=assessment.recommendations,
        ).items()
    }

    ml_schema = _to_ml_schema(ml_pred, assessment.ml_score_contribution)
    rules_schema = [to_rule_schema(f) for f in assessment.detected_rules]
    domain_schema = DomainIntelligenceSchema(**assessment.domain_intelligence)
    _, input_redacted = sanitize_input_for_storage("url", payload.url)
    report_payload = build_sanitized_report_payload(
        rule_score=assessment.rule_score,
        inspection_status=assessment.inspection_status,
        inspection_note=assessment.inspection_note,
        detected_rules=rules_schema,
        ml_analysis=ml_schema,
        domain_intelligence=domain_schema,
        reputation_status=assessment.reputation_status,
        detected_urls=[payload.url],
        redacted=input_redacted,
    )

    try:
        saved = save_scan_history(
            db,
            scan_type="url",
            input_text=payload.url,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            detected_indicators=assessment.detected_indicators,
            explanations=assessment.explanations,
            recommendations=assessment.recommendations,
            report_payload=report_payload,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save scan history due to a database error.",
        ) from exc

    trackers_schema = [to_rule_schema(f) for f in assessment.tracker_indicators]
    phishing_schema = [to_rule_schema(f) for f in assessment.phishing_indicators]
    malware_schema = [to_rule_schema(f) for f in assessment.malware_indicators]
    redirects_schema = [to_rule_schema(f) for f in assessment.redirect_indicators]
    downloads_schema = [to_rule_schema(f) for f in assessment.file_download_indicators]

    url_item = UrlScanItem(
        url=payload.url,
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

    return ScanResponse(
        success=True,
        scan_id=saved.id,
        scan_type="url",
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        rule_score=assessment.rule_score,
        combined_risk_score=assessment.risk_score,
        ml_analysis=_to_ml_schema(ml_pred, assessment.ml_score_contribution),
        inspection_status=assessment.inspection_status,
        inspection_note=assessment.inspection_note,
        blocked_destinations=assessment.blocked_destinations,
        completed_checks=assessment.completed_checks,
        detected_rules=rules_schema,
        rule_explanations=assessment.rule_explanations,
        tracker_indicators=trackers_schema,
        phishing_indicators=phishing_schema,
        malware_indicators=malware_schema,
        redirect_indicators=redirects_schema,
        domain_intelligence=domain_schema,
        file_download_indicators=downloads_schema,
        reputation_status=assessment.reputation_status,
        detected_indicators=assessment.detected_indicators,
        explanations=assessment.explanations,
        recommendations=assessment.recommendations,
        multilingual_explanations=multi_exp,
        limitations=assessment.limitations,
        detected_urls=[payload.url],
        url_results=[url_item],
        overall_risk_score=assessment.risk_score,
        overall_risk_level=assessment.risk_level,
        status="completed",
        explanation=assessment.inspection_note,
    )


@router.post(
    "/scan/message",
    response_model=ScanResponse,
    summary="Scan a message using URL-first analysis",
)
def scan_message(
    payload: MessageScanRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Extract URLs from a message and analyze ONLY those URLs via the centralized engine."""
    try:
        analysis = analyze_message_urls(
            payload.message,
            inspect_website=payload.inspect_website,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    ml_msg_pred = predict_message_ml(payload.message)
    ml_msg_schema = _to_ml_schema(ml_msg_pred, 0)
    _, input_redacted = sanitize_input_for_storage("message", payload.message)
    msg_report_payload = build_sanitized_report_payload(
        rule_score=analysis.overall_risk_score or 0,
        inspection_status=analysis.inspection_status,
        inspection_note=analysis.inspection_note,
        detected_rules=analysis.detected_rules,
        ml_analysis=ml_msg_schema,
        domain_intelligence=analysis.domain_intelligence,
        reputation_status=analysis.reputation_status,
        detected_urls=analysis.detected_urls,
        redacted=input_redacted,
    )

    saved_id: int | None = None
    if (
        analysis.overall_risk_score is not None
        and analysis.overall_risk_level in SAVABLE_RISK_LEVELS
    ):
        try:
            saved = save_scan_history(
                db,
                scan_type="message",
                input_text=payload.message,
                risk_score=analysis.overall_risk_score,
                risk_level=analysis.overall_risk_level,
                detected_indicators=analysis.detected_indicators,
                explanations=analysis.explanations,
                recommendations=analysis.recommendations,
                report_payload=msg_report_payload,
            )
            saved_id = saved.id
        except SQLAlchemyError as exc:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to save scan history due to a database error.",
            ) from exc

    multi_exp = _build_message_multi_exp(analysis)

    return ScanResponse(
        success=True,
        scan_id=saved_id,
        scan_type="message",
        risk_score=analysis.overall_risk_score,
        risk_level=analysis.overall_risk_level,
        rule_score=analysis.overall_risk_score,
        combined_risk_score=analysis.overall_risk_score,
        ml_analysis=_to_ml_schema(ml_msg_pred, 0),
        inspection_status=analysis.inspection_status,
        inspection_note=analysis.inspection_note,
        blocked_destinations=analysis.blocked_destinations,
        completed_checks=analysis.completed_checks,
        detected_rules=analysis.detected_rules,
        rule_explanations=analysis.rule_explanations,
        tracker_indicators=analysis.tracker_indicators,
        phishing_indicators=analysis.phishing_indicators,
        malware_indicators=analysis.malware_indicators,
        redirect_indicators=analysis.redirect_indicators,
        domain_intelligence=analysis.domain_intelligence,
        file_download_indicators=analysis.file_download_indicators,
        reputation_status=analysis.reputation_status,
        detected_indicators=analysis.detected_indicators,
        explanations=analysis.explanations,
        recommendations=analysis.recommendations,
        multilingual_explanations=multi_exp,
        limitations=analysis.limitations,
        extracted_text=payload.message,
        detected_urls=analysis.detected_urls,
        url_results=analysis.url_results,
        overall_risk_score=analysis.overall_risk_score,
        overall_risk_level=analysis.overall_risk_level,
        status=analysis.status,
        explanation=analysis.explanation,
        disclaimer=(
            "URL-first analysis inspects extracted links only. "
            "A low-risk result does not guarantee that a message or link is safe."
        ),
    )


@router.post(
    "/scan/message-image",
    response_model=ScanResponse,
    summary="Extract text from an uploaded screenshot/image via OCR and scan detected URLs",
)
async def scan_message_image(
    file: UploadFile = File(...),
    inspect_website: bool = Form(default=False),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Validate an uploaded image, extract text via OCR, and run centralized URL analysis."""
    max_bytes = settings.image_config.max_file_size_bytes
    file_bytes = await file.read(max_bytes + 1)
    if len(file_bytes) > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Image exceeds the maximum allowed size of {max_mb} MB.",
        )

    try:
        validated_bytes = validate_and_load_image(
            file_bytes=file_bytes,
            filename=file.filename,
            content_type=file.content_type,
        )
        ocr_result = extract_text_from_image(validated_bytes)
    except ImageValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except OcrUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if not ocr_result.extracted_text:
        return ScanResponse(
            success=True,
            scan_id=None,
            scan_type="message-image",
            risk_score=None,
            risk_level="Unavailable",
            inspection_status="Check unavailable",
            inspection_note="No readable text or URLs were detected in the image.",
            reputation_status="Check unavailable",
            recommendations=[
                "No readable text was detected in the image. Try uploading a clearer screenshot."
            ],
            limitations=[
                "No readable text or URLs were detected via OCR; URL-based risk assessment is unavailable."
            ],
            extracted_text="",
            detected_urls=[],
            url_results=[],
            overall_risk_score=None,
            overall_risk_level="Unavailable",
            ocr_confidence=ocr_result.ocr_confidence,
            low_ocr_confidence_warning=ocr_result.low_confidence_warning,
            status="no_url_detected",
            explanation=(
                "No readable text or URLs were detected in the uploaded image. "
                "URL-based risk assessment is unavailable."
            ),
            disclaimer=(
                "OCR accuracy depends on image clarity. Always verify extracted URLs manually."
            ),
        )

    ocr_text_for_scan = ocr_result.extracted_text[: settings.message_config.max_message_length]
    analysis = analyze_message_urls(
        ocr_text_for_scan,
        inspect_website=inspect_website,
    )

    ml_msg_pred = predict_message_ml(ocr_text_for_scan)
    ml_img_schema = _to_ml_schema(ml_msg_pred, 0)
    _, img_redacted = sanitize_input_for_storage("message-image", ocr_text_for_scan)
    img_report_payload = build_sanitized_report_payload(
        rule_score=analysis.overall_risk_score or 0,
        inspection_status=analysis.inspection_status,
        inspection_note=analysis.inspection_note,
        detected_rules=analysis.detected_rules,
        ml_analysis=ml_img_schema,
        domain_intelligence=analysis.domain_intelligence,
        reputation_status=analysis.reputation_status,
        detected_urls=analysis.detected_urls,
        redacted=img_redacted,
    )

    saved_id: int | None = None
    if (
        analysis.overall_risk_score is not None
        and analysis.overall_risk_level in SAVABLE_RISK_LEVELS
    ):
        try:
            saved = save_scan_history(
                db,
                scan_type="message-image",
                input_text=ocr_text_for_scan,
                risk_score=analysis.overall_risk_score,
                risk_level=analysis.overall_risk_level,
                detected_indicators=analysis.detected_indicators,
                explanations=analysis.explanations,
                recommendations=analysis.recommendations,
                report_payload=img_report_payload,
            )
            saved_id = saved.id
        except SQLAlchemyError as exc:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to save scan history due to a database error.",
            ) from exc

    multi_exp = _build_message_multi_exp(analysis)

    return ScanResponse(
        success=True,
        scan_id=saved_id,
        scan_type="message-image",
        risk_score=analysis.overall_risk_score,
        risk_level=analysis.overall_risk_level,
        rule_score=analysis.overall_risk_score,
        combined_risk_score=analysis.overall_risk_score,
        ml_analysis=_to_ml_schema(ml_msg_pred, 0),
        inspection_status=analysis.inspection_status,
        inspection_note=analysis.inspection_note,
        blocked_destinations=analysis.blocked_destinations,
        completed_checks=analysis.completed_checks,
        detected_rules=analysis.detected_rules,
        rule_explanations=analysis.rule_explanations,
        tracker_indicators=analysis.tracker_indicators,
        phishing_indicators=analysis.phishing_indicators,
        malware_indicators=analysis.malware_indicators,
        redirect_indicators=analysis.redirect_indicators,
        domain_intelligence=analysis.domain_intelligence,
        file_download_indicators=analysis.file_download_indicators,
        reputation_status=analysis.reputation_status,
        detected_indicators=analysis.detected_indicators,
        explanations=analysis.explanations,
        recommendations=analysis.recommendations,
        multilingual_explanations=multi_exp,
        limitations=analysis.limitations,
        extracted_text=ocr_result.extracted_text,
        detected_urls=analysis.detected_urls,
        url_results=analysis.url_results,
        overall_risk_score=analysis.overall_risk_score,
        overall_risk_level=analysis.overall_risk_level,
        ocr_confidence=ocr_result.ocr_confidence,
        low_ocr_confidence_warning=ocr_result.low_confidence_warning,
        status=analysis.status,
        explanation=analysis.explanation,
        disclaimer=(
            "OCR accuracy depends on image clarity, and URL-first analysis inspects extracted links only. "
            "A low-risk result does not guarantee safety."
        ),
    )


@router.post(
    "/ml/predict/url",
    response_model=MLAnalysisSchema,
    summary="Run standalone ML prediction on a URL",
)
def ml_predict_url(payload: UrlScanRequest) -> MLAnalysisSchema:
    """Validate URL text and run cached ML phishing URL prediction."""
    try:
        normalized = normalize_and_validate_url(payload.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    pred = predict_url_ml(normalized.normalized)
    return _to_ml_schema(pred, 0)


@router.post(
    "/ml/predict/message",
    response_model=MLAnalysisSchema,
    summary="Run standalone ML prediction on a message",
)
def ml_predict_message(payload: MessageScanRequest) -> MLAnalysisSchema:
    """Validate message text and run cached 4-class ML message prediction."""
    pred = predict_message_ml(payload.message)
    return _to_ml_schema(pred, 0)


@router.get("/history", response_model=HistoryListResponse, summary="List scan history")
def get_history(
    limit: int = Query(default=10, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    scan_type: Literal["url", "message", "message-image"] | None = Query(default=None),
    risk_level: Literal[
        "Safe",
        "Suspicious",
        "Dangerous",
        "No strong indicators detected",
        "Inspection unavailable",
    ]
    | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    sort_by: Literal["date_desc", "date_asc", "score_desc", "score_asc"] = Query(
        default="date_desc"
    ),
    db: Session = Depends(get_db),
) -> HistoryListResponse:
    """Return scan records with pagination, search, date range, and sorting."""
    try:
        total, items = list_scan_history(
            db,
            limit=limit,
            offset=offset,
            scan_type=scan_type,
            risk_level=risk_level,
            search=search,
            date_from=date_from,
            date_to=date_to,
            sort_by=sort_by,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve scan history due to a database error.",
        ) from exc

    return HistoryListResponse(
        success=True,
        total=total,
        limit=limit,
        offset=offset,
        items=[HistorySummary.model_validate(item) for item in items],
    )


@router.get(
    "/history/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Get a detailed scan report",
)
def get_history_report(
    scan_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> ScanReportResponse:
    """Return a structured, validated detailed report for one scan record."""
    try:
        record = get_scan_history_by_id(db, scan_id)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve scan report due to a database error.",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    return build_scan_report(record)


@router.get(
    "/history/{scan_id}/export",
    summary="Export a detailed scan report as JSON or PDF",
)
def export_history_report(
    scan_id: int = Path(..., ge=1),
    format: Literal["json", "pdf"] = Query(default="json"),
    db: Session = Depends(get_db),
) -> Response:
    """Validate and export a single scan report in JSON or PDF format."""
    try:
        record = get_scan_history_by_id(db, scan_id)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to export scan report due to a database error.",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    report = build_scan_report(record)
    if format == "pdf":
        content = export_report_pdf(report)
        return Response(
            content=content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="scamshield-report-{scan_id}.pdf"'
            },
        )

    content = export_report_json(report)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scamshield-report-{scan_id}.json"'
        },
    )


@router.get(
    "/analytics",
    response_model=AnalyticsResponse,
    summary="Get real-database scan analytics",
)
def get_analytics(
    scan_type: Literal["url", "message", "message-image"] | None = Query(default=None),
    risk_level: Literal[
        "Safe",
        "Suspicious",
        "Dangerous",
        "No strong indicators detected",
        "Inspection unavailable",
    ]
    | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
) -> AnalyticsResponse:
    """Compute scan analytics from actual stored scan history records."""
    try:
        return compute_analytics(
            db,
            scan_type=scan_type,
            risk_level=risk_level,
            date_from=date_from,
            date_to=date_to,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to compute analytics due to a database error.",
        ) from exc


@router.get(
    "/history/{scan_id}",
    response_model=HistoryDetailResponse,
    summary="Get details for one scan",
)
def get_history_detail(
    scan_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> HistoryDetailResponse:
    """Return complete details for a single scan record."""
    try:
        record = get_scan_history_by_id(db, scan_id)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve scan details due to a database error.",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    return HistoryDetailResponse.model_validate(record)


@router.delete(
    "/history/{scan_id}",
    response_model=HistoryDeleteResponse,
    summary="Delete a single scan record",
)
def delete_history_item(
    scan_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
) -> HistoryDeleteResponse:
    """Delete a selected scan history record by ID."""
    try:
        deleted = delete_scan_history_by_id(db, scan_id)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to delete scan record due to a database error.",
        ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    return HistoryDeleteResponse(
        success=True,
        message="Scan record deleted.",
        deleted_id=scan_id,
    )


@router.delete(
    "/history",
    response_model=HistoryClearResponse,
    summary="Clear all scan history",
)
def delete_all_history(db: Session = Depends(get_db)) -> HistoryClearResponse:
    """Delete all scan history records."""
    try:
        deleted_count = clear_scan_history(db)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to clear scan history due to a database error.",
        ) from exc

    return HistoryClearResponse(
        success=True,
        message="All scan history cleared.",
        deleted_count=deleted_count,
    )

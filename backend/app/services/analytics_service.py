"""Real-database analytics calculation service for ScamShield AI."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import ScanHistory
from app.schemas.history import (
    AnalyticsClassificationsSchema,
    AnalyticsResponse,
    IndicatorFrequencySchema,
    MLStatsSchema,
    RiskBucketSchema,
    ThreatIntelStatsSchema,
    TrendPointSchema,
)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def compute_analytics(
    db: Session,
    *,
    scan_type: str | None = None,
    risk_level: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> AnalyticsResponse:
    """Compute scan analytics strictly from actual stored ScanHistory rows."""
    query = db.query(ScanHistory)
    if scan_type:
        query = query.filter(ScanHistory.scan_type == scan_type)
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)
    if date_from:
        query = query.filter(ScanHistory.created_at >= _ensure_utc(date_from))
    if date_to:
        query = query.filter(ScanHistory.created_at <= _ensure_utc(date_to))

    records = query.order_by(ScanHistory.created_at.asc(), ScanHistory.id.asc()).all()
    total = len(records)

    empty_buckets = [
        RiskBucketSchema(label="0-24 (Low)", min_score=0, max_score=24, count=0, percentage=0.0),
        RiskBucketSchema(label="25-49 (Medium)", min_score=25, max_score=49, count=0, percentage=0.0),
        RiskBucketSchema(label="50-74 (High)", min_score=50, max_score=74, count=0, percentage=0.0),
        RiskBucketSchema(label="75-100 (Critical)", min_score=75, max_score=100, count=0, percentage=0.0),
    ]

    if total == 0:
        return AnalyticsResponse(
            success=True,
            has_data=False,
            total_scans=0,
            url_scans=0,
            message_scans=0,
            message_image_scans=0,
            average_risk_score=None,
            high_risk_rate=0.0,
            classifications=AnalyticsClassificationsSchema(),
            risk_distribution=empty_buckets,
            daily_trends=[],
            weekly_trends=[],
            top_indicators=[],
            ml_stats=MLStatsSchema(),
            threat_intel_stats=ThreatIntelStatsSchema(),
        )

    url_scans = 0
    message_scans = 0
    message_image_scans = 0
    score_sum = 0

    cls_counts = {
        "Safe": 0,
        "Suspicious": 0,
        "Dangerous": 0,
        "No strong indicators detected": 0,
        "Inspection unavailable": 0,
    }
    bucket_counts = [0, 0, 0, 0]
    daily_map: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "safe": 0, "suspicious": 0, "dangerous": 0}
    )
    weekly_map: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "safe": 0, "suspicious": 0, "dangerous": 0}
    )
    indicator_counter: Counter[str] = Counter()

    ml_recorded = 0
    ml_available = 0
    ml_unavailable = 0
    ml_flagged = 0
    ml_confidences: list[float] = []

    intel_recorded = 0
    intel_matches = 0
    intel_clean = 0
    intel_unavailable = 0

    for rec in records:
        if rec.scan_type == "url":
            url_scans += 1
        elif rec.scan_type == "message":
            message_scans += 1
        elif rec.scan_type == "message-image":
            message_scans += 1
            message_image_scans += 1

        score = int(rec.risk_score)
        score_sum += score
        if score <= 24:
            bucket_counts[0] += 1
        elif score <= 49:
            bucket_counts[1] += 1
        elif score <= 74:
            bucket_counts[2] += 1
        else:
            bucket_counts[3] += 1

        if rec.risk_level in cls_counts:
            cls_counts[rec.risk_level] += 1

        dt = _ensure_utc(rec.created_at)
        day_key = dt.strftime("%Y-%m-%d")
        iso_year, iso_week, _ = dt.isocalendar()
        week_key = f"{iso_year}-W{iso_week:02d}"

        for target_map, key in ((daily_map, day_key), (weekly_map, week_key)):
            target_map[key]["total"] += 1
            if rec.risk_level in {"Safe", "No strong indicators detected"}:
                target_map[key]["safe"] += 1
            elif rec.risk_level == "Suspicious":
                target_map[key]["suspicious"] += 1
            elif rec.risk_level == "Dangerous":
                target_map[key]["dangerous"] += 1

        for ind in rec.detected_indicators or []:
            if ind:
                indicator_counter[str(ind)] += 1

        payload = rec.report_payload if isinstance(rec.report_payload, dict) else None
        if payload:
            ml_info = payload.get("ml_analysis")
            if isinstance(ml_info, dict):
                ml_recorded += 1
                if ml_info.get("available"):
                    ml_available += 1
                    pred_str = str(ml_info.get("prediction", "")).lower()
                    if any(tok in pred_str for tok in ("phishing", "scam", "spam", "malicious")):
                        ml_flagged += 1
                    conf = ml_info.get("confidence")
                    if isinstance(conf, (int, float)):
                        ml_confidences.append(float(conf))
                else:
                    ml_unavailable += 1

            intel_info = payload.get("threat_intelligence")
            if isinstance(intel_info, dict):
                intel_recorded += 1
                rep = intel_info.get("reputation_status")
                if rep == "Detected":
                    intel_matches += 1
                elif rep == "Not detected":
                    intel_clean += 1
                else:
                    intel_unavailable += 1

    risk_distribution = [
        RiskBucketSchema(
            label="0-24 (Low)",
            min_score=0,
            max_score=24,
            count=bucket_counts[0],
            percentage=round((bucket_counts[0] / total) * 100, 1),
        ),
        RiskBucketSchema(
            label="25-49 (Medium)",
            min_score=25,
            max_score=49,
            count=bucket_counts[1],
            percentage=round((bucket_counts[1] / total) * 100, 1),
        ),
        RiskBucketSchema(
            label="50-74 (High)",
            min_score=50,
            max_score=74,
            count=bucket_counts[2],
            percentage=round((bucket_counts[2] / total) * 100, 1),
        ),
        RiskBucketSchema(
            label="75-100 (Critical)",
            min_score=75,
            max_score=100,
            count=bucket_counts[3],
            percentage=round((bucket_counts[3] / total) * 100, 1),
        ),
    ]

    daily_trends = [
        TrendPointSchema(period=k, **daily_map[k]) for k in sorted(daily_map.keys())[-14:]
    ]
    weekly_trends = [
        TrendPointSchema(period=k, **weekly_map[k]) for k in sorted(weekly_map.keys())[-12:]
    ]
    top_indicators = [
        IndicatorFrequencySchema(indicator=ind, count=cnt)
        for ind, cnt in indicator_counter.most_common(10)
    ]

    flagged_total = cls_counts["Suspicious"] + cls_counts["Dangerous"]
    avg_conf = (
        round(sum(ml_confidences) / len(ml_confidences), 4) if ml_confidences else None
    )

    return AnalyticsResponse(
        success=True,
        has_data=True,
        total_scans=total,
        url_scans=url_scans,
        message_scans=message_scans,
        message_image_scans=message_image_scans,
        average_risk_score=round(score_sum / total, 1),
        high_risk_rate=round((flagged_total / total) * 100, 1),
        classifications=AnalyticsClassificationsSchema(
            safe=cls_counts["Safe"],
            suspicious=cls_counts["Suspicious"],
            dangerous=cls_counts["Dangerous"],
            no_strong_indicators=cls_counts["No strong indicators detected"],
            inspection_unavailable=cls_counts["Inspection unavailable"],
        ),
        risk_distribution=risk_distribution,
        daily_trends=daily_trends,
        weekly_trends=weekly_trends,
        top_indicators=top_indicators,
        ml_stats=MLStatsSchema(
            recorded_scans=ml_recorded,
            available_scans=ml_available,
            unavailable_scans=ml_unavailable,
            flagged_predictions=ml_flagged,
            average_confidence=avg_conf,
        ),
        threat_intel_stats=ThreatIntelStatsSchema(
            recorded_scans=intel_recorded,
            malicious_matches=intel_matches,
            clean_checks=intel_clean,
            unavailable_checks=intel_unavailable,
        ),
    )

"""Database service layer for saving, querying, and deleting scan history."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from app.db.models import ScanHistory
from app.services.report_service import sanitize_input_for_storage

# Short deduplication window to prevent duplicate records from accidental frontend retries.
RETRY_DEDUP_WINDOW_SECONDS = 5


def save_scan_history(
    db: Session,
    *,
    scan_type: str,
    input_text: str,
    risk_score: int,
    risk_level: str,
    detected_indicators: list[str],
    explanations: list[str],
    recommendations: list[str],
    report_payload: dict[str, Any] | None = None,
) -> ScanHistory:
    """Persist a sanitized scan result, avoiding duplicate records from rapid retries."""
    sanitized_input, _ = sanitize_input_for_storage(scan_type, input_text)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=RETRY_DEDUP_WINDOW_SECONDS)

    latest = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.scan_type == scan_type,
            ScanHistory.input_text == sanitized_input,
            ScanHistory.risk_score == risk_score,
        )
        .order_by(ScanHistory.id.desc())
        .first()
    )

    if latest is not None:
        latest_created = latest.created_at
        if latest_created.tzinfo is None:
            latest_created = latest_created.replace(tzinfo=timezone.utc)
        if latest_created >= cutoff:
            return latest

    record = ScanHistory(
        scan_type=scan_type,
        input_text=sanitized_input,
        risk_score=risk_score,
        risk_level=risk_level,
        detected_indicators=list(detected_indicators),
        explanations=list(explanations),
        recommendations=list(recommendations),
        report_payload=report_payload,
        created_at=now,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_scan_history(
    db: Session,
    *,
    limit: int = 10,
    offset: int = 0,
    scan_type: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str = "date_desc",
) -> tuple[int, list[ScanHistory]]:
    """Return (total_count, records) with optional filtering, search, date range, and sorting."""
    query = db.query(ScanHistory)
    if scan_type:
        query = query.filter(ScanHistory.scan_type == scan_type)
    if risk_level:
        query = query.filter(ScanHistory.risk_level == risk_level)
    if date_from:
        dt_from = date_from if date_from.tzinfo else date_from.replace(tzinfo=timezone.utc)
        query = query.filter(ScanHistory.created_at >= dt_from)
    if date_to:
        dt_to = date_to if date_to.tzinfo else date_to.replace(tzinfo=timezone.utc)
        query = query.filter(ScanHistory.created_at <= dt_to)
    if search and search.strip():
        term = search.strip()
        like_pattern = f"%{term}%"
        if term.isdigit():
            query = query.filter(
                or_(
                    ScanHistory.id == int(term),
                    cast(ScanHistory.id, String).ilike(like_pattern),
                    ScanHistory.input_text.ilike(like_pattern),
                )
            )
        else:
            query = query.filter(
                or_(
                    ScanHistory.input_text.ilike(like_pattern),
                    ScanHistory.risk_level.ilike(like_pattern),
                    cast(ScanHistory.id, String).ilike(like_pattern),
                )
            )

    total = query.with_entities(func.count(ScanHistory.id)).scalar() or 0

    if sort_by == "date_asc":
        order_clauses = (ScanHistory.created_at.asc(), ScanHistory.id.asc())
    elif sort_by == "score_desc":
        order_clauses = (ScanHistory.risk_score.desc(), ScanHistory.id.desc())
    elif sort_by == "score_asc":
        order_clauses = (ScanHistory.risk_score.asc(), ScanHistory.id.asc())
    else:
        order_clauses = (ScanHistory.created_at.desc(), ScanHistory.id.desc())

    items = query.order_by(*order_clauses).offset(offset).limit(limit).all()
    return int(total), items


def get_scan_history_by_id(db: Session, scan_id: int) -> ScanHistory | None:
    """Fetch a single scan history record by ID."""
    return db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()


def delete_scan_history_by_id(db: Session, scan_id: int) -> bool:
    """Delete a single scan history record; return True if deleted, False if not found."""
    record = get_scan_history_by_id(db, scan_id)
    if record is None:
        return False
    db.delete(record)
    db.commit()
    return True


def clear_scan_history(db: Session) -> int:
    """Delete all scan history records and return the number of rows deleted."""
    deleted_count = db.query(ScanHistory).delete()
    db.commit()
    return int(deleted_count)

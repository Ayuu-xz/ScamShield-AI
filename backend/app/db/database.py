"""SQLite database engine, session management, and initialization helpers."""

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


def _build_engine(database_url: str):
    """Create a SQLAlchemy engine with SQLite-safe threading options."""
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, future=True)


engine = _build_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(target_engine=engine) -> None:
    """Create database tables if they do not already exist and apply lightweight migrations."""
    # Import models so metadata is registered before create_all.
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=target_engine)

    inspector = inspect(target_engine)
    if "scan_history" in inspector.get_table_names():
        existing_cols = {col["name"] for col in inspector.get_columns("scan_history")}
        if "report_payload" not in existing_cols:
            with target_engine.begin() as conn:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN report_payload JSON"))


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session and closes it safely."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

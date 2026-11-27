"""Shared pytest fixtures ensuring all tests use an isolated temporary SQLite database."""

from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.database import get_db, init_db
from app.main import app


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path: Path) -> Generator[sessionmaker[Session], None, None]:
    """Override FastAPI's get_db dependency with a fresh per-test SQLite file."""
    db_file = tmp_path / "test_scamshield.db"
    test_engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    init_db(target_engine=test_engine)

    def _override_get_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        test_engine.dispose()

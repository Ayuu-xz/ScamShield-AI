"""FastAPI entrypoint for ScamShield AI."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router as api_router
from app.core.config import settings
from app.db.database import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize SQLite tables on application startup."""
    init_db()
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Phishing Link & Scam Message Checker API (text-only analysis).",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
        """Return a safe generic error response without leaking stack traces."""
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected server error occurred. Please try again later."},
        )

    application.include_router(api_router)
    return application


app = create_app()

"""Pydantic response schema for the health-check endpoint."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health status payload returned by GET /api/health."""

    status: str
    service: str
    version: str
    environment: str
    timestamp: str

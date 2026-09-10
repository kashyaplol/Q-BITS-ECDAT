"""Health and info endpoints.

These are simple "does the API exist and respond" endpoints.
The heavier scan/CBOM/risk endpoints will be added in Phase 5.
"""

from __future__ import annotations

from fastapi import APIRouter

from ..core.config import settings

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check used by load balancers / monitors / the dashboard."""
    return {"status": "healthy", "project": settings.project_name}


@router.get("/info")
async def info() -> dict[str, str]:
    """Return basic metadata about the running service."""
    return {
        "project": settings.project_name,
        "version": settings.version,
        "description": settings.project_description,
    }

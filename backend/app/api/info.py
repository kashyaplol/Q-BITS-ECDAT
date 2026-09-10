"""Info endpoint for the API version 1 namespace."""

from __future__ import annotations

from fastapi import APIRouter

from ..core.config import settings

router = APIRouter(tags=["info"])


@router.get("/info")
async def info() -> dict[str, str]:
    """Return basic metadata about the running service."""
    return {
        "project": settings.project_name,
        "version": settings.version,
        "description": settings.project_description,
    }

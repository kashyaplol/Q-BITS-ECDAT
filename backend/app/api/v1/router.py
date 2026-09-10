"""Compatibility shim for the v1 API package.

The canonical routes live in ``backend.app.api.*``; this package re-exports them
so older imports keep working while the app uses one consistent API surface.
"""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.analysis import router as analysis_router
from backend.app.api.health import router as health_router
from backend.app.api.info import router as info_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router)
api_router.include_router(info_router)
api_router.include_router(analysis_router)
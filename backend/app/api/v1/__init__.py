"""API v1 router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from ..analysis import router as analysis_router
from ..health import router as health_router
from ..info import router as info_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router)
api_router.include_router(info_router)
api_router.include_router(analysis_router)
"""API version 1 aggregation.

All versioned endpoints live under the ``/api/v1`` prefix.

Endpoints:
    GET  /api/v1/health              - health check
    GET  /api/v1/info                - project metadata
    POST /api/v1/scan                - scan + full analysis
    GET  /api/v1/cbom                - CBOM of the most recent scan
    GET  /api/v1/risk                - risk assessments of the latest scan
    GET  /api/v1/dashboard/summary   - headline dashboard numbers
"""

from __future__ import annotations

from fastapi import APIRouter

from .analysis import router as analysis_router
from .health import router as health_router
from .info import router as info_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router)
api_router.include_router(info_router)
api_router.include_router(analysis_router)

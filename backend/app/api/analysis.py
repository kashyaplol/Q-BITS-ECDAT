"""Scanning and analysis API endpoints.

Endpoints:
    POST /api/v1/scan              - scan a directory & run full analysis
    GET  /api/v1/cbom              - CBOM of the most recent scan
    GET  /api/v1/risk              - quantum-risk assessments of latest scan
    GET  /api/v1/risk/summary      - risk roll-up of the latest scan
    POST /api/v1/risk/assess       - assess a single algorithm on the spot
    GET  /api/v1/risk/prioritized  - latest scan assessments + priority scores
    GET  /api/v1/migration/roadmap - organization-level migration roadmap
    POST /api/v1/migration/plan    - build an asset-level migration plan
    GET  /api/v1/dashboard/summary - headline numbers for the dashboard
    POST /api/v1/report            - scan a directory & render the report (text)
    GET  /api/v1/report            - render the report for the latest scan (text)
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from backend.risk import priority_engine, risk_engine, roadmap_engine

from ...app.models import (
    CBOM,
    MigrationPlan,
    OrganizationRoadmap,
    RiskAssessment,
    RiskSummary,
    UsageType,
)
from ...app.services.analysis import analysis_service

router = APIRouter()

# Make the shared singleton accessible to pytest for state reset.
svc = analysis_service


class ScanRequest(BaseModel):
    """Payload for POST /api/v1/scan."""

    path: str = Field(min_length=1, description="Filesystem path of the project to scan")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("path must not be empty or whitespace-only")
        return value


class ScanResponse(BaseModel):
    """Body returned by POST /api/v1/scan (follows the example contract)."""

    scanned_path: str
    scanned_at: str
    files_scanned: int
    crypto_assets_found: int
    algorithm_counts: dict[str, int]
    findings: list[object]
    cbom: object
    risks: object
    summary: object
    prioritized: object | None = None
    roadmap: object | None = None


class AssessRequest(BaseModel):
    """Payload for POST /api/v1/risk/assess and POST /api/v1/migration/plan.

    ``usage`` accepts a ``UsageType`` value or any free-text description
    such as ``"encryption"`` or ``"digital signature"``.
    """

    algorithm: str = Field(description="Algorithm name, e.g. 'RSA' or 'AES-128'")
    key_size: int | None = Field(default=None, description="Key size in bits, if known")
    usage: str | UsageType | None = Field(
        default=None,
        description="Use of the crypto: encryption, key-exchange, signature, hashing, ...",
    )
    file_path: str | None = Field(default=None, description="Where the usage was found")
    line_number: int | None = Field(default=None, description="Line number of the usage")

    model_config = {"json_schema_extra": {"examples": [{"algorithm": "RSA", "key_size": 1024}]}}


@router.post("/scan", response_model=ScanResponse)
async def run_scan(payload: ScanRequest) -> ScanResponse:
    """Scan a directory, generate the CBOM and assess quantum risk."""
    if not os.path.exists(payload.path):
        raise HTTPException(
            status_code=400,
            detail=f"Path does not exist: {payload.path}",
        )
    try:
        result = analysis_service.run_full_analysis(payload.path)
    except OSError as exc:  # permission denied, etc.
        raise HTTPException(status_code=400, detail=f"Cannot scan path: {exc}") from exc

    scan = result["scan"]
    return ScanResponse(
        scanned_path=scan.scanned_path,
        scanned_at=scan.scanned_at.isoformat(),
        files_scanned=scan.files_scanned,
        crypto_assets_found=len(scan.assets),
        algorithm_counts=scan.algorithm_counts,
        findings=[a.model_dump(mode="json") for a in scan.assets],
        cbom=result["cbom"].model_dump(mode="json"),
        risks=[r.model_dump(mode="json") for r in result["risks"]],
        summary=result["summary"],
        prioritized=[
            p.model_dump(mode="json") for p in result["prioritized"]
        ],
        roadmap=result["roadmap"].model_dump(mode="json"),
    )


@router.post("/cbom/generate", response_model=CBOM)
async def generate_cbom(payload: ScanRequest) -> CBOM:
    """Scan a directory and return ONLY the CBOM for it.

    This is a thin alias of ``POST /api/v1/scan`` focused on the
    inventory report: it runs the scanner, generates the CBOM and caches
    it so ``GET /api/v1/cbom`` can return it afterwards.
    """
    if not os.path.exists(payload.path):
        raise HTTPException(
            status_code=400,
            detail=f"Path does not exist: {payload.path}",
        )
    try:
        scan_result = analysis_service.scan(payload.path)
        bom = analysis_service.generate_cbom(scan_result)
    except OSError as exc:  # permission denied, etc.
        raise HTTPException(status_code=400, detail=f"Cannot scan path: {exc}") from exc

    # Cache for the read-only endpoints.
    analysis_service.latest_scan = scan_result
    analysis_service.latest_cbom = bom
    return bom


@router.get("/cbom")
async def get_cbom():
    """Return the CBOM of the most recent scan."""
    if analysis_service.latest_cbom is None:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    return analysis_service.latest_cbom


@router.get("/risk")
async def get_risks():
    """Return quantum-risk assessments for the most recent scan."""
    if not analysis_service.latest_risks:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    return analysis_service.latest_risks


@router.get("/risk/summary", response_model=RiskSummary)
async def get_risk_summary():
    """Return a risk roll-up (counts by level) for the most recent scan."""
    if not analysis_service.latest_risks:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    return analysis_service.risk_summary()


@router.post("/risk/assess", response_model=RiskAssessment)
async def assess_algorithm(payload: AssessRequest):
    """Assess a single algorithm immediately, without a full scan."""
    return risk_engine.assess(
        algorithm=payload.algorithm,
        key_size=payload.key_size,
        usage=payload.usage,
        file_path=payload.file_path,
        line_number=payload.line_number,
    )


@router.get("/risk/prioritized")
async def get_prioritized_risk():
    """Return the latest scan's assessments sorted by priority score.

    Every item embeds the plain ``RiskAssessment`` plus the priority
    score/level, migration urgency and the explainable risk factors.
    """
    prioritized = analysis_service.prioritized_risks()
    if not prioritized:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    ordered = sorted(
        prioritized, key=lambda p: p.priority_score, reverse=True
    )
    return [p.model_dump(mode="json") for p in ordered]


@router.get("/migration/roadmap", response_model=OrganizationRoadmap)
async def get_migration_roadmap():
    """Return the organization-level migration roadmap for the latest scan."""
    roadmap = analysis_service.migration_roadmap()
    if roadmap is None:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    return roadmap


@router.post("/migration/plan", response_model=MigrationPlan)
async def build_migration_plan(payload: AssessRequest):
    """Build an asset-level migration plan for a single algorithm/usage."""
    assessment = risk_engine.assess(
        algorithm=payload.algorithm,
        key_size=payload.key_size,
        usage=payload.usage,
        file_path=payload.file_path,
        line_number=payload.line_number,
    )
    prioritized = priority_engine.prioritize(assessment)
    return roadmap_engine.build_plan(prioritized)


@router.get("/dashboard/summary")
async def get_dashboard_summary(limit: int = 5):
    """Return headline dashboard numbers for the most recent scan.

    ``limit`` (default 5) controls the size of ``top_migration_priorities``.
    """
    if analysis_service.latest_summary is None:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    summary = dict(analysis_service.latest_summary)
    if limit >= 1:
        summary["top_migration_priorities"] = summary[
            "top_migration_priorities"
        ][:limit]
    return summary


@router.post("/report")
async def generate_report(payload: ScanRequest):
    """Scan a directory and return the plain-text Q-BITS-ECDAT report.

    Renders the report for the just-scanned project:
    Project Summary, risk distribution, top migration priorities and the
    PQC readiness status.
    """
    if not os.path.exists(payload.path):
        raise HTTPException(
            status_code=400,
            detail=f"Path does not exist: {payload.path}",
        )
    try:
        analysis_service.run_full_analysis(payload.path)
    except OSError as exc:  # permission denied, etc.
        raise HTTPException(status_code=400, detail=f"Cannot scan path: {exc}") from exc
    return PlainTextResponse(analysis_service.render_report())


@router.get("/report")
async def get_report(top_n: int = 5):
    """Return the plain-text Q-BITS-ECDAT report for the latest scan."""
    if analysis_service.latest_scan is None:
        raise HTTPException(
            status_code=404, detail="No scan has been run yet. POST /api/v1/scan first."
        )
    return PlainTextResponse(analysis_service.render_report(top_n=top_n))

"""Schemas for the local filesystem scan endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from backend.cbom import CBOM
from backend.risk import CBOMRiskReport
from backend.scanners import CryptoFinding


class ScanRequest(BaseModel):
    """Request to scan a repository available on the backend filesystem."""

    path: str = Field(min_length=1, description="Local repository directory to scan.")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Reject blank paths while preserving the caller's path value."""
        if not value.strip():
            raise ValueError("path must not be empty or whitespace-only")
        return value


class ScanResponse(BaseModel):
    """Result returned by the MVP scanner integration."""

    status: str
    files_scanned: int
    finding_count: int
    findings: list[CryptoFinding]
    cbom: CBOM
    risk: CBOMRiskReport
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

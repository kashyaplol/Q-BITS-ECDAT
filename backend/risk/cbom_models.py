"""Serializable output models for deterministic CBOM risk assessment."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
MigrationPriority = Literal["P0", "P1", "P2", "P3"]
QuantumRelevance = Literal["HIGH", "LIMITED", "NOT_ESTABLISHED", "UNKNOWN"]


class CBOMRiskFactors(BaseModel):
    """Only factors supplied by the CBOM, plus explicit unavailable factors."""

    key_sizes: list[int] = Field(default_factory=list)
    detection_confidence: float | None = None
    usage_contexts: list[str] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)


class CBOMRiskResult(BaseModel):
    """One deterministic assessment of a CBOM cryptographic component."""

    identifier: str
    algorithm: str
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    key_sizes: list[int] = Field(default_factory=list)
    quantum_relevance: QuantumRelevance
    migration_priority: MigrationPriority
    recommendation: str
    factors: CBOMRiskFactors


class CBOMRiskReport(BaseModel):
    """A deterministic assessment report for every CBOM component."""

    assets_assessed: int = 0
    assessments: list[CBOMRiskResult] = Field(default_factory=list)
    risk_distribution: dict[RiskLevel, int] = Field(default_factory=dict)
    migration_priority_distribution: dict[MigrationPriority, int] = Field(default_factory=dict)

"""Configurable numerical risk scoring.

A simple, human-readable scoring system is used across the engine:

    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4
    UNKNOWN  = 0

The final score of an algorithm is the **worst** of its classical and
quantum risk dimensions, optionally nudged by configurable weights and a
bonus for deprecated/legacy algorithms. Everything is capped at
``max_score`` so scores stay in a predictable 0-4 range.

Examples (with default config):
    MD5      CRITICAL + HIGH  -> 4
    RSA-1024 HIGH     + CRIT  -> 4
    RSA-2048 MEDIUM   + CRIT  -> 4
    AES-128  LOW      + MED   -> 2
    AES-256  LOW      + LOW   -> 1

The config lives in ``ScoringConfig`` -- tweak one dataclass to change
the behaviour everywhere; no engine code needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.app.models import QuantumRisk, RiskLevel


@dataclass(frozen=True)
class ScoringConfig:
    """Tunable parameters for risk scoring.

    Attributes:
        rank:              Mapping of risk level -> score points.
        deprecated_bonus:  Extra points added for deprecated algorithms.
        max_score:         Upper cap for any score.
    """

    rank: dict[RiskLevel, int] = field(
        default_factory=lambda: {
            RiskLevel.UNKNOWN: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
    )
    deprecated_bonus: int = 0
    max_score: int = 4


class RiskScorer:
    """Stateless scorer that turns risk dimensions into a number."""

    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or ScoringConfig()
        # QuantumRisk reuses the same numeric scale as RiskLevel.
        self._quantum_rank: dict[QuantumRisk, int] = {
            QuantumRisk.UNKNOWN: self.config.rank[RiskLevel.UNKNOWN],
            QuantumRisk.LOW: self.config.rank[RiskLevel.LOW],
            QuantumRisk.MEDIUM: self.config.rank[RiskLevel.MEDIUM],
            QuantumRisk.HIGH: self.config.rank[RiskLevel.HIGH],
            QuantumRisk.CRITICAL: self.config.rank[RiskLevel.CRITICAL],
        }

    def level_score(self, level: RiskLevel) -> int:
        """Score for a single RiskLevel."""
        return self.config.rank.get(level, 0)

    def quantum_score(self, level: QuantumRisk) -> int:
        """Score for a single QuantumRisk."""
        return self._quantum_rank.get(level, 0)

    def compute(
        self,
        classical: RiskLevel,
        quantum: QuantumRisk,
        deprecated: bool = False,
    ) -> int:
        """Final numerical score for an algorithm.

        Score = worst(classical, quantum) + deprecated bonus, capped at
        ``max_score``. Unknown contributes 0 so the worst-known dimension
        still drives the score.
        """
        base = max(self.level_score(classical), self.quantum_score(quantum))
        if deprecated:
            base += self.config.deprecated_bonus
        return max(0, min(base, self.config.max_score))

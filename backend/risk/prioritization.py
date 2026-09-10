"""Q-BITS-ECDAT Risk Prioritization Policy.

This module adds a **priority score** (0-100) on top of the existing 0-4
``RiskAssessment.risk_score``. The two coexist: ``risk_score`` remains the
plain risk dimension, while ``priority_score`` decides *what needs attention
first* -- the ordering used by reports, dashboards and the migration roadmap.

Every point in the score is produced by one of a fixed set of **rules**, and
each rule emits an explainable ``RiskFactor`` back to the caller:

    rule                     contribution            factor name
    -----------------------  ----------------------  -------------------------
    classical-risk           up to 30 pts            Classical Vulnerability
    quantum-risk             up to 30 pts            Quantum Vulnerability
    deprecated               +40 pts                 Algorithm Deprecation
    pqc-requirement          +10 pts                 Quantum Migration Requirement
    weak-key-size            +10 pts                 Weak Key Size
    usage-sensitivity        +8  pts                 Cryptographic Usage
    weak-configuration       +25 pts                 Weak Configuration
    unknown                  0 pts                   Unknown Algorithm

Weights, thresholds and score bands are centralized in
``PrioritizationConfig`` -- tune one dataclass to change the whole system.

IMPORTANT
    The priority score is a **Q-BITS-ECDAT policy-based prioritization aid**.
    It is not an official security standard and does not guarantee a
    security rating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.app.models import (
    MigrationUrgency,
    PriorityAssessment,
    PriorityLevel,
    QuantumRisk,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    UsageType,
)
from backend.risk.knowledge import get_profile, resolve_algorithm

# Standard disclaimer attached to every policy output.
POLICY_NOTE = (
    "Q-BITS-ECDAT Risk Prioritization Policy output. This is a prioritization "
    "aid for the tool and not an official security standard or a guaranteed "
    "security rating."
)

# Score bands: minimum score -> level. Lowest band must start at 0.
_BANDS: tuple[tuple[int, PriorityLevel], ...] = (
    (81, PriorityLevel.IMMEDIATE),
    (61, PriorityLevel.CRITICAL),
    (41, PriorityLevel.HIGH),
    (21, PriorityLevel.MEDIUM),
    (0, PriorityLevel.LOW),
)


@dataclass(frozen=True)
class PrioritizationConfig:
    """Centralized, configurable parameters for the priority policy.

    Attributes:
        classical_weights:    Points per ``RiskLevel`` for the classical rule.
        quantum_weights:      Points per ``QuantumRisk`` for the quantum rule.
        weight_deprecated:    Points for deprecated algorithms.
        weight_pqc_requirement: Points when Shor's breaks the algorithm.
        weight_weak_key_size: Points when a *known* key size is too small.
        weight_usage_sensitive: Points for quantum-sensitive usage.
        weight_weak_configuration: Points for weak configurations (AES-ECB).
        max_score:            Upper cap for the final score (100).
        weak_key_thresholds:  Minimum recommended key size per canonical algo.
        usage_sensitive:      Usages that demand PQC when Shor's-vulnerable.
        top_n:                Default size of top-risk/top-priority lists.
    """

    classical_weights: dict[RiskLevel, int] = field(
        default_factory=lambda: {
            RiskLevel.UNKNOWN: 0,
            RiskLevel.LOW: 5,
            RiskLevel.MEDIUM: 10,
            RiskLevel.HIGH: 15,
            RiskLevel.CRITICAL: 30,
        }
    )
    quantum_weights: dict[QuantumRisk, int] = field(
        default_factory=lambda: {
            QuantumRisk.UNKNOWN: 0,
            QuantumRisk.LOW: 5,
            QuantumRisk.MEDIUM: 12,
            QuantumRisk.HIGH: 18,
            QuantumRisk.CRITICAL: 30,
        }
    )
    weight_deprecated: int = 40
    weight_pqc_requirement: int = 10
    weight_weak_key_size: int = 10
    weight_usage_sensitive: int = 8
    weight_weak_configuration: int = 25
    max_score: int = 100
    weak_key_thresholds: dict[str, int] = field(
        default_factory=lambda: {
            "RSA": 2048,
            "DH": 2048,
            "DSA": 2048,
            "ECC": 224,
            "ECDSA": 224,
            "ECDH": 224,
            "AES": 192,
        }
    )
    usage_sensitive: frozenset[UsageType] = field(
        default_factory=lambda: frozenset(
            {
                UsageType.ENCRYPTION,
                UsageType.DECRYPTION,
                UsageType.KEY_EXCHANGE,
                UsageType.KEY_ESTABLISHMENT,
                UsageType.SIGNATURE,
                UsageType.DIGITAL_SIGNATURE,
                UsageType.SIGNATURE_VERIFICATION,
            }
        )
    )
    top_n: int = 5


class PriorityEngine:
    """Pure, stateless service that applies the prioritization policy."""

    def __init__(self, config: PrioritizationConfig | None = None) -> None:
        self.config = config or PrioritizationConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def level_for(self, score: int) -> PriorityLevel:
        """Map a 0-100 score onto its level band."""
        for lower, level in _BANDS:
            if score >= lower:
                return level
        return PriorityLevel.LOW

    def risk_factors(
        self,
        assessment: RiskAssessment,
        mode: str | None = None,
    ) -> list[RiskFactor]:
        """Generate the rule-derived, explainable factors for an assessment."""
        factors: list[RiskFactor] = []
        canonical, implied = resolve_algorithm(assessment.algorithm)
        profile = get_profile(canonical)
        key_size = assessment.key_size if assessment.key_size is not None else implied
        usage = assessment.usage

        if profile is None:
            factors.append(
                RiskFactor(
                    rule="unknown",
                    factor="Unknown Algorithm",
                    impact="UNKNOWN",
                    reason=(
                        "Algorithm is not present in the current risk knowledge "
                        "base; the score cannot be computed and manual security "
                        "review is required."
                    ),
                    points=0,
                )
            )
            return factors

        # 1. Classical vulnerability ----------------------------------
        classical = assessment.classical_risk
        classical_points = self.config.classical_weights.get(classical, 0)
        if classical != RiskLevel.UNKNOWN:
            reason = (
                f"{assessment.algorithm} has classical risk {classical.value}: "
                f"{profile.reason}"
            )
            factors.append(
                RiskFactor(
                    rule="classical-risk",
                    factor="Classical Vulnerability",
                    impact=classical.value,
                    reason=reason,
                    points=classical_points,
                )
            )

        # 2. Quantum vulnerability ------------------------------------
        quantum = assessment.quantum_risk
        quantum_points = self.config.quantum_weights.get(quantum, 0)
        if quantum != QuantumRisk.UNKNOWN:
            factors.append(
                RiskFactor(
                    rule="quantum-risk",
                    factor="Quantum Vulnerability",
                    impact=quantum.value,
                    reason=(
                        f"{assessment.algorithm} has quantum risk "
                        f"{quantum.value}: {profile.reason}"
                    ),
                    points=quantum_points,
                )
            )

        # 3. Algorithm deprecation ------------------------------------
        if profile.deprecated:
            factors.append(
                RiskFactor(
                    rule="deprecated",
                    factor="Algorithm Deprecation",
                    impact="HIGH",
                    reason=(
                        f"{assessment.algorithm} is deprecated for "
                        "security-sensitive use and must be replaced."
                    ),
                    points=self.config.weight_deprecated,
                )
            )

        # 4. PQC migration requirement (Shor's) -----------------------
        if quantum == QuantumRisk.CRITICAL:
            factors.append(
                RiskFactor(
                    rule="pqc-requirement",
                    factor="Quantum Migration Requirement",
                    impact="CRITICAL",
                    reason=(
                        f"{assessment.algorithm} is vulnerable to Shor's "
                        "algorithm; post-quantum migration is required "
                        "regardless of classical strength."
                    ),
                    points=self.config.weight_pqc_requirement,
                )
            )

        # 5. Weak key size (only when actually known) ------------------
        threshold = self.config.weak_key_thresholds.get(canonical)
        if key_size is not None and threshold and key_size < threshold:
            factors.append(
                RiskFactor(
                    rule="weak-key-size",
                    factor="Weak Key Size",
                    impact="HIGH",
                    reason=(
                        f"{assessment.algorithm} key size {key_size} is below "
                        f"the recommended minimum of {threshold} bits."
                    ),
                    points=self.config.weight_weak_key_size,
                )
            )

        # 6. Cryptographic usage (only when actually detected) ---------
        if usage is not None and usage in self.config.usage_sensitive and quantum.value == "CRITICAL":
            factors.append(
                RiskFactor(
                    rule="usage-sensitivity",
                    factor="Cryptographic Usage",
                    impact="HIGH",
                    reason=(
                        f"{assessment.algorithm} is used for {usage.value}; "
                        "this usage sits on a Shor's-vulnerable algorithm and "
                        "requires a post-quantum replacement."
                    ),
                    points=self.config.weight_usage_sensitive,
                )
            )

        # 7. Weak configuration (only when actually detected) ----------
        if canonical == "AES" and mode and mode.strip().upper() == "ECB":
            factors.append(
                RiskFactor(
                    rule="weak-configuration",
                    factor="Weak Configuration",
                    impact="HIGH",
                    reason=(
                        "AES in ECB mode leaks data patterns; use an "
                        "authenticated mode such as AES-GCM (or CBC with "
                        "proper padding)."
                    ),
                    points=self.config.weight_weak_configuration,
                )
            )

        return factors

    def score(
        self,
        assessment: RiskAssessment,
        mode: str | None = None,
    ) -> int:
        """Compute the 0-100 priority score for an assessment.

        The score is simply the sum of every active factor's points, capped
        at ``max_score`` -- fully explainable.
        """
        total = sum(factor.points for factor in self.risk_factors(assessment, mode))
        return max(0, min(total, self.config.max_score))

    def urgency(
        self,
        assessment: RiskAssessment,
        mode: str | None = None,
    ) -> MigrationUrgency:
        """Map an assessment onto the migration timeline (Phase 5 policy).

        Priority order of rules:
            1. unknown algorithm           -> HIGH (needs review)
            2. deprecated / broken         -> IMMEDIATE
            3. Shor's-vulnerable (quantum) -> URGENT
            4. weak key / weak config      -> HIGH
            5. migration_priority HIGH     -> HIGH
            6. migration_priority MEDIUM   -> PLANNED
            7. strong modern crypto        -> LOW
        """
        canonical, _ = resolve_algorithm(assessment.algorithm)
        profile = get_profile(canonical)
        key_size = assessment.key_size
        threshold = self.config.weak_key_thresholds.get(canonical)

        if profile is None:
            return MigrationUrgency.HIGH
        if profile.deprecated:
            return MigrationUrgency.IMMEDIATE
        if assessment.quantum_risk == QuantumRisk.CRITICAL:
            return MigrationUrgency.URGENT
        if canonical == "AES" and mode and mode.strip().upper() == "ECB":
            return MigrationUrgency.HIGH
        if key_size is not None and threshold and key_size < threshold:
            return MigrationUrgency.HIGH
        if assessment.migration_priority.value in ("HIGH", "CRITICAL"):
            return MigrationUrgency.HIGH
        if assessment.migration_priority.value == "MEDIUM":
            return MigrationUrgency.PLANNED
        if assessment.migration_priority.value == "LOW":
            return MigrationUrgency.LOW
        return MigrationUrgency.PLANNED

    def prioritize(
        self,
        assessment: RiskAssessment,
        mode: str | None = None,
    ) -> PriorityAssessment:
        """Enrich a risk assessment with the full prioritization output."""
        score = self.score(assessment, mode)
        return PriorityAssessment(
            assessment=assessment,
            priority_score=score,
            priority_level=self.level_for(score),
            urgency=self.urgency(assessment, mode),
            risk_factors=self.risk_factors(assessment, mode),
            mode=mode,
        )


# Single shared, stateless instance.
priority_engine = PriorityEngine()

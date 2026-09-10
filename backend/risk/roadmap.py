"""Migration Roadmap Engine.

Builds asset-level migration plans and rolls them up into an
organization-level roadmap:

* ``RoadmapEngine.build_plan(priority)``   -- one ``MigrationPlan`` per asset,
* ``RoadmapEngine.build_roadmap(plans)``   -- one ``OrganizationRoadmap``.

Strategy selection (Phase 4):

    category / state                      strategy
    ------------------------------------  -------------------------------------
    deprecated / broken (MD5, SHA-1,      IMMEDIATE_REPLACEMENT
    DES, 3DES, RC4)
    public key, quantum-vulnerable        PHASED_PQC_MIGRATION
    (RSA, ECC, ECDSA, ECDH, DSA, DH)
    symmetric/hash needing modernization  SECURITY_STRENGTH_UPGRADE
    (AES-128, AES-192, SHA-256)
    strong modern crypto                  NO_MIGRATION_REQUIRED
    (AES-256, SHA-384, SHA-512, SHA-3)
    unknown algorithm                     REVIEW_REQUIRED

Migration phases (Phase 4) are reusable and only the phases that make sense
for the chosen strategy are included: e.g. IMMEDIATE_REPLACEMENT skips the
HYBRID_DEPLOYMENT phase, while PHASED_PQC_MIGRATION includes it.
"""

from __future__ import annotations

from backend.app.models import (
    AlgorithmCategory,
    MigrationPhase,
    MigrationPlan,
    MigrationStatus,
    MigrationStep,
    MigrationStrategy,
    MigrationUrgency,
    OrganizationRoadmap,
    PriorityAssessment,
    PriorityLevel,
    RoadmapPriorityItem,
    TopRiskAsset,
)
from backend.risk.knowledge import get_profile, resolve_algorithm
from backend.risk.prioritization import POLICY_NOTE, PriorityEngine

# Concrete validation actions for the VALIDATION phase.
_VALIDATION_ACTIONS = (
    "Security testing",
    "Regression testing",
    "Compliance review",
    "Monitoring",
)


class RoadmapEngine:
    """Pure service that turns priority assessments into migration plans."""

    def __init__(
        self,
        priority_engine: PriorityEngine | None = None,
        top_n: int | None = None,
    ) -> None:
        self.priority_engine = priority_engine or PriorityEngine()
        self.top_n = top_n or self.priority_engine.config.top_n

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def build_plan(self, priority: PriorityAssessment) -> MigrationPlan:
        """Generate an asset-level migration plan for a priority assessment."""
        assessment = priority.assessment
        canonical, _ = resolve_algorithm(assessment.algorithm)
        profile = get_profile(canonical)

        strategy = self._strategy(priority, profile)
        replacement = self._replacement(priority, profile)
        why = self._why_needed(priority)
        steps = self._steps(
            strategy,
            algorithm=assessment.algorithm,
            replacement=replacement,
        )

        return MigrationPlan(
            algorithm=assessment.algorithm,
            category=assessment.category,
            classical_risk=assessment.classical_risk,
            quantum_risk=assessment.quantum_risk,
            risk_level=assessment.risk_level,
            risk_score=assessment.risk_score,
            key_size=assessment.key_size,
            usage=assessment.usage,
            mode=priority.mode,
            file_path=assessment.file_path,
            line_number=assessment.line_number,
            priority_score=priority.priority_score,
            priority_level=priority.priority_level,
            urgency=priority.urgency,
            migration_status=(
                MigrationStatus.NOT_REQUIRED
                if strategy == MigrationStrategy.NO_MIGRATION_REQUIRED
                else MigrationStatus.NOT_STARTED
            ),
            strategy=strategy,
            why_needed=why,
            recommended_replacement=replacement,
            pqc_recommendation=assessment.pqc_recommendation,
            steps=steps,
            validation_steps=[
                step.description
                for step in steps
                if step.phase == MigrationPhase.VALIDATION
            ],
        )

    def build_roadmap(self, plans: list[MigrationPlan]) -> OrganizationRoadmap:
        """Roll asset plans up into an organization-level roadmap.

        Args:
            plans: Migration plans for every assessed asset.

        Returns:
            An ``OrganizationRoadmap`` with per-urgency counts and the top-N
            plans by priority score, all computed dynamically.
        """
        counts = {
            MigrationUrgency.IMMEDIATE: 0,
            MigrationUrgency.URGENT: 0,
            MigrationUrgency.HIGH: 0,
            MigrationUrgency.PLANNED: 0,
            MigrationUrgency.LOW: 0,
        }
        for plan in plans:
            counts[plan.urgency] = counts.get(plan.urgency, 0) + 1

        sorted_plans = sorted(
            plans, key=lambda plan: plan.priority_score, reverse=True
        )
        top_priorities = [
            RoadmapPriorityItem(
                algorithm=plan.algorithm,
                file_path=plan.file_path,
                line_number=plan.line_number,
                priority_score=plan.priority_score,
                priority_level=plan.priority_level,
                urgency=plan.urgency,
                strategy=plan.strategy,
                recommended_replacement=plan.recommended_replacement,
            )
            for plan in sorted_plans[: self.top_n]
        ]

        return OrganizationRoadmap(
            total_assets=len(plans),
            immediate=counts[MigrationUrgency.IMMEDIATE],
            urgent=counts[MigrationUrgency.URGENT],
            high=counts[MigrationUrgency.HIGH],
            planned=counts[MigrationUrgency.PLANNED],
            low=counts[MigrationUrgency.LOW],
            migration_candidates=len(plans)
            - counts[MigrationUrgency.LOW],
            top_priorities=top_priorities,
            note=POLICY_NOTE,
        )

    @staticmethod
    def top_risk_assets(
        plans: list[MigrationPlan],
        top_n: int = 5,
    ) -> list[TopRiskAsset]:
        """Top ``top_n`` assets by priority score (for the risk summary)."""
        sorted_plans = sorted(
            plans, key=lambda plan: plan.priority_score, reverse=True
        )
        return [
            TopRiskAsset(
                algorithm=plan.algorithm,
                file_path=plan.file_path,
                line_number=plan.line_number,
                priority_score=plan.priority_score,
                priority_level=plan.priority_level,
            )
            for plan in sorted_plans[:top_n]
        ]

    # ------------------------------------------------------------------
    # Strategy / replacement / why / steps
    # ------------------------------------------------------------------
    def _strategy(
        self,
        priority: PriorityAssessment,
        profile,
    ) -> MigrationStrategy:
        assessment = priority.assessment
        if profile is None:
            return MigrationStrategy.REVIEW_REQUIRED
        if profile.deprecated:
            return MigrationStrategy.IMMEDIATE_REPLACEMENT
        if assessment.category == AlgorithmCategory.PUBLIC_KEY:
            return MigrationStrategy.PHASED_PQC_MIGRATION
        if (
            priority.urgency == MigrationUrgency.LOW
            and priority.priority_level in (PriorityLevel.LOW, PriorityLevel.MEDIUM)
        ):
            return MigrationStrategy.NO_MIGRATION_REQUIRED
        return MigrationStrategy.SECURITY_STRENGTH_UPGRADE

    def _replacement(
        self,
        priority: PriorityAssessment,
        profile,
    ) -> str:
        assessment = priority.assessment
        strategy = self._strategy(priority, profile)
        if strategy == MigrationStrategy.NO_MIGRATION_REQUIRED:
            return "None (maintain current implementation)"
        if strategy == MigrationStrategy.REVIEW_REQUIRED:
            return "Manual security review"
        # Preference order: usage-aware PQC text, then the KB recommendation.
        replacement = assessment.pqc_recommendation or profile.pqc_recommendation
        return replacement or "Review required"

    def _why_needed(self, priority: PriorityAssessment) -> str:
        """Derive the migration justification from the active risk factors."""
        reasons: list[str] = []
        for factor in priority.risk_factors:
            if factor.rule == "deprecated":
                reasons.append("Algorithm is deprecated for security-sensitive use")
            elif factor.rule == "pqc-requirement":
                reasons.append("Vulnerable to Shor's algorithm on quantum computers")
            elif factor.rule == "weak-configuration":
                reasons.append("ECB mode leaks data patterns")
            elif factor.rule == "weak-key-size":
                reasons.append("Key size is below the recommended minimum")
            elif factor.rule == "classical-risk" and factor.impact in ("HIGH", "CRITICAL"):
                reasons.append(f"Classical risk is {factor.impact}")
            elif factor.rule == "unknown":
                reasons.append("Algorithm requires manual security review")
        if not reasons:
            reasons.append("Long-term cryptographic modernization recommended")
        return "; ".join(reasons[:3])

    @staticmethod
    def _steps(
        strategy: MigrationStrategy,
        algorithm: str,
        replacement: str,
    ) -> list[MigrationStep]:
        """Produce the ordered migration steps for a strategy."""
        steps: list[MigrationStep] = []

        if strategy in (
            MigrationStrategy.IMMEDIATE_REPLACEMENT,
            MigrationStrategy.PHASED_PQC_MIGRATION,
            MigrationStrategy.SECURITY_STRENGTH_UPGRADE,
        ):
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.DISCOVERY,
                    description=(
                        f"Identify all usages of {algorithm}, its dependencies "
                        "and the affected systems."
                    ),
                )
            )
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.ASSESSMENT,
                    description=(
                        "Analyze risk and compatibility; identify migration "
                        "blockers."
                    ),
                )
            )
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.PREPARATION,
                    description=(
                        f"Prepare the replacement ({replacement}) and the "
                        "test environment."
                    ),
                )
            )
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.PILOT,
                    description=(
                        "Pilot the migration; validate compatibility and "
                        "measure performance."
                    ),
                )
            )
            if strategy == MigrationStrategy.PHASED_PQC_MIGRATION:
                steps.append(
                    MigrationStep(
                        phase=MigrationPhase.HYBRID_DEPLOYMENT,
                        description=(
                            f"Deploy hybrid mode supporting both {algorithm} "
                            f"and {replacement} where appropriate; validate "
                            "interoperability."
                        ),
                    )
                )
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.FULL_MIGRATION,
                    description=(
                        f"Replace {algorithm} with {replacement}; rotate keys, "
                        "update certificates and remove deprecated usage."
                    ),
                )
            )
        elif strategy == MigrationStrategy.REVIEW_REQUIRED:
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.ASSESSMENT,
                    description=(
                        "Document the algorithm and its usage; obtain a "
                        "security review."
                    ),
                )
            )
        elif strategy == MigrationStrategy.NO_MIGRATION_REQUIRED:
            steps.append(
                MigrationStep(
                    phase=MigrationPhase.VALIDATION,
                    description=(
                        "Maintain the current implementation; re-validate "
                        "periodically against the risk knowledge base."
                    ),
                )
            )

        # Everything except NO_MIGRATION_REQUIRED finishes with validation.
        if strategy != MigrationStrategy.NO_MIGRATION_REQUIRED:
            for action in _VALIDATION_ACTIONS:
                steps.append(
                    MigrationStep(
                        phase=MigrationPhase.VALIDATION,
                        description=action,
                    )
                )
        return steps


# Single shared, stateless instance.
roadmap_engine = RoadmapEngine()

"""Risk summary builder.

Aggregates a list of scanned assets (or assessments) into a single
``RiskSummary`` object that the dashboard / ``GET /api/v1/risk/summary``
endpoint can return directly.

Phase 4 added the prioritization roll-up fields on ``RiskSummary``:

* ``total_priority_score`` / ``average_priority_score``,
* per-urgency counts (``immediate_assets``, ``urgent_assets``,
  ``high_priority_assets``, ``planned_assets``),
* ``migration_candidates`` (any asset with urgency != LOW),
* ``top_risk_assets`` (top-N by priority score).
"""

from __future__ import annotations

from backend.app.models import (
    CryptographicAsset,
    MigrationPriority,
    MigrationUrgency,
    PriorityAssessment,
    RiskAssessment,
    RiskLevel,
    RiskSummary,
    TopRiskAsset,
)
from backend.risk.engine import RiskEngine
from backend.risk.prioritization import priority_engine

# Migration priorities that count as PQC migration candidates.
_PQC_CANDIDATE_PRIORITIES = frozenset(
    {MigrationPriority.HIGH, MigrationPriority.CRITICAL, MigrationPriority.IMMEDIATE}
)

# Default size of the top-risk list.
_TOP_N = 5


def build_risk_summary(
    assets: list[CryptographicAsset],
    engine: RiskEngine,
) -> RiskSummary:
    """Count scanned assets by their overall risk and migration priority.

    Args:
        assets:  The raw cryptographic assets from a scan.
        engine:  A RiskEngine used to assess every asset.

    Returns:
        A ``RiskSummary`` with totals, per-level counts, per-urgency counts
        and the top-risk assets by priority score.
    """
    prioritized = [
        priority_engine.prioritize(engine.assess(asset), mode=asset.mode)
        for asset in assets
    ]
    return _build_from_prioritized(prioritized)


def summarize_assessments(assessments: list[RiskAssessment]) -> RiskSummary:
    """Build a RiskSummary from already-computed assessments.

    Useful for tests and callers that already hold assessments. Because the
    original asset objects are not available here, the weak-configuration
    rule (which needs the cipher mode) does not apply -- call
    ``build_risk_summary`` instead when asset metadata is available.
    """
    prioritized = [
        priority_engine.prioritize(assessment) for assessment in assessments
    ]
    return _build_from_prioritized(prioritized)


# ---------------------------------------------------------------------------
# Shared aggregation
# ---------------------------------------------------------------------------
def _build_from_prioritized(prioritized: list[PriorityAssessment]) -> RiskSummary:
    counts: dict[RiskLevel, int] = {}
    immediate = 0
    pqc_candidates = 0

    priority_counts = {
        MigrationUrgency.IMMEDIATE: 0,
        MigrationUrgency.URGENT: 0,
        MigrationUrgency.HIGH: 0,
        MigrationUrgency.PLANNED: 0,
        MigrationUrgency.LOW: 0,
    }

    for priority in prioritized:
        assessment = priority.assessment
        counts[assessment.overall_risk] = counts.get(assessment.overall_risk, 0) + 1
        if assessment.migration_priority == MigrationPriority.IMMEDIATE:
            immediate += 1
        if assessment.migration_priority in _PQC_CANDIDATE_PRIORITIES:
            pqc_candidates += 1
        priority_counts[priority.urgency] = (
            priority_counts.get(priority.urgency, 0) + 1
        )

    n = len(prioritized)
    total_score = sum(priority.priority_score for priority in prioritized)
    average = round(total_score / n, 1) if n else 0.0

    top = sorted(
        prioritized, key=lambda p: p.priority_score, reverse=True
    )[:_TOP_N]
    top_risk_assets = [
        TopRiskAsset(
            algorithm=priority.assessment.algorithm,
            file_path=priority.assessment.file_path,
            line_number=priority.assessment.line_number,
            priority_score=priority.priority_score,
            priority_level=priority.priority_level,
        )
        for priority in top
    ]

    return RiskSummary(
        total_assets=n,
        critical_risk_assets=counts.get(RiskLevel.CRITICAL, 0),
        high_risk_assets=counts.get(RiskLevel.HIGH, 0),
        medium_risk_assets=counts.get(RiskLevel.MEDIUM, 0),
        low_risk_assets=counts.get(RiskLevel.LOW, 0),
        unknown_risk_assets=counts.get(RiskLevel.UNKNOWN, 0),
        immediate_migrations_required=immediate,
        pqc_migration_candidates=pqc_candidates,
        total_priority_score=total_score,
        average_priority_score=average,
        immediate_assets=priority_counts[MigrationUrgency.IMMEDIATE],
        urgent_assets=priority_counts[MigrationUrgency.URGENT],
        high_priority_assets=priority_counts[MigrationUrgency.HIGH],
        planned_assets=priority_counts[MigrationUrgency.PLANNED],
        migration_candidates=n - priority_counts[MigrationUrgency.LOW],
        top_risk_assets=top_risk_assets,
    )

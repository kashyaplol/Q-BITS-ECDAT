"""Plain-text Q-BITS-ECDAT report rendering.

Turns a full analysis into the human-readable report format shown in the
project brief::

    Q-BITS-ECDAT REPORT

    Project Summary
    ──────────────────

    Files Scanned: 12
    ...
    TOP MIGRATION PRIORITIES
    ...
    PQC READINESS
    ...

The renderer is pure: it takes already-computed data (scan / CBOM / risk
summary / roadmap priorities) and formats it, so it never runs its own
analysis.
"""

from __future__ import annotations

from backend.app.models import (
    CBOM,
    MigrationStrategy,
    RiskLevel,
    RiskSummary,
    RoadmapPriorityItem,
    ScanResult,
)

_SEPARATOR = "─" * 18
_DEFAULT_TOP_N = 5


def _short_replacement(replacement: str) -> str:
    """Trim a replacement label to its scheme names.

    ``"ML-KEM or ML-DSA (FIPS 203 / 204)"`` -> ``"ML-KEM / ML-DSA"``.
    """
    if not replacement:
        return "A PQC algorithm"
    head = replacement.split("(", 1)[0].strip()
    return head.replace(" or ", " / ")


def _action(strategy: MigrationStrategy, replacement: str) -> str:
    """Render the one-line action for a roadmap priority item."""
    actions = {
        MigrationStrategy.IMMEDIATE_REPLACEMENT: "Replace Immediately",
        MigrationStrategy.PHASED_PQC_MIGRATION: f"Migrate to {_short_replacement(replacement)}",
        MigrationStrategy.SECURITY_STRENGTH_UPGRADE: f"Upgrade to {_short_replacement(replacement)}",
        MigrationStrategy.NO_MIGRATION_REQUIRED: "No Action Required",
        MigrationStrategy.REVIEW_REQUIRED: "Manual Review Required",
    }
    return actions.get(strategy, "Manual Review Required")


def _status(migration_candidates: int) -> str:
    return "NEEDS MODERNIZATION" if migration_candidates > 0 else "READY"


def _risk_line(level: RiskLevel, count: int) -> str:
    return f"{level.value}: {count}"


def render_report(
    *,
    scan: ScanResult,
    cbom: CBOM,
    risk_summary: RiskSummary,
    top_priorities: list[RoadmapPriorityItem],
    top_n: int = _DEFAULT_TOP_N,
) -> str:
    """Render the Q-BITS-ECDAT report from already-computed results."""
    lines: list[str] = []
    lines.append("Q-BITS-ECDAT REPORT")
    lines.append("")
    lines.append("Project Summary")
    lines.append(_SEPARATOR)
    lines.append("")
    lines.append(f"Files Scanned: {scan.files_scanned}")
    lines.append(f"Crypto Findings: {len(scan.assets)}")
    lines.append(f"CBOM Assets: {cbom.total_assets}")
    lines.append("")
    lines.append("Risk Distribution:")
    lines.append("")
    lines.append(_risk_line(RiskLevel.CRITICAL, risk_summary.critical_risk_assets))
    lines.append(_risk_line(RiskLevel.HIGH, risk_summary.high_risk_assets))
    lines.append(_risk_line(RiskLevel.MEDIUM, risk_summary.medium_risk_assets))
    lines.append(_risk_line(RiskLevel.LOW, risk_summary.low_risk_assets))
    lines.append("")
    lines.append(_SEPARATOR)
    lines.append("")
    lines.append("TOP MIGRATION PRIORITIES")
    lines.append("")
    priorities = top_priorities[:top_n]
    if not priorities:
        lines.append("No migration priorities identified.")
    else:
        for index, item in enumerate(priorities, start=1):
            lines.append(f"{index}. {item.algorithm}")
            lines.append(f"   Score: {item.priority_score}")
            lines.append(f"   Action: {_action(item.strategy, item.recommended_replacement)}")
            if index < len(priorities):
                lines.append("")
    lines.append("")
    lines.append(_SEPARATOR)
    lines.append("")
    lines.append("PQC READINESS")
    lines.append("")
    lines.append(f"Migration Candidates: {risk_summary.migration_candidates}")
    lines.append("")
    lines.append("Status:")
    lines.append("")
    lines.append(_status(risk_summary.migration_candidates))
    return "\n".join(lines) + "\n"

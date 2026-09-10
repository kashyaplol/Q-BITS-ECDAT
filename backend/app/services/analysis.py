"""Service layer for the ECDAT application.

Services are the orchestration layer between the API and the domain
modules (scanners, CBOM, risk). Keeping this logic out of the API
routers keeps them thin and makes the workflow easy to unit-test::

    from backend.app.services.analysis import AnalysisService

    service = AnalysisService()
    scan = service.scan("data/sample")
"""

from __future__ import annotations

from backend.app.models import (
    CBOM,
    MigrationPriority,
    OrganizationRoadmap,
    PriorityAssessment,
    RiskAssessment,
    RiskSummary,
    ScanResult,
)
from backend.cbom import CBOMGenerator
from backend.report import render_report
from backend.risk import (
    build_risk_summary,
    priority_engine,
    risk_engine,
    roadmap_engine,
)
from backend.scanners.source import SourceCodeScanner


class AnalysisService:
    """Coordinates scanning, CBOM generation and risk assessment.

    The service also remembers the *latest* full analysis so the read-only
    endpoints (``GET /api/v1/cbom``, ...) can return data about the most
    recent scan. In a production deployment you would replace this
    in-memory state with a real database.
    """

    def __init__(self, project: str = "Q-BITS-ECDAT") -> None:
        self.project = project
        self.scanner = SourceCodeScanner()
        self.cbom_generator = CBOMGenerator(project=project)
        self.risk_engine = risk_engine
        self.priority_engine = priority_engine
        self.roadmap_engine = roadmap_engine

        # Latest analysis results (None until the first scan happens).
        self.latest_scan: ScanResult | None = None
        self.latest_cbom: CBOM | None = None
        self.latest_risks: list[RiskAssessment] = []
        self.latest_prioritized: list[PriorityAssessment] = []
        self.latest_plans: list = []
        self.latest_roadmap: OrganizationRoadmap | None = None
        self.latest_summary: dict | None = None

    # -- Single helpers, used independently by the API ---------------------
    def scan(self, path: str) -> ScanResult:
        """Scan a directory and return the raw ScanResult."""
        return self.scanner.scan_directory(path)

    def generate_cbom(self, scan_result: ScanResult) -> CBOM:
        """Build a CBOM from a ScanResult."""
        return self.cbom_generator.generate(scan_result)

    def assess_risks(self, scan_result: ScanResult) -> list[RiskAssessment]:
        """Return one risk assessment per unique algorithm in the scan."""
        algorithms = {asset.algorithm.value for asset in scan_result.assets}
        return self.risk_engine.assess_many(sorted(algorithms))

    def prioritize_assets(self, scan_result: ScanResult) -> list[PriorityAssessment]:
        """Enrich every scanned asset with the prioritization policy output."""
        return [
            self.priority_engine.prioritize(
                self.risk_engine.assess(asset),
                mode=asset.mode,
            )
            for asset in scan_result.assets
        ]

    def build_migration_plans(
        self, prioritized: list[PriorityAssessment]
    ) -> list:
        """Generate one asset-level migration plan per priority assessment."""
        return [
            self.roadmap_engine.build_plan(priority) for priority in prioritized
        ]

    # -- The full pipeline, used by POST /api/v1/scan ----------------------
    def run_full_analysis(self, path: str) -> dict:
        """Scan path, build CBOM, assess risks -- and remember the results."""
        scan_result = self.scan(path)
        cbom = self.generate_cbom(scan_result)
        risks = self.assess_risks(scan_result)
        prioritized = self.prioritize_assets(scan_result)
        plans = self.build_migration_plans(prioritized)
        roadmap = self.roadmap_engine.build_roadmap(plans)
        summary = self.dashboard_summary(
            scan_result, cbom, prioritized=prioritized, plans=plans
        )

        # Cache the latest results for the read-only endpoints.
        self.latest_scan = scan_result
        self.latest_cbom = cbom
        self.latest_risks = risks
        self.latest_prioritized = prioritized
        self.latest_plans = plans
        self.latest_roadmap = roadmap
        self.latest_summary = summary

        return {
            "scan": scan_result,
            "cbom": cbom,
            "risks": risks,
            "prioritized": prioritized,
            "plans": plans,
            "roadmap": roadmap,
            "summary": summary,
        }

    def dashboard_summary(
        self,
        scan_result: ScanResult,
        cbom: CBOM,
        prioritized: list[PriorityAssessment] | None = None,
        plans: list | None = None,
    ) -> dict:
        """Aggregate the key numbers shown on the dashboard."""
        high_risk_assets = cbom.high_risk_assets

        # Count occurrences whose algorithm has a CRITICAL or IMMEDIATE
        # migration priority (RSA, ECC, DSA, DH, MD5, SHA1, DES, 3DES, RC4, ...).
        critical_migrations = 0
        urgent_priorities = {MigrationPriority.CRITICAL, MigrationPriority.IMMEDIATE}
        for entry in cbom.cryptographic_assets:
            assessment = self.risk_engine.assess(entry.algorithm)
            if assessment.migration_priority in urgent_priorities:
                critical_migrations += entry.occurrences

        # Priority distribution across every scanned finding.
        priority_distribution: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "IMMEDIATE": 0}
        if prioritized is None:
            prioritized = self.prioritize_assets(scan_result)
        for priority in prioritized:
            level = priority.priority_level.value
            priority_distribution[level] = priority_distribution.get(level, 0) + 1

        # Top migration priorities (algorithm / file / line / score / level /
        # strategy / recommended replacement).
        top_migration_priorities: list[dict] = []
        if plans is None:
            plans = self.build_migration_plans(prioritized)
        for plan in sorted(plans, key=lambda p: p.priority_score, reverse=True)[
            : self.roadmap_engine.top_n
        ]:
            top_migration_priorities.append(
                {
                    "algorithm": plan.algorithm,
                    "file_path": plan.file_path,
                    "line_number": plan.line_number,
                    "priority_score": plan.priority_score,
                    "priority_level": plan.priority_level.value,
                    "migration_strategy": plan.strategy.value,
                    "recommended_algorithm": plan.recommended_replacement,
                }
            )

        return {
            "total_files_scanned": scan_result.files_scanned,
            "crypto_assets_found": len(scan_result.assets),
            "high_risk_assets": high_risk_assets,
            "critical_migrations": critical_migrations,
            "priority_distribution": priority_distribution,
            "top_migration_priorities": top_migration_priorities,
        }

    def risk_summary(self) -> RiskSummary:
        """Roll-up of the latest scan's risk levels by category."""
        if self.latest_scan is None:
            return RiskSummary()
        return build_risk_summary(self.latest_scan.assets, self.risk_engine)

    def prioritized_risks(self) -> list[PriorityAssessment]:
        """Priority-enriched assessments of the latest scan."""
        return self.latest_prioritized

    def migration_roadmap(self) -> OrganizationRoadmap | None:
        """Organization-level roadmap of the latest scan."""
        return self.latest_roadmap

    def render_report(self, *, top_n: int = 5) -> str:
        """Render the plain-text Q-BITS-ECDAT report for the latest scan.

        Returns an empty string when no scan has been run yet.
        """
        if self.latest_scan is None or self.latest_cbom is None:
            return ""
        return render_report(
            scan=self.latest_scan,
            cbom=self.latest_cbom,
            risk_summary=self.risk_summary(),
            top_priorities=(
                self.latest_roadmap.top_priorities
                if self.latest_roadmap is not None
                else []
            ),
            top_n=top_n,
        )


# Ready-to-use shared instance.
analysis_service = AnalysisService()

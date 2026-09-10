"""Tests for the Q-BITS-ECDAT plain-text report renderer + report API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models import (
    CBOM,
    MigrationStrategy,
    MigrationUrgency,
    PriorityLevel,
    RiskSummary,
    RoadmapPriorityItem,
    ScanResult,
)
from backend.app.services.analysis import analysis_service
from backend.report import render_report
from backend.risk import build_risk_summary, priority_engine, risk_engine, roadmap_engine

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_service_state():
    """Make sure each test starts with a clean service state."""
    analysis_service.latest_scan = None
    analysis_service.latest_cbom = None
    analysis_service.latest_risks = []
    analysis_service.latest_prioritized = []
    analysis_service.latest_plans = []
    analysis_service.latest_roadmap = None
    analysis_service.latest_summary = None
    yield


def _entry(
    algorithm: str,
    score: int,
    *,
    strategy: MigrationStrategy,
    replacement: str,
) -> RoadmapPriorityItem:
    return RoadmapPriorityItem(
        algorithm=algorithm,
        priority_score=score,
        priority_level=PriorityLevel.IMMEDIATE
        if score >= 81
        else PriorityLevel.MEDIUM,
        urgency=MigrationUrgency.IMMEDIATE,
        strategy=strategy,
        recommended_replacement=replacement,
    )


# ---------------------------------------------------------------------------
# Renderer (pure formatting)
# ---------------------------------------------------------------------------
class TestReportRenderer:
    def test_full_pipeline_sample(self) -> None:
        from backend.app.services.analysis import AnalysisService

        result = AnalysisService().run_full_analysis("data/sample")
        text = render_report(
            scan=result["scan"],
            cbom=result["cbom"],
            risk_summary=build_risk_summary(
                result["scan"].assets, risk_engine
            ),
            top_priorities=result["roadmap"].top_priorities,
        )
        assert "Q-BITS-ECDAT REPORT" in text
        assert "Files Scanned: 12" in text
        assert "Crypto Findings: 95" in text
        assert "CBOM Assets: 59" in text
        assert "CRITICAL: 61" in text
        assert "1. MD5" in text
        assert "   Score: 88" in text
        assert "   Action: Replace Immediately" in text
        assert "Migration Candidates: 88" in text
        assert "NEEDS MODERNIZATION" in text

    def test_action_mapping_rsa_signature(self) -> None:
        assessment = risk_engine.assess(
            algorithm="RSA", key_size=1024, usage="digital signature"
        )
        priority = priority_engine.prioritize(assessment)
        plan = roadmap_engine.build_plan(priority)
        text = render_report(
            scan=ScanResult(scanned_path="x"),
            cbom=CBOM(),
            risk_summary=RiskSummary(
                critical_risk_assets=1, migration_candidates=1
            ),
            top_priorities=[
                _entry(
                    "RSA-1024",
                    priority.priority_score,
                    strategy=plan.strategy,
                    replacement=plan.recommended_replacement,
                )
            ],
        )
        assert "1. RSA-1024" in text
        assert "   Action: Migrate to ML-DSA" in text
        assert "NEEDS MODERNIZATION" in text

    def test_ready_status_when_no_candidates(self) -> None:
        text = render_report(
            scan=ScanResult(scanned_path="x"),
            cbom=CBOM(total_assets=2),
            risk_summary=RiskSummary(migration_candidates=0),
            top_priorities=[],
        )
        assert "Migration Candidates: 0" in text
        assert "Status:" in text
        assert "READY" in text
        assert "NEEDS MODERNIZATION" not in text

    def test_empty_analysis(self) -> None:
        text = render_report(
            scan=ScanResult(scanned_path="x"),
            cbom=CBOM(),
            risk_summary=RiskSummary(),
            top_priorities=[],
        )
        assert "Files Scanned: 0" in text
        assert "Crypto Findings: 0" in text
        assert "No migration priorities identified." in text
        assert "READY" in text

    def test_top_n_limits_priorities(self) -> None:
        priorities = [
            _entry(
                f"ALG-{index}",
                90,
                strategy=MigrationStrategy.IMMEDIATE_REPLACEMENT,
                replacement="",
            )
            for index in range(5)
        ]
        text = render_report(
            scan=ScanResult(scanned_path="x"),
            cbom=CBOM(),
            risk_summary=RiskSummary(migration_candidates=5),
            top_priorities=priorities,
            top_n=2,
        )
        assert "1. ALG-0" in text
        assert "2. ALG-1" in text
        assert "3. ALG-2" not in text

    def test_long_scheme_names_are_trimmed(self) -> None:
        text = render_report(
            scan=ScanResult(scanned_path="x"),
            cbom=CBOM(),
            risk_summary=RiskSummary(migration_candidates=1),
            top_priorities=[
                _entry(
                    "RSA-2048",
                    50,
                    strategy=MigrationStrategy.PHASED_PQC_MIGRATION,
                    replacement="ML-KEM or ML-DSA (FIPS 203 / 204)",
                )
            ],
        )
        assert "Migrate to ML-KEM / ML-DSA" in text
        assert "(FIPS" not in text


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
class TestReportAPI:
    def test_post_report_returns_text(self, tmp_path) -> None:
        (tmp_path / "app.py").write_text(
            "import hashlib\nhashlib.md5(b'data')\n", encoding="utf-8"
        )
        response = client.post("/api/v1/report", json={"path": str(tmp_path)})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "Q-BITS-ECDAT REPORT" in response.text
        assert "MD5" in response.text
        assert "NEEDS MODERNIZATION" in response.text

    def test_post_report_validates_missing_path(self) -> None:
        response = client.post("/api/v1/report", json={"path": "C:/not/here"})
        assert response.status_code == 400

    def test_get_report_requires_scan_first(self) -> None:
        response = client.get("/api/v1/report")
        assert response.status_code == 404
        assert "No scan" in response.json()["detail"]

    def test_get_report_after_scan(self, tmp_path) -> None:
        (tmp_path / "app.py").write_text(
            "import hashlib\nhashlib.sha256(b'data')\n", encoding="utf-8"
        )
        scan = client.post("/api/v1/scan", json={"path": str(tmp_path)})
        assert scan.status_code == 200
        response = client.get("/api/v1/report")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "Q-BITS-ECDAT REPORT" in response.text

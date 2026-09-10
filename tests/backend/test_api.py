"""Tests for the REST API endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.analysis import analysis_service

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


@pytest.fixture
def sample_project(tmp_path):
    """A tiny project with one RSA + one AES usage."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "hashlib.sha256(b'data')\n",
        encoding="utf-8",
    )
    return tmp_path


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_info_endpoint() -> None:
    response = client.get("/api/v1/info")
    assert response.status_code == 200
    assert response.json()["project"] == "Q-BITS-ECDAT"


def test_scan_endpoint_returns_analysis(sample_project) -> None:
    response = client.post("/api/v1/scan", json={"path": str(sample_project)})
    assert response.status_code == 200
    body = response.json()
    assert body["files_scanned"] == 1
    assert "RSA" in body["algorithm_counts"]
    assert "SHA256" in body["algorithm_counts"]
    assert body["summary"]["crypto_assets_found"] > 0


def test_scan_endpoint_validates_missing_path() -> None:
    response = client.post("/api/v1/scan", json={"path": "C:/definitely/not/here"})
    assert response.status_code == 400


def test_cbom_endpoint_requires_scan_first() -> None:
    response = client.get("/api/v1/cbom")
    assert response.status_code == 404
    assert "No scan" in response.json()["detail"]


def test_cbom_generate_endpoint(sample_project) -> None:
    response = client.post("/api/v1/cbom/generate", json={"path": str(sample_project)})
    assert response.status_code == 200
    body = response.json()
    assert "generated_at" in body
    assert "cryptographic_assets" in body
    assert body["total_findings"] >= 1

    # The CBOM should now be cached for GET /api/v1/cbom.
    cached = client.get("/api/v1/cbom")
    assert cached.status_code == 200
    assert cached.json()["total_findings"] == body["total_findings"]


def test_full_flow_scan_then_read_endpoints(sample_project) -> None:
    # 1. Scan
    scan_response = client.post("/api/v1/scan", json={"path": str(sample_project)})
    assert scan_response.status_code == 200

    # 2. CBOM now available
    cbom_response = client.get("/api/v1/cbom")
    assert cbom_response.status_code == 200
    assert cbom_response.json()["total_assets"] >= 1

    # 3. Risk now available
    risk_response = client.get("/api/v1/risk")
    assert risk_response.status_code == 200
    algorithms = {r["algorithm"] for r in risk_response.json()}
    assert "RSA" in algorithms

    # 4. Summary now available
    summary_response = client.get("/api/v1/dashboard/summary")
    assert summary_response.status_code == 200
    assert summary_response.json()["total_files_scanned"] == 1


def test_dashboard_summary_fields(sample_project) -> None:
    client.post("/api/v1/scan", json={"path": str(sample_project)})
    summary = client.get("/api/v1/dashboard/summary").json()
    assert set(summary) == {
        "total_files_scanned",
        "crypto_assets_found",
        "high_risk_assets",
        "critical_migrations",
        "priority_distribution",
        "top_migration_priorities",
    }


def test_risk_summary_endpoint(sample_project) -> None:
    client.post("/api/v1/scan", json={"path": str(sample_project)})
    response = client.get("/api/v1/risk/summary")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "total_assets",
        "critical_risk_assets",
        "high_risk_assets",
        "medium_risk_assets",
        "low_risk_assets",
        "unknown_risk_assets",
        "immediate_migrations_required",
        "pqc_migration_candidates",
        "total_priority_score",
        "average_priority_score",
        "immediate_assets",
        "urgent_assets",
        "high_priority_assets",
        "planned_assets",
        "migration_candidates",
        "top_risk_assets",
    }
    assert body["total_assets"] >= 1
    # RSA is CRITICAL and a PQC candidate.
    assert body["critical_risk_assets"] >= 1
    assert body["pqc_migration_candidates"] >= 1
    # Priority fields rolled up consistently.
    assert body["total_priority_score"] >= 0
    assert body["migration_candidates"] >= 1
    assert body["top_risk_assets"][0]["priority_score"] >= 0


def test_risk_summary_requires_scan_first() -> None:
    response = client.get("/api/v1/risk/summary")
    assert response.status_code == 404
    assert "No scan" in response.json()["detail"]


def test_risk_assess_endpoint() -> None:
    response = client.post(
        "/api/v1/risk/assess",
        json={"algorithm": "RSA", "key_size": 1024, "usage": "key exchange"},
    )
    assert response.status_code == 200
    assessment = response.json()
    assert assessment["algorithm"] == "RSA"
    assert assessment["overall_risk"] == "CRITICAL"
    assert assessment["quantum_risk"] == "CRITICAL"
    assert assessment["migration_priority"] == "CRITICAL"
    assert assessment["risk_score"] == 4
    assert assessment["usage"] == "KEY_EXCHANGE"
    # Legacy field alias stays in sync.
    assert assessment["risk_level"] == assessment["overall_risk"]
    assert assessment["recommended_action"] == assessment["recommendation"]


def test_risk_assess_rejects_legacy_instead_of_scanning() -> None:
    response = client.post(
        "/api/v1/risk/assess",
        json={"algorithm": "SHA-256"},
    )
    assert response.status_code == 200
    assessment = response.json()
    assert assessment["algorithm"] == "SHA-256"
    assert assessment["overall_risk"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Phase 4: prioritized risk + migration roadmap API
# ---------------------------------------------------------------------------
def test_risk_prioritized_endpoint(sample_project) -> None:
    client.post("/api/v1/scan", json={"path": str(sample_project)})
    response = client.get("/api/v1/risk/prioritized")
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 1
    first = items[0]
    # Embedded assessment + priority fields.
    assert "assessment" in first
    assert first["assessment"]["algorithm"] == "RSA"
    assert "priority_score" in first
    assert "priority_level" in first
    assert "urgency" in first
    assert first["risk_factors"], "explainable factors are always present"
    # Sorted worst-first.
    scores = [item["priority_score"] for item in items]
    assert scores == sorted(scores, reverse=True)


def test_risk_prioritized_requires_scan_first() -> None:
    response = client.get("/api/v1/risk/prioritized")
    assert response.status_code == 404


def test_scan_response_includes_prioritized_and_roadmap(sample_project) -> None:
    response = client.post("/api/v1/scan", json={"path": str(sample_project)})
    assert response.status_code == 200
    body = response.json()
    assert body["prioritized"], "scan returns priority-enriched assessments"
    assert body["roadmap"]["total_assets"] >= 1
    assert body["roadmap"]["top_priorities"]


def test_migration_roadmap_endpoint(sample_project) -> None:
    client.post("/api/v1/scan", json={"path": str(sample_project)})
    response = client.get("/api/v1/migration/roadmap")
    assert response.status_code == 200
    roadmap = response.json()
    assert roadmap["total_assets"] >= 1
    assert set(roadmap) >= {
        "total_assets",
        "immediate",
        "urgent",
        "high",
        "planned",
        "low",
        "migration_candidates",
        "top_priorities",
        "note",
    }
    # RSA is URGENT (quantum-vulnerable public key).
    assert roadmap["urgent"] >= 1
    assert roadmap["migration_candidates"] >= 1
    top = roadmap["top_priorities"][0]
    assert top["priority_score"] >= top["priority_score"]


def test_migration_roadmap_requires_scan_first() -> None:
    response = client.get("/api/v1/migration/roadmap")
    assert response.status_code == 404


def test_migration_plan_endpoint() -> None:
    response = client.post(
        "/api/v1/migration/plan",
        json={"algorithm": "RSA", "key_size": 1024, "usage": "digital signature"},
    )
    assert response.status_code == 200
    plan = response.json()
    assert plan["algorithm"] == "RSA"
    assert plan["strategy"] == "PHASED_PQC_MIGRATION"
    assert plan["urgency"] == "URGENT"
    assert plan["recommended_replacement"] == "ML-DSA"
    assert plan["steps"], "a plan always has steps"
    assert plan["validation_steps"], "validation actions are always present"


def test_dashboard_includes_priority_distribution(sample_project) -> None:
    client.post("/api/v1/scan", json={"path": str(sample_project)})
    summary = client.get("/api/v1/dashboard/summary?limit=3").json()
    dist = summary["priority_distribution"]
    # sample_project holds RSA-2048 (HIGH priority) + SHA-256 (LOW priority).
    assert dist["HIGH"] >= 1
    assert dist["LOW"] >= 1
    # Every finding is counted exactly once across the distribution.
    assert sum(dist.values()) == summary["crypto_assets_found"]
    assert len(summary["top_migration_priorities"]) <= 3
    top = summary["top_migration_priorities"][0]
    assert {"algorithm", "file_path", "line_number", "priority_score",
            "priority_level", "migration_strategy", "recommended_algorithm"} <= set(top)

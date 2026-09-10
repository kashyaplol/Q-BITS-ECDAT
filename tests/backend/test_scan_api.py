from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.api.scan import get_scan_service
from backend.app.main import app
from backend.app.schemas.scan import ScanResponse

client = TestClient(app)
DEMO_TARGET = Path(__file__).parents[2] / "data" / "sample" / "demo-target"


def test_api_health() -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scan_demo_target_returns_actual_findings() -> None:
    response = client.post("/api/scan", json={"path": str(DEMO_TARGET)})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["files_scanned"] > 0
    assert body["finding_count"] == len(body["findings"])
    assert body["finding_count"] > 0
    assert {"id", "algorithm", "file", "line", "confidence"} <= body["findings"][0].keys()
    assert body["cbom"]["components"]
    assert body["risk"]["assets_assessed"] == len(body["cbom"]["components"])


def test_scan_missing_path_returns_not_found() -> None:
    response = client.post("/api/scan", json={"path": str(DEMO_TARGET / "missing")})

    assert response.status_code == 404
    assert "does not exist" in response.json()["detail"]


def test_scan_failure_returns_safe_server_error() -> None:
    class FailingService:
        def scan(self, path: str) -> ScanResponse:
            raise RuntimeError("scanner internals must not leak")

    app.dependency_overrides[get_scan_service] = lambda: FailingService()
    try:
        response = client.post("/api/scan", json={"path": str(DEMO_TARGET)})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json() == {"detail": "The scan could not be completed."}


def test_scan_response_schema_matches_contract() -> None:
    response = client.post("/api/scan", json={"path": str(DEMO_TARGET)})

    parsed = ScanResponse.model_validate(response.json())
    assert parsed.finding_count == len(parsed.findings)
    assert parsed.risk.assets_assessed == len(parsed.cbom.components)
    assert parsed.errors == []

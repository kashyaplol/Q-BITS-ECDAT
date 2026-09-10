from fastapi.testclient import TestClient

from backend.app.api.v1.dependencies import get_analysis_service
from backend.app.main import app
from backend.app.services.analysis import AnalysisService

client = TestClient(app)


def test_scan_accepts_valid_directory() -> None:
    response = client.post("/api/v1/scan", json={"path": "data/sample/demo-target"})
    assert response.status_code == 200
    data = response.json()
    assert data["scanned_path"]
    assert data["files_scanned"] >= 1
    assert data["crypto_assets_found"] >= 0
    assert "findings" in data


def test_scan_rejects_missing_path() -> None:
    response = client.post("/api/v1/scan", json={"path": "data/does-not-exist"})
    assert response.status_code == 400
    assert "Path does not exist" in response.json()["detail"]


def test_scan_rejects_blank_path() -> None:
    response = client.post("/api/v1/scan", json={"path": "   "})
    assert response.status_code == 422


def test_get_analysis_service_returns_analysis_service() -> None:
    service = get_analysis_service()
    assert isinstance(service, AnalysisService)

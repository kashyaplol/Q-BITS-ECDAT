from fastapi.testclient import TestClient

from app.api.v1.dependencies import get_analysis_service
from app.main import app
from app.services.interfaces import AnalysisService

client = TestClient(app)

VALID_REQUEST = {"target": "c:/code/app", "target_type": "directory"}


class RecordingService(AnalysisService):
    def __init__(self) -> None:
        self.called = False

    def analyze(self) -> None:
        self.called = True


def test_analysis_returns_501_not_implemented() -> None:
    response = client.post("/api/v1/analysis", json=VALID_REQUEST)
    assert response.status_code == 501
    assert response.json() == {
        "detail": "Analysis service integration has not been configured yet."
    }


def test_analysis_uses_injected_service() -> None:
    service = RecordingService()
    app.dependency_overrides[get_analysis_service] = lambda: service
    try:
        client.post("/api/v1/analysis", json=VALID_REQUEST)
        assert service.called
    finally:
        app.dependency_overrides.clear()


def test_analysis_rejects_blank_target() -> None:
    response = client.post(
        "/api/v1/analysis", json={"target": "", "target_type": "directory"}
    )
    assert response.status_code == 422


def test_analysis_rejects_whitespace_target() -> None:
    response = client.post(
        "/api/v1/analysis", json={"target": "   ", "target_type": "directory"}
    )
    assert response.status_code == 422


def test_analysis_rejects_blank_target_type() -> None:
    response = client.post(
        "/api/v1/analysis", json={"target": "c:/code/app", "target_type": ""}
    )
    assert response.status_code == 422


def test_analysis_rejects_whitespace_target_type() -> None:
    response = client.post(
        "/api/v1/analysis", json={"target": "c:/code/app", "target_type": " \t\n "}
    )
    assert response.status_code == 422
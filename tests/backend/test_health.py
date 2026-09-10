"""Tests for the application health and info endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    """GET /health should always answer 200 with our status."""
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["project"] == "Q-BITS-ECDAT"


def test_v1_info_returns_metadata() -> None:
    """GET /api/v1/info returns project name and version."""
    response = client.get("/api/v1/info")
    assert response.status_code == 200
    body = response.json()
    assert body["project"] == "Q-BITS-ECDAT"
    assert "version" in body


def test_v1_health_also_available() -> None:
    """The versioned health endpoint should exist too."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_unknown_route_returns_404() -> None:
    """Any undefined route should give a 404."""
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404

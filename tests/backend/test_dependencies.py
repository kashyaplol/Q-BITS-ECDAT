import pytest

from backend.app.api.v1.dependencies import get_analysis_service
from backend.app.services.analysis import AnalysisService, analysis_service


def test_get_analysis_service_returns_analysis_service() -> None:
    service = get_analysis_service()
    assert isinstance(service, AnalysisService)


def test_get_analysis_service_returns_singleton_instance() -> None:
    assert get_analysis_service() is analysis_service


def test_analysis_service_handles_missing_path_without_crashing() -> None:
    result = get_analysis_service().run_full_analysis("C:/definitely/missing/path")
    assert result["scan"].files_scanned == 0
    assert result["cbom"].total_assets == 0
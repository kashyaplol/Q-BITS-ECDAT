import pytest

from app.api.v1.dependencies import get_analysis_service
from app.services.analysis_service import UnconfiguredAnalysisService
from app.services.interfaces import AnalysisService


def test_get_analysis_service_returns_analysis_service() -> None:
    service = get_analysis_service()
    assert isinstance(service, AnalysisService)


def test_get_analysis_service_returns_unconfigured_service() -> None:
    assert isinstance(get_analysis_service(), UnconfiguredAnalysisService)


def test_unconfigured_service_analyze_raises_not_implemented() -> None:
    with pytest.raises(NotImplementedError, match="not been configured yet"):
        get_analysis_service().analyze()
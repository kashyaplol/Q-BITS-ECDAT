from app.services.analysis_service import UnconfiguredAnalysisService
from app.services.interfaces import AnalysisService


def get_analysis_service() -> AnalysisService:
    return UnconfiguredAnalysisService()
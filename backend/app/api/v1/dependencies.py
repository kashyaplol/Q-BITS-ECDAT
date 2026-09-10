from backend.app.services.analysis import analysis_service
from backend.app.services.analysis import AnalysisService


def get_analysis_service() -> AnalysisService:
    return analysis_service
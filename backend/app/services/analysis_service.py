from app.services.interfaces import AnalysisService


class UnconfiguredAnalysisService(AnalysisService):
    def analyze(self) -> None:
        raise NotImplementedError(
            "Analysis service integration has not been configured yet."
        )
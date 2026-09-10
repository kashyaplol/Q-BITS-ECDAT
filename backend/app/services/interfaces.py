from abc import ABC, abstractmethod


class AnalysisService(ABC):
    @abstractmethod
    def analyze(self) -> None:
        raise NotImplementedError
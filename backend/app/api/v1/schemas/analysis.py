from pydantic import BaseModel, field_validator


class AnalysisRequest(BaseModel):
    target: str
    target_type: str

    @field_validator("target", "target_type")
    @classmethod
    def _validate_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value
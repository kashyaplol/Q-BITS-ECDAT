"""Pydantic data models produced by source-code scanning."""

from pydantic import BaseModel, Field


class CryptoFinding(BaseModel):
    """A cryptographic asset discovered in source code.

    The model describes a finding without performing detection itself.  Source
    scanners can populate optional location and context details when available.
    """

    id: str
    algorithm: str
    key_size: int | None = Field(default=None, ge=0)
    library: str | None = None
    file: str
    line: int | None = Field(default=None, ge=0)
    column: int | None = Field(default=None, ge=0)
    language: str | None = None
    code_snippet: str | None = None
    detection_method: str
    confidence: float = Field(ge=0, le=1)
    category: str | None = None
    usage_context: str | None = None
    symbol_name: str | None = None
    arguments: dict[str, str] | None = None


# Keep the original foundation name available for existing scanner imports.
CryptoAsset = CryptoFinding

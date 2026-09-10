"""JSON-serializable models for the CryptoFinding-based CBOM contract."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CBOMMetadata(BaseModel):
    """Static metadata; omitting a clock makes the document reproducible."""

    format: str = "Q-BITS-ECDAT-CBOM"
    format_version: str = "1.0"
    specification_note: str = (
        "Uses CycloneDX-compatible inventory concepts; it is not a full CycloneDX BOM."
    )
    total_input_findings: int = 0
    unique_findings: int = 0
    duplicate_findings: int = 0


class CBOMSourceReference(BaseModel):
    """Source evidence retained when findings are grouped."""

    reference_id: str
    finding_id: str
    file: str
    line: int | None = None
    column: int | None = None
    language: str | None = None
    code_snippet: str | None = None
    detection_method: str
    confidence: float
    usage_context: str | None = None
    symbol_name: str | None = None
    arguments: dict[str, str] | None = None
    occurrences: int = Field(default=1, ge=1)


class CBOMCryptographicInformation(BaseModel):
    algorithm: str
    category: str | None = None
    key_sizes: list[int] = Field(default_factory=list)
    library: str | None = None
    detection_methods: list[str] = Field(default_factory=list)
    confidence: float | None = None
    usage_contexts: list[str] = Field(default_factory=list)
    source_reference_ids: list[str] = Field(default_factory=list)


class CBOMComponent(BaseModel):
    """A cryptographic component, using a CycloneDX-compatible concept."""

    bom_ref: str
    name: str
    type: str = "cryptographic-asset"
    cryptographic_information: CBOMCryptographicInformation


class CBOMAsset(BaseModel):
    """A source file affected by one or more cryptographic components."""

    bom_ref: str
    path: str
    language: str | None = None
    component_refs: list[str] = Field(default_factory=list)
    source_reference_ids: list[str] = Field(default_factory=list)


class CBOM(BaseModel):
    """A deterministic, source-evidenced cryptographic inventory."""

    metadata: CBOMMetadata = Field(default_factory=CBOMMetadata)
    components: list[CBOMComponent] = Field(default_factory=list)
    assets: list[CBOMAsset] = Field(default_factory=list)
    source_references: list[CBOMSourceReference] = Field(default_factory=list)

"""Deterministic generation of a CBOM from ``CryptoFinding`` objects."""

from __future__ import annotations

import json
from collections import defaultdict
from hashlib import sha256
from urllib.parse import quote

from backend.app.models import (
    CBOM as LegacyCbom,  # noqa: N811 - distinguishes the retained legacy model.
)
from backend.app.models import (
    CBOMEntry,
    CryptographicAsset,
    RiskLevel,
    ScanResult,
)
from backend.risk import risk_engine as default_risk_engine
from backend.scanners.source.models import CryptoFinding

from .models import (
    CBOM,
    CBOMAsset,
    CBOMComponent,
    CBOMCryptographicInformation,
    CBOMMetadata,
    CBOMSourceReference,
)


def generate_cbom(findings: list[CryptoFinding]) -> CBOM:
    """Convert scanner findings into a reproducible, JSON-serializable CBOM.

    A component groups compatible findings by algorithm, category, and library.
    Exact duplicate evidence becomes one source reference with an occurrences
    count, so duplicate input is accounted for without losing location data.
    No cryptographic fields are inferred or enriched.
    """
    counted: dict[str, tuple[CryptoFinding, int]] = {}
    for finding in findings:
        fingerprint = json.dumps(
            finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        previous, occurrences = counted.get(fingerprint, (finding, 0))
        counted[fingerprint] = (previous, occurrences + 1)

    ordered = sorted(counted.values(), key=lambda item: _finding_sort_key(item[0]))
    source_records = [
        (finding, _source_reference(finding, occurrences)) for finding, occurrences in ordered
    ]
    sources = [source for _, source in source_records]

    groups: dict[
        tuple[str, str | None, str | None], list[tuple[CryptoFinding, CBOMSourceReference]]
    ] = defaultdict(list)
    for finding, source in source_records:
        groups[(finding.algorithm, finding.category, finding.library)].append((finding, source))

    components: list[CBOMComponent] = []
    for algorithm, category, library in sorted(groups, key=_component_key_sort):
        entries = groups[(algorithm, category, library)]
        grouped_findings = [finding for finding, _ in entries]
        grouped_sources = [source for _, source in entries]
        components.append(
            CBOMComponent(
                bom_ref=_component_ref(algorithm, category, library),
                name=algorithm,
                cryptographic_information=CBOMCryptographicInformation(
                    algorithm=algorithm,
                    category=category,
                    key_sizes=sorted(
                        {
                            finding.key_size
                            for finding in grouped_findings
                            if finding.key_size is not None
                        }
                    ),
                    library=library,
                    detection_methods=sorted(
                        {source.detection_method for source in grouped_sources}
                    ),
                    confidence=max(source.confidence for source in grouped_sources),
                    usage_contexts=sorted(
                        {
                            source.usage_context
                            for source in grouped_sources
                            if source.usage_context is not None
                        }
                    ),
                    source_reference_ids=[source.reference_id for source in grouped_sources],
                ),
            )
        )

    component_by_source = {
        source_id: component.bom_ref
        for component in components
        for source_id in component.cryptographic_information.source_reference_ids
    }
    unique_findings = len(sources)
    return CBOM(
        metadata=CBOMMetadata(
            total_input_findings=len(findings),
            unique_findings=unique_findings,
            duplicate_findings=len(findings) - unique_findings,
        ),
        components=components,
        assets=_assets(sources, component_by_source),
        source_references=sources,
    )


def _source_reference(finding: CryptoFinding, occurrences: int) -> CBOMSourceReference:
    fingerprint = json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return CBOMSourceReference(
        reference_id=f"source:{quote(finding.id, safe='')}:{sha256(fingerprint.encode()).hexdigest()[:12]}",
        finding_id=finding.id,
        file=finding.file,
        line=finding.line,
        column=finding.column,
        language=finding.language,
        code_snippet=finding.code_snippet,
        detection_method=finding.detection_method,
        confidence=finding.confidence,
        usage_context=finding.usage_context,
        symbol_name=finding.symbol_name,
        arguments=dict(sorted(finding.arguments.items())) if finding.arguments else None,
        occurrences=occurrences,
    )


def _assets(
    sources: list[CBOMSourceReference], component_by_source: dict[str, str]
) -> list[CBOMAsset]:
    grouped: dict[tuple[str, str | None], list[CBOMSourceReference]] = defaultdict(list)
    for source in sources:
        grouped[(source.file, source.language)].append(source)
    return [
        CBOMAsset(
            bom_ref=f"asset:{quote(path, safe='')}",
            path=path,
            language=language,
            component_refs=sorted({component_by_source[source.reference_id] for source in entries}),
            source_reference_ids=[source.reference_id for source in entries],
        )
        for (path, language), entries in sorted(
            grouped.items(), key=lambda item: (item[0][0], item[0][1] or "")
        )
    ]


def _finding_sort_key(finding: CryptoFinding) -> tuple[object, ...]:
    return (
        finding.file,
        finding.line if finding.line is not None else -1,
        finding.column if finding.column is not None else -1,
        finding.algorithm,
        finding.category or "",
        finding.library or "",
        finding.id,
    )


def _component_key_sort(key: tuple[str, str | None, str | None]) -> tuple[str, str, str]:
    return key[0], key[1] or "", key[2] or ""


def _component_ref(algorithm: str, category: str | None, library: str | None) -> str:
    return f"component:{quote('|'.join((algorithm, category or '', library or '')), safe='')}"


class CBOMGenerator:
    """Generator facade.

    ``list[CryptoFinding]`` is the current public CBOM contract.  The legacy
    ScanResult path is retained solely for existing analysis endpoints while
    they are migrated; it is not used by the discovery scanner or this CBOM
    contract.
    """

    def __init__(self, project: str = "Unknown", risk_engine=None) -> None:
        self.project = project
        self.risk_engine = risk_engine or default_risk_engine
        self._legacy_mode = project != "Unknown" or risk_engine is not None

    def generate(
        self, findings: list[CryptoFinding] | ScanResult | list[CryptographicAsset]
    ) -> CBOM | LegacyCbom:
        if (
            isinstance(findings, ScanResult)
            or (findings and isinstance(findings[0], CryptographicAsset))
            or (not findings and self._legacy_mode)
        ):
            return self._generate_legacy(findings)
        return generate_cbom(findings)

    def _generate_legacy(self, findings: ScanResult | list[CryptographicAsset]) -> LegacyCbom:
        """Preserve the established analysis-service behavior during migration."""
        assets = findings.assets if isinstance(findings, ScanResult) else findings
        groups: dict[tuple[str, str | None, str], list[CryptographicAsset]] = {}
        for asset in assets:
            groups.setdefault((asset.algorithm.value, asset.library, asset.file_path), []).append(
                asset
            )
        entries = [
            CBOMEntry(
                algorithm=algorithm,
                library=library,
                file=file_path,
                occurrences=len(grouped),
                risk_level=self.risk_engine.assess(algorithm).risk_level,
                line_numbers=sorted({finding.line_number for finding in grouped}),
                detection_methods=sorted({finding.detection_method.value for finding in grouped}),
                contexts=[finding.context for finding in grouped if finding.context],
                key_sizes=sorted(
                    {finding.key_size for finding in grouped if finding.key_size is not None}
                ),
                usages=sorted(
                    {finding.usage.value for finding in grouped if finding.usage is not None}
                ),
                curves=sorted({finding.curve for finding in grouped if finding.curve}),
                modes=sorted({finding.mode for finding in grouped if finding.mode}),
            )
            for (algorithm, library, file_path), grouped in groups.items()
        ]
        risk_order = [
            RiskLevel.CRITICAL,
            RiskLevel.HIGH,
            RiskLevel.MEDIUM,
            RiskLevel.LOW,
            RiskLevel.UNKNOWN,
        ]
        entries.sort(
            key=lambda entry: (
                risk_order.index(entry.risk_level),
                entry.algorithm.value,
                entry.file,
            )
        )
        cbom = LegacyCbom(project=self.project, cryptographic_assets=entries)
        cbom.build_summary()
        return cbom

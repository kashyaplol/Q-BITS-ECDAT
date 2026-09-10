"""CBOM (Cryptographic Bill of Materials) generator.

A CBOM is the cryptographic equivalent of an SBOM (Software Bill of
Materials): a structured inventory of *which* cryptography is used and
*where* in a codebase.

This generator accepts **scanner findings** and produces a ``CBOM``:

* ``generate(scan_result)``        -- a whole ``ScanResult``,
* ``generate(findings)``           -- a plain ``list[CryptographicAsset]``,
* ``generate_from_findings(...)``  -- explicit variant.

Every aggregated entry carries a quantum-risk level (from the risk
engine) and the summary fields (totals, per-algorithm list) are
calculated automatically.

Example usage::

    from backend.scanners.source import SourceCodeScanner
    from backend.cbom import CBOMGenerator

    scan = SourceCodeScanner().scan_directory("project/")
    bom = CBOMGenerator(project="My Project").generate(scan)
    print(bom.model_dump_json(indent=2))
"""

from __future__ import annotations

from backend.app.models import CBOM, CBOMEntry, CryptographicAsset, RiskLevel, ScanResult
from backend.risk import risk_engine as default_risk_engine


class CBOMGenerator:
    """Turn scanner findings into a Cryptographic Bill of Materials.

    The generator is a thin aggregation layer: it never scans source
    code itself and never invents fields the scanner did not produce.
    All evidence the ``CryptographicAsset`` model carries (file path,
    line number, library, detection method, source context) is preserved
    in the aggregated entries.
    """

    def __init__(self, project: str = "Unknown", risk_engine=None) -> None:
        self.project = project
        self.risk_engine = risk_engine or default_risk_engine

    def generate(self, findings: ScanResult | list[CryptographicAsset]) -> CBOM:
        """Aggregate scanner findings into a CBOM.

        Accepts either a ``ScanResult`` (the normal scanner output) or a
        plain list of ``CryptographicAsset`` findings. Passing an empty
        list (or an empty scan) produces an empty, well-formed CBOM.
        """
        assets = findings.assets if isinstance(findings, ScanResult) else findings
        # Group by (algorithm, library, file path). Using ``None`` as the
        # library key for keyword-only findings so they group separately.
        groups: dict[tuple[str, str | None, str], list[CryptographicAsset]] = {}
        for asset in assets:
            key = (
                asset.algorithm.value,
                asset.library,
                asset.file_path,
            )
            groups.setdefault(key, []).append(asset)

        # Build one CBOMEntry per group, preserving scanner evidence.
        entries = [
            self._entry_for(algorithm, library, file_path, findings_in_group)
            for (algorithm, library, file_path), findings_in_group in groups.items()
        ]

        # Sort by risk (worst first), then by algorithm, then by file name.
        entries.sort(
            key=lambda entry: (
                _RISK_ORDER.index(entry.risk_level),
                entry.algorithm.value,
                entry.file,
            )
        )

        bom = CBOM(
            project=self.project,
            cryptographic_assets=entries,
        )
        bom.build_summary()
        return bom

    def _entry_for(
        self,
        algorithm: str,
        library: str | None,
        file_path: str,
        findings: list[CryptographicAsset],
    ) -> CBOMEntry:
        """Aggregate one group of findings into a single CBOM entry.

        Keeps every detail the scanner actually produced: the distinct
        detection methods used, the line numbers and the matching source
        snippets (evidence).
        """
        return CBOMEntry(
            algorithm=algorithm,
            library=library,
            file=file_path,
            occurrences=len(findings),
            risk_level=self._risk_level_for(algorithm),
            line_numbers=sorted(
                {finding.line_number for finding in findings}
            ),
            detection_methods=sorted(
                {finding.detection_method.value for finding in findings}
            ),
            contexts=[finding.context for finding in findings if finding.context],
            key_sizes=sorted(
                {finding.key_size for finding in findings if finding.key_size is not None}
            ),
            usages=sorted(
                {finding.usage.value for finding in findings if finding.usage is not None}
            ),
            curves=sorted(
                {finding.curve for finding in findings if finding.curve}
            ),
            modes=sorted(
                {finding.mode for finding in findings if finding.mode}
            ),
        )

    def _risk_level_for(self, algorithm: str) -> RiskLevel:
        """Map an algorithm name to its overall quantum-risk level."""
        return self.risk_engine.assess(algorithm).risk_level


# Ordering used when sorting CBOM entries: worst risk first.
# UNKNOWN is appended so .index() never raises if a scanner returns a
# name the risk engine cannot classify.
_RISK_ORDER = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.UNKNOWN,
]

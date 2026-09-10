"""Service boundary for the MVP scanner integration."""

from __future__ import annotations

import logging
from pathlib import Path

from backend.app.schemas.scan import ScanResponse
from backend.cbom import generate_cbom
from backend.risk import assess_risk
from backend.scanners import CryptoFinding, CryptoScanner
from backend.scanners.source.utils import discover_source_files


class ScanService:
    """Adapt the scanner's public ``CryptoFinding[]`` API to HTTP responses."""

    def __init__(self, scanner: CryptoScanner | None = None) -> None:
        self.scanner = scanner or CryptoScanner()
        self.logger = logging.getLogger(__name__)

    def scan(self, path: str) -> ScanResponse:
        """Scan a local repository and return actual scanner findings."""
        repository = Path(path).expanduser()
        if not repository.exists():
            raise FileNotFoundError(f"Scan path does not exist: {repository}")
        if not repository.is_dir():
            raise NotADirectoryError(
                f"Scan path must be a repository directory: {repository}"
            )

        repository = repository.resolve()
        files_scanned = len(discover_source_files(repository))
        findings: list[CryptoFinding] = self.scanner.scan(repository)
        warnings = list(getattr(self.scanner, "parsing_errors", []))
        cbom = generate_cbom(findings)
        risk = assess_risk(cbom)

        return ScanResponse(
            status="completed",
            files_scanned=files_scanned,
            finding_count=len(findings),
            findings=findings,
            cbom=cbom,
            risk=risk,
            warnings=warnings,
        )

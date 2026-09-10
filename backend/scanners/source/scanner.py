"""Source code cryptographic scanner.

The scanner walks a directory recursively and analyses source files for
signs of cryptographic usage -- algorithm names and crypto library calls.

It is deliberately language-agnostic: the actual detection logic lives in
``rules.py`` as a list of regex-based ``DetectionRule`` objects, so adding
a new library or pattern requires zero changes to this file.

For Python files the scanner runs a **hybrid** pipeline:

    regex detection (existing)
              +
    AST detection (``PythonAstScanner``)
              ↓
    normalized findings  →  deduplicated  →  CryptographicAsset[]

The regex pass keeps working exactly as before (it is the safe fallback
for Java/JS/TS and for Python files the AST cannot parse). The AST pass
adds rich structural metadata (key size, usage, curve, mode) and, when a
regex hit and an AST hit agree on the same usage, the asset is marked as a
``hybrid`` detection to avoid duplicate noise.

Example::

    from backend.scanners.source import SourceCodeScanner

    scanner = SourceCodeScanner()
    result = scanner.scan_directory("./sample_project")
    print(result.assets)
"""

from __future__ import annotations

import os
import re

from backend.app.core.config import settings
from backend.app.core.logging import get_logger
from backend.app.models import (
    CryptographicAsset,
    DetectionMethod,
    ScanResult,
)

from .ast_scanner import PythonAstScanner
from .normalize import normalize_findings as _normalize
from .rules import ALL_RULES, DetectionRule

logger = get_logger(__name__)


class SourceCodeScanner:
    """Recursively scan a directory tree for cryptographic usage."""

    def __init__(
        self,
        extensions: list[str] | None = None,
        excluded_dirs: list[str] | None = None,
    ) -> None:
        """Configure the scanner.

        Args:
            extensions:     File extensions to scan (defaults to settings).
            excluded_dirs:  Directory names to skip entirely.
        """
        self.extensions = extensions or list(settings.supported_extensions)
        self.excluded_dirs = excluded_dirs or list(settings.excluded_dirs)
        self.use_ast = True  # Python files additionally get AST analysis

        # Pre-compile every rule so scanning is fast. We also remember
        # which extensions each compiled rule applies to.
        self._compiled_rules: list[tuple[DetectionRule, re.Pattern[str]]] = []
        for rule in ALL_RULES:
            for pattern in rule.patterns:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_rules.append((rule, compiled))

        # AST scanner instance (stateless across files thanks to its own
        # per-scan parse + walk in ``PythonAstScanner``).
        self._ast_scanner = PythonAstScanner()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan_directory(self, directory: str) -> ScanResult:
        """Scan every supported file under ``directory`` (recursively).

        Returns a ``ScanResult`` with matched assets, per-algorithm counts
        and any AST parse errors that were safely skipped.
        """
        assets: list[CryptographicAsset] = []
        files_scanned = 0
        parse_errors: list[str] = []

        for file_path in self._iter_supported_files(directory):
            files_scanned += 1
            file_assets, file_errors = self._scan_file_with_errors(file_path)
            assets.extend(file_assets)
            parse_errors.extend(file_errors)

        result = ScanResult(
            scanned_path=directory,
            files_scanned=files_scanned,
            assets=assets,
            parse_errors=parse_errors,
        )
        self._summarize(result)
        if parse_errors:
            logger.warning(
                "AST parsing failed for %d file(s) - regex fallback used: %s",
                len(parse_errors),
                parse_errors,
            )
        logger.info(
            "Scanned %s files in %s - found %d crypto assets",
            files_scanned,
            directory,
            len(assets),
        )
        return result

    def scan_file(self, file_path: str) -> list[CryptographicAsset]:
        """Analyse a single file and return matching assets.

        Encoding is handled defensively: some source files are UTF-8 with a
        BOM, others use latin-1 -- we try a few encodings before giving up.
        """
        assets, _ = self._scan_file_with_errors(file_path)
        return assets

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _scan_file_with_errors(
        self, file_path: str
    ) -> tuple[list[CryptographicAsset], list[str]]:
        """Analyse one file: regex pass + (for Python) AST pass.

        Returns ``(assets, parse_errors)`` so callers can keep a record of
        files the AST could not parse (they still get regex scanning).
        """
        extension = os.path.splitext(file_path)[1]
        if extension not in self.extensions:
            return [], []

        content, encoding = self._read_file(file_path)
        if content is None:
            logger.warning("Could not read file %s (skipped)", file_path)
            return [], []

        regex_assets: list[CryptographicAsset] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            regex_assets.extend(self._match_line(file_path, line_number, line, extension))

        if extension != ".py" or not self.use_ast:
            return regex_assets, []

        ast_assets, parse_error = self._ast_scanner.analyze(file_path, content)
        if parse_error is not None:
            logger.debug("AST scan skipped for %s: %s", file_path, parse_error)
            return regex_assets, [parse_error]

        return _normalize(regex_assets, ast_assets), []
    def _iter_supported_files(self, directory: str):
        """Yield every supported file under ``directory`` recursively.

        Skips anything inside an excluded directory (node_modules, .git, ...).
        """
        for root, dirs, files in os.walk(directory):
            # Mutating ``dirs`` in-place prevents os.walk from descending.
            dirs[:] = [
                d
                for d in dirs
                if d not in self.excluded_dirs and not d.startswith(".")
            ]
            for file_name in files:
                if file_name.startswith("."):
                    continue
                extension = os.path.splitext(file_name)[1]
                if extension in self.extensions:
                    yield os.path.join(root, file_name)

    def _read_file(self, file_path: str) -> tuple[str | None, str | None]:
        """Read a file trying multiple encodings. Returns (content, encoding)."""
        for encoding in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                with open(file_path, encoding=encoding) as handle:
                    return handle.read(), encoding
            except (UnicodeDecodeError, OSError):
                continue
        return None, None

    def _match_line(
        self, file_path: str, line_number: int, line: str, extension: str
    ) -> list[CryptographicAsset]:
        """Check one source line against every applicable rule.

        If a keyword match fires on the very same line as a library match
        for the same algorithm, the keyword match is dropped -- the library
        match already gives stronger, more useful information.
        """
        matches: list[CryptographicAsset] = []
        for rule, pattern in self._compiled_rules:
            if extension not in rule.extensions:
                continue  # Rule does not apply to this file type.
            if pattern.search(line):
                matches.append(
                    CryptographicAsset(
                        file_path=file_path,
                        line_number=line_number,
                        algorithm=rule.algorithm,
                        library=rule.library,
                        detection_method=rule.detection_method,
                        context=line.strip()[:200],
                    )
                )

        # Suppress redundant keyword hits when a library hit exists for the
        # same algorithm on this line.
        regex_algorithms = {
            asset.algorithm
            for asset in matches
            if asset.detection_method == DetectionMethod.REGEX
        }
        return [
            asset
            for asset in matches
            if not (
                asset.detection_method == DetectionMethod.KEYWORD
                and asset.algorithm in regex_algorithms
            )
        ]

    def _summarize(self, result: ScanResult) -> None:
        """Fill in per-algorithm counts on the ScanResult."""
        counts: dict[str, int] = {}
        for asset in result.assets:
            counts[asset.algorithm.value] = counts.get(asset.algorithm.value, 0) + 1
        result.algorithm_counts = counts

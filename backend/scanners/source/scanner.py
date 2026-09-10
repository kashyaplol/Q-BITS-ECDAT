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


# Compatibility deterministic scanner API from main branch.
import ast
from pathlib import Path

from .models import CryptoFinding
from .patterns import (
    CRYPTOGRAPHIC_PATTERNS,
    PatternDefinition,
    extract_key_size,
)
from .utils import DiscoveredFile, discover_source_files
from .utils import read_source_text

class CryptoScanner:
    """Discover source files and identify potential cryptographic usage."""

    def __init__(self) -> None:
        """Initialize a scanner with an empty parse-error record."""

        self.parsing_errors: list[str] = []

    def scan(self, path: str | Path) -> list[CryptoFinding]:
        """Validate ``path`` and return deterministic potential findings.

        Pattern matches indicate potential usage only; they do not prove that
        cryptographic code executes.

        Args:
            path: Existing repository directory to scan.

        Returns:
            Potential cryptographic usages found in supported files.

        Raises:
            ValueError: If ``path`` is empty, does not exist, or is not a
                directory.
        """

        if isinstance(path, str) and not path.strip():
            raise ValueError("Scan path must not be empty.")

        scan_path = Path(path).expanduser()
        if not scan_path.exists():
            raise ValueError(f"Scan path does not exist: {scan_path}")
        if not scan_path.is_dir():
            raise ValueError(f"Scan path must be a repository directory: {scan_path}")

        repository_path = scan_path.resolve()
        self.parsing_errors = []
        findings: list[CryptoFinding] = []
        for discovered_file in discover_source_files(repository_path):
            source_text = read_source_text(discovered_file.path)
            if source_text is None:
                continue
            findings.extend(self._findings_for_file(discovered_file, source_text))
            if discovered_file.extension == ".py":
                findings.extend(self._ast_findings_for_file(discovered_file, source_text))
        return _deduplicate_findings(findings)

    @staticmethod
    def _findings_for_file(
        discovered_file: DiscoveredFile, source_text: str
    ) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        lines = source_text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            for pattern in CRYPTOGRAPHIC_PATTERNS:
                match = pattern.compiled_pattern.search(line)
                if match is None:
                    continue
                findings.append(
                    CryptoFinding(
                        id=_finding_id(discovered_file, line_number, match.start(), pattern),
                        algorithm=pattern.algorithm,
                        key_size=extract_key_size(pattern.algorithm, line),
                        file=discovered_file.relative_path.as_posix(),
                        line=line_number,
                        column=match.start() + 1,
                        language=_language_for(discovered_file.extension),
                        code_snippet=line or None,
                        detection_method=pattern.detection_method,
                        confidence=pattern.confidence,
                        category=pattern.category,
                        usage_context="potential cryptographic usage",
                    )
                )
        return findings

    def _ast_findings_for_file(
        self, discovered_file: DiscoveredFile, source_text: str
    ) -> list[CryptoFinding]:
        """Find Python crypto imports and calls using the standard AST."""

        try:
            tree = ast.parse(source_text, filename=str(discovered_file.path))
        except SyntaxError as error:
            self.parsing_errors.append(
                f"{discovered_file.relative_path.as_posix()}: {error.msg}"
            )
            return []

        lines = source_text.splitlines()
        findings: list[CryptoFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                import_name = _import_name(node)
                if import_name is None:
                    continue
                library = _python_library_for(import_name)
                if library is None:
                    continue
                findings.append(
                    _ast_finding(
                        discovered_file,
                        node,
                        lines,
                        algorithm=library,
                        category="library",
                        symbol_name=import_name,
                    )
                )
            elif isinstance(node, ast.Call):
                call_name = _call_name(node)
                target = _python_call_target(call_name)
                if target is None or call_name is None:
                    continue
                algorithm, category = target
                findings.append(
                    _ast_finding(
                        discovered_file,
                        node,
                        lines,
                        algorithm=algorithm,
                        category=category,
                        symbol_name=call_name,
                        arguments=_ast_arguments(node),
                    )
                )
        return findings


def _finding_id(
    discovered_file: DiscoveredFile,
    line_number: int,
    column: int,
    pattern: PatternDefinition,
) -> str:
    """Create a stable identifier for one deterministic pattern match."""

    return (
        f"{discovered_file.relative_path.as_posix()}:"
        f"{line_number}:{column}:{pattern.algorithm}"
    )


def _import_name(node: ast.Import | ast.ImportFrom) -> str | None:
    if isinstance(node, ast.Import):
        return node.names[0].name if node.names else None
    return node.module


def _python_library_for(import_name: str) -> str | None:
    roots = {
        "cryptography": "cryptography",
        "Crypto": "Crypto",
        "Cryptodome": "Cryptodome",
        "hashlib": "hashlib",
        "ssl": "ssl",
    }
    return roots.get(import_name.split(".", maxsplit=1)[0])


def _call_name(node: ast.Call) -> str | None:
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _python_call_target(call_name: str | None) -> tuple[str, str] | None:
    if call_name is None:
        return None
    lowered_name = call_name.lower()
    if lowered_name.endswith(("rsa.generate", "rsa.generate_private_key")):
        return "RSA", "asymmetric"
    final_name = call_name.rsplit(".", maxsplit=1)[-1].lower()
    algorithms = {
        "rsa": ("RSA", "asymmetric"),
        "dsa": ("DSA", "asymmetric"),
        "ec": ("ECC", "asymmetric"),
        "ecdsa": ("ECDSA", "asymmetric"),
        "aes": ("AES", "symmetric"),
        "des": ("DES", "symmetric"),
        "blowfish": ("Blowfish", "symmetric"),
        "chacha20": ("ChaCha20", "symmetric"),
        "md5": ("MD5", "hash"),
        "sha1": ("SHA-1", "hash"),
        "sha256": ("SHA-256", "hash"),
        "sha384": ("SHA-384", "hash"),
        "sha512": ("SHA-512", "hash"),
    }
    return algorithms.get(final_name)


def _ast_arguments(node: ast.Call) -> dict[str, str] | None:
    arguments: dict[str, str] = {}
    for index, argument in enumerate(node.args):
        value = _constant_value(argument)
        if value is not None:
            arguments[f"arg{index}"] = value
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        value = _constant_value(keyword.value)
        if value is not None:
            arguments[keyword.arg] = value
    return arguments or None


def _constant_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)):
        return str(node.value)
    return None


def _ast_finding(
    discovered_file: DiscoveredFile,
    node: ast.AST,
    lines: list[str],
    *,
    algorithm: str,
    category: str,
    symbol_name: str,
    arguments: dict[str, str] | None = None,
) -> CryptoFinding:
    line_number = getattr(node, "lineno", 1)
    column = getattr(node, "col_offset", 0) + 1
    source_line = lines[line_number - 1] if line_number <= len(lines) else ""
    key_size = _ast_key_size(algorithm, arguments)
    return CryptoFinding(
        id=(
            f"{discovered_file.relative_path.as_posix()}:"
            f"{line_number}:{column}:ast:{symbol_name}"
        ),
        algorithm=algorithm,
        key_size=key_size,
        file=discovered_file.relative_path.as_posix(),
        line=line_number,
        column=column,
        language="Python",
        code_snippet=source_line or None,
        detection_method="ast",
        confidence=0.95,
        category=category,
        usage_context="potential cryptographic usage",
        symbol_name=symbol_name,
        arguments=arguments,
    )


def _ast_key_size(algorithm: str, arguments: dict[str, str] | None) -> int | None:
    if algorithm == "RSA" and arguments:
        value = arguments.get("key_size") or arguments.get("arg0")
        if value and value.isdigit():
            return int(value)
    return None


def _deduplicate_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Merge overlapping detector records without hiding separate usages."""

    deduplicated: list[CryptoFinding] = []
    for finding in findings:
        duplicate_index = next(
            (
                index
                for index, existing in enumerate(deduplicated)
                if _same_usage(existing, finding)
            ),
            None,
        )
        if duplicate_index is None:
            deduplicated.append(finding)
            continue
        deduplicated[duplicate_index] = _merge_findings(
            deduplicated[duplicate_index], finding
        )
    return deduplicated


def _same_usage(left: CryptoFinding, right: CryptoFinding) -> bool:
    """Return whether two findings describe the same algorithm occurrence."""

    if (left.file, left.line, left.algorithm) != (
        right.file,
        right.line,
        right.algorithm,
    ):
        return False
    if left.column == right.column:
        return True
    if left.detection_method == right.detection_method:
        return False
    ast_finding = left if left.detection_method == "ast" else right
    pattern_finding = right if ast_finding is left else left
    if ast_finding.symbol_name is None:
        return False
    return abs((ast_finding.column or 0) - (pattern_finding.column or 0)) <= len(
        ast_finding.symbol_name
    )


def _merge_findings(left: CryptoFinding, right: CryptoFinding) -> CryptoFinding:
    """Preserve the most useful fields when detector records overlap."""

    ast_finding = left if left.detection_method == "ast" else right
    methods = {left.detection_method, right.detection_method}
    method = "+".join(
        name for name in ("pattern", "deterministic_regex", "ast") if name in methods
    )
    return left.model_copy(
        update={
            "key_size": left.key_size or right.key_size,
            "column": ast_finding.column or left.column or right.column,
            "code_snippet": left.code_snippet or right.code_snippet,
            "detection_method": method,
            "confidence": max(left.confidence, right.confidence),
            "symbol_name": left.symbol_name or right.symbol_name,
            "arguments": left.arguments or right.arguments,
        }
    )


def _language_for(extension: str) -> str | None:
    """Map a supported file extension to a readable language label."""

    languages = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".c": "C",
        ".cpp": "C++",
        ".h": "C/C++",
        ".hpp": "C++",
        ".go": "Go",
        ".rs": "Rust",
        ".php": "PHP",
        ".rb": "Ruby",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".xml": "XML",
        ".conf": "Config",
        ".config": "Config",
    }
    return languages.get(extension)

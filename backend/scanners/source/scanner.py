"""Entry point for source-code cryptographic scanning."""

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

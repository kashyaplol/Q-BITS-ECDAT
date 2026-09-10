"""Source code cryptographic scanner.

Exposes the ``SourceCodeScanner`` class and the rule definitions::

    from backend.scanners.source import SourceCodeScanner
    result = SourceCodeScanner().scan_directory("path/to/code")

For Python files the scanner runs a hybrid regex + AST pipeline; the
AST components (``PythonAstScanner``) and the fuse logic
(``normalize_findings``) are also importable directly.
"""

from .ast_scanner import PythonAstScanner  # noqa: F401
from .normalize import normalize_findings  # noqa: F401
from .rules import ALL_RULES, KEYWORD_RULES, LIBRARY_RULES, DetectionRule  # noqa: F401
from .scanner import SourceCodeScanner  # noqa: F401

__all__ = [
    "ALL_RULES",
    "KEYWORD_RULES",
    "LIBRARY_RULES",
    "DetectionRule",
    "PythonAstScanner",
    "SourceCodeScanner",
    "normalize_findings",
]

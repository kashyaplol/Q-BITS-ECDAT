"""Tests for the source code cryptographic scanner."""

from __future__ import annotations

from backend.scanners.source import SourceCodeScanner


def test_scanner_detects_hashlib_usage(tmp_path) -> None:
    """A Python file using hashlib should be detected with the library name."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "h = hashlib.sha256(b'data')\n"
        "weak = hashlib.md5(b'data')\n",
        encoding="utf-8",
    )

    result = SourceCodeScanner().scan_directory(str(tmp_path))

    assert result.files_scanned == 1
    algorithms = {a.algorithm.value for a in result.assets}
    assert "SHA256" in algorithms
    assert "MD5" in algorithms

    # Every SHA256 hit should name hashlib as its library.
    hashlib_hits = [a for a in result.assets if a.algorithm.value == "SHA256"]
    assert all(a.library == "hashlib" for a in hashlib_hits)
    # The MD5 line should be line 3 (1-indexed).
    md5_hits = [a for a in result.assets if a.algorithm.value == "MD5"]
    assert any(a.line_number == 3 for a in md5_hits)


def test_scanner_detects_keywords_without_library(tmp_path) -> None:
    """Plain algorithm names (no library) should be found as keyword hits."""
    (tmp_path / "notes.js").write_text(
        "// We use RSA for signing and AES for encryption.\n",
        encoding="utf-8",
    )

    result = SourceCodeScanner().scan_directory(str(tmp_path))
    algorithms = {a.algorithm.value for a in result.assets}
    assert "RSA" in algorithms
    assert "AES" in algorithms
    # Keyword-only hits have no library.
    rsa_hits = [a for a in result.assets if a.algorithm.value == "RSA"]
    assert all(a.library is None for a in rsa_hits)
    assert all(a.detection_method.value == "keyword" for a in rsa_hits)


def test_scanner_skips_unsupported_extensions(tmp_path) -> None:
    """Non-source files (.txt, .bin) must be ignored."""
    (tmp_path / "readme.txt").write_text("MD5", encoding="utf-8")
    (tmp_path / "data.bin").write_bytes(b"RSA AES")

    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert result.files_scanned == 0
    assert result.assets == []


def test_scanner_skips_excluded_directories(tmp_path) -> None:
    """node_modules / .git / __pycache__ content must never be scanned."""
    excluded = tmp_path / "node_modules" / "lib"
    excluded.mkdir(parents=True)
    (excluded / "dep.js").write_text(
        "const c = require('crypto'); c.createHash('md5');",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text("import hashlib; hashlib.sha256(b'x')", encoding="utf-8")

    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert result.files_scanned == 1
    assert all("node_modules" not in a.file_path for a in result.assets)


def test_scanner_supports_java_and_typescript(tmp_path) -> None:
    """Java MessageDigest and TypeScript crypto calls should be found."""
    (tmp_path / "Crypto.java").write_text(
        'MessageDigest digest = MessageDigest.getInstance("SHA-256");\n',
        encoding="utf-8",
    )
    (tmp_path / "crypto.ts").write_text(
        "import crypto from 'crypto';\n"
        "crypto.createHash('sha512');\n",
        encoding="utf-8",
    )

    result = SourceCodeScanner().scan_directory(str(tmp_path))
    algorithms = {a.algorithm.value for a in result.assets}
    assert "SHA256" in algorithms
    assert "SHA512" in algorithms


def test_scanner_reports_algorithm_counts(tmp_path) -> None:
    """ScanResult.algorithm_counts should match detected assets."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "hashlib.md5(b'x')\n"
        "hashlib.md5(b'y')\n"
        "hashlib.sha256(b'z')\n",
        encoding="utf-8",
    )

    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert result.algorithm_counts["MD5"] == 2
    assert result.algorithm_counts["SHA256"] == 1


def test_scanner_handles_empty_directory(tmp_path) -> None:
    """Scanning an empty directory returns an empty result, not an error."""
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert result.files_scanned == 0
    assert result.assets == []

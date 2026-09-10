"""Tests for CBOM generation and quantum risk assessment."""

from __future__ import annotations

from backend.app.models import (
    CBOM,
    CBOMEntry,
    CryptographicAsset,
    DetectionMethod,
    RiskLevel,
    ScanResult,
)
from backend.cbom import CBOMGenerator
from backend.risk import RiskEngine, risk_engine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_scan_result(assets: list[CryptographicAsset]) -> ScanResult:
    return ScanResult(scanned_path="test", files_scanned=1, assets=assets)


def _asset(algorithm: str, file: str = "app.py", library: str | None = None) -> CryptographicAsset:
    return CryptographicAsset(
        file_path=file,
        line_number=1,
        algorithm=algorithm,
        library=library,
        detection_method=DetectionMethod.REGEX,
        context="line",
    )


# ---------------------------------------------------------------------------
# Risk engine
# ---------------------------------------------------------------------------
class TestRiskEngine:
    def test_rsa_is_critical_migration(self) -> None:
        assessment = risk_engine.assess("RSA")
        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.migration_priority.value == "CRITICAL"
        assert assessment.quantum_risk.value == "CRITICAL"

    def test_aes_is_medium_risk(self) -> None:
        assessment = risk_engine.assess("AES")
        assert assessment.risk_level == RiskLevel.MEDIUM
        assert assessment.migration_priority.value == "MEDIUM"

    def test_md5_is_immediate_migration(self) -> None:
        assessment = risk_engine.assess("MD5")
        assert assessment.risk_level == RiskLevel.CRITICAL
        assert assessment.migration_priority.value == "IMMEDIATE"

    def test_unknown_algorithm_is_review_required(self) -> None:
        assessment = RiskEngine().assess("TOTALLY_FAKE_ALGO")
        assert assessment.risk_level == RiskLevel.UNKNOWN
        assert assessment.migration_priority.value == "REVIEW_REQUIRED"
        assert "knowledge base" in assessment.recommendation

    def test_assess_many_deduplicates(self) -> None:
        assessments = risk_engine.assess_many(["RSA", "RSA", "AES", "AES"])
        keys = [(a.algorithm, a.risk_level.value) for a in assessments]
        # First-appearance order is preserved; duplicates are dropped.
        assert keys == [("RSA", "CRITICAL"), ("AES", "MEDIUM")]


# ---------------------------------------------------------------------------
# CBOM generation
# ---------------------------------------------------------------------------
class TestCBOMGenerator:
    def test_aggregates_identical_assets(self) -> None:
        """Same algorithm+library+file should be one entry with occurrences."""
        scan = _make_scan_result(
            [
                _asset("RSA", "app.py", "cryptography"),
                _asset("RSA", "app.py", "cryptography"),
                _asset("RSA", "app.py", "cryptography"),
            ]
        )
        bom = CBOMGenerator(project="Demo").generate(scan)
        assert bom.project == "Demo"
        assert bom.total_assets == 1
        assert bom.total_findings == 3
        assert bom.cryptographic_assets[0].occurrences == 3

    def test_keyword_and_library_assets_stay_separate(self) -> None:
        """A keyword hit (no library) and a library hit should be distinct."""
        scan = _make_scan_result(
            [
                _asset("RSA", "app.py", "cryptography"),
                _asset("RSA", "app.py", None),  # keyword finding
            ]
        )
        bom = CBOMGenerator("Demo").generate(scan)
        assert bom.total_assets == 2

    def test_unique_algorithms_are_listed(self) -> None:
        scan = _make_scan_result(
            [_asset("RSA", "a.py"), _asset("AES", "b.py"), _asset("MD5", "c.py")]
        )
        bom = CBOMGenerator("Demo").generate(scan)
        assert "RSA" in bom.unique_algorithms
        assert "AES" in bom.unique_algorithms
        assert "MD5" in bom.unique_algorithms

    def test_build_summary_counts_high_risk(self) -> None:
        scan = _make_scan_result(
            [
                _asset("MD5", "a.py"),    # CRITICAL
                _asset("RSA", "b.py"),    # CRITICAL
                _asset("AES", "c.py"),    # MEDIUM
                _asset("SHA256", "d.py"), # MEDIUM
            ]
        )
        bom = CBOMGenerator("Demo").generate(scan)
        assert bom.total_assets == 4
        # CBOM.high_risk_assets counts HIGH *and* CRITICAL entries.
        assert bom.high_risk_assets == 2
        assert bom.medium_risk_assets == 2

    def test_entries_are_sorted_worst_risk_first(self) -> None:
        scan = _make_scan_result(
            [
                _asset("AES", "a.py"),   # MEDIUM
                _asset("RSA", "b.py"),   # CRITICAL
                _asset("MD5", "c.py"),   # CRITICAL
            ]
        )
        bom = CBOMGenerator("Demo").generate(scan)
        levels = [e.risk_level for e in bom.cryptographic_assets]
        # CRITICAL entries before MEDIUM entries.
        assert levels == [RiskLevel.CRITICAL, RiskLevel.CRITICAL, RiskLevel.MEDIUM]

    def test_empty_scan_yields_empty_cbom(self) -> None:
        bom = CBOMGenerator("Demo").generate(_make_scan_result([]))
        assert bom.total_assets == 0
        assert bom.total_findings == 0
        assert bom.cryptographic_assets == []

    def test_generate_accepts_plain_finding_list(self) -> None:
        """The generator must also consume list[CryptographicAsset] directly."""
        findings = [
            _asset("AES", "app.py", "cryptography"),
            _asset("RSA", "app.py", "cryptography"),
        ]
        bom = CBOMGenerator("Demo").generate(findings)
        assert bom.total_assets == 2
        assert bom.total_findings == 2

    def test_generate_accepts_empty_list(self) -> None:
        bom = CBOMGenerator("Demo").generate([])
        assert bom.total_assets == 0
        assert bom.total_findings == 0

    def test_evidence_is_preserved_in_entries(self) -> None:
        """Line numbers, detection methods and contexts survive grouping."""
        scan = _make_scan_result(
            [
                _asset("SHA256", "app.py", "hashlib"),
                _asset("SHA256", "app.py", "hashlib"),
                _asset("MD5", "app.py", None),  # keyword finding
            ]
        )
        scan.assets[0].line_number = 3
        scan.assets[1].line_number = 7
        scan.assets[0].context = "hashlib.sha256(b'x')"
        scan.assets[1].context = "hashlib.sha256(b'x')"
        bom = CBOMGenerator("Demo").generate(scan)
        entry = next(e for e in bom.cryptographic_assets if e.library == "hashlib")
        assert entry.occurrences == 2
        assert entry.line_numbers == [3, 7]
        assert entry.detection_methods == ["regex"]
        assert entry.contexts == ["hashlib.sha256(b'x')", "hashlib.sha256(b'x')"]

    def test_duplicate_algorithms_group_by_usage_location(self) -> None:
        """RSA in different files yields separate entries."""
        scan = _make_scan_result(
            [_asset("RSA", "a.py"), _asset("RSA", "b.py")]
        )
        bom = CBOMGenerator("Demo").generate(scan)
        assert bom.total_assets == 2
        assert [e.file for e in bom.cryptographic_assets] == ["a.py", "b.py"]


# A pyflakes guard: CBOM/CBOMEntry are referenced by type annotations below.
def test_cbom_model_shapes() -> None:
    entry = CBOMEntry(algorithm="RSA", file="f.py")
    bom = CBOM(cryptographic_assets=[entry])
    bom.build_summary()
    assert bom.total_assets == 1
    assert bom.total_findings == 1
    assert bom.unique_algorithms == ["RSA"]


# ---------------------------------------------------------------------------
# End-to-end: scanner -> CBOM -> risk -> summary (uses the real scanner)
# ---------------------------------------------------------------------------
def test_end_to_end_scanner_to_cbom_to_risk() -> None:
    from backend.risk import build_risk_summary
    from backend.scanners.source import SourceCodeScanner

    scan = SourceCodeScanner().scan_directory("data/sample")

    # 1. Scanner produced real findings.
    assert scan.files_scanned >= 1
    assert len(scan.assets) > 0

    # 2. CBOM from findings.
    bom = CBOMGenerator(project="Q-BITS-ECDAT demo").generate(scan)
    assert bom.total_findings == len(scan.assets)
    assert bom.total_assets <= bom.total_findings
    assert bom.unique_algorithms

    # 3. Risk assessments for every unique algorithm.
    assessments = risk_engine.assess_many(bom.unique_algorithms)
    assert len(assessments) == len(bom.unique_algorithms)
    assert all(a.overall_risk.value != "UNKNOWN" for a in assessments)

    # 4. Risk summary from the scanner findings.
    summary = build_risk_summary(scan.assets, risk_engine)
    assert summary.total_assets == len(scan.assets)
    assert (
        summary.critical_risk_assets
        + summary.high_risk_assets
        + summary.medium_risk_assets
        + summary.low_risk_assets
        + summary.unknown_risk_assets
        == summary.total_assets
    )
    assert summary.pqc_migration_candidates >= 1
    assert summary.immediate_migrations_required >= 1

    # 5. Everything is JSON serializable.
    import json

    json.dumps(bom.model_dump(mode="json"))
    json.dumps([a.model_dump(mode="json") for a in assessments])
    json.dumps(summary.model_dump(mode="json"))

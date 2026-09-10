"""Tests for deterministic assessment of the current CryptoFinding CBOM."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.cbom import generate_cbom
from backend.risk import assess_risk
from backend.scanners import CryptoFinding, CryptoScanner


def _cbom(algorithm: str, key_size: int | None = None):
    finding = CryptoFinding(
        id=f"src/main.py:1:1:{algorithm}",
        algorithm=algorithm,
        key_size=key_size,
        library=None,
        file="src/main.py",
        line=1,
        column=1,
        language="Python",
        code_snippet=algorithm,
        detection_method="test",
        confidence=0.9,
        category=None,
        usage_context="potential cryptographic usage",
    )
    return generate_cbom([finding])


def _assessment(algorithm: str, key_size: int | None = None):
    return assess_risk(_cbom(algorithm, key_size)).assessments[0]


def test_empty_cbom() -> None:
    report = assess_risk(generate_cbom([]))
    assert report.assets_assessed == 0
    assert report.risk_distribution == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "DES", "3DES"])
def test_deprecated_algorithms_are_p0_critical(algorithm: str) -> None:
    result = _assessment(algorithm)
    assert (result.risk_level, result.migration_priority, result.risk_score) == (
        "CRITICAL",
        "P0",
        100,
    )


def test_weak_rsa_is_critical() -> None:
    result = _assessment("RSA", 1024)
    assert (result.risk_level, result.migration_priority) == ("CRITICAL", "P0")


def test_stronger_rsa_is_high_and_pqc_relevant() -> None:
    result = _assessment("RSA", 2048)
    assert (result.risk_level, result.migration_priority, result.quantum_relevance) == (
        "HIGH",
        "P1",
        "HIGH",
    )


@pytest.mark.parametrize("algorithm", ["ECDSA", "ECC"])
def test_ecc_algorithms_are_high_pqc_migration_items(algorithm: str) -> None:
    result = _assessment(algorithm)
    assert (result.risk_level, result.quantum_relevance, result.migration_priority) == (
        "HIGH",
        "HIGH",
        "P1",
    )


def test_aes_is_not_claimed_broken_by_quantum_computing() -> None:
    result = _assessment("AES", 256)
    assert (result.risk_level, result.quantum_relevance, result.migration_priority) == (
        "LOW",
        "LIMITED",
        "P3",
    )
    assert "not classified as broken" in " ".join(result.reasons)


def test_missing_key_size_is_explicitly_unavailable() -> None:
    result = _assessment("RSA")
    assert "key_size" in result.factors.unavailable
    assert result.risk_level == "HIGH"


def test_multiple_algorithms_and_duplicate_assets() -> None:
    findings = [
        CryptoFinding(
            id="a:1",
            algorithm="MD5",
            file="main.py",
            line=1,
            detection_method="test",
            confidence=0.9,
        ),
        CryptoFinding(
            id="b:1",
            algorithm="RSA",
            key_size=2048,
            file="other.py",
            line=1,
            detection_method="test",
            confidence=0.9,
        ),
        CryptoFinding(
            id="b:1",
            algorithm="RSA",
            key_size=2048,
            file="other.py",
            line=1,
            detection_method="test",
            confidence=0.9,
        ),
    ]
    report = assess_risk(generate_cbom(findings))
    assert report.assets_assessed == 2
    assert report.risk_distribution["CRITICAL"] == 1
    assert report.risk_distribution["HIGH"] == 1


def test_repeated_execution_is_deterministic_and_json_serializable() -> None:
    cbom = _cbom("RSA", 2048)
    first = assess_risk(cbom)
    second = assess_risk(cbom)
    assert first == second
    assert json.loads(json.dumps(first.model_dump(mode="json")))["assets_assessed"] == 1


def test_demo_scanner_to_cbom_to_risk() -> None:
    target = Path(__file__).parents[2] / "data" / "sample" / "demo-target"
    findings = CryptoScanner().scan(target)
    report = assess_risk(generate_cbom(findings))
    assert len(findings) == 29
    assert report.assets_assessed == 13
    assert sum(report.risk_distribution.values()) == report.assets_assessed

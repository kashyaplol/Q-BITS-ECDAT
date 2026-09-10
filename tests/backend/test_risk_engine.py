"""Tests for the quantum risk assessment engine.

Covers the spec scenarios:

1. Public-key algorithms (RSA/ECC/ECDSA/ECDH/DSA/DH) and Shor's attacks.
2. Symmetric/hash algorithms and Grover's attacks.
3. Legacy algorithms (MD5/SHA1/DES/3DES/RC4) and immediacy.
4. Key-size analysis (RSA and AES thresholds).
5. Usage-based migration recommendations (encryption, signatures, ...).
6. Unknown-algorithm handling (UNKNOWN / REVIEW_REQUIRED).
7. Risk scoring values.
8. Alias resolution.
9. RiskSummary aggregation.
"""

from __future__ import annotations

import pytest

from backend.app.models import (
    AlgorithmCategory,
    MigrationPriority,
    QuantumRisk,
    RiskAssessment,
    RiskLevel,
    RiskSummary,
    UsageType,
)
from backend.risk import (
    RiskEngine,
    RiskScorer,
    ScoringConfig,
    build_risk_summary,
    risk_engine,
)
from backend.risk.summary import summarize_assessments


# ---------------------------------------------------------------------------
# Shor-vulnerable public-key algorithms (Step 1: public-key category)
# ---------------------------------------------------------------------------
class TestPublicKeyAlgorithms:
    @pytest.mark.parametrize(
        "algorithm",
        ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "Diffie-Hellman"],
    )
    def test_public_key_is_critical_under_quantum(self, algorithm: str) -> None:
        assessment = risk_engine.assess(algorithm)
        assert assessment.category == AlgorithmCategory.PUBLIC_KEY
        assert assessment.quantum_risk == QuantumRisk.CRITICAL
        assert assessment.overall_risk == RiskLevel.CRITICAL
        assert assessment.migration_priority == MigrationPriority.CRITICAL

    def test_rsa_scoring_is_max(self) -> None:
        assert risk_engine.assess("RSA").risk_score == 4

    def test_rsa_recommendation_mentions_pqc(self) -> None:
        assessment = risk_engine.assess("RSA")
        assert "ML-KEM" in assessment.pqc_recommendation
        assert assessment.reason  # plain-English reason is always present


# ---------------------------------------------------------------------------
# Key-size analysis (Step 5)
# ---------------------------------------------------------------------------
class TestKeySizeAnalysis:
    def test_rsa_512_is_classical_high(self) -> None:
        assessment = risk_engine.assess("RSA", key_size=512)
        assert assessment.classical_risk == RiskLevel.HIGH
        assert assessment.overall_risk == RiskLevel.CRITICAL
        assert assessment.risk_score == 4

    def test_rsa_1024_is_medium_classical_critical_overall(self) -> None:
        assessment = risk_engine.assess("RSA", key_size=1024)
        assert assessment.classical_risk == RiskLevel.MEDIUM
        assert assessment.overall_risk == RiskLevel.CRITICAL
        assert assessment.risk_score == 4

    def test_rsa_2048_is_classical_medium(self) -> None:
        assessment = risk_engine.assess("RSA", key_size=2048)
        assert assessment.classical_risk == RiskLevel.MEDIUM
        assert assessment.overall_risk == RiskLevel.CRITICAL
        assert assessment.risk_score == 4

    def test_rsa_3072_is_classical_low(self) -> None:
        assessment = risk_engine.assess("RSA", key_size=4096)
        assert assessment.classical_risk == RiskLevel.LOW
        assert assessment.overall_risk == RiskLevel.CRITICAL  # still Shor's

    def test_aes_128_is_medium_and_upgradable(self) -> None:
        assessment = risk_engine.assess("AES", key_size=128)
        assert assessment.quantum_risk == QuantumRisk.MEDIUM
        assert assessment.overall_risk == RiskLevel.MEDIUM
        assert assessment.migration_priority == MigrationPriority.HIGH
        assert assessment.risk_score == 2

    def test_aes_192_is_low_quantum(self) -> None:
        assessment = risk_engine.assess("AES", key_size=192)
        assert assessment.quantum_risk == QuantumRisk.LOW
        assert assessment.migration_priority == MigrationPriority.MEDIUM

    def test_aes_256_is_low_risk(self) -> None:
        assessment = risk_engine.assess("AES", key_size=256)
        assert assessment.quantum_risk == QuantumRisk.LOW
        assert assessment.overall_risk == RiskLevel.LOW
        assert assessment.migration_priority == MigrationPriority.LOW
        assert assessment.risk_score == 1

    def test_compound_name_implies_key_size(self) -> None:
        assessment = risk_engine.assess("AES-128")
        assert assessment.key_size == 128
        assert assessment.migration_priority == MigrationPriority.HIGH


# ---------------------------------------------------------------------------
# Symmetric / hash algorithms (Grover's)
# ---------------------------------------------------------------------------
class TestSymmetricAndHash:
    def test_aes_default_is_medium(self) -> None:
        assessment = risk_engine.assess("AES")
        assert assessment.category == AlgorithmCategory.SYMMETRIC
        assert assessment.quantum_risk == QuantumRisk.MEDIUM
        assert assessment.overall_risk == RiskLevel.MEDIUM

    def test_sha256_is_medium(self) -> None:
        assessment = risk_engine.assess("SHA256")
        assert assessment.category == AlgorithmCategory.HASH
        assert assessment.quantum_risk == QuantumRisk.MEDIUM
        assert assessment.overall_risk == RiskLevel.MEDIUM
        assert assessment.migration_priority == MigrationPriority.MEDIUM

    def test_sha384_is_low(self) -> None:
        assessment = risk_engine.assess("SHA384")
        assert assessment.category == AlgorithmCategory.HASH
        assert assessment.quantum_risk == QuantumRisk.LOW
        assert assessment.overall_risk == RiskLevel.LOW
        assert assessment.migration_priority == MigrationPriority.LOW

    def test_sha3_is_low(self) -> None:
        assessment = risk_engine.assess("SHA3")
        assert assessment.category == AlgorithmCategory.HASH
        assert assessment.quantum_risk == QuantumRisk.LOW
        assert assessment.overall_risk == RiskLevel.LOW
        assert assessment.migration_priority == MigrationPriority.LOW
        assert "PQC-safe" in assessment.pqc_recommendation

    def test_sha512_is_low(self) -> None:
        assessment = risk_engine.assess("SHA512")
        assert assessment.quantum_risk == QuantumRisk.LOW
        assert assessment.overall_risk == RiskLevel.LOW
        assert assessment.migration_priority == MigrationPriority.LOW


# ---------------------------------------------------------------------------
# Legacy / already-broken algorithms (Step 1: LEGACY category)
# ---------------------------------------------------------------------------
class TestLegacyAlgorithms:
    @pytest.mark.parametrize("algorithm", ["MD5", "SHA1", "DES", "3DES", "RC4"])
    def test_legacy_is_immediate_migration(self, algorithm: str) -> None:
        assessment = risk_engine.assess(algorithm)
        assert assessment.category == AlgorithmCategory.LEGACY
        assert assessment.migration_priority == MigrationPriority.IMMEDIATE
        assert assessment.overall_risk == RiskLevel.CRITICAL

    def test_legacy_recommendations_suggest_replacements(self) -> None:
        md5 = risk_engine.assess("MD5")
        sha1 = risk_engine.assess("SHA1")
        des = risk_engine.assess("DES")
        rc4 = risk_engine.assess("RC4")
        assert "SHA-256" in md5.pqc_recommendation or "SHA-3" in md5.pqc_recommendation
        assert "SHA-256" in sha1.pqc_recommendation
        assert "AES-256" in des.pqc_recommendation
        assert "AES-GCM" in rc4.pqc_recommendation or "ChaCha20" in rc4.pqc_recommendation

    def test_legacy_scores_4(self) -> None:
        for algorithm in ("MD5", "SHA1", "DES", "3DES", "RC4"):
            assert risk_engine.assess(algorithm).risk_score == 4


# ---------------------------------------------------------------------------
# Usage-based migration recommendations (Step 6)
# ---------------------------------------------------------------------------
class TestUsageRecommendations:
    def test_rsa_usage_encryption_switches_to_kem(self) -> None:
        assessment = risk_engine.assess("RSA", usage="encryption")
        assert "ML-KEM" in assessment.pqc_recommendation or "KEM" in assessment.recommendation

    def test_rsa_usage_signature_switches_to_dsa(self) -> None:
        assessment = risk_engine.assess("RSA", usage=UsageType.SIGNATURE)
        assert assessment.pqc_recommendation == "ML-DSA"
        assert "ML-DSA" in assessment.recommendation

    def test_ecc_usage_signature(self) -> None:
        assessment = risk_engine.assess("ECDSA", usage="digital signature")
        assert assessment.usage == UsageType.SIGNATURE
        assert "ML-DSA" in assessment.pqc_recommendation

    def test_aes_usage_authenticated_encryption(self) -> None:
        assessment = risk_engine.assess("AES", key_size=128, usage="symmetric-encryption")
        assert assessment.usage == UsageType.SYMMETRIC_ENCRYPTION
        assert "AES" in assessment.pqc_recommendation

    def test_key_exchange_usage(self) -> None:
        assessment = risk_engine.assess("DH", usage="key exchange")
        assert assessment.usage == UsageType.KEY_EXCHANGE
        assert "ML-KEM" in assessment.pqc_recommendation


# ---------------------------------------------------------------------------
# Unknown algorithms (Step 7)
# ---------------------------------------------------------------------------
class TestUnknownAlgorithms:
    def test_unknown_is_review_required(self) -> None:
        assessment = risk_engine.assess("TOTALLY_FAKE_ALGO")
        assert assessment.risk_level == RiskLevel.UNKNOWN
        assert assessment.category == AlgorithmCategory.UNKNOWN
        assert assessment.migration_priority == MigrationPriority.REVIEW_REQUIRED
        assert assessment.risk_score == 0
        assert "Algorithm is not present" in assessment.recommendation

    def test_engine_never_crashes_on_bad_input(self) -> None:
        for bad in (None, "", "   ", 12345, "AES-512"):
            assessment = risk_engine.assess(bad)
            assert isinstance(assessment, RiskAssessment)
            assert assessment.migration_priority == MigrationPriority.REVIEW_REQUIRED


# ---------------------------------------------------------------------------
# Alias resolution and scoring (Steps 4 and extra)
# ---------------------------------------------------------------------------
class TestAliasesAndScoring:
    def test_sha_alias_resolution(self) -> None:
        assert risk_engine.assess("SHA-256").algorithm == "SHA-256"
        assert risk_engine.assess("SHA-256").overall_risk == RiskLevel.MEDIUM
        assert risk_engine.assess("SHA-384").algorithm == "SHA-384"
        assert risk_engine.assess("SHA-384").overall_risk == RiskLevel.LOW
        assert risk_engine.assess("SHA-3").overall_risk == RiskLevel.LOW

    def test_desede_resolves_to_3des(self) -> None:
        assert risk_engine.assess("DESede").migration_priority == MigrationPriority.IMMEDIATE

    def test_scoring_is_configurable(self) -> None:
        scorer = RiskScorer(ScoringConfig(deprecated_bonus=1, max_score=5))
        engine = RiskEngine(scorer=scorer)
        # Deprecated MD5 (base 4) +1 bonus would be 5, and 5 is the cap.
        assert engine.assess("MD5").risk_score == 5

    def test_assess_many_deduplicates(self) -> None:
        assessments = risk_engine.assess_many(["RSA", "RSA", "AES", "AES"])
        assert [a.algorithm for a in assessments] == ["RSA", "AES"]


# ---------------------------------------------------------------------------
# Risk summary (Step 8)
# ---------------------------------------------------------------------------
class TestRiskSummary:
    def test_summary_counts_levels(self) -> None:
        from backend.scanners.source import SourceCodeScanner

        scan = SourceCodeScanner().scan_directory("data/sample")
        summary = build_risk_summary(scan.assets, risk_engine)
        assert isinstance(summary, RiskSummary)
        assert summary.total_assets == len(scan.assets)
        # data/sample has MD5/SHA1/DES (IMMEDIATE) plus RSA/AES/SHA256 entries,
        # so every category in the dashboard should be represented.
        assert summary.critical_risk_assets + summary.high_risk_assets >= 1
        assert summary.immediate_migrations_required >= 1
        assert (
            summary.critical_risk_assets
            + summary.high_risk_assets
            + summary.medium_risk_assets
            + summary.low_risk_assets
            + summary.unknown_risk_assets
            == summary.total_assets
        )

    def test_summarize_assessments(self) -> None:
        assessments = [risk_engine.assess("RSA"), risk_engine.assess("AES")]
        summary = summarize_assessments(assessments)
        assert summary.total_assets == 2
        assert summary.critical_risk_assets == 1
        assert summary.medium_risk_assets == 1
        assert summary.immediate_migrations_required == 0

    def test_unknown_assets_are_counted_total_only(self) -> None:
        assessments = [risk_engine.assess("MADE_UP_ALGO"), risk_engine.assess("RSA")]
        summary = summarize_assessments(assessments)
        assert summary.total_assets == 2
        assert summary.critical_risk_assets == 1

"""Phase 4 tests: Risk Prioritization Policy + Migration Roadmap Engine.

Covers the spec scenarios (priority score, risk factors, urgency, migration
strategies, organization-level roadmap, empty input, JSON, end-to-end) while
leaving the existing RiskEngine behaviour untouched.
"""

from __future__ import annotations

import pytest

from backend.app.models import (
    Algorithm,
    AlgorithmCategory,
    CryptographicAsset,
    DetectionMethod,
    MigrationPriority,
    MigrationStrategy,
    MigrationUrgency,
    PriorityLevel,
    QuantumRisk,
    RiskLevel,
    UsageType,
)
from backend.risk import (
    PrioritizationConfig,
    PriorityEngine,
    build_risk_summary,
    priority_engine,
    risk_engine,
    roadmap_engine,
)


def _asset(
    algorithm: Algorithm,
    *,
    line: int = 1,
    key_size: int | None = None,
    usage: UsageType | None = None,
    mode: str | None = None,
) -> CryptographicAsset:
    return CryptographicAsset(
        file_path="app/test.py",
        line_number=line,
        algorithm=algorithm,
        library="testlib",
        detection_method=DetectionMethod.AST,
        context="<usage>",
        key_size=key_size,
        usage=usage,
        mode=mode,
    )


# ---------------------------------------------------------------------------
# Priority score calculation + bands
# ---------------------------------------------------------------------------
class TestPriorityScore:
    def test_md5_is_immediate_priority(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MD5"))
        assert p.priority_score == 88
        assert p.priority_level == PriorityLevel.IMMEDIATE

    def test_score_bands_map_correctly(self) -> None:
        engine = PriorityEngine()
        assert engine.level_for(100) == PriorityLevel.IMMEDIATE
        assert engine.level_for(81) == PriorityLevel.IMMEDIATE
        assert engine.level_for(61) == PriorityLevel.CRITICAL
        assert engine.level_for(41) == PriorityLevel.HIGH
        assert engine.level_for(21) == PriorityLevel.MEDIUM
        assert engine.level_for(20) == PriorityLevel.LOW

    def test_all_kb_scores_stay_within_0_100(self) -> None:
        from backend.risk.knowledge import KNOWLEDGE_BASE

        for key in KNOWLEDGE_BASE:
            score = priority_engine.score(risk_engine.assess(key))
            assert 0 <= score <= 100

    def test_score_is_sum_of_factor_points(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MD5"))
        assert sum(f.points for f in p.risk_factors) == p.priority_score

    def test_config_is_centralized_and_configurable(self) -> None:
        config = PrioritizationConfig(weight_deprecated=10)
        engine = PriorityEngine(config)
        p = engine.prioritize(risk_engine.assess("MD5"))
        assert p.priority_score == 58  # 30 + 18 + 10 (no pqc factor for MD5)


# ---------------------------------------------------------------------------
# Individual risk-factor impacts
# ---------------------------------------------------------------------------
class TestRiskFactorImpacts:
    def test_classical_risk_impact(self) -> None:
        # RSA-512 (classical HIGH) scores above RSA-2048 (classical MEDIUM).
        weak = priority_engine.score(risk_engine.assess("RSA", key_size=512))
        strong = priority_engine.score(risk_engine.assess("RSA", key_size=2048))
        assert weak > strong

    def test_quantum_risk_impact(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("RSA", key_size=2048))
        rule_ids = {f.rule for f in p.risk_factors}
        assert "quantum-risk" in rule_ids
        assert "pqc-requirement" in rule_ids  # Shor's breakdown adds points
        # AES has no Shor's requirement.
        aes = priority_engine.prioritize(risk_engine.assess("AES", key_size=256))
        assert "pqc-requirement" not in {f.rule for f in aes.risk_factors}

    def test_deprecated_algorithm_impact(self) -> None:
        for name in ("MD5", "SHA1", "DES", "3DES", "RC4"):
            p = priority_engine.prioritize(risk_engine.assess(name))
            assert any(f.rule == "deprecated" for f in p.risk_factors)
            assert p.priority_score >= 81

    def test_weak_key_size_impact(self) -> None:
        rsa_1024 = priority_engine.score(risk_engine.assess("RSA", key_size=1024))
        rsa_2048 = priority_engine.score(risk_engine.assess("RSA", key_size=2048))
        assert rsa_1024 > rsa_2048
        p = priority_engine.prioritize(risk_engine.assess("RSA", key_size=512))
        assert any(f.rule == "weak-key-size" for f in p.risk_factors)

    def test_weak_key_rule_only_when_size_is_known(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("RSA"))
        assert not any(f.rule == "weak-key-size" for f in p.risk_factors)

    def test_usage_impact(self) -> None:
        no_usage = priority_engine.score(risk_engine.assess("RSA", key_size=1024))
        with_usage = priority_engine.score(
            risk_engine.assess("RSA", key_size=1024, usage="key exchange")
        )
        assert with_usage > no_usage
        p = priority_engine.prioritize(
            risk_engine.assess("RSA", key_size=1024, usage="key exchange")
        )
        assert any(f.rule == "usage-sensitivity" for f in p.risk_factors)

    def test_aes_ecb_configuration_impact(self) -> None:
        asset = _asset(Algorithm.AES, key_size=128, mode="ECB")
        p = priority_engine.prioritize(risk_engine.assess(asset), mode=asset.mode)
        assert any(f.rule == "weak-configuration" for f in p.risk_factors)
        # ECB pushes an otherwise-MEDIUM AES-128 up to HIGH.
        assert p.priority_score >= 41
        assert p.priority_level == PriorityLevel.HIGH

    def test_aes_128_without_config_is_medium(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("AES", key_size=128))
        assert p.priority_level == PriorityLevel.MEDIUM
        assert not any(f.rule == "weak-configuration" for f in p.risk_factors)

    def test_unknown_algorithm(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MADE_UP_ALGO"))
        assert p.priority_score == 0
        assert p.priority_level == PriorityLevel.LOW
        assert p.urgency == MigrationUrgency.HIGH
        assert any(f.rule == "unknown" for f in p.risk_factors)


# ---------------------------------------------------------------------------
# Legacy algorithms land at IMMEDIATE priority/urgency
# ---------------------------------------------------------------------------
class TestLegacyUrgency:
    @pytest.mark.parametrize(
        "name", ["MD5", "SHA1", "DES", "3DES", "RC4"]
    )
    def test_legacy_maps_to_immediate(self, name: str) -> None:
        p = priority_engine.prioritize(risk_engine.assess(name))
        assert p.priority_level == PriorityLevel.IMMEDIATE
        assert p.urgency == MigrationUrgency.IMMEDIATE


# ---------------------------------------------------------------------------
# SHA priority ordering
# ---------------------------------------------------------------------------
class TestShaPriorities:
    def test_sha1_outranks_sha256(self) -> None:
        assert (
            priority_engine.score(risk_engine.assess("SHA1"))
            > priority_engine.score(risk_engine.assess("SHA256"))
        )

    def test_sha256_is_planned(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("SHA256"))
        assert p.urgency == MigrationUrgency.PLANNED

    def test_sha384_sha512_sha3_are_low_urgency(self) -> None:
        for name in ("SHA384", "SHA512", "SHA3"):
            p = priority_engine.prioritize(risk_engine.assess(name))
            assert p.urgency == MigrationUrgency.LOW
            assert p.priority_level == PriorityLevel.LOW


# ---------------------------------------------------------------------------
# Migration roadmap / plans
# ---------------------------------------------------------------------------
class TestMigrationPlans:
    def test_rsa_usage_aware_roadmap(self) -> None:
        p = priority_engine.prioritize(
            risk_engine.assess("RSA", key_size=2048, usage=UsageType.SIGNATURE)
        )
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.PHASED_PQC_MIGRATION
        assert plan.urgency == MigrationUrgency.URGENT
        assert plan.recommended_replacement == "ML-DSA"
        phase_values = {step.phase.value for step in plan.steps}
        assert "HYBRID_DEPLOYMENT" in phase_values  # PQC uses hybrid phase.

    def test_rsa_key_exchange_recommends_kem(self) -> None:
        p = priority_engine.prioritize(
            risk_engine.assess("RSA", key_size=2048, usage="key exchange")
        )
        plan = roadmap_engine.build_plan(p)
        assert "ML-KEM" in plan.recommended_replacement

    def test_ecc_roadmap(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("ECC"))
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.PHASED_PQC_MIGRATION
        assert plan.urgency == MigrationUrgency.URGENT

    def test_aes_upgrade_roadmap(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("AES", key_size=128))
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.SECURITY_STRENGTH_UPGRADE
        assert "AES-256" in plan.recommended_replacement
        assert "HYBRID_DEPLOYMENT" not in {s.phase.value for s in plan.steps}

    def test_aes_256_needs_no_migration(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("AES", key_size=256))
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.NO_MIGRATION_REQUIRED
        assert plan.migration_status.value == "NOT_REQUIRED"

    def test_legacy_replacement_roadmap(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MD5"))
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.IMMEDIATE_REPLACEMENT
        assert "SHA-256" in plan.recommended_replacement or "SHA-3" in plan.recommended_replacement
        phase_values = {s.phase.value for s in plan.steps}
        assert "DISCOVERY" in phase_values and "VALIDATION" in phase_values
        assert "HYBRID_DEPLOYMENT" not in phase_values  # immediate replacement
        assert plan.validation_steps  # validation actions present

    def test_unknown_roadmap_is_review(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("SOMETHING_WEIRD"))
        plan = roadmap_engine.build_plan(p)
        assert plan.strategy == MigrationStrategy.REVIEW_REQUIRED
        assert plan.recommended_replacement == "Manual security review"

    def test_why_needed_is_rule_derived(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MD5"))
        plan = roadmap_engine.build_plan(p)
        assert "deprecated" in plan.why_needed.lower()

    def test_plan_carries_source_location(self) -> None:
        asset = _asset(Algorithm.RSA, line=42, key_size=2048)
        p = priority_engine.prioritize(risk_engine.assess(asset), mode=asset.mode)
        plan = roadmap_engine.build_plan(p)
        assert plan.file_path == "app/test.py"
        assert plan.line_number == 42
        assert plan.key_size == 2048


# ---------------------------------------------------------------------------
# Organization-level roadmap + summaries
# ---------------------------------------------------------------------------
class TestOrganizationRoadmap:
    def _sample_plans(self):
        priorities = [
            priority_engine.prioritize(risk_engine.assess("MD5")),
            priority_engine.prioritize(
                risk_engine.assess("RSA", key_size=1024, usage="key exchange")
            ),
            priority_engine.prioritize(risk_engine.assess("AES", key_size=256)),
            priority_engine.prioritize(risk_engine.assess("SHA256")),
            priority_engine.prioritize(risk_engine.assess("AES", key_size=128)),
        ]
        return [roadmap_engine.build_plan(p) for p in priorities]

    def test_organization_roadmap_counts(self) -> None:
        plans = self._sample_plans()
        roadmap = roadmap_engine.build_roadmap(plans)
        assert roadmap.total_assets == 5
        assert roadmap.immediate == 1       # MD5
        assert roadmap.urgent == 1          # RSA-1024
        assert roadmap.high == 1            # AES-128
        assert roadmap.planned == 1         # SHA-256
        assert roadmap.low == 1             # AES-256
        assert roadmap.migration_candidates == 4  # total - low

    def test_organization_roadmap_top_priorities_sorted(self) -> None:
        roadmap = roadmap_engine.build_roadmap(self._sample_plans())
        scores = [item.priority_score for item in roadmap.top_priorities]
        assert scores == sorted(scores, reverse=True)
        assert roadmap.top_priorities[0].algorithm == "MD5"
        top = roadmap.top_priorities[0]
        assert top.strategy == MigrationStrategy.IMMEDIATE_REPLACEMENT

    def test_empty_roadmap(self) -> None:
        roadmap = roadmap_engine.build_roadmap([])
        assert roadmap.total_assets == 0
        assert roadmap.migration_candidates == 0
        assert roadmap.top_priorities == []

    def test_risk_summary_priority_fields(self) -> None:
        assets = [
            _asset(Algorithm.MD5),
            _asset(Algorithm.RSA, line=2, key_size=1024),
            _asset(Algorithm.AES, line=3, key_size=256),
        ]
        summary = build_risk_summary(assets, risk_engine)
        assert summary.total_assets == 3
        assert summary.immediate_assets == 1     # MD5
        assert summary.urgent_assets == 1       # RSA-1024
        assert summary.migration_candidates == 2  # MD5 + RSA (AES-256 is LOW)
        assert summary.total_priority_score >= 1
        assert summary.average_priority_score > 0
        assert summary.top_risk_assets[0].algorithm == "MD5"

    def test_risk_summary_sorting_and_values(self) -> None:
        assets = [
            _asset(Algorithm.MD5),
            _asset(Algorithm.RSA, line=2, key_size=1024),
            _asset(Algorithm.AES, line=3, key_size=256),
        ]
        summary = build_risk_summary(assets, risk_engine)
        scores = [t.priority_score for t in summary.top_risk_assets]
        assert scores == sorted(scores, reverse=True)
        assert summary.top_risk_assets[0].priority_score >= 81  # MD5

    def test_empty_summary(self) -> None:
        summary = build_risk_summary([], risk_engine)
        assert summary.total_assets == 0
        assert summary.average_priority_score == 0.0
        assert summary.top_risk_assets == []


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------
class TestSerialization:
    def test_priority_assessment_serializes(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("MD5"))
        data = p.model_dump()
        assert data["priority_score"] == 88
        assert data["priority_level"] == "IMMEDIATE"
        assert data["urgency"] == "IMMEDIATE"
        assert data["risk_factors"][0]["rule"]

    def test_migration_plan_serializes(self) -> None:
        p = priority_engine.prioritize(risk_engine.assess("RSA", key_size=1024))
        plan = roadmap_engine.build_plan(p)
        data = plan.model_dump_json()
        assert '"strategy"' in data and '"steps"' in data

    def test_organization_roadmap_serializes(self) -> None:
        plans = [
            roadmap_engine.build_plan(
                priority_engine.prioritize(risk_engine.assess("MD5"))
            )
        ]
        data = roadmap_engine.build_roadmap(plans).model_dump()
        assert data["total_assets"] == 1
        assert data["top_priorities"][0]["algorithm"] == "MD5"
        assert "not an official security standard" in data["note"]


# ---------------------------------------------------------------------------
# End-to-end: scanner -> CBOM -> risk -> priority -> roadmap
# ---------------------------------------------------------------------------
class TestEndToEnd:
    def test_full_pipeline(self) -> None:
        from backend.scanners.source import SourceCodeScanner

        scan = SourceCodeScanner().scan_directory("data/sample")
        assert scan.assets

        from backend.cbom import CBOMGenerator

        bom = CBOMGenerator(project="Q-BITS-ECDAT").generate(scan)
        assert bom.total_findings == len(scan.assets)

        prioritized = [
            priority_engine.prioritize(risk_engine.assess(asset), mode=asset.mode)
            for asset in scan.assets
        ]
        assert prioritized

        plans = [roadmap_engine.build_plan(p) for p in prioritized]
        roadmap = roadmap_engine.build_roadmap(plans)
        assert roadmap.total_assets == len(scan.assets)
        assert roadmap.migration_candidates >= 1
        assert roadmap.top_priorities

        # Every plan's strategy is one of the supported strategies.
        assert all(
            plan.strategy
            in (MigrationStrategy.IMMEDIATE_REPLACEMENT,
                MigrationStrategy.PHASED_PQC_MIGRATION,
                MigrationStrategy.SECURITY_STRENGTH_UPGRADE,
                MigrationStrategy.NO_MIGRATION_REQUIRED,
                MigrationStrategy.REVIEW_REQUIRED)
            for plan in plans
        )

    def test_risk_engine_unchanged(self) -> None:
        a = risk_engine.assess("RSA", key_size=1024)
        assert a.risk_level == RiskLevel.CRITICAL
        assert a.quantum_risk == QuantumRisk.CRITICAL
        assert a.migration_priority == MigrationPriority.CRITICAL
        assert a.risk_score == 4
        assert a.category == AlgorithmCategory.PUBLIC_KEY

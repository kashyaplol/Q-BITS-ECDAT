"""Quantum risk assessment engine.

The ``RiskEngine`` is the entry point for ALL risk logic:

* it can assess a raw algorithm name, a ``CryptographicAsset`` from the
  source scanner, or a CBOM entry,
* it looks every algorithm up in the knowledge base
  (``backend/risk/knowledge.py``), applies key-size rules and
  usage-specific recommendations,
* it computes a numerical risk score (``backend/risk/scoring.py``),
* unknown algorithms are reported as UNKNOWN with
  ``MigrationPriority.REVIEW_REQUIRED`` -- the engine never crashes on
  input it has not seen before.

The engine is pure (no I/O, no state), which keeps it trivial to test
and safe to share as a singleton.
"""

from __future__ import annotations

from backend.app.models import (
    AlgorithmCategory,
    CryptographicAsset,
    MigrationPriority,
    QuantumRisk,
    RiskAssessment,
    RiskLevel,
    UsageType,
)
from backend.risk.knowledge import (
    KNOWLEDGE_BASE,
    PQC_BY_USAGE,
    RiskProfile,
    apply_key_size_classical,
    apply_key_size_priority,
    apply_key_size_quantum,
    as_name,
    get_profile,
    resolve_algorithm,
)
from backend.risk.scoring import RiskScorer

# Message used whenever an algorithm is not in the knowledge base.
_UNKNOWN_RECOMMENDATION = (
    "Algorithm is not present in the current risk knowledge base. "
    "Manual security review is recommended."
)


class RiskEngine:
    """Pure service that turns algorithms/assets into risk assessments."""

    def __init__(self, scorer: RiskScorer | None = None) -> None:
        self.scorer = scorer or RiskScorer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def assess(
        self,
        algorithm: str | CryptographicAsset | object,
        key_size: int | None = None,
        usage: str | UsageType | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> RiskAssessment:
        """Assess a single piece of cryptography.

        ``algorithm`` accepts either a name (``"RSA"``, ``"AES-128"``) or
        a ``CryptographicAsset`` produced by the source scanner. When an
        asset is passed, its file path / line number are carried over
        automatically.

        Extra, optional context:
            key_size:   RSA/AES key size in bits, if known.
            usage:      How the crypto is used ("encryption", "signature", ...).
            file_path / line_number: source location for the report.
        """
        # Allow passing a scanned asset directly: risk_engine.assess(asset).
        if isinstance(algorithm, CryptographicAsset):
            asset = algorithm
            if key_size is None:
                key_size = getattr(asset, "key_size", None)
            if usage is None:
                usage = getattr(asset, "usage", None)
            if file_path is None:
                file_path = asset.file_path
            if line_number is None:
                line_number = asset.line_number
            algorithm = asset.algorithm

        # Resolve the name to a canonical knowledge-base key (+ key hint).
        canonical, implied_key_size = resolve_algorithm(algorithm)
        effective_key_size = key_size if key_size is not None else implied_key_size
        usage_parsed = self._parse_usage(usage)

        profile = get_profile(canonical)
        if profile is None:
            return self._unknown_assessment(
                display_name=self._display_name(algorithm, canonical),
                key_size=effective_key_size,
                usage=usage_parsed,
                file_path=file_path,
                line_number=line_number,
            )

        # Apply key-size rules to the baseline risks (Step 5).
        classical = apply_key_size_classical(profile, effective_key_size)
        quantum = apply_key_size_quantum(profile, effective_key_size)
        priority = apply_key_size_priority(profile, effective_key_size)

        overall = self._worst(classical, quantum)
        score = self.scorer.compute(classical, quantum, deprecated=profile.deprecated)

        recommendation, pqc = self._recommendations(profile, usage_parsed)

        return RiskAssessment(
            algorithm=self._display_name(algorithm, canonical),
            category=profile.category,
            classical_risk=classical,
            quantum_risk=quantum,
            risk_level=overall,
            overall_risk=overall,
            risk_score=score,
            migration_priority=priority,
            recommendation=recommendation,
            pqc_recommendation=pqc,
            reason=profile.reason,
            key_size=effective_key_size,
            usage=usage_parsed,
            file_path=file_path,
            line_number=line_number,
        )

    def assess_many(
        self, algorithms: list[str | CryptographicAsset | object]
    ) -> list[RiskAssessment]:
        """Assess a list of inputs, de-duplicated, in first-seen order."""
        seen: dict[tuple[str, int | None], RiskAssessment] = {}
        for item in algorithms:
            datum = item.algorithm if isinstance(item, CryptographicAsset) else item
            canonical, key_hint = resolve_algorithm(datum)
            seen.setdefault((canonical, key_hint), self.assess(item))
        return list(seen.values())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _unknown_assessment(
        self,
        display_name: str,
        key_size: int | None,
        usage: UsageType | None,
        file_path: str | None,
        line_number: int | None,
    ) -> RiskAssessment:
        """Build a safe UNKNOWN assessment for an unrecognized algorithm."""
        return RiskAssessment(
            algorithm=display_name,
            category=AlgorithmCategory.UNKNOWN,
            classical_risk=RiskLevel.UNKNOWN,
            quantum_risk=QuantumRisk.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            overall_risk=RiskLevel.UNKNOWN,
            risk_score=0,
            migration_priority=MigrationPriority.REVIEW_REQUIRED,
            recommendation=_UNKNOWN_RECOMMENDATION,
            pqc_recommendation="Manual review required",
            reason="Algorithm not found in the risk knowledge base.",
            key_size=key_size,
            usage=usage,
            file_path=file_path,
            line_number=line_number,
        )

    @staticmethod
    def _display_name(raw: object, canonical: str) -> str:
        """Pick a readable name: the raw input when it differs / is meaningful."""
        text = as_name(raw).strip()
        return text if text else canonical

    @staticmethod
    def _worst(classical: RiskLevel, quantum: QuantumRisk) -> RiskLevel:
        """Overall risk = the worst of the classical and quantum dimensions."""
        order = {
            RiskLevel.UNKNOWN: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        c, q = order[classical], order[RiskLevel(quantum.value)]
        return classical if c >= q else RiskLevel(quantum.value)

    def _recommendations(
        self, profile: RiskProfile, usage: UsageType | None
    ) -> tuple[str, str]:
        """Pick usage-specific recommendation + PQC text when available."""
        recommendation = profile.recommendation
        pqc = profile.pqc_recommendation

        if usage is None or usage == UsageType.UNKNOWN:
            return recommendation, pqc

        key = usage.value
        recommendation = profile.usage_recommendation.get(key, recommendation)
        # Prefer the profile's usage override; fall back to the generic map.
        pqc = profile.usage_pqc.get(key, PQC_BY_USAGE.get(usage, pqc))
        return recommendation, pqc

    @staticmethod
    def _parse_usage(usage: str | UsageType | None) -> UsageType | None:
        """Normalise free-text usage descriptions into a UsageType."""
        if usage is None:
            return None
        if isinstance(usage, UsageType):
            return usage

        normalized = "".join(ch for ch in str(usage).lower() if ch.isalnum())
        mapping = {
            "encryption": UsageType.ENCRYPTION,
            "encrypt": UsageType.ENCRYPTION,
            "decryption": UsageType.DECRYPTION,
            "decrypt": UsageType.DECRYPTION,
            "keyexchange": UsageType.KEY_EXCHANGE,
            "keyagreement": UsageType.KEY_EXCHANGE,
            "keyestablishment": UsageType.KEY_EXCHANGE,
            "keyestablisment": UsageType.KEY_EXCHANGE,  # tolerate a typo
            "keygeneration": UsageType.KEY_GENERATION,
            "signature": UsageType.SIGNATURE,
            "signing": UsageType.SIGNATURE,
            "digitalsignature": UsageType.SIGNATURE,
            "sign": UsageType.SIGNATURE,
            "signatureverification": UsageType.SIGNATURE_VERIFICATION,
            "verify": UsageType.SIGNATURE_VERIFICATION,
            "hashing": UsageType.HASHING,
            "hash": UsageType.HASHING,
            "digest": UsageType.HASHING,
            "symmetric": UsageType.SYMMETRIC_ENCRYPTION,
            "symmetricencryption": UsageType.SYMMETRIC_ENCRYPTION,
        }
        return mapping.get(normalized, UsageType.UNKNOWN)


# Single shared, stateless instance.
risk_engine = RiskEngine()

# Backwards-compatible alias: the knowledge base table.
RISK_PROFILES = KNOWLEDGE_BASE

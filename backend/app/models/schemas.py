"""Data models for the ECDAT application.

These Pydantic models define the shape of the data that flows
through the system:

* ``CryptographicAsset``   - one detected crypto usage in a file
* ``ScanResult``           - the output of running a scanner
* ``CBOMEntry``            - one entry in the CBOM report
* ``CBOM``                 - the full Cryptographic Bill of Materials
* ``RiskAssessment``       - quantum-risk details for one algorithm
* ``RiskSummary``          - risk-count roll-up for the dashboard
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enums -- shared vocabulary so values stay consistent across modules
# ---------------------------------------------------------------------------
class Algorithm(str, Enum):
    """Cryptographic algorithms the scanner/risk engine can handle."""

    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    SHA3 = "SHA3"
    AES = "AES"
    AES_128 = "AES-128"
    AES_192 = "AES-192"
    AES_256 = "AES-256"
    DES = "DES"
    TRIPLE_DES = "3DES"
    RC4 = "RC4"
    RSA = "RSA"
    ECC = "ECC"
    ECDSA = "ECDSA"
    ECDH = "ECDH"
    DSA = "DSA"
    DH = "Diffie-Hellman"


class DetectionMethod(str, Enum):
    """How a piece of crypto usage was found."""

    REGEX = "regex"
    KEYWORD = "keyword"
    PATTERN = "pattern"
    AST = "ast"
    HYBRID = "hybrid"  # the same usage was found by regex AND AST


class RiskLevel(str, Enum):
    """Risk categories used across the project."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value


class QuantumRisk(str, Enum):
    """How vulnerable an algorithm is to quantum attacks.

    Values mirror ``RiskLevel`` but the separate type makes it explicit
    that this dimension is purely about quantum-vulnerability.
    """

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlgorithmCategory(str, Enum):
    """Family/category a cryptographic algorithm belongs to."""

    PUBLIC_KEY = "PUBLIC_KEY"
    SYMMETRIC = "SYMMETRIC"
    HASH = "HASH"
    LEGACY = "LEGACY"
    UNKNOWN = "UNKNOWN"


class UsageType(str, Enum):
    """How a piece of cryptography is used in the code."""

    ENCRYPTION = "ENCRYPTION"
    DECRYPTION = "DECRYPTION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    KEY_GENERATION = "KEY_GENERATION"
    SIGNATURE = "SIGNATURE"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    SIGNATURE_VERIFICATION = "SIGNATURE_VERIFICATION"
    HASHING = "HASHING"
    SYMMETRIC_ENCRYPTION = "SYMMETRIC_ENCRYPTION"
    UNKNOWN = "UNKNOWN"


class MigrationPriority(str, Enum):
    """Priority for moving an algorithm to post-quantum crypto."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    IMMEDIATE = "IMMEDIATE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class PriorityLevel(str, Enum):
    """Levels produced by the Q-BITS-ECDAT Risk Prioritization Policy.

    Derived from a 0-100 priority score:

        IMMEDIATE   81 - 100
        CRITICAL    61 -  80
        HIGH        41 -  60
        MEDIUM      21 -  40
        LOW          0 -  20

    This is a policy-based prioritization aid for the tool, **not** an
    official security standard or guaranteed security rating.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    IMMEDIATE = "IMMEDIATE"


class MigrationUrgency(str, Enum):
    """How urgently an asset should be migrated (roadmap timeline).

    Distinct from ``PriorityLevel``: it maps the asset onto the
    migration timeline rather than a score band.
    """

    IMMEDIATE = "IMMEDIATE"  # legacy / broken algorithms (MD5, DES, RC4, ...)
    URGENT = "URGENT"        # quantum-vulnerable public-key algorithms (RSA, ECC, ...)
    HIGH = "HIGH"            # weak configurations / key sizes
    PLANNED = "PLANNED"      # long-term modernization (e.g. SHA-256, AES-128)
    LOW = "LOW"              # strong, modern cryptography


class MigrationStatus(str, Enum):
    """Lifecycle status of an asset-level migration plan."""

    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    NOT_REQUIRED = "NOT_REQUIRED"


class MigrationStrategy(str, Enum):
    """High-level strategy a ``MigrationPlan`` uses."""

    IMMEDIATE_REPLACEMENT = "IMMEDIATE_REPLACEMENT"
    PHASED_PQC_MIGRATION = "PHASED_PQC_MIGRATION"
    SECURITY_STRENGTH_UPGRADE = "SECURITY_STRENGTH_UPGRADE"
    NO_MIGRATION_REQUIRED = "NO_MIGRATION_REQUIRED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class MigrationPhase(str, Enum):
    """Reusable step in the migration lifecycle."""

    DISCOVERY = "DISCOVERY"
    ASSESSMENT = "ASSESSMENT"
    PREPARATION = "PREPARATION"
    PILOT = "PILOT"
    HYBRID_DEPLOYMENT = "HYBRID_DEPLOYMENT"
    FULL_MIGRATION = "FULL_MIGRATION"
    VALIDATION = "VALIDATION"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------
class CryptographicAsset(BaseModel):
    """A single detected use of cryptography inside some source code.

    Attributes:
        file_path:   Path of the file where the usage was found.
        line_number: 1-based line number of the match.
        algorithm:   Detected algorithm (see ``Algorithm`` enum).
        library:     Programming library / module used (e.g. "hashlib").
        detection_method: How the match was found (regex, pattern, ...).
        context:     Short snippet of the matching source line.
        key_size:    Key size in bits, when the AST could determine it.
        usage:       What the crypto is used for (from AST call structure).
        curve:       Elliptic-curve name (e.g. SECP256R1), when available.
        mode:        Block-cipher mode (e.g. GCM / CBC), when available.
    """

    file_path: str
    line_number: int
    algorithm: Algorithm
    library: str | None = None
    detection_method: DetectionMethod
    context: str | None = None
    key_size: int | None = None
    usage: UsageType | None = None
    curve: str | None = None
    mode: str | None = None


class ScanResult(BaseModel):
    """The structured result produced by a scanner run."""

    scanned_path: str
    files_scanned: int = 0
    assets: list[CryptographicAsset] = Field(default_factory=list)
    # Per-algorithm counts: {"RSA": 3, "AES": 1, ...}
    algorithm_counts: dict[str, int] = Field(default_factory=dict)
    # Files the AST scanner could not parse (they still got regex scanning).
    parse_errors: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CBOMEntry(BaseModel):
    """A single aggregated entry inside the CBOM report.

    Groups together all occurrences of the same algorithm+library
    combination within one file, while preserving the scanner evidence
    (line numbers, detection methods and source snippets).
    """

    algorithm: Algorithm
    library: str | None = None
    file: str
    occurrences: int = 1
    risk_level: RiskLevel = RiskLevel.MEDIUM
    line_numbers: list[int] = Field(default_factory=list)
    detection_methods: list[str] = Field(default_factory=list)
    contexts: list[str] = Field(default_factory=list)
    key_sizes: list[int] = Field(default_factory=list)
    usages: list[str] = Field(default_factory=list)
    curves: list[str] = Field(default_factory=list)
    modes: list[str] = Field(default_factory=list)


class CBOM(BaseModel):
    """Cryptographic Bill of Materials.

    Summarises the entire scan: which crypto is used where, plus
    totals to see the inventory at a glance.
    """

    project: str = "Unknown"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cryptographic_assets: list[CBOMEntry] = Field(default_factory=list)
    total_assets: int = 0
    total_findings: int = 0
    unique_algorithms: list[str] = Field(default_factory=list)
    high_risk_assets: int = 0
    medium_risk_assets: int = 0

    def build_summary(self) -> None:
        """Recalculate summary fields from ``cryptographic_assets``.

        Call this after populating ``cryptographic_assets`` so the
        totals match the entries.
        """
        self.total_assets = len(self.cryptographic_assets)
        self.total_findings = sum(entry.occurrences for entry in self.cryptographic_assets)
        algorithms = {entry.algorithm.value for entry in self.cryptographic_assets}
        self.unique_algorithms = sorted(algorithms)
        self.high_risk_assets = sum(
            1
            for entry in self.cryptographic_assets
            if entry.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )
        self.medium_risk_assets = sum(
            1 for entry in self.cryptographic_assets if entry.risk_level == RiskLevel.MEDIUM
        )


class RiskAssessment(BaseModel):
    """A complete risk assessment for one piece of cryptography.

    Attributes:
        algorithm:            Algorithm name (e.g. "RSA", "AES-128").
        category:             Algorithm family (public key, symmetric, ...).
        classical_risk:       Risk level with today's computers.
        quantum_risk:         Risk level against quantum computers.
        risk_level:           Overall risk (kept for backwards compatibility).
        overall_risk:         Same as ``risk_level`` (canonical name).
        risk_score:           Number 0-4 based on the risk dimensions.
        migration_priority:   Urgency of migrating away from the algorithm.
        recommendation:       Human-readable recommended action.
        recommended_action:   Alias of ``recommendation`` (kept for backwards
                              compatibility with earlier API clients).
        pqc_recommendation:   Suggested post-quantum replacement, e.g. ML-KEM.
        reason:               Plain-English explanation of the risks.
        key_size:             Algorithm key size, if provided by the user/scan.
        usage:                How the algorithm is used (encryption, signature, ...).
        file_path:            Where the usage was found (optional).
        line_number:          Line number of the usage (optional).
    """

    algorithm: str
    category: AlgorithmCategory = AlgorithmCategory.UNKNOWN
    classical_risk: RiskLevel = RiskLevel.UNKNOWN
    quantum_risk: QuantumRisk = QuantumRisk.UNKNOWN
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    overall_risk: RiskLevel = RiskLevel.UNKNOWN
    risk_score: int = 0
    migration_priority: MigrationPriority = MigrationPriority.REVIEW_REQUIRED
    recommendation: str = ""
    recommended_action: str | None = None
    pqc_recommendation: str = ""
    reason: str = ""
    key_size: int | None = None
    usage: UsageType | None = None
    file_path: str | None = None
    line_number: int | None = None

    @model_validator(mode="after")
    def _sync_legacy_fields(self) -> RiskAssessment:
        """Keep old-style fields in sync with their new counterparts.

        ``recommended_action`` is an alias of ``recommendation`` and
        ``risk_level`` is an alias of ``overall_risk``. Either spelling
        populated by the engine ends up mirrored in the other.
        """
        if self.recommended_action is None:
            self.recommended_action = self.recommendation
        if self.overall_risk is RiskLevel.UNKNOWN and self.risk_level is not RiskLevel.UNKNOWN:
            self.overall_risk = self.risk_level
        if self.risk_level is RiskLevel.UNKNOWN and self.overall_risk is not RiskLevel.UNKNOWN:
            self.risk_level = self.overall_risk
        return self


class RiskSummary(BaseModel):
    """Roll-up of risk counts for the dashboard / risk summary endpoint.

    Attributes:
        total_assets:                  Number of crypto assets assessed.
        critical_risk_assets:          Assets whose overall risk is CRITICAL.
        high_risk_assets:              Assets whose overall risk is HIGH.
        medium_risk_assets:            Assets whose overall risk is MEDIUM.
        low_risk_assets:               Assets whose overall risk is LOW.
        unknown_risk_assets:           Assets whose overall risk is UNKNOWN.
        immediate_migrations_required: Assets whose migration priority is IMMEDIATE.
        pqc_migration_candidates:      Assets whose migration priority >= HIGH.
        total_priority_score:          Sum of every asset's 0-100 priority score.
        average_priority_score:        ``total_priority_score`` / ``total_assets``.
        immediate_assets:              Assets whose migration urgency is IMMEDIATE.
        urgent_assets:                 Assets whose migration urgency is URGENT.
        high_priority_assets:          Assets whose migration urgency is HIGH.
        planned_assets:                Assets whose migration urgency is PLANNED.
        migration_candidates:          Assets requiring migration (urgency != LOW).
        top_risk_assets:               Top N assets by priority score (default 5).
    """

    total_assets: int = 0
    critical_risk_assets: int = 0
    high_risk_assets: int = 0
    medium_risk_assets: int = 0
    low_risk_assets: int = 0
    unknown_risk_assets: int = 0
    immediate_migrations_required: int = 0
    pqc_migration_candidates: int = 0
    total_priority_score: int = 0
    average_priority_score: float = 0.0
    immediate_assets: int = 0
    urgent_assets: int = 0
    high_priority_assets: int = 0
    planned_assets: int = 0
    migration_candidates: int = 0
    top_risk_assets: list[TopRiskAsset] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Risk prioritization + migration roadmap models (Phase 4)
# ---------------------------------------------------------------------------
class RiskFactor(BaseModel):
    """One explainable, rule-derived risk factor.

    Attributes:
        rule:   Stable policy-rule id the factor maps to (e.g. ``deprecated``).
        factor: Human-readable factor name.
        impact: Severity this factor contributes (""LOW"... "CRITICAL", "UNKNOWN").
        reason: Rule-generated explanation (never filler text).
        points: Points this factor contributes to the 0-100 priority score.
    """

    rule: str
    factor: str
    impact: str
    reason: str
    points: int = 0


class PriorityAssessment(BaseModel):
    """A ``RiskAssessment`` enriched with the prioritization policy output.

    Attributes:
        assessment:      The underlying quantum-risk assessment.
        priority_score:  Score 0-100 from the Q-BITS-ECDAT priority policy.
        priority_level:  Score band (LOW ... IMMEDIATE).
        urgency:         Migration timeline urgency.
        risk_factors:    Rule-derived, explainable factors that drive the score.
        mode:            Cipher mode when known (used by the weak-config rule).
    """

    assessment: RiskAssessment
    priority_score: int
    priority_level: PriorityLevel = PriorityLevel.LOW
    urgency: MigrationUrgency = MigrationUrgency.LOW
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    mode: str | None = None


class TopRiskAsset(BaseModel):
    """A single row in the top-risk list of a summary."""

    algorithm: str
    file_path: str | None = None
    line_number: int | None = None
    priority_score: int
    priority_level: PriorityLevel = PriorityLevel.LOW


class MigrationStep(BaseModel):
    """One phase-plus-action inside a migration plan."""

    phase: MigrationPhase
    description: str


class MigrationPlan(BaseModel):
    """Asset-level migration plan generated by the roadmap engine.

    Attributes:
        algorithm:               Current (assessed) algorithm.
        category:                Algorithm family.
        classical_risk:          Classical risk level.
        quantum_risk:            Quantum risk level.
        risk_level:              Overall risk level.
        risk_score:              Existing 0-4 risk score.
        key_size / usage / mode: Evidence available to the plan.
        file_path / line_number: Source location when known.
        priority_score:          0-100 priority score.
        priority_level:          Score band (LOW ... IMMEDIATE).
        urgency:                 Migration timeline urgency.
        migration_status:        Plan lifecycle status (NOT_STARTED by default).
        strategy:                Selected migration strategy.
        why_needed:              Rule-derived migration justification.
        recommended_replacement: Replacement algorithm.
        pqc_recommendation:      Post-quantum recommendation.
        steps:                   Ordered migration steps (phases).
        validation_steps:        Concrete validation actions after migration.
    """

    algorithm: str
    category: AlgorithmCategory = AlgorithmCategory.UNKNOWN
    classical_risk: RiskLevel = RiskLevel.UNKNOWN
    quantum_risk: QuantumRisk = QuantumRisk.UNKNOWN
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_score: int = 0
    key_size: int | None = None
    usage: UsageType | None = None
    mode: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    priority_score: int = 0
    priority_level: PriorityLevel = PriorityLevel.LOW
    urgency: MigrationUrgency = MigrationUrgency.LOW
    migration_status: MigrationStatus = MigrationStatus.NOT_STARTED
    strategy: MigrationStrategy = MigrationStrategy.REVIEW_REQUIRED
    why_needed: str = ""
    recommended_replacement: str = ""
    pqc_recommendation: str = ""
    steps: list[MigrationStep] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)


class RoadmapPriorityItem(BaseModel):
    """One row of the organization-level roadmap ``top_priorities`` list."""

    algorithm: str
    file_path: str | None = None
    line_number: int | None = None
    priority_score: int
    priority_level: PriorityLevel = PriorityLevel.LOW
    urgency: MigrationUrgency = MigrationUrgency.LOW
    strategy: MigrationStrategy = MigrationStrategy.REVIEW_REQUIRED
    recommended_replacement: str = ""


class OrganizationRoadmap(BaseModel):
    """Organization-level migration roadmap combining every assessed asset.

    All counts/priorities are computed dynamically from the input plans.

    Attributes:
        project:              Project label.
        total_assets:         Number of assessed assets.
        immediate / urgent / high / planned / low: counts per urgency.
        migration_candidates: Assets that require migration (urgency != LOW).
        top_priorities:       Top N plans by priority score (default 5).
        note:                 Standard disclaimer (policy aid, not a standard).
    """

    project: str = "Unknown"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_assets: int = 0
    immediate: int = 0
    urgent: int = 0
    high: int = 0
    planned: int = 0
    low: int = 0
    migration_candidates: int = 0
    top_priorities: list[RoadmapPriorityItem] = Field(default_factory=list)
    note: str = (
        "Q-BITS-ECDAT Risk Prioritization Policy output. This is a "
        "prioritization aid for the tool and not an official security "
        "standard or a guaranteed security rating."
    )

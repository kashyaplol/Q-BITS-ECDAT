"""Risk classification knowledge base.

This module is the single place where every algorithm's baseline risk
is described. Keeping it here (separate from the engine logic) makes it
trivial to extend: add one ``RiskProfile`` entry and the whole system
picks it up.

Each profile stores:

* which **family** the algorithm belongs to (``AlgorithmCategory``),
* a baseline **classical** and **quantum** risk level,
* a baseline **migration priority**,
* a human-readable **recommendation** and a PQC replacement suggestion,
* the plain-English **reason**,
* optional key-size thresholds that refine the baseline risks,
* optional usage-specific recommendation/PQC overrides.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from backend.app.models import (
    AlgorithmCategory,
    MigrationPriority,
    QuantumRisk,
    RiskLevel,
    UsageType,
)


class RiskProfile(BaseModel):
    """The risk "rule" for one algorithm.

    ``key_size_X`` lists are sorted lists of ``(max_key_size, level)``
    thresholds. Example: ``[(1023, HIGH), (3071, MEDIUM)]`` means key
    sizes <= 1023 are HIGH, 1024..3071 are MEDIUM, anything larger is LOW.
    """

    algorithm: str
    category: AlgorithmCategory
    classical_risk: RiskLevel
    quantum_risk: QuantumRisk
    migration_priority: MigrationPriority
    recommendation: str
    pqc_recommendation: str
    reason: str
    deprecated: bool = False
    key_size_classical: list[tuple[int, RiskLevel]] = []
    key_size_quantum: list[tuple[int, QuantumRisk]] = []
    key_size_priority: list[tuple[int, MigrationPriority]] = []
    usage_recommendation: dict[str, str] = {}
    usage_pqc: dict[str, str] = {}


# Shared reasons (plain-English) so we never repeat long strings.
_REASON_PUBLIC_KEY = (
    "This public-key algorithm is vulnerable to Shor's algorithm on a "
    "sufficiently powerful cryptographically relevant quantum computer."
)
_REASON_SYMMETRIC = (
    "Symmetric cryptography is affected by Grover's algorithm, which can "
    "reduce its effective brute-force security strength."
)
_REASON_HASH = (
    "Hash functions are only mildly affected by quantum computers, but "
    "long-term assurance favours larger digests (SHA-384/SHA-512/SHA-3)."
)
_REASON_LEGACY = (
    "This algorithm already has known classical security weaknesses or "
    "has been formally deprecated."
)

# Recommended PQC switches by usage, used when profiles do not override.
PQC_BY_USAGE: dict[UsageType, str] = {
    UsageType.ENCRYPTION: "ML-KEM (CRYSTALS-Kyber)",
    UsageType.DECRYPTION: "ML-KEM (CRYSTALS-Kyber)",
    UsageType.KEY_EXCHANGE: "ML-KEM (CRYSTALS-Kyber)",
    UsageType.KEY_ESTABLISHMENT: "ML-KEM (CRYSTALS-Kyber)",
    UsageType.KEY_GENERATION: "ML-KEM or ML-DSA (FIPS 203 / 204)",
    UsageType.SIGNATURE: "ML-DSA (CRYSTALS-Dilithium) or SLH-DSA (SPHINCS+)",
    UsageType.DIGITAL_SIGNATURE: "ML-DSA (CRYSTALS-Dilithium) or SLH-DSA (SPHINCS+)",
    UsageType.SIGNATURE_VERIFICATION: "ML-DSA (CRYSTALS-Dilithium) or SLH-DSA (SPHINCS+)",
    UsageType.HASHING: "SHA-3 (Keccak)",
    UsageType.SYMMETRIC_ENCRYPTION: "AES-256-GCM",
    UsageType.UNKNOWN: "See recommendation",
}


# ---------------------------------------------------------------------------
# The knowledge base itself
# ---------------------------------------------------------------------------
KNOWLEDGE_BASE: dict[str, RiskProfile] = {
    # ---- Public-key systems: broken by Shor's algorithm -------------------
    "RSA": RiskProfile(
        algorithm="RSA",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,   # fine at >= 2048 bits today
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Plan migration from RSA to a Post-Quantum Cryptography "
            "solution (ML-KEM for key establishment/encryption, ML-DSA for "
            "digital signatures)."
        ),
        pqc_recommendation="ML-KEM or ML-DSA (FIPS 203 / 204)",
        reason=_REASON_PUBLIC_KEY,
        key_size_classical=[(1023, RiskLevel.HIGH), (3071, RiskLevel.MEDIUM), (65535, RiskLevel.LOW)],
        usage_recommendation={
            UsageType.ENCRYPTION.value: (
                "Migrate toward a suitable Post-Quantum Key Encapsulation "
                "Mechanism (KEM) such as ML-KEM."
            ),
            UsageType.KEY_EXCHANGE.value: (
                "Migrate toward a suitable Post-Quantum Key Encapsulation "
                "Mechanism (KEM) such as ML-KEM."
            ),
            UsageType.SIGNATURE.value: (
                "Migrate toward a suitable Post-Quantum Digital Signature "
                "Algorithm such as ML-DSA."
            ),
        },
        usage_pqc={
            UsageType.ENCRYPTION.value: "ML-KEM",
            UsageType.KEY_EXCHANGE.value: "ML-KEM",
            UsageType.SIGNATURE.value: "ML-DSA",
        },
    ),
    "ECC": RiskProfile(
        algorithm="ECC",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Migrate from ECC to a Post-Quantum Cryptography solution "
            "(ML-KEM for key establishment, ML-DSA for signatures)."
        ),
        pqc_recommendation="ML-KEM or ML-DSA (FIPS 203 / 204)",
        reason=_REASON_PUBLIC_KEY,
    ),
    "ECDSA": RiskProfile(
        algorithm="ECDSA",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Migrate from ECDSA to a Post-Quantum Digital Signature "
            "Algorithm. Choose ML-DSA or SLH-DSA depending on your "
            "signature-size / verification-speed requirements."
        ),
        pqc_recommendation="ML-DSA or SLH-DSA (FIPS 204 / 205)",
        reason=_REASON_PUBLIC_KEY,
    ),
    "ECDH": RiskProfile(
        algorithm="ECDH",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Migrate from ECDH key agreement to a Post-Quantum Key "
            "Encapsulation Mechanism such as ML-KEM."
        ),
        pqc_recommendation="ML-KEM (FIPS 203)",
        reason=_REASON_PUBLIC_KEY,
    ),
    "DSA": RiskProfile(
        algorithm="DSA",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Migrate from DSA to a Post-Quantum Digital Signature "
            "Algorithm such as ML-DSA."
        ),
        pqc_recommendation="ML-DSA (FIPS 204)",
        reason=_REASON_PUBLIC_KEY,
    ),
    "DH": RiskProfile(
        algorithm="DH",
        category=AlgorithmCategory.PUBLIC_KEY,
        classical_risk=RiskLevel.MEDIUM,
        quantum_risk=QuantumRisk.CRITICAL,
        migration_priority=MigrationPriority.CRITICAL,
        recommendation=(
            "Migrate from Diffie-Hellman key exchange to a Post-Quantum "
            "Key Encapsulation Mechanism such as ML-KEM."
        ),
        pqc_recommendation="ML-KEM (FIPS 203)",
        reason=_REASON_PUBLIC_KEY,
    ),
    # ---- Symmetric algorithms: weakened by Grover's algorithm -------------
    "AES": RiskProfile(
        algorithm="AES",
        category=AlgorithmCategory.SYMMETRIC,
        classical_risk=RiskLevel.LOW,
        quantum_risk=QuantumRisk.MEDIUM,
        migration_priority=MigrationPriority.MEDIUM,
        recommendation=(
            "AES remains usable, but Grover's algorithm halves its "
            "effective key strength. Prefer AES-256 for stronger long-term "
            "protection and keep crypto-agility."
        ),
        pqc_recommendation="AES-256-GCM (symmetric key doubling)",
        reason=_REASON_SYMMETRIC,
        key_size_quantum=[(128, QuantumRisk.MEDIUM), (192, QuantumRisk.LOW), (65535, QuantumRisk.LOW)],
        key_size_priority=[
            (128, MigrationPriority.HIGH),
            (192, MigrationPriority.MEDIUM),
            (65535, MigrationPriority.LOW),
        ],
        usage_recommendation={
            UsageType.SYMMETRIC_ENCRYPTION.value: (
                "Upgrade to AES-256 and use an authenticated mode such as "
                "AES-GCM or ChaCha20-Poly1305."
            ),
        },
    ),
    # ---- Hash functions ---------------------------------------------------
    "SHA256": RiskProfile(
        algorithm="SHA256",
        category=AlgorithmCategory.HASH,
        classical_risk=RiskLevel.LOW,
        quantum_risk=QuantumRisk.MEDIUM,
        migration_priority=MigrationPriority.MEDIUM,
        recommendation=(
            "SHA-256 hashing remains usable today. Consider SHA-384 or "
            "SHA-512 where stronger security margins are required, or "
            "SHA-3 for post-quantum headroom."
        ),
        pqc_recommendation="SHA-3 (or SHA-384/SHA-512)",
        reason=_REASON_HASH,
    ),
    "SHA384": RiskProfile(
        algorithm="SHA384",
        category=AlgorithmCategory.HASH,
        classical_risk=RiskLevel.LOW,
        quantum_risk=QuantumRisk.LOW,
        migration_priority=MigrationPriority.LOW,
        recommendation=(
            "SHA-384 provides strong margin against quantum attacks; no "
            "immediate migration required. Keep crypto-agility."
        ),
        pqc_recommendation="SHA-3 if enhanced assurance is desired",
        reason=_REASON_HASH,
    ),
    "SHA512": RiskProfile(
        algorithm="SHA512",
        category=AlgorithmCategory.HASH,
        classical_risk=RiskLevel.LOW,
        quantum_risk=QuantumRisk.LOW,
        migration_priority=MigrationPriority.LOW,
        recommendation=(
            "SHA-512 provides strong margin against quantum attacks; no "
            "immediate migration required. Keep crypto-agility."
        ),
        pqc_recommendation="SHA-3 if enhanced assurance is desired",
        reason=_REASON_HASH,
    ),
    "SHA3": RiskProfile(
        algorithm="SHA3",
        category=AlgorithmCategory.HASH,
        classical_risk=RiskLevel.LOW,
        quantum_risk=QuantumRisk.LOW,
        migration_priority=MigrationPriority.LOW,
        recommendation=(
            "SHA-3 (Keccak) provides strong margin against quantum attacks; "
            "no immediate migration required. Keep crypto-agility."
        ),
        pqc_recommendation="SHA-3 (Keccak) is itself PQC-safe",
        reason=_REASON_HASH,
    ),
    # ---- Legacy / already-broken algorithms -------------------------------
    "MD5": RiskProfile(
        algorithm="MD5",
        category=AlgorithmCategory.LEGACY,
        classical_risk=RiskLevel.CRITICAL,
        quantum_risk=QuantumRisk.HIGH,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommendation=(
            "Immediately replace MD5 with SHA-256 or SHA-3 -- MD5 is "
            "cryptographically broken and must not be used."
        ),
        pqc_recommendation="SHA-256 / SHA-3",
        reason=_REASON_LEGACY,
        deprecated=True,
    ),
    "SHA1": RiskProfile(
        algorithm="SHA1",
        category=AlgorithmCategory.LEGACY,
        classical_risk=RiskLevel.CRITICAL,
        quantum_risk=QuantumRisk.HIGH,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommendation=(
            "Immediately migrate from SHA-1 to SHA-256, SHA-384, SHA-512 "
            "or SHA-3 depending on your use case -- SHA-1 is deprecated "
            "and collision-broken."
        ),
        pqc_recommendation="SHA-256 / SHA-384 / SHA-512 / SHA-3",
        reason=_REASON_LEGACY,
        deprecated=True,
    ),
    "DES": RiskProfile(
        algorithm="DES",
        category=AlgorithmCategory.LEGACY,
        classical_risk=RiskLevel.CRITICAL,
        quantum_risk=QuantumRisk.HIGH,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommendation=(
            "Immediately replace DES (56-bit key) with AES-256 or a modern "
            "AEAD such as AES-GCM."
        ),
        pqc_recommendation="AES-256 / AES-GCM",
        reason=_REASON_LEGACY,
        deprecated=True,
    ),
    "3DES": RiskProfile(
        algorithm="3DES",
        category=AlgorithmCategory.LEGACY,
        classical_risk=RiskLevel.CRITICAL,
        quantum_risk=QuantumRisk.HIGH,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommendation=(
            "Immediately replace 3DES (deprecated by NIST after 2023) with "
            "AES-256 or a modern AEAD such as AES-GCM."
        ),
        pqc_recommendation="AES-256 / AES-GCM",
        reason=_REASON_LEGACY,
        deprecated=True,
    ),
    "RC4": RiskProfile(
        algorithm="RC4",
        category=AlgorithmCategory.LEGACY,
        classical_risk=RiskLevel.CRITICAL,
        quantum_risk=QuantumRisk.HIGH,
        migration_priority=MigrationPriority.IMMEDIATE,
        recommendation=(
            "Immediately replace RC4 -- it is cryptographically broken. "
            "Use AES-GCM or ChaCha20-Poly1305 instead."
        ),
        pqc_recommendation="AES-GCM / ChaCha20-Poly1305",
        reason=_REASON_LEGACY,
        deprecated=True,
    ),
}


# ---------------------------------------------------------------------------
# Algorithm-name resolution
# ---------------------------------------------------------------------------
# Alternative spellings -> (canonical knowledge-base key, implied key size).
_KEY_HINTS: dict[str, tuple[int, str]] = {
    "AES128": (128, "AES"),
    "AES_128": (128, "AES"),
    "AES-128": (128, "AES"),
    "AES192": (192, "AES"),
    "AES_192": (192, "AES"),
    "AES-192": (192, "AES"),
    "AES256": (256, "AES"),
    "AES_256": (256, "AES"),
    "AES-256": (256, "AES"),
}

# Plain alias inputs -> (canonical key, no key hint).
_ALIASES: dict[str, str] = {
    "SHA-1": "SHA1",
    "SHA-256": "SHA256",
    "SHA-384": "SHA384",
    "SHA-512": "SHA512",
    "SHA-3": "SHA3",
    "SHA256": "SHA256",
    "SHA384": "SHA384",
    "SHA512": "SHA512",
    "SHA3": "SHA3",
    "DESEDE": "3DES",
    "DIFFIEHELLMAN": "DH",
    "DIFFIE-HELLMAN": "DH",
    "EC": "ECC",
}


def as_name(name: object) -> str:
    """Turn an algorithm reference into a plain string.

    Handles our ``Algorithm`` enums, whose ``str()`` on Python >= 3.11
    would render as ``"Algorithm.MD5"`` instead of ``"MD5"``.
    """
    if isinstance(name, Enum):
        return str(name.value)
    return str(name)


def _normalize(name: object) -> str:
    """Lower-case everything, keep letters/digits/hyphens, strip spaces."""
    raw = as_name(name)
    return "".join(ch for ch in raw.strip() if ch.isalnum() or ch in "-_").upper()


def resolve_algorithm(name: object) -> tuple[str, int | None]:
    """Map an arbitrary algorithm spelling to (canonical key, implied key size).

    Returns:
        A tuple of the canonical knowledge-base key (e.g. ``"RSA"``, ``"AES"``)
        and an implied key size where the name itself carries one
        (``"AES-128"`` -> ``"AES"``, ``128``). Unknown names are returned
        unchanged as the canonical key, which the engine treats as UNKNOWN.
    """
    normalized = _normalize(name)

    # 1. Known canonical key: check the knowledge base first so that
    #    canonical names like "SHA384" do not get short-circuited by the
    #    alias map (which also contains them).
    if normalized in KNOWLEDGE_BASE:
        return normalized, None
    if normalized == "3DES":
        return "3DES", None

    # 2. Compound names that imply a key size (AES-128 / AES-256, ...).
    if normalized in _KEY_HINTS:
        key_size, key = _KEY_HINTS[normalized]
        return key, key_size

    # 3. Aliases (SHA-256 -> SHA256, Diffie-Hellman -> DH, ...).
    if normalized in _ALIASES:
        key = _ALIASES[normalized]
        return key, None

    # 4. Nothing matched -- it is an unknown algorithm.
    return normalized, None


def get_profile(key: str) -> RiskProfile | None:
    """Look up a profile by its canonical key; None when unknown."""
    return KNOWLEDGE_BASE.get(key)


def apply_key_size_classical(profile: RiskProfile, key_size: int | None) -> RiskLevel:
    """Return the classical risk adjusted for the key size, if rules exist."""
    if key_size is None or not profile.key_size_classical:
        return profile.classical_risk
    result = profile.classical_risk
    for upper, level in profile.key_size_classical:
        if key_size <= upper:
            result = level
            break
    return result


def apply_key_size_quantum(profile: RiskProfile, key_size: int | None) -> QuantumRisk:
    """Return the quantum risk adjusted for the key size, if rules exist."""
    if key_size is None or not profile.key_size_quantum:
        return profile.quantum_risk
    result = profile.quantum_risk
    for upper, level in profile.key_size_quantum:
        if key_size <= upper:
            result = level
            break
    return result


def apply_key_size_priority(
    profile: RiskProfile, key_size: int | None
) -> MigrationPriority:
    """Return the migration priority adjusted for the key size, if rules exist."""
    if key_size is None or not profile.key_size_priority:
        return profile.migration_priority
    result = profile.migration_priority
    for upper, level in profile.key_size_priority:
        if key_size <= upper:
            result = level
            break
    return result

"""Deterministic patterns for potential cryptographic usage."""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class PatternDefinition:
    """A deterministic pattern and metadata for a potential usage finding."""

    algorithm: str
    category: str
    detection_pattern: str
    detection_method: str
    confidence: float

    @property
    def compiled_pattern(self) -> re.Pattern[str]:
        """Return the compiled regular expression for this pattern."""

        return re.compile(self.detection_pattern, re.IGNORECASE)


def extract_key_size(algorithm: str, source_line: str) -> int | None:
    """Extract a key size only from an explicit, supported source form."""

    if algorithm == "RSA":
        patterns = (
            r"\bRSA\s*[-(]\s*(1024|2048|3072|4096)\b",
            r"\bRSA\s+(1024|2048|3072|4096)\b",
            r"\b(?:generate|initialize)\s*\(\s*(1024|2048|3072|4096)\s*\)",
            r"\bkey_size\s*=\s*(1024|2048|3072|4096)\b",
        )
    elif algorithm == "AES":
        patterns = (r"\bAES\s*[-_ ]\s*(128|192|256)\b",)
    elif algorithm in {"ECDSA", "ECC"}:
        patterns = (
            r"\b(?:ECDSA|ECC|EC)\s*[-_ ]\s*(224|256|384|521)\b",
            r"\bsecp(224r1|256r1|384r1|521r1)\b",
        )
    else:
        return None

    for pattern in patterns:
        match = re.search(pattern, source_line, re.IGNORECASE)
        if match is None:
            continue
        value = match.group(1)
        if value.isdigit():
            return int(value)
        return int(value.removesuffix("r1"))
    return None


CRYPTOGRAPHIC_PATTERNS = (
    PatternDefinition(
        "RSA", "asymmetric", r"\bRSA\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "DSA", "asymmetric", r"\bDSA\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "ECDSA", "asymmetric", r"\bECDSA\b", "deterministic_regex", 0.95
    ),
    PatternDefinition("ECC", "asymmetric", r"\bECC\b", "deterministic_regex", 0.9),
    PatternDefinition(
        "Diffie-Hellman",
        "key_exchange",
        r"\bDiffie[- ]Hellman\b|\bDH\b",
        "deterministic_regex",
        0.9,
    ),
    PatternDefinition("AES", "symmetric", r"\bAES\b", "deterministic_regex", 0.95),
    PatternDefinition("DES", "symmetric", r"\bDES\b", "deterministic_regex", 0.95),
    PatternDefinition(
        "3DES", "symmetric", r"\b(?:3DES|3-DES|Triple[ -]?DES)\b",
        "deterministic_regex",
        0.95,
    ),
    PatternDefinition(
        "Blowfish", "symmetric", r"\bBlowfish\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "ChaCha20", "symmetric", r"\bChaCha20\b", "deterministic_regex", 0.95
    ),
    PatternDefinition("MD5", "hash", r"\bMD5\b", "deterministic_regex", 0.95),
    PatternDefinition(
        "SHA-1", "hash", r"\bSHA[- ]?1\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "SHA-256", "hash", r"\bSHA[- ]?256\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "SHA-384", "hash", r"\bSHA[- ]?384\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "SHA-512", "hash", r"\bSHA[- ]?512\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "cryptography", "library", r"\bcryptography\b", "deterministic_regex", 0.9
    ),
    PatternDefinition("Crypto", "library", r"\bCrypto\b", "deterministic_regex", 0.85),
    PatternDefinition(
        "PyCryptodome", "library", r"\bPyCryptodome\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "hashlib", "library", r"\bhashlib\b", "deterministic_regex", 0.95
    ),
    PatternDefinition("ssl", "library", r"\bssl\b", "deterministic_regex", 0.85),
    PatternDefinition(
        "javax.crypto", "library", r"\bjavax\.crypto\b", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "java.security",
        "library",
        r"\bjava\.security\b",
        "deterministic_regex",
        0.95,
    ),
    PatternDefinition(
        "crypto", "library", r"\b(?:node:)?crypto\b", "deterministic_regex", 0.9
    ),
    PatternDefinition(
        "Go crypto", "library", r"\bcrypto/", "deterministic_regex", 0.95
    ),
    PatternDefinition(
        "OpenSSL", "library", r"\bOpenSSL\b", "deterministic_regex", 0.95
    ),
)

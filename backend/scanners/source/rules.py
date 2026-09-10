"""Detection rules for the source code cryptographic scanner.

This file is the "brain" of the scanner. Each rule describes:

* which algorithm it detects (``Algorithm`` enum),
* which library the call belongs to (e.g. Python ``hashlib``),
* which file extensions it applies to (``.py``, ``.java``, ...),
* one or more regular-expression patterns to look for.

The scanner iterates these rules, compiles the patterns, and checks
each line of each file. Rules are intentionally kept simple and
readable so they are easy to extend.

Two kinds of rules exist:

1. **Library/API rules** -- match a real API call such as
   ``hashlib.md5(...)``. These are strong signals and use
   ``DetectionMethod.REGEX``.
2. **Keyword rules** -- match an algorithm name written in the code,
   such as ``"AES"`` or ``"RSA"``. These are weaker signals and use
   ``DetectionMethod.KEYWORD``.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.models import Algorithm, DetectionMethod

# ---------------------------------------------------------------------------
# Small helper constants to keep rule definitions readable
# ---------------------------------------------------------------------------
PY = (".py",)
JAVA = (".java",)
JS_TS = (".js", ".ts")
ALL = (".py", ".java", ".js", ".ts")

# Hashing algorithms shared across languages
HASH_ALGOS = r"(MD5|SHA1|SHA-1|SHA256|SHA-256|SHA512|SHA-512)"


@dataclass(frozen=True)
class DetectionRule:
    """One detection rule for the scanner.

    Attributes:
        algorithm:       The crypto algorithm this rule detects.
        library:         Python/Java/JS library involved, if known.
        extensions:      File extensions the rule applies to.
        patterns:        Regex patterns to search for (case-insensitive).
        detection_method: How matches are classified.
    """

    algorithm: Algorithm
    extensions: tuple[str, ...]
    patterns: tuple[str, ...]
    library: str | None = None
    detection_method: DetectionMethod = DetectionMethod.REGEX


# ---------------------------------------------------------------------------
# Library / API rules -- strong signals with a known library
# ---------------------------------------------------------------------------
LIBRARY_RULES: list[DetectionRule] = [
    # --- Python: hashlib ------------------------------------------------
    DetectionRule(
        algorithm=Algorithm.SHA256,
        library="hashlib",
        extensions=PY,
        patterns=(
            r"hashlib\.sha256\(",
            r"hashlib\.new\(['\"](sha256|sha-256)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA512,
        library="hashlib",
        extensions=PY,
        patterns=(
            r"hashlib\.sha512\(",
            r"hashlib\.new\(['\"](sha512|sha-512)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA1,
        library="hashlib",
        extensions=PY,
        patterns=(
            r"hashlib\.sha1\(",
            r"hashlib\.new\(['\"]sha1",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.MD5,
        library="hashlib",
        extensions=PY,
        patterns=(
            r"hashlib\.md5\(",
            r"hashlib\.new\(['\"]md5",
        ),
    ),
    # --- Python: cryptography (hazmat) ----------------------------------
    DetectionRule(
        algorithm=Algorithm.RSA,
        library="cryptography",
        extensions=PY,
        patterns=(
            r"from cryptography\.hazmat\.primitives\.asymmetric import .*rsa",
            r"rsa\.(generate_private_key|generate)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.ECC,
        library="cryptography",
        extensions=PY,
        patterns=(
            r"from cryptography\.hazmat\.primitives\.asymmetric import .*\bec\b",
            r"ec\.(generate_private_key|ECDSA|SECP)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.DSA,
        library="cryptography",
        extensions=PY,
        patterns=(
            r"from cryptography\.hazmat\.primitives\.asymmetric import .*\bdsa\b",
            r"dsa\.(generate_private_key|DSAParameterNumbers)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.AES,
        library="cryptography",
        extensions=PY,
        patterns=(
            r"algorithms\.AES\(",
            r"Cipher\(algorithms\.AES",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.TRIPLE_DES,
        library="cryptography",
        extensions=PY,
        patterns=(r"algorithms\.TripleDES\(",),
    ),
    DetectionRule(
        algorithm=Algorithm.DES,
        library="cryptography",
        extensions=PY,
        patterns=(r"algorithms\.DES\(",),
    ),
    # --- Python: pycryptodome -------------------------------------------
    DetectionRule(
        algorithm=Algorithm.AES,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Cipher\.AES",),
    ),
    DetectionRule(
        algorithm=Algorithm.DES,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Cipher\.DES\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.TRIPLE_DES,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Cipher\.DES3",),
    ),
    DetectionRule(
        algorithm=Algorithm.MD5,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Hash\.MD5",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA1,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Hash\.SHA1",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA256,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Hash\.SHA256",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA512,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.Hash\.SHA512",),
    ),
    DetectionRule(
        algorithm=Algorithm.RSA,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.PublicKey\.RSA",),
    ),
    DetectionRule(
        algorithm=Algorithm.DSA,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.PublicKey\.DSA",),
    ),
    DetectionRule(
        algorithm=Algorithm.ECC,
        library="pycryptodome",
        extensions=PY,
        patterns=(r"Crypto\.PublicKey\.ECC",),
    ),
    # --- Java: javax.crypto / java.security -----------------------------
    DetectionRule(
        algorithm=Algorithm.SHA256,
        library="MessageDigest",
        extensions=JAVA,
        patterns=(r"MessageDigest\.getInstance\(['\"](SHA-?256)",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA512,
        library="MessageDigest",
        extensions=JAVA,
        patterns=(r"MessageDigest\.getInstance\(['\"](SHA-?512)",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA1,
        library="MessageDigest",
        extensions=JAVA,
        patterns=(r"MessageDigest\.getInstance\(['\"](SHA-?1)",),
    ),
    DetectionRule(
        algorithm=Algorithm.MD5,
        library="MessageDigest",
        extensions=JAVA,
        patterns=(r"MessageDigest\.getInstance\(['\"]MD5",),
    ),
    DetectionRule(
        algorithm=Algorithm.AES,
        library="javax.crypto",
        extensions=JAVA,
        patterns=(r"Cipher\.getInstance\(['\"]AES",),
    ),
    DetectionRule(
        algorithm=Algorithm.DES,
        library="javax.crypto",
        extensions=JAVA,
        patterns=(
            r"Cipher\.getInstance\(['\"]DES(?!ede)",
            r"KeyGenerator\.getInstance\(['\"]DES(?!ede)",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.TRIPLE_DES,
        library="javax.crypto",
        extensions=JAVA,
        patterns=(
            r"Cipher\.getInstance\(['\"]DESede",
            r"KeyGenerator\.getInstance\(['\"]DESede",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.RSA,
        library="java.security",
        extensions=JAVA,
        patterns=(
            r"KeyPairGenerator\.getInstance\(['\"]RSA",
            r"Cipher\.getInstance\(['\"]RSA",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.DSA,
        library="java.security",
        extensions=JAVA,
        patterns=(r"KeyPairGenerator\.getInstance\(['\"]DSA",),
    ),
    DetectionRule(
        algorithm=Algorithm.ECC,
        library="java.security",
        extensions=JAVA,
        patterns=(
            r"KeyPairGenerator\.getInstance\(['\"]EC",
            r"ECGenParameterSpec",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.DH,
        library="javax.crypto",
        extensions=JAVA,
        patterns=(
            r"KeyPairGenerator\.getInstance\(['\"]DiffieHellman",
            r"KeyAgreement\.getInstance\(['\"]DiffieHellman",
        ),
    ),
    # --- Node.js crypto module -------------------------------------------
    DetectionRule(
        algorithm=Algorithm.MD5,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.createHash\(['\"]md5",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA1,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.createHash\(['\"]sha1",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA256,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.createHash\(['\"]sha256",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA512,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.createHash\(['\"]sha512",),
    ),
    DetectionRule(
        algorithm=Algorithm.AES,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.(createCipheriv?|createDecipheriv?)\(['\"]aes",),
    ),
    DetectionRule(
        algorithm=Algorithm.DES,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(
            r"crypto\.(createCipheriv?|createDecipheriv?)\(['\"]des[^e]",
        ),
    ),
    DetectionRule(
        algorithm=Algorithm.TRIPLE_DES,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(r"crypto\.(createCipheriv?|createDecipheriv?)\(['\"]des(?:ede|3)",),
    ),
    DetectionRule(
        algorithm=Algorithm.RSA,
        library="Node.js crypto",
        extensions=JS_TS,
        patterns=(
            r"crypto\.generateKeyPair.*rsa",
            r"crypto\.publicEncrypt\(",
            r"crypto\.privateDecrypt\(",
        ),
    ),
]


# ---------------------------------------------------------------------------
# Keyword rules -- weaker signal, catches algorithm names written in code
# ---------------------------------------------------------------------------
# Each entry is (Algorithm, display keyword). The scanner wraps the keyword
# in word boundaries (\\b...\\b) so "RSA" does not match "RSA256".
KEYWORD_RULES: list[DetectionRule] = [
    DetectionRule(
        algorithm=Algorithm.MD5,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bMD5\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA1,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bSHA1\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA256,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bSHA256\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.SHA512,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bSHA512\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.AES,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bAES\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.DES,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bDES\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.TRIPLE_DES,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"3DES",),
    ),
    DetectionRule(
        algorithm=Algorithm.RSA,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bRSA\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.DSA,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bDSA\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.ECC,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bECC\b",),
    ),
    DetectionRule(
        algorithm=Algorithm.DH,
        extensions=ALL,
        library=None,
        detection_method=DetectionMethod.KEYWORD,
        patterns=(r"\bDiffie-?Hellman\b",),
    ),
]

# Combined list used by the scanner.
ALL_RULES: list[DetectionRule] = LIBRARY_RULES + KEYWORD_RULES

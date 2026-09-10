"""Declarative detection data for the Python AST crypto scanner.

This file is the AST counterpart of ``rules.py``: it describes *what*
the AST scanner looks for (module paths, function names, algorithm
enums), while the walking logic in ``ast_scanner.py`` stays generic and
readable.

Everything here is plain data so adding a new library or function does
not require touching the scanner logic.
"""

from __future__ import annotations

from backend.app.models import Algorithm, UsageType

# ---------------------------------------------------------------------------
# Imports: dotted module path -> library label used in findings
# ---------------------------------------------------------------------------
IMPORT_LIBRARIES: dict[str, str] = {
    "hashlib": "hashlib",
    "cryptography.hazmat.primitives.hashes": "cryptography",
    "cryptography.hazmat.primitives.ciphers": "cryptography",
    "cryptography.hazmat.primitives.ciphers.algorithms": "cryptography",
    "cryptography.hazmat.primitives.ciphers.modes": "cryptography",
    "cryptography.hazmat.primitives.asymmetric": "cryptography",
    "cryptography.hazmat.primitives.asymmetric.rsa": "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ec": "cryptography",
    "cryptography.hazmat.primitives.asymmetric.dsa": "cryptography",
    "Crypto": "pycryptodome",
    "Crypto.Cipher": "pycryptodome",
    "Crypto.Cipher.AES": "pycryptodome",
    "Crypto.Cipher.DES": "pycryptodome",
    "Crypto.Cipher.DES3": "pycryptodome",
    "Crypto.Cipher.ARC4": "pycryptodome",
    "Crypto.Hash": "pycryptodome",
    "Crypto.Hash.MD5": "pycryptodome",
    "Crypto.Hash.SHA1": "pycryptodome",
    "Crypto.Hash.SHA256": "pycryptodome",
    "Crypto.Hash.SHA384": "pycryptodome",
    "Crypto.Hash.SHA512": "pycryptodome",
    "Crypto.Hash.SHA3": "pycryptodome",
    "Crypto.PublicKey.RSA": "pycryptodome",
    "Crypto.PublicKey.DSA": "pycryptodome",
    "Crypto.PublicKey.ECC": "pycryptodome",
}

# ---------------------------------------------------------------------------
# Hash functions: hashlib.<name>(...) -> algorithm
# ---------------------------------------------------------------------------
HASH_FUNCTIONS: dict[str, Algorithm] = {
    "md5": Algorithm.MD5,
    "sha1": Algorithm.SHA1,
    "sha256": Algorithm.SHA256,
    "sha384": Algorithm.SHA384,
    "sha512": Algorithm.SHA512,
    "sha3_224": Algorithm.SHA3,  # SHA3 family shares one enum entry
    "sha3_256": Algorithm.SHA3,
    "sha3_384": Algorithm.SHA3,
    "sha3_512": Algorithm.SHA3,
}

# hashlib.new("sha256") / "SHA3-256" style string names -> algorithm.
HASH_NEW_NAMES: dict[str, Algorithm] = {
    "md5": Algorithm.MD5,
    "sha1": Algorithm.SHA1,
    "sha-1": Algorithm.SHA1,
    "sha256": Algorithm.SHA256,
    "sha-256": Algorithm.SHA256,
    "sha384": Algorithm.SHA384,
    "sha-384": Algorithm.SHA384,
    "sha512": Algorithm.SHA512,
    "sha-512": Algorithm.SHA512,
    "sha3": Algorithm.SHA3,
    "sha3-256": Algorithm.SHA3,
    "sha3-384": Algorithm.SHA3,
    "sha3-512": Algorithm.SHA3,
}

# cryptography.hazmat.primitives.hashes.<ClassName>(...) -> algorithm.
CRYPTOGRAPHY_HASH_CLASSES: dict[str, Algorithm] = {
    "MD5": Algorithm.MD5,
    "SHA1": Algorithm.SHA1,
    "SHA256": Algorithm.SHA256,
    "SHA384": Algorithm.SHA384,
    "SHA512": Algorithm.SHA512,
    "SHA3_256": Algorithm.SHA3,
    "SHA3_384": Algorithm.SHA3,
    "SHA3_512": Algorithm.SHA3,
}

# pycryptodome Crypto.Hash.<Module>.new() -> algorithm (module tail is key).
PYCRYPTODOME_HASH_MODULES: dict[str, Algorithm] = {
    "MD5": Algorithm.MD5,
    "SHA1": Algorithm.SHA1,
    "SHA256": Algorithm.SHA256,
    "SHA384": Algorithm.SHA384,
    "SHA512": Algorithm.SHA512,
    "SHA3": Algorithm.SHA3,
}

# ---------------------------------------------------------------------------
# Public-key generation: (module path, function name) -> (algorithm, usage)
# ---------------------------------------------------------------------------
KEYGEN_RULES: dict[tuple[str, str], tuple[Algorithm, UsageType | None]] = {
    ("cryptography.hazmat.primitives.asymmetric.rsa", "generate_private_key"): (
        Algorithm.RSA,
        UsageType.KEY_GENERATION,
    ),
    ("cryptography.hazmat.primitives.asymmetric.rsa", "generate_public_key"): (
        Algorithm.RSA,
        UsageType.KEY_GENERATION,
    ),
    ("cryptography.hazmat.primitives.asymmetric.ec", "generate_private_key"): (
        Algorithm.ECC,
        UsageType.KEY_GENERATION,
    ),
    ("cryptography.hazmat.primitives.asymmetric.dsa", "generate_private_key"): (
        Algorithm.DSA,
        UsageType.KEY_GENERATION,
    ),
    ("Crypto.PublicKey.RSA", "generate"): (Algorithm.RSA, UsageType.KEY_GENERATION),
    ("Crypto.PublicKey.RSA", "import_key"): (Algorithm.RSA, None),
    ("Crypto.PublicKey.RSA", "construct"): (Algorithm.RSA, None),
    ("Crypto.PublicKey.DSA", "generate"): (Algorithm.DSA, UsageType.KEY_GENERATION),
    ("Crypto.PublicKey.DSA", "import_key"): (Algorithm.DSA, None),
    ("Crypto.PublicKey.ECC", "generate"): (Algorithm.ECC, UsageType.KEY_GENERATION),
    ("Crypto.PublicKey.ECC", "import_key"): (Algorithm.ECC, None),
}

# Argument names that carry the key size for key-generation calls.
KEY_SIZE_KWARGS: tuple[str, ...] = ("key_size", "bits", "key_bits")

# ---------------------------------------------------------------------------
# Symmetric ciphers
# ---------------------------------------------------------------------------
# pycryptodome: Crypto.Cipher.<Module>.new(...) -> algorithm.
PYCRYPTODOME_CIPHER_MODULES: dict[str, Algorithm] = {
    "Crypto.Cipher.AES": Algorithm.AES,
    "Crypto.Cipher.DES": Algorithm.DES,
    "Crypto.Cipher.DES3": Algorithm.TRIPLE_DES,
    "Crypto.Cipher.ARC4": Algorithm.RC4,
}

# cryptography: algorithms.<ClassName>(key) -> algorithm.
CRYPTOGRAPHY_CIPHER_CLASSES: dict[str, Algorithm] = {
    "AES": Algorithm.AES,
    "DES": Algorithm.DES,
    "TripleDES": Algorithm.TRIPLE_DES,
    "ARC4": Algorithm.RC4,
}

# mode names, extracted from cryptography modes.GCM(...) / AES.MODE_GCM.
MODE_ALIASES: dict[str, str] = {
    "GCM": "GCM",
    "CBC": "CBC",
    "ECB": "ECB",
    "CTR": "CTR",
    "CFB": "CFB",
    "OFB": "OFB",
    "XTS": "XTS",
    "CCM": "CCM",
}

# ---------------------------------------------------------------------------
# Usage: method calls on objects bound to a detected crypto value.
# ---------------------------------------------------------------------------
# Functions that switch a detected value's usage (e.g. private_key.sign()).
USAGE_CALLS: dict[str, UsageType] = {
    "encrypt": UsageType.ENCRYPTION,
    "decrypt": UsageType.DECRYPTION,
    "sign": UsageType.DIGITAL_SIGNATURE,
    "verify": UsageType.SIGNATURE_VERIFICATION,
    # "update"/"digest"/"hexdigest" stay hashing; constructor already says so.
}

# Functions that hand back an encryptor/decryptor for a cipher object.
CIPHER_CONTEXT_CALLS: dict[str, UsageType] = {
    "encryptor": UsageType.ENCRYPTION,
    "decryptor": UsageType.DECRYPTION,
}

# Methods on a bound key/cipher object that return another crypto object
# with the same algorithm (e.g. ``private_key.public_key()``).
BINDING_PASSTHROUGH: tuple[str, ...] = ("public_key", "private_key")

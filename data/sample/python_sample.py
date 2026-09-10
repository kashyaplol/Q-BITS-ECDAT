"""Sample Python file demonstrating crypto usage (for testing)."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def hash_password(password: str) -> str:
    # Weak: MD5 / SHA1 are legacy and quantum-vulnerable.
    md5 = hashlib.md5(password.encode()).hexdigest()
    sha1 = hashlib.sha1(password.encode()).hexdigest()
    return md5 + sha1


def secure_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_keys() -> None:
    # RSA key generation (quantum-vulnerable - needs PQC migration).
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print(private_key)

    # ECC key pair.
    ec_private = ec.generate_private_key(ec.SECP256R1())
    print(ec_private)


# AES reference - commonly used for symmetric encryption.
ALGORITHM = "AES-GCM"
print(ALGORITHM, "3DES is legacy")
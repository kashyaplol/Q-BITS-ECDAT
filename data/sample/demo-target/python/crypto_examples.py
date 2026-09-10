"""DEMO/TEST DATA ONLY: intentionally detectable crypto references."""

import hashlib
import ssl

from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Cipher import AES


# Explicit key-size examples. These are labels and demo calls, not real keys.
rsa_1024 = "RSA 1024"
rsa_2048 = RSA.generate(2048)
aes_256 = "AES-256"
cipher = AES.new(b"demo-only")

# Hash and signature algorithm references.
sha1_name = "SHA-1"
sha256_digest = hashlib.sha256(b"demo")
md5_digest = hashlib.md5(b"demo")
signature_algorithm = "ECDSA"
curve_name = "ECC P-256"

# Key-exchange reference for scanner coverage.
exchange = "Diffie-Hellman (DH)"

# This is only a harmless normal value, not a credential or secret.
demo_message = "hello demo repository"

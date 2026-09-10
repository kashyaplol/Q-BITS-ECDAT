"""AST sample: RSA-1024 (too small for modern standards).

The key size is passed as a keyword argument; the AST scanner extracts it
and marks the later ``sign()`` call as a digital-signature usage, so the
risk engine can recommend ML-DSA for a signing use case.
"""

from cryptography.hazmat.primitives.asymmetric import rsa


def demo_rsa_1024() -> None:
    weak_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    signature = weak_key.sign(b"legacy message", padding=None)  # padding: keep simple
    print(signature)
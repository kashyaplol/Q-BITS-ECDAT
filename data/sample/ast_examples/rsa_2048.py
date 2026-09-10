"""AST sample: RSA-2048 (minimum recommended size today).

Illustrates that the AST scanner distinguishes 1024-bit (HIGH classical
risk) from 2048-bit RSA, and that ``public_key().verify()`` is read as a
signature-verification usage.
"""

from cryptography.hazmat.primitives.asymmetric import rsa


def demo_rsa_2048() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    message = b"post-quantum readiness"
    signature = private_key.sign(message, padding=None)
    is_valid = public_key.verify(signature, message, None)
    print(is_valid)
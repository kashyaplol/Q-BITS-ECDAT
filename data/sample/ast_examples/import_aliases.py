"""AST sample: import aliases.

The AST scanner resolves simple aliases so ``as``-renamed imports are
detected just like the canonical names:

    import hashlib as h
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_lib
    from Crypto.Cipher import AES as AES_CTR
"""

import hashlib as h
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_lib
from cryptography.hazmat.primitives.asymmetric import ec as ec_lib
from Crypto.Cipher import AES as AES_CTR


def demo_aliases() -> None:
    summary = h.sha256(b"aliased import")
    key = rsa_lib.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec_lib.generate_private_key(ec_lib.SECP256R1())
    cipher = AES_CTR.new(b"k" * 16, AES_CTR.MODE_ECB)
    print(summary, key, ec_key, cipher)
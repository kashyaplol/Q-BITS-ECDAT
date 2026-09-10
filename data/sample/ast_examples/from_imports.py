"""AST sample: ``from X import Y`` style imports.

Covers the remaining import flavours the AST scanner resolves:

    from hashlib import sha256, sha512
    from cryptography.hazmat.primitives.ciphers import Cipher
    from Crypto.Hash import SHA256, MD5
"""

from hashlib import sha256, sha512
from cryptography.hazmat.primitives.ciphers import Cipher
from Crypto.Hash import MD5, SHA256


def demo_from_imports() -> None:
    a = sha256(b"from import")
    b = sha512(b"from import")
    c = MD5.new(b"legacy")
    d = SHA256.new(b"modern")

    cipher = Cipher(None, None)  # algorithm comes from the code below
    print(a, b, c, d, cipher)
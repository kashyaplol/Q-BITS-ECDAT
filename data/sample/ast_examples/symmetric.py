"""AST sample: symmetric ciphers (AES, DES, 3DES, RC4).

- AES-GCM via the cryptography library (modern authenticated encryption).
- AES-CBC, DES-ECB and 3DES-CBC via pycryptodome ``Cipher.new(...)``.
- RC4 stream cipher (legacy).

The AST scanner can read the cipher *mode* straight from the call
structure (``modes.GCM(iv)``, ``AES.MODE_CBC``, ...).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES, ARC4, DES, DES3


def demo_symmetric() -> None:
    key = b"k" * 32
    iv = b"i" * 12

    # cryptography: modern authenticated encryption (GCM).
    aes_gcm = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = aes_gcm.encryptor()
    ciphertext = encryptor.encrypt(b"hello gm")

    # pycryptodome: legacy/simple block modes.
    aes_cbc = AES.new(key, AES.MODE_CBC, iv=b"i" * 16)
    des_ecb = DES.new(b"12345678", DES.MODE_ECB)
    des3 = DES3.new(b"123456789012345678901234", DES3.MODE_CBC)

    # RC4 stream cipher (legacy, must never be used for new code).
    rc4 = ARC4.new(b"rc4key")

    print(ciphertext, aes_cbc, des_ecb, des3, rc4)
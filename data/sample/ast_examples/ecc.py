"""AST sample: ECC (Elliptic Curve Cryptography) with three curves.

The curve is passed as an object alive in the syntax tree
(``ec.SECP256R1()``, ``ec.SECP384R1()``, ``ec.SECP521R1()``), so the AST
scanner can report the exact curve name as metadata.
"""

from cryptography.hazmat.primitives.asymmetric import ec


def demo_ecc() -> None:
    key_256 = ec.generate_private_key(ec.SECP256R1())
    key_384 = ec.generate_private_key(ec.SECP384R1())
    key_521 = ec.generate_private_key(ec.SECP521R1())

    print(key_256, key_384, key_521)
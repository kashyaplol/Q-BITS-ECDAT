"""AST sample: DSA key generation at 2048 bits.

DSA is weak against Shor's algorithm; the AST scanner records both the
algorithm and the chosen key size.
"""

from cryptography.hazmat.primitives.asymmetric import dsa


def demo_dsa() -> None:
    private_key = dsa.generate_private_key(key_size=2048)
    print(private_key.public_key().public_numbers())
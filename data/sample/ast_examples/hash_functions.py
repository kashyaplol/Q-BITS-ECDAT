"""AST sample: hash functions (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3).

Demonstrates structural hashing detection -- the hash *call* itself is
visible in the syntax tree, so the AST scanner can label the usage as
``HASHING`` instead of guessing from a name in a comment.
"""

import hashlib


def demo_hashes(data: bytes) -> None:
    legacy_md5 = hashlib.md5(data).hexdigest()
    legacy_sha1 = hashlib.sha1(data).hexdigest()

    modern_sha256 = hashlib.sha256(data).hexdigest()
    modern_sha384 = hashlib.sha384(data).hexdigest()
    modern_sha512 = hashlib.sha512(data).hexdigest()

    # SHA-3 family (introduced in Python 3.6+).
    sha3 = hashlib.sha3_256(data).digest()
    sha3_wide = hashlib.new("sha3-512", data).digest()

    print(legacy_md5, legacy_sha1, modern_sha256, modern_sha384, modern_sha512, sha3, sha3_wide)
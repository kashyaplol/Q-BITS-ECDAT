# AST-Based Cryptographic Scanner

Phase 3 enhancement of the `SourceCodeScanner`: a **hybrid** scanner that
combines the original regex pass with Python AST analysis to detect
cryptographic usage structurally and reduce false positives.

## Pipeline

```
source file (.py)
   │
   ├── regex pass  (rules.py)  ──╮
   │                             ├── normalize.py  →  CryptographicAsset[]
   └── AST pass   (ast_scanner) ─╯
                                    │
                                    ▼
                          CBOM → Risk Engine → Summary
```

* The regex pass is unchanged and remains the fallback for Java / JS / TS
  and for Python files the AST cannot parse.
* The AST pass only runs for `.py` files.

## New files

| File                     | Purpose                                          |
| ------------------------ | ------------------------------------------------ |
| `ast_rules.py`           | Declarative tables (imports, hash functions, keygen, ciphers, modes, usage). |
| `ast_scanner.py`         | `PythonAstScanner` - walks the parse tree.       |
| `normalize.py`           | Fuses regex + AST findings (dedup / hybrid).     |

## What the AST scanner detects

* Imports (incl. `as` aliases and `from X import Y`):
  `hashlib`, `cryptography.hazmat.*`, `Crypto.*` (pycryptodome).
* Hash calls: `hashlib.md5/sha1/sha256/sha384/sha512/sha3_*`,
  `hashlib.new("sha256")`, `cryptography ...hashes.SHA256()`,
  `Crypto.Hash.<Name>.new()`.
* Key generation: `rsa/ec/dsa .generate_private_key(...)`,
  pycryptodome `RSA/DSA/ECC .generate(...)` / `.import_key(...)`.
* Symmetric ciphers: `algorithms.AES(key)` (and `DES`, `TripleDES`,
  `ARC4`), `Cipher(algorithms.AES(key), modes.GCM(iv))`,
  `Crypto.Cipher.AES/DES/DES3/ARC4 .new(...)`.
* ECC curves: `ec.SECP256R1()`, `SECP384R1`, `SECP521R1`.
* Usage, only when the code structure clearly shows it:
  `key.sign(...)` -> `DIGITAL_SIGNATURE`,
  `public_key.verify(...)` -> `SIGNATURE_VERIFICATION`,
  `encryptor/decryptor .encrypt/.decrypt` -> `ENCRYPTION` / `DECRYPTION`,
  key-generation calls and hash calls.

## Metadata

When available the AST fills the (optional, backwards-compatible) fields:

* `CryptographicAsset.key_size` - from `key_size=` kwargs, pycryptodome
  positional args, or literal byte-string lengths.
* `CryptographicAsset.usage`, `.curve`, `.mode`.
* `ScanResult.parse_errors` - files the AST could not parse.

`CBOMEntry` aggregates the new metadata into `key_sizes`, `usages`,
`curves`, `modes`.

## How regex and AST work together

Both passes run and their findings are deduplicated by
`(algorithm, library, file, line)`:

* regex hit + AST hit for the same usage -> `DetectionMethod.HYBRID` and
  the richest metadata wins (nothing is invented).
* keyword hit on a line is dropped if a stronger (regex/AST) finding exists.
* different lines are kept as separate occurrences.

## Error handling

`PythonAstScanner.analyze()` returns `(assets, error_message)` and never
raises. `SyntaxError` / `ValueError` / `RecursionError` are caught, the
error is recorded in `ScanResult.parse_errors`, and the file still gets
regex scanning. Read errors (`UnicodeDecodeError`, `PermissionError`,
`FileNotFoundError`, other `OSError`) are handled by the existing
`_read_file` guard.

## Known limitations

* AST metadata is best-effort: sizes/curves/modes are only reported when
  they literally appear in the code (e.g. `key = b"..." * n` sizes are
  not inferred).
* Chained calls such as `cipher.encryptor().encrypt(...)` need the
  intermediate object bound to a name to derive usage.
* No key-size parsing for `bytes(key_)`-derived buffers or constants
  produced by other calls.

## Notes

* All new model fields are optional with `None`/empty defaults, so every
  existing constructor and API response remains valid.
* The `UsageType` enum gained `DECRYPTION`, `KEY_GENERATION`,
  `KEY_ESTABLISHMENT`, `DIGITAL_SIGNATURE`, `SIGNATURE_VERIFICATION`
  (additive only).
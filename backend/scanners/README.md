# Crypto Discovery Scanner

The Crypto Discovery Scanner performs deterministic, source-level discovery of
potential cryptographic usage. It recursively discovers supported source and
configuration files, applies pattern matching to all supported files, and adds
Python AST analysis for imports and known cryptographic calls. A match is a
potential usage signal, not proof that cryptographic code executes.

## Import

```python
from backend.scanners import CryptoScanner
```

`CryptoFinding` is also available from the public package:

```python
from backend.scanners import CryptoFinding
```

## Scan a repository

```python
from pathlib import Path

from backend.scanners import CryptoScanner

scanner = CryptoScanner()
findings = scanner.scan(Path("data/sample/demo-target"))

for finding in findings:
    print(finding.model_dump(mode="json"))
```

`scan(path)` accepts an existing repository directory and returns a
`list[CryptoFinding]`. Each Pydantic finding is JSON serializable with
`finding.model_dump(mode="json")` or `finding.model_dump_json()`.

Python syntax errors do not abort a scan. They are recorded on
`scanner.parsing_errors` as relative-file error messages.

## `CryptoFinding` fields

| Field | Type | Description |
| --- | --- | --- |
| `id` | `str` | Stable finding identifier |
| `algorithm` | `str` | Detected algorithm or library reference |
| `key_size` | `int \| null` | Explicitly detected key size, otherwise `null` |
| `library` | `str \| null` | Reserved library metadata |
| `file` | `str` | Repository-relative file path |
| `line` | `int \| null` | 1-based source line |
| `column` | `int \| null` | 1-based source column when available |
| `language` | `str \| null` | Extension-derived language |
| `code_snippet` | `str \| null` | Source line containing the match |
| `detection_method` | `str` | `deterministic_regex`, `ast`, or a merged method |
| `confidence` | `float` | Deterministic confidence from 0 to 1 |
| `category` | `str \| null` | For example `asymmetric`, `symmetric`, `hash`, or `library` |
| `usage_context` | `str \| null` | Currently `potential cryptographic usage` |
| `symbol_name` | `str \| null` | Python AST import or call name when available |
| `arguments` | `dict[str, str] \| null` | Safely recovered constant AST arguments |

## Example input

`src/auth.py`:

```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
```

## Example output

```json
{
  "id": "src/auth.py:3:6:RSA",
  "algorithm": "RSA",
  "key_size": 2048,
  "library": null,
  "file": "src/auth.py",
  "line": 3,
  "column": 7,
  "language": "Python",
  "code_snippet": "key = RSA.generate(2048)",
  "detection_method": "deterministic_regex+ast",
  "confidence": 0.95,
  "category": "asymmetric",
  "usage_context": "potential cryptographic usage",
  "symbol_name": "RSA.generate",
  "arguments": {"arg0": "2048"}
}
```

Pattern and AST records for the same usage are merged; distinct algorithms or
distinct usages on one source line are retained.

## Supported languages

Language is identified by file extension:

- Python (`.py`)
- JavaScript (`.js`, `.jsx`)
- TypeScript (`.ts`, `.tsx`)
- Java (`.java`)
- C (`.c`)
- C++ (`.cpp`, `.hpp`)
- C/C++ headers (`.h`)
- Go (`.go`)
- Rust (`.rs`)
- PHP (`.php`)
- Ruby (`.rb`)
- YAML (`.yaml`, `.yml`)
- JSON (`.json`)
- XML (`.xml`)
- Config (`.conf`, `.config`)

## Currently detected algorithms and references

Algorithms include RSA, DSA, ECDSA, ECC, Diffie-Hellman/DH, AES, DES, 3DES,
Blowfish, ChaCha20, MD5, SHA-1, SHA-256, SHA-384, and SHA-512.

Library references include Python `cryptography`, `Crypto`, `PyCryptodome`,
`Cryptodome`, `hashlib`, and `ssl`; Java `javax.crypto` and `java.security`;
JavaScript/Node `crypto` and `node:crypto`; Go `crypto/`; and OpenSSL.

## Known limitations

- Detection is deterministic pattern matching and lightweight Python AST
  analysis; it does not prove runtime execution or semantic intent.
- Python files with syntax errors are skipped by the AST pass and reported in
  `scanner.parsing_errors`; pattern matching may still produce findings.
- Key sizes are populated only for explicitly recognized forms.
- Binary files and ignored directories (`.git`, `node_modules`, `venv`,
  `.venv`, `__pycache__`, `.next`, `dist`, and `build`) are not scanned.
- The scanner does not generate CBOM data, risk scores, or API responses.

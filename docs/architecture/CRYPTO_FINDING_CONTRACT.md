# CryptoFinding Integration Contract

This document defines the current JSON-compatible output contract of the Q-BITS
ECDAT Crypto Discovery Scanner. It reflects the implemented
`backend.scanners.source.models.CryptoFinding` Pydantic model and is consumed by
the CBOM and Risk layers.

## Public scanner interface

Import the scanner from:

```python
from backend.scanners import CryptoScanner
```

Scan an existing repository directory with:

```python
from pathlib import Path

scanner = CryptoScanner()
findings = scanner.scan(Path("data/sample/demo-target"))
```

`CryptoScanner.scan(path)` returns:

```python
list[CryptoFinding]
```

Each finding is JSON serializable with either:

```python
finding.model_dump(mode="json")
```

or:

```python
finding.model_dump_json()
```

## `CryptoFinding` schema

The model is imported from:

```python
from backend.scanners import CryptoFinding
```

| Field | Type | Required | Current meaning |
| --- | --- | --- | --- |
| `id` | `str` | Yes | Finding identifier |
| `algorithm` | `str` | Yes | Detected algorithm or cryptographic library reference |
| `key_size` | `int \| null` | No | Explicitly detected key size; otherwise `null` |
| `library` | `str \| null` | No | Library metadata when populated |
| `file` | `str` | Yes | Repository-relative source file path |
| `line` | `int \| null` | No | 1-based source line when available |
| `column` | `int \| null` | No | 1-based source column when available |
| `language` | `str \| null` | No | Language identified from the file extension |
| `code_snippet` | `str \| null` | No | Source line containing the detection |
| `detection_method` | `str` | Yes | Detector that produced or merged the finding |
| `confidence` | `float` | Yes | Deterministic confidence value from 0 to 1 |
| `category` | `str \| null` | No | Finding category such as `asymmetric`, `symmetric`, `hash`, or `library` |
| `usage_context` | `str \| null` | No | Current context label for the potential usage |
| `symbol_name` | `str \| null` | No | Python AST import or call name when available |
| `arguments` | `dict[str, str] \| null` | No | Safely recovered constant Python AST arguments |

Pydantic validation currently requires `confidence` to be between 0 and 1,
and rejects negative `key_size`, `line`, or `column` values.

## Example actual output

The following is an actual serialized finding shape produced by scanning a
Python source file containing `RSA.generate(2048)`:

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
  "arguments": {
    "arg0": "2048"
  }
}
```

The `file` value is repository-relative; absolute machine paths are not part of
this contract.

## Detection methods currently supported

- `deterministic_regex`: deterministic source-line pattern matching.
- `ast`: Python `ast.parse()` analysis of supported imports and calls.
- `deterministic_regex+ast`: a merged finding where both detectors identify the
  same usage.

## Current limitations

- Findings represent potential cryptographic usage, not proof of runtime
  execution or semantic intent.
- The scanner currently performs source-file discovery and Python AST analysis;
  binary and container scanning are not part of this contract.
- Python syntax errors are recorded on `scanner.parsing_errors`; malformed
  Python does not abort scanning of other files.
- Binary files and configured ignored directories are skipped.
- Key sizes are populated only when an explicitly recognized form is present;
  uncertain sizes remain `null`.
- Duplicate detector records for the same usage may be merged, while distinct
  algorithms or usages on one source line remain separate.
- This contract does not define CBOM generation, risk scoring, or API response
  behavior.


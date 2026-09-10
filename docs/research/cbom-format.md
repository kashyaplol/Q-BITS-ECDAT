# CBOM Format

A **CBOM** (Cryptographic Bill of Materials) is a structured inventory
of the cryptography used across a codebase. Think of it as an SBOM for
cryptographic assets instead of software components.

## Full document shape

A `POST /api/v1/scan`, `POST /api/v1/cbom/generate` or
`GET /api/v1/cbom` returns the same shape:

```json
{
  "project": "Q-BITS-ECDAT",
  "generated_at": "2026-09-10T11:00:00Z",
  "cryptographic_assets": [
    {
      "algorithm": "RSA",
      "library": "cryptography",
      "file": "app/utils.py",
      "occurrences": 2,
      "risk_level": "CRITICAL",
      "line_numbers": [12, 40],
      "detection_methods": ["ast", "hybrid"],
      "contexts": ["rsa.generate_private_key(key_size=2048)"],
      "key_sizes": [2048],
      "usages": ["KEY_GENERATION"],
      "curves": [],
      "modes": []
    },
    {
      "algorithm": "AES",
      "library": "javax.crypto",
      "file": "src/Crypto.java",
      "occurrences": 1,
      "risk_level": "MEDIUM",
      "line_numbers": [7],
      "detection_methods": ["regex"],
      "contexts": ["Cipher.getInstance(\"AES/CBC/PKCS5Padding\")"],
      "key_sizes": [],
      "usages": [],
      "curves": [],
      "modes": []
    }
  ],
  "total_assets": 2,
  "total_findings": 3,
  "unique_algorithms": ["AES", "RSA"],
  "high_risk_assets": 1,
  "medium_risk_assets": 1
}
```

## Field reference

| Field                  | Type     | Meaning                                             |
|------------------------|----------|-----------------------------------------------------|
| `project`              | string   | Label given to the CBOM (defaults to "Q-BITS-ECDAT") |
| `generated_at`         | datetime | When the CBOM was generated (UTC)                    |
| `cryptographic_assets` | array    | One entry per unique (algorithm + library + file)    |
| `total_assets`         | integer  | Number of entries in `cryptographic_assets`          |
| `total_findings`       | integer  | Raw scanner findings before grouping (sum of `occurrences`) |
| `unique_algorithms`    | array    | Sorted, de-duplicated list of detected algorithms    |
| `high_risk_assets`     | integer  | Entries with risk `HIGH` or `CRITICAL`               |
| `medium_risk_assets`   | integer  | Entries with risk `MEDIUM`                           |

### Entry fields

| Field               | Meaning                                                            |
|---------------------|--------------------------------------------------------------------|
| `algorithm`         | Detected algorithm (MD5, SHA1, SHA256, SHA384, SHA512, AES, 3DES, RSA, ECC, ...) |
| `library`           | Library detected (`hashlib`, `javax.crypto`, `crypto` from Node.js, ...) or `null` for keyword-only hits |
| `file`              | File path where the usage was found                                 |
| `occurrences`       | How many times that algorithm+library appears in that file          |
| `risk_level`        | Overall quantum-risk level assigned by the risk engine (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) |
| `line_numbers`      | All line numbers where this entry was found (scanner evidence)      |
| `detection_methods` | Distinct detection methods used (`regex`, `keyword`, `pattern`, `ast`, `hybrid`) |
| `contexts`          | The matching source line snippets (scanner evidence)                |
| `key_sizes`         | Distinct key sizes (bits) reported by the AST pass, e.g. `[2048]`   |
| `usages`            | Distinct detected usages, e.g. `["KEY_GENERATION", "DIGITAL_SIGNATURE"]` |
| `curves`            | Distinct ECC curves, e.g. `["SECP256R1"]`                           |
| `modes`             | Distinct block-cipher modes, e.g. `["GCM", "CBC"]`                  |

## Aggregation rules

* Assets (or findings) are grouped by **algorithm + library + file path**.
* A keyword hit (library `null`) is grouped separately from a library
  hit of the same algorithm in the same file.
* Entries are **sorted worst-risk-first**, then alphabetically by
  algorithm, then by file.
* **Scanner evidence is never discarded**: the line numbers, detection
  methods and source snippets of every grouped finding are preserved on
  the entry.
* Python files are scanned by a **hybrid regex + AST** pipeline. When the
  regex pass and the AST pass agree on the same usage the finding is
  labelled `hybrid`; AST-only attributes (key sizes, usages, curves,
  modes) appear on the entry whenever the syntax tree made them
  discoverable.

## Why group instead of listing every line?

The raw scan contains one asset *per line*. Grouping compresses the
report (95 line-level findings become 59 CBOM entries for the sample
project) while keeping "where to look" information through
`line_numbers` and `contexts`. The raw, line-by-line view stays
available in the scan response (`ScanResult.assets`).

The `ScanResult` also carries `parse_errors`: a list of files the AST
scanner could not parse (each still receives regex-only scanning).

## Schema source of truth

The Pydantic models in `backend/app/models/schemas.py`
(`CBOMEntry`, `CBOM`) are the single source of truth for this format.
A JSON Schema can be exported at any time:

```python
from backend.app.models import CBOM
print(CBOM.model_json_schema())
```
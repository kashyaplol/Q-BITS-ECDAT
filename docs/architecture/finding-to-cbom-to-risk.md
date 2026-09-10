# Finding → CBOM → Risk: Mapping and Architecture

This document ties the three layers together:

```
SourceCodeScanner
      ↓  ScanResult.assets: list[CryptographicAsset]
CBOMGenerator
      ↓  CBOM (grouped inventory, evidence preserved)
RiskEngine
      ↓  RiskAssessment per algorithm + RiskSummary
API / Dashboard (JSON)
```

> Note: the scanner in this project is `SourceCodeScanner` and it emits
> `CryptographicAsset` objects (the "finding" model for this codebase).
> Earlier planning docs refer to a generic `CryptoFinding`; the real
> concrete type is `CryptographicAsset`, defined in
> `backend/app/models/schemas.py`. This document uses the real types.

## 1. The finding contract (`CryptographicAsset`)

Produced by `SourceCodeScanner.scan_file()` / `.scan_directory()`.

| Field             | Type               | Required | Meaning                                  |
|-------------------|--------------------|----------|------------------------------------------|
| `file_path`       | `str`              | yes      | File location                            |
| `line_number`     | `int`              | yes      | Line location (1-based)                  |
| `algorithm`       | `Algorithm` (enum) | yes      | Algorithm identification                 |
| `library`         | `str \| None`      | no       | Library identification (`hashlib`, ...)  |
| `detection_method`| `DetectionMethod`  | yes      | Detection type (`regex`, `keyword`, ...) |
| `context`         | `str \| None`      | no       | Matching source snippet (evidence)       |

There is **no** `confidence`, `usage`, or `key_size` field — the risk
engine never assumes those exist and never invents them.

## 2. Finding → CBOM mapping

`CBOMGenerator.generate()` accepts either a `ScanResult` or a plain
`list[CryptographicAsset]`.

* **One CBOM entry per (algorithm + library + file)** group.
* `occurrences` = how many findings collapsed into that entry.
* `line_numbers`, `detection_methods`, `contexts` = the aggregated
  scanner evidence for that group (deduplicated/sorted).
* Each entry is enriched with `risk_level` from the risk engine.
* Empty input → empty, well-formed CBOM (never crashes).

## 3. CBOM architecture (`backend/cbom/`)

```
backend/cbom/
  generator.py   CBOMGenerator (group, preserve evidence, enrich, sort)
  __init__.py    public exports
```

The generator is a **pure aggregation layer** — it never scans code and
never invents scanner fields. Models live in `backend/app/models`.

## 4. Risk engine architecture (`backend/risk/`)

```
backend/risk/
  knowledge.py   The risk knowledge base (RiskProfile per algorithm),
                 name aliases/resolution, PQC-mapping by usage.
  engine.py      RiskEngine — the public entry point.
  scoring.py     Configurable numerical scoring (0-4).
  summary.py     RiskSummary aggregation.
  __init__.py    public exports (risk_engine singleton, ...)
```

`RiskEngine.assess()` accepts an algorithm name, a `CryptographicAsset`,
or a CBOM entry — so the scanner output flows in untouched.

## 5. Algorithm normalization

All name normalization is centralized in
`backend/risk/knowledge.py` (`resolve_algorithm`, `_normalize`,
`_ALIASES`, `_KEY_HINTS`). No other module does its own mapping.

| Input            | Canonical | Key-size hint |
|------------------|-----------|---------------|
| `rsa`, `RSA`      | RSA      | –             |
| `sha1`, `SHA-1`   | SHA1     | –             |
| `sha256`, `SHA-256` | SHA256  | –             |
| `sha384`, `SHA-384` | SHA384 | –             |
| `sha512`, `SHA-512` | SHA512 | –             |
| `sha3`, `SHA-3`    | SHA3     | –             |
| `aes`, `AES-128`  | AES      | 128 (from name) |
| `3des`, `DESede`  | 3DES     | –             |
| `ecdh`            | ECDH     | –             |
| `ecdsa`           | ECDSA    | –             |
| `Diffie-Hellman`  | DH       | –             |

Unknown names are preserved (upper-cased) and reported as
`UNKNOWN` by the risk engine — never a crash.

## 6. Risk classification methodology

Documented in detail in
`docs/research/quantum-risk-methodology.md`. Summary:

* Public-key algorithms (RSA, ECC, ECDSA, ECDH, DSA, DH) → Shor's
  algorithm → quantum **CRITICAL**, migration **CRITICAL**.
* Symmetric (AES) → Grover's algorithm → MEDIUM by default,
  LOW at 192/256-bit keys.
* Hashes → SHA-256 MEDIUM, SHA-384/SHA-512/SHA-3 LOW.
* Legacy (MD5, SHA-1, DES, 3DES, RC4) → already broken/deprecated →
  **IMMEDIATE** migration.
* Unknown → `UNKNOWN` / `REVIEW_REQUIRED`.

Recommended PQC replacements come from NIST FIPS 203/204/205:
ML-KEM for key establishment/encryption, ML-DSA for signatures,
SLH-DSA as hash-based signature alternative.

## 7. Known limitations and disclaimer

**Disclaimer.** This tool performs cryptographic *discovery* and *risk
prioritization*. It does **not** automatically prove that a
cryptographic implementation is secure or insecure. Risk levels are
based on well-known algorithmic attacks (Shor, Grover) and algorithm
status; they are a prioritization aid for humans, not a formal
security certification.

Known limitations:

* **No key-size extraction** — the scanner does not currently read key
  sizes from the source; key-size-aware rules only apply when a key size
  is supplied explicitly (e.g. via `POST /api/v1/risk/assess`).
* **No usage detection** — the scanner does not classify how an
  algorithm is used (encryption vs signature); usage-aware PQC
  recommendations only apply when usage is supplied explicitly.
* **Regex-based, language-agnostic scanning** — may produce false
  positives (e.g. a string that merely *mentions* "RSA") and cannot yet
  follow imports/variables. AST-based detection is a future phase.
* **In-memory state** — the API keeps only the most recent analysis in
  memory; there is no persistence layer.
* **Expert-reviewed knowledge base** — the risk ratings encode current
  NIST guidance and are a policy choice; they are explicit and easy to
  change in `backend/risk/knowledge.py`.

## 8. End-to-end reference flow

```python
from backend.scanners.source import SourceCodeScanner
from backend.cbom import CBOMGenerator
from backend.risk import risk_engine, build_risk_summary

scan = SourceCodeScanner().scan_directory("data/sample")   # findings
bom = CBOMGenerator(project="demo").generate(scan)          # CBOM
assessments = risk_engine.assess_many(bom.unique_algorithms)
summary = build_risk_summary(scan.assets, risk_engine)      # RiskSummary
```

The demo script `scripts/sample_risk_report.py` runs exactly this flow
and writes `data/sample/cbom_samples.json` and
`data/sample/risk_assessment_samples.json`.
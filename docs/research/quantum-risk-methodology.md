# Quantum Risk Methodology

This document explains *why* each algorithm gets the risk rating it
does. The ratings live in the **risk knowledge base**
(`backend/risk/knowledge.py`); the engine that applies them is
`backend/risk/engine.py`, and scoring lives in
`backend/risk/scoring.py`.

All ratings are driven by two well-known quantum algorithms plus the
classical state of the art.

## The two quantum threats

### 1. Shor's algorithm — breaks public-key cryptography

Shor's algorithm lets a sufficiently large quantum computer:

* **factorise large numbers** (breaks RSA), and
* **solve discrete logs** (breaks ECC/ECDSA/ECDH, DSA, Diffie-Hellman).

For these algorithms, "quantum computer arrives" = "algorithm is dead".
No amount of key size increase saves them — you must switch to a
different algorithm entirely.

**Affected (rated CRITICAL quantum risk, CRITICAL migration):**
RSA, ECC, ECDSA, ECDH, DSA, Diffie-Hellman.

### 2. Grover's algorithm — halves symmetric strength

Grover's algorithm gives a quadratic speed-up to brute-force search.
Consequences:

* AES-128 becomes as hard to break as AES-64 today → MEDIUM quantum risk;
* AES-192 / AES-256 remain safe → LOW quantum risk;
* hash functions are only mildly affected.

**Mitigation:** double the key size where possible, keep "crypto
agility" (the ability to switch algorithms easily).

**Affected:** AES (MEDIUM by default, LOW at 192/256-bit keys),
SHA-256 (MEDIUM), SHA-512 (LOW).

## What about the "already broken" algorithms?

Some algorithms are insecure *today*, with or without quantum computers:

| Algorithm | Why it is already bad                    | Classical / Quantum | Migration      |
|-----------|------------------------------------------|---------------------|----------------|
| MD5       | collision attacks since 2004            | CRITICAL / HIGH     | IMMEDIATE      |
| SHA-1     | collision attacks demonstrated in 2017  | CRITICAL / HIGH     | IMMEDIATE      |
| DES       | 56-bit key, brute-forced in 1999        | CRITICAL / HIGH     | IMMEDIATE      |
| 3DES      | deprecated by NIST after 2023           | CRITICAL / HIGH     | IMMEDIATE      |
| RC4       | bias-based attacks, ciphersuite removal | CRITICAL / HIGH     | IMMEDIATE      |

These are the first things to remove from a codebase, independent of
quantum progress — hence the dedicated `IMMEDIATE` migration priority.

## Risk-level computation

Each algorithm has two dimensions:

```
classical_risk      how dangerous it is with today's computers
quantum_risk        how dangerous it becomes with quantum computers
```

The **overall risk level** is the worst of the two:

```
CRITICAL > HIGH > MEDIUM > LOW
```

The **migration priority** is stored explicitly per algorithm so urgent
("migrate to ML-KEM/ML-DSA now") items stand out from "consider later"
items.

### Risk scoring

Every assessment carries a `risk_score`:

| Level    | Score |
|----------|-------|
| LOW      | 1     |
| MEDIUM   | 2     |
| HIGH     | 3     |
| CRITICAL | 4     |

The score is the worst of the classical and quantum scores, capped at 4
and configurable via `ScoringConfig` (see `backend/risk/scoring.py` for
the `deprecated_bonus` / `max_score` knobs):

```
MD5       CRITICAL + HIGH  -> 4
RSA-1024  MEDIUM   + CRIT  -> 4
RSA-2048  MEDIUM   + CRIT  -> 4
AES-128   LOW      + MED   -> 2
AES-256   LOW      + LOW   -> 1
```

### Key-size analysis

Optional key-size rules refine the baseline risks:

* **RSA:**  `<=1023` bits → classical HIGH; `1024..3071` → MEDIUM;
  `>=3072` → LOW. (Overall stays CRITICAL in every case — Shor's.)
* **AES:**  `128`-bit → quantum MEDIUM + HIGH migration priority;
  `192`-bit → LOW + MEDIUM; `256`-bit → LOW + LOW.

## Post-quantum replacements (NIST FIPS 203/204/205)

| Classical algorithm                   | Recommended PQC replacement              | NIST standard |
|---------------------------------------|-------------------------------------------|---------------|
| RSA - key exchange/encryption         | ML-KEM (CRYSTALS-Kyber)                   | FIPS 203      |
| RSA / ECDSA / DSA - signatures        | ML-DSA (CRYSTALS-Dilithium)               | FIPS 204      |
| ECC / ECDH / Diffie-Hellman           | ML-KEM for key establishment              | FIPS 203      |
| ECDSA signatures (hash-based options) | SLH-DSA (SPHINCS+)                        | FIPS 205      |

When a scan reports the *usage* of an algorithm (encryption, key
exchange, signature, hashing, symmetric encryption), the engine picks
the matching recommendation from
`backend/risk/knowledge.py` (see `usage_recommendation` / `usage_pqc`).

## Legacy algorithm replacements

| Legacy | Replacement                          |
|--------|--------------------------------------|
| MD5    | SHA-256 or SHA-3                     |
| SHA-1  | SHA-256 / SHA-384 / SHA-512 / SHA-3  |
| DES    | AES-256 / AES-GCM                    |
| 3DES   | AES-256 / AES-GCM                    |
| RC4    | AES-GCM / ChaCha20-Poly1305          |

## Unknown algorithms

If the engine is given an algorithm it has never seen, it does **not**
guess. It returns:

* `RiskLevel.UNKNOWN` for classical / quantum / overall risk,
* `MigrationPriority.REVIEW_REQUIRED`,
* `risk_score = 0`,
* a recommendation: *"Algorithm is not present in the current risk
  knowledge base. Manual security review is recommended."*

Unknown algorithms never crash the engine and surface in reports as
"needs manual review" instead of being silently dismissed.
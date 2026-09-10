# Q-BITS-ECDAT Risk Prioritization Policy

The **priority score** (0-100) sits on top of the existing 0-4 risk score.
It answers *"what needs attention first"*: which assets are most
dangerous, which findings top the reports, and in which order migrations
should happen.

The priority score complements `RiskAssessment.risk_score` -- the existing
classical/quantum risk dimension is **kept untouched**.

> **IMPORTANT**
> The priority score is a **Q-BITS-ECDAT policy-based prioritization aid**.
> It is **not** an official security standard and does not guarantee a
> security rating. Treat it as an internal triage ordering, not a
> certification result.

## Where it lives

* Policy + scoring: `backend/risk/prioritization.py`
  (`PrioritizationConfig`, `PriorityEngine`, `priority_engine`).
* Output models: `backend/app/models/schemas.py`
  (`PriorityLevel`, `RiskFactor`, `PriorityAssessment`, `TopRiskAsset`).
* Defaults: `backend/risk/__init__.py` re-exports `priority_engine`.

## Score bands

| Priority level | Score   |
|----------------|---------|
| `IMMEDIATE`    | 81-100  |
| `CRITICAL`     | 61-80   |
| `HIGH`         | 41-60   |
| `MEDIUM`       | 21-40   |
| `LOW`          | 0-20    |

## Formula

The score is the **sum of every active factor's points**, capped at 100.
This keeps it fully explainable: `sum(factor.points) == priority_score`.

| Factor (rule id)            | Contribution             | When it applies                                  |
|-----------------------------|--------------------------|--------------------------------------------------|
| Classical Vulnerability     | up to 30 pts (LOW..CRIT) | always (UNKNOWN = 0)                             |
| Quantum Vulnerability       | up to 30 pts (LOW..CRIT) | always (UNKNOWN = 0)                             |
| Algorithm Deprecation       | +40 pts                  | algorithm marked `deprecated` in the knowledge base |
| Quantum Migration Requirement | +10 pts                | quantum risk is CRITICAL (public key / Shor's)   |
| Weak Key Size               | +10 pts                  | key size is *actually known* and below threshold |
| Cryptographic Usage         | +8 pts                   | usage is *actually detected* on a Shor's-vulnerable algorithm |
| Weak Configuration          | +25 pts                  | AES in ECB mode is *actually detected*           |
| Unknown Algorithm           | 0 pts                    | algorithm missing from the knowledge base       |

All weights live in `PrioritizationConfig` (`backend/risk/prioritization.py`)
-- change one dataclass to tune the whole system. Per-algorithm weak key
thresholds: RSA/DH/DSA `< 2048`, ECC/ECDSA/ECDH `< 224`, AES `< 192`.

## Risk factors (explainability)

Every prioritized assessment returns the contributing **risk factors**:

```json
{
  "rule": "deprecated",
  "factor": "Algorithm Deprecation",
  "impact": "HIGH",
  "reason": "MD5 is deprecated for security-sensitive use and must be replaced.",
  "points": 40
}
```

Reasons are **generated from actual rules**, never filler text. Each factor
maps to one rule in the policy table above.

## Example outcomes (default policy)

| Algorithm / context                | Score | Level     |
|------------------------------------|-------|-----------|
| MD5, SHA-1, DES, 3DES, RC4         | 88    | IMMEDIATE |
| RSA-1024, key exchange             | 68    | CRITICAL  |
| RSA-2048, no usage                 | 50    | HIGH      |
| RSA-2048, digital signature        | 58    | HIGH      |
| AES-128 + ECB                      | 52    | HIGH      |
| AES-128 (no config)                | 27    | MEDIUM    |
| SHA-256                            | 17    | LOW       |
| AES-256, SHA-384/512/3             | 10    | LOW       |
| Unknown algorithm                  | 0     | LOW (REVIEW required) |

## Migration timeline (urgency)

`PriorityAssessment.urgency` maps the asset onto the migration timeline:

| Urgency    | Applies to                                        |
|------------|---------------------------------------------------|
| `IMMEDIATE`| legacy / broken algorithms (MD5, SHA-1, DES, 3DES, RC4) |
| `URGENT`   | quantum-vulnerable public-key algorithms (RSA, ECC, ECDSA, ECDH, DSA, DH) |
| `HIGH`     | weak configurations / weak key sizes (AES-128/ECB) |
| `PLANNED`  | longer-term modernization (SHA-256)               |
| `LOW`      | strong, modern cryptography (AES-256, SHA-384/512/3) |

## Known limitations

* Metadata is only used when actually present: if a key size or usage was
  never detected, the corresponding factor is skipped (never invented).
* Unknown algorithms score 0 (no rule matched) but are flagged `HIGH`
  urgency / `REVIEW_REQUIRED` for a manual review.
* The score is a triage aid for this tool -- see the disclaimer above.
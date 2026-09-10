# CBOM Risk Engine

## Input model

`backend.risk.assess_risk(cbom)` consumes the current
`backend.cbom.models.CBOM`. It assesses each CBOM component and uses its
cryptographic information plus linked assets. It does not read source files,
rescan a repository, call an LLM, or mutate the CBOM.

The result is a JSON-serializable `CBOMRiskReport` with one `CBOMRiskResult`
per component. Each result has its component `identifier`, algorithm, risk
level and score, reasons, affected files, observed key sizes, quantum
relevance, migration priority, recommendation, and an explicit factor record.

## Available factors

The engine evaluates algorithm, supplied key sizes, known legacy status,
post-quantum relevance, scanner confidence, and supplied usage contexts.
Confidence is reported as evidence quality and deliberately does not reduce an
algorithm's technical risk score. Generic scanner usage contexts are retained,
but do not cause a use-case-specific adjustment.

Missing key sizes, confidence, usage context, and an algorithm-specific rule
are listed by name in `factors.unavailable`; no value is guessed.

## Scoring and levels

Scores are fixed integers on a 0–100 scale. The mapping is exact:

| Rule | Score | Level |
| --- | ---: | --- |
| MD5, SHA-1, DES, 3DES | 100 | CRITICAL |
| RSA below 2048 bits | 95 | CRITICAL |
| RSA at/above 2048 bits; DSA, DH, ECDSA, ECC/ECDH | 70 | HIGH |
| AES-128 | 40 | MEDIUM |
| Unknown algorithm | 50 | MEDIUM |
| AES with no key size | 30 | LOW |
| AES-192/256; modern SHA-2/SHA-3 variants | 20 | LOW |

No score is derived from business criticality, data lifetime, runtime reachability,
or the source snippet because the CBOM does not provide those facts.

## Migration priorities

- `P0`: critical deprecated crypto or RSA below 2048 bits; migrate first.
- `P1`: public-key algorithms relevant to post-quantum migration planning.
- `P2`: AES-128 or unknown algorithms requiring review.
- `P3`: lower-priority AES and recognized modern hashes.

## Quantum relevance

`HIGH` is assigned to RSA, DSA, DH, ECDSA, ECC, and ECDH because they are
public-key systems affected by Shor's algorithm. `LIMITED` is assigned to AES
and modern hashes: this engine does not claim that AES-256 is broken by quantum
computing. Legacy algorithms receive `NOT_ESTABLISHED` because their P0 status
comes from known classical weakness, not a quantum determination. Unknown
algorithms receive `UNKNOWN`.

## Recommendations

Recommendations are fixed rule text. MD5 and SHA-1 advise migration to a
modern hash appropriate to the use case; DES/3DES advise modern encryption.
Public-key findings advise post-quantum or hybrid planning but deliberately do
not select a particular PQC algorithm. AES guidance retains AES and suggests
considering AES-256 where stronger long-term margin is required.

## Limitations

This is an inventory-driven prioritization aid, not a security certification.
It does not know business criticality, data lifetime, key provenance, cipher
mode, runtime execution, protocol role, or whether a detected string is an
active production use. It does not choose a specific PQC replacement.

## Example output

```json
{
  "assets_assessed": 1,
  "assessments": [{
    "identifier": "component:RSA%7Casymmetric%7C",
    "algorithm": "RSA",
    "risk_level": "HIGH",
    "risk_score": 70,
    "quantum_relevance": "HIGH",
    "migration_priority": "P1",
    "affected_files": ["src/auth.py"]
  }]
}
```

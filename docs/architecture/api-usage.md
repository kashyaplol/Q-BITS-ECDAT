# API Usage Guide

All endpoints live under `/api/v1` (plus a root `/health` endpoint).
FastAPI auto-generates interactive documentation:

* Swagger UI:  http://127.0.0.1:8000/docs
* ReDoc:       http://127.0.0.1:8000/redoc

## Endpoint summary

| Method | Path                            | Description                              |
|--------|---------------------------------|------------------------------------------|
| GET    | `/health`                       | Health check                              |
| GET    | `/api/v1/health`                | Health check (versioned)                  |
| GET    | `/api/v1/info`                  | Project metadata                          |
| POST   | `/api/v1/scan`                  | Scan a path & run full analysis           |
| POST   | `/api/v1/cbom/generate`         | Scan a path & return only the CBOM        |
| GET    | `/api/v1/cbom`                  | CBOM of the most recent scan              |
| GET    | `/api/v1/risk`                  | Risk assessments of the latest scan       |
| GET    | `/api/v1/risk/summary`          | Risk counts roll-up of the latest scan    |
| POST   | `/api/v1/risk/assess`           | Assess a single algorithm on the spot     |
| GET    | `/api/v1/risk/prioritized`      | Latest scan + priority scores (sorted)    |
| GET    | `/api/v1/migration/roadmap`     | Organization-level migration roadmap      |
| POST   | `/api/v1/migration/plan`        | Build an asset-level migration plan       |
| GET    | `/api/v1/dashboard/summary`     | Headline numbers for the dashboard        |
| POST   | `/api/v1/report`                | Scan a directory & return the report (text) |
| GET    | `/api/v1/report`                | Report for the most recent scan (text)    |

## Example calls (curl)

### Health

```bash
curl http://127.0.0.1:8000/health
```

```json
{"status": "healthy", "project": "Q-BITS-ECDAT"}
```

### Info

```bash
curl http://127.0.0.1:8000/api/v1/info
```

### Scan a project

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "data/sample"}'
```

Response (abridged):

```json
{
  "scanned_path": "data/sample",
  "files_scanned": 3,
  "crypto_assets_found": 26,
  "algorithm_counts": {"MD5": 5, "SHA1": 4, "SHA256": 3, "AES": 5, "RSA": 5, "ECC": 3, "3DES": 1},
  "cbom": { "...": "full CBOM document" },
  "risks": [
    {
      "algorithm": "RSA",
      "category": "PUBLIC_KEY",
      "classical_risk": "MEDIUM",
      "quantum_risk": "CRITICAL",
      "risk_level": "CRITICAL",
      "overall_risk": "CRITICAL",
      "risk_score": 4,
      "migration_priority": "CRITICAL",
      "recommendation": "Plan migration from RSA to a Post-Quantum Cryptography solution (ML-KEM for key establishment/encryption, ML-DSA for digital signatures).",
      "recommended_action": "Plan migration from RSA to a Post-Quantum Cryptography solution (ML-KEM for key establishment/encryption, ML-DSA for digital signatures).",
      "pqc_recommendation": "ML-KEM or ML-DSA (FIPS 203 / 204)",
      "reason": "This public-key algorithm is vulnerable to Shor's algorithm on a sufficiently powerful cryptographically relevant quantum computer.",
      "key_size": null,
      "usage": null,
      "file_path": null,
      "line_number": null
    }
  ],
  "summary": {
    "total_files_scanned": 3,
    "crypto_assets_found": 26,
    "high_risk_assets": 14,
    "critical_migrations": 18
  }
}
```

The `POST /api/v1/scan` call caches its results, so the read-only
endpoints below work for the most recent scan.

### Get the CBOM

```bash
curl http://127.0.0.1:8000/api/v1/cbom
```

### Generate a CBOM only (no risk report)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/cbom/generate \
  -H "Content-Type: application/json" \
  -d '{"path": "data/sample"}'
```

Returns just the CBOM document and caches it for `GET /api/v1/cbom`.

### Get risk assessments

```bash
curl http://127.0.0.1:8000/api/v1/risk
```

### Get risk summary

```bash
curl http://127.0.0.1:8000/api/v1/risk/summary
```

```json
{
  "total_assets": 26,
  "critical_risk_assets": 18,
  "high_risk_assets": 0,
  "medium_risk_assets": 8,
  "low_risk_assets": 0,
  "immediate_migrations_required": 10
}
```

### Assess a single algorithm (no scan needed)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/risk/assess \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "AES-128", "usage": "encryption", "key_size": 128}'
```

Supported input: any algorithm name, `key_size`, `usage`
("encryption", "key exchange", "signature", "hashing",
"symmetric-encryption" or a free-text variant), plus optional
`file_path` / `line_number` for report provenance.

### Get dashboard summary

```bash
curl "http://127.0.0.1:8000/api/v1/dashboard/summary?limit=5"
```

```json
{
  "total_files_scanned": 12,
  "crypto_assets_found": 95,
  "high_risk_assets": 45,
  "critical_migrations": 61,
  "priority_distribution": {"LOW": 33, "MEDIUM": 0, "HIGH": 34, "CRITICAL": 1, "IMMEDIATE": 27},
  "top_migration_priorities": [
    {
      "algorithm": "MD5",
      "file_path": "data/sample/java_sample.java",
      "line_number": 8,
      "priority_score": 88,
      "priority_level": "IMMEDIATE",
      "migration_strategy": "IMMEDIATE_REPLACEMENT",
      "recommended_algorithm": "SHA-256 / SHA-3"
    }
  ]
}
```

The `limit` query parameter (default 5) controls the size of
`top_migration_priorities`.

### Get prioritized risk (Phase 4)

Returns the latest scan's assessments, enriched with
`priority_score`, `priority_level`, `urgency` and the explainable
`risk_factors`, sorted worst-first.

```bash
curl http://127.0.0.1:8000/api/v1/risk/prioritized
```

### Get the organization migration roadmap (Phase 4)

```bash
curl http://127.0.0.1:8000/api/v1/migration/roadmap
```

```json
{
  "project": "Q-BITS-ECDAT",
  "total_assets": 95,
  "immediate": 27,
  "urgent": 34,
  "high": 1,
  "planned": 26,
  "low": 7,
  "migration_candidates": 88,
  "top_priorities": [
    {
      "algorithm": "MD5",
      "file_path": "data/sample/java_sample.java",
      "line_number": 8,
      "priority_score": 88,
      "priority_level": "IMMEDIATE",
      "urgency": "IMMEDIATE",
      "strategy": "IMMEDIATE_REPLACEMENT",
      "recommended_replacement": "SHA-256 / SHA-3"
    }
  ],
  "note": "Q-BITS-ECDAT Risk Prioritization Policy output. This is a prioritization aid ..."
}
```

### Build an asset-level migration plan (Phase 4)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/migration/plan \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "RSA", "key_size": 1024, "usage": "digital signature"}'
```

Returns the current risk, priority score/level, migration urgency,
`why_needed`, recommended replacement, strategy, ordered steps and
validation steps.

### Generate / fetch the plain-text report (Phase 4)

`POST /api/v1/report` scans a directory and renders the report; `GET
/api/v1/report` renders it for the most recent scan. Both return
`text/plain`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/report \
  -H "Content-Type: application/json" \
  -d '{"path": "data/sample"}'
```

Output:

```text
Q-BITS-ECDAT REPORT

Project Summary
──────────────────

Files Scanned: 12
Crypto Findings: 95
CBOM Assets: 59

Risk Distribution:

CRITICAL: 61
HIGH: 0
MEDIUM: 27
LOW: 7

──────────────────

TOP MIGRATION PRIORITIES

1. MD5
   Score: 88
   Action: Replace Immediately

──────────────────

PQC READINESS

Migration Candidates: 88

Status:

NEEDS MODERNIZATION
```

`GET /api/v1/report?top_n=3` limits the listed priorities.

## Error responses

* `400` — path does not exist (or could not be scanned).
* `404` — read-only endpoint called before any scan (the message tells
  you to run `POST /api/v1/scan` first).

## Using Python instead of curl

```python
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)
response = client.post("/api/v1/scan", json={"path": "data/sample"})
print(response.json()["summary"])
```
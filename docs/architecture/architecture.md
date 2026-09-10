# System Architecture

This document explains how the Q-BITS-ECDAT backend is put together and
how the pieces talk to each other.

## High-level diagram

```
                ┌──────────────────────────────┐
                │      HTTP client / UI        │
                │  (Postman, browser, future    │
                │   React frontend)             │
                └──────────────┬───────────────┘
                               │ REST / JSON
                               ▼
                ┌──────────────────────────────┐
                │          FastAPI app          │
                │   backend/app/main.py         │
                │   routes registered in        │
                │   backend/app/api/v1.py       │
                └──────────────┬───────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │       AnalysisService         │
                │ backend/app/services/         │
                │ analysis.py                   │
                └───┬──────────┬───────────┬───┘
                    │          │           │
                    ▼          ▼           ▼
        ┌───────────────┐ ┌────────┐ ┌────────┐
        │  Scanner      │ │  CBOM  │ │  Risk  │
        │ backend/      │ │backend/│ │backend/│
        │ scanners/source│ │ cbom/  │ │ risk/  │
        └──────┬────────┘ └────┬───┘ └────────┘
               │               │
               ▼               ▼
        ┌──────────────────────────────────┐
        │        Pydantic models           │
        │  backend/app/models/schemas.py   │
        └──────────────────────────────────┘
```

## Layer-by-layer

### 1. API layer (`backend/app/api/`)
Thin HTTP endpoints. Each router handles:
- request validation (Pydantic schemas),
- calling the relevant service,
- turning service output into JSON.

No business logic lives here, which keeps it testable and readable.

### 2. Service layer (`backend/app/services/analysis.py`)
The orchestrator. `AnalysisService.run_full_analysis(path)`:

1. runs the **scanner**,
2. builds the **CBOM** from scan results,
3. computes **risk assessments** for every unique algorithm,
4. prepares the **dashboard summary**,
5. remembers the latest results so the read-only endpoints (`GET
   /api/v1/cbom`, `/api/v1/risk`, `/api/v1/dashboard/summary`) can reply.

### 3. Scanner (`backend/scanners/source/`)
Walks a directory tree, reads supported source files, and applies the
detection rules from `rules.py` line-by-line. Produces a `ScanResult`
containing `CryptographicAsset` items.

The scanner is designed to be a cheap, regex-based first pass. In the
future, more accurate `AST`-based detectors can be added without
changing the API.

### 4. CBOM generator (`backend/cbom/generator.py`)
Takes a `ScanResult` and groups assets by `algorithm + library + file`.
Every resulting `CBOMEntry` gets a quantum-risk level from the risk
engine. Summary statistics are calculated automatically.

### 5. Risk engine (`backend/risk/`)
Pure, stateless classification split across small modules:
- `knowledge.py`  — the risk knowledge base: per-algorithm profiles,
  key-size rules, usage-specific PQC recommendations, name aliases;
- `engine.py`     — `RiskEngine` turns any algorithm / asset / CBOM
  entry into a `RiskAssessment` (classical risk, quantum risk, overall
  risk, score, migration priority, recommendation, PQC replacement);
- `scoring.py`    — the configurable numerical scoring (0-4);
- `summary.py`    — aggregates assessments into a `RiskSummary`.

Unknown algorithms are reported as `UNKNOWN` /
`REVIEW_REQUIRED` instead of crashing.

### 6. Models (`backend/app/models/schemas.py`)
The "vocabulary" of the whole system — Pydantic models used by every
layer. Because they are Pydantic models, they double as:
- request/response schemas (auto-documented in Swagger),
- validation rules,
- serialization helpers (`model_dump()` / `model_dump_json()`).

### 7. Core (`backend/app/core/`)
Configuration (`config.py`, driven by environment variables) and
logging (`logging.py`).

## Request lifecycle (example)

```
POST /api/v1/scan  {"path": "data/sample"}
        │
        ▼
analysis_service.run_full_analysis("data/sample")
        │
        ├──► SourceCodeScanner.scan_directory(...)  ──► ScanResult
        │         │  (finds RSA, AES, MD5, ... per file + line)
        │         ▼
        ├──► CBOMGenerator.generate(ScanResult)     ──► CBOM
        │         │  (groups, adds risk levels, summaries)
        │         ▼
        ├──► risk_engine.assess_many(algorithms)    ──► [RiskAssessment, ...]
        │
        └──► returns {"scan", "cbom", "risks", "summary"}
```

## State

Results are held **in memory** in `AnalysisService` (the singleton
`analysis_service`). This is perfect for a demo / hackathon, but a real
deployment would swap it for a database (Postgres/Redis) without
changing the API surface.
# Q-BITS-ECDAT

**Enterprise Cryptographic Discovery and Analysis Tool** for:

- Cryptographic inventory scanning
- CBOM (Cryptographic Bill of Materials) generation
- Quantum-risk assessment
- Post-Quantum Cryptography (PQC) migration prioritization

---

## Features

- 🔍 **Source code scanner** – detects cryptographic algorithms (MD5, SHA, AES, RSA, ECC, DSA, ...) and libraries (`hashlib`, `javax.crypto`, Node `crypto`, ...) in `.py`, `.java`, `.js`, `.ts` files.
- 📋 **CBOM generation** – aggregates scan results into a structured Cryptographic Bill of Materials.
- ⚠️ **Quantum-risk assessment** – classifies each algorithm's quantum vulnerability and migration priority.
- 🔌 **REST API** – FastAPI-based, with interactive Swagger docs at `/docs`.

---

## Architecture

```
[Frontend / API client]  --HTTPS-->  [FastAPI backend]
                                        │
                     ┌──────────────────┼───────────────────┐
                     │                  │                   │
              [Scanners]           [CBOM module]       [Risk module]
          source | binary | container
                     │                  │                   │
                     └──────►  [Pydantic models]  ◄────────┘
                                        │
                                  [Core config]
```

1. The **scanners** inspect source code / binaries / containers and report crypto usage.
2. Results are normalised into **Pydantic models** (`CryptographicAsset`, `ScanResult`).
3. The **CBOM module** turns scan results into a Cryptographic Bill of Materials.
4. The **risk module** grades each algorithm for quantum vulnerability and migration priority.
5. The **API layer** exposes all of it via REST endpoints.

---

## Installation

### Prerequisites

- Python 3.10 or newer
- pip

### 1. Create a virtual environment (recommended)

```bash
python -m venv .venv
```

Activate it:

- **Windows (PowerShell):** `.venv\Scripts\Activate.ps1`
- **Windows (cmd):** `.venv\Scripts\activate.bat`
- **macOS / Linux:** `source .venv/bin/activate`

### 2. Install dependencies

```bash
pip install -e ".[dev]"
```

Or, if you prefer the plain `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Running the Backend

```bash
uvicorn backend.app.main:app --reload
```

Your API will be available at **http://127.0.0.1:8000**

| Resource            | URL                                   |
|---------------------|---------------------------------------|
| Health check        | http://127.0.0.1:8000/health          |
| Versioned endpoints | http://127.0.0.1:8000/api/v1/...      |
| Swagger UI (docs)   | http://127.0.0.1:8000/docs            |
| ReDoc               | http://127.0.0.1:8000/redoc           |

## Running the Frontend

From the project root:

```bash
npm install
npm run dev
```

The frontend runs on **http://localhost:3000** and proxies `/api` requests to
`http://127.0.0.1:8000` by default (configured in `frontend/vite.config.js`).

If your backend runs on another port, set:

```bash
VITE_API_TARGET=http://127.0.0.1:8001 npm run dev
```

### Configuration via environment variables

All settings can be overridden with `ECDAT_`-prefixed env vars, e.g.:

```bash
ECDAT_HOST=0.0.0.0 ECDAT_PORT=9000 ECDAT_DEBUG=false uvicorn backend.app.main:app
```

Or create a `.env` file next to the project root. See
`backend/app/core/config.py` for all available settings.

---

## API Documentation

### `GET /health`

Health check used by monitors and dashboards.

**Response:**
```json
{
  "status": "healthy",
  "project": "Q-BITS-ECDAT"
}
```

### `GET /api/v1/info`

Returns metadata about the running service.

```json
{
  "project": "Q-BITS-ECDAT",
  "version": "0.1.0",
  "description": "Enterprise Cryptographic Discovery and Analysis Tool..."
}
```

### `POST /api/v1/scan`

Scans a directory, builds the CBOM and assesses quantum risk. Request:

```json
{ "path": "data/sample" }
```

### `GET /api/v1/cbom`

Returns the CBOM of the most recent scan.

### `GET /api/v1/risk`

Returns quantum-risk assessments for the algorithms found in the
most recent scan.

### `GET /api/v1/risk/summary`

Returns a risk roll-up (counts by level) for the most recent scan:

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

### `POST /api/v1/risk/assess`

Assess a single algorithm immediately, without a full scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/risk/assess \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "RSA", "key_size": 1024, "usage": "signature"}'
```

Returns a full `RiskAssessment` (classical/quantum/overall risk,
score, migration priority, recommendation, and PQC replacement).

### `GET /api/v1/dashboard/summary`

Returns headline numbers for the dashboard:

```json
{
  "total_files_scanned": 3,
  "crypto_assets_found": 26,
  "high_risk_assets": 14,
  "critical_migrations": 18
}
```

### `POST /api/v1/report` / `GET /api/v1/report`

Renders the plain-text Q-BITS-ECDAT report (project summary, risk
distribution, top migration priorities, PQC readiness status). The POST
variant scans a directory first; the GET variant uses the latest scan:

```bash
curl http://127.0.0.1:8000/api/v1/report
```

```text
Q-BITS-ECDAT REPORT

Project Summary
──────────────────

Files Scanned: 12
Crypto Findings: 95
CBOM Assets: 59
...
```

### Try it in one command

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "data/sample"}'
```

Full usage examples live in [`docs/architecture/api-usage.md`](docs/architecture/api-usage.md).

The Python source scanner runs a hybrid regex + AST pipeline (structured
crypto detection with key sizes, usages, curves and modes). See
[`docs/architecture/ast-scanner.md`](docs/architecture/ast-scanner.md).

Risk prioritization (0-100 priority scores + explainable factors) and the
PQC migration roadmap are documented in
[`docs/architecture/risk-prioritization.md`](docs/architecture/risk-prioritization.md)
and [`docs/architecture/migration-roadmap.md`](docs/architecture/migration-roadmap.md).

---

## Project Structure

```
Q-BITS-ECDAT/
├── backend/
│   ├── app/
│   │   ├── api/          # REST API routes (health, scan, cbom, risk, dashboard)
│   │   ├── core/         # Configuration & logging
│   │   ├── models/       # Pydantic data models
│   │   ├── services/     # Business logic (AnalysisService)
│   │   └── main.py       # FastAPI entry point
│   ├── scanners/         # Source scanner (regex + Python AST hybrid)
│   ├── cbom/             # CBOM generation
│   └── risk/             # Quantum risk assessment engine
├── frontend/             # Frontend app (future)
├── data/
│   ├── sample/           # Sample projects to scan
│   └── schemas/          # JSON schemas
├── docs/
│   ├── architecture/     # Architecture & workflow docs
│   └── research/         # CBOM format & quantum risk methodology
├── tests/                # pytest tests
├── pyproject.toml        # Project config & dependencies
└── requirements.txt      # Plain dependency list (alternative)
```

---

## Development

Run the test suite:

```bash
pytest
```

Lint / format check with Ruff:

```bash
ruff check .
```

---

## License

MIT

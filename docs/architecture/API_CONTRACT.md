# MVP API Contract

The MVP API connects the local filesystem scanner to API clients such as the
frontend. The scan endpoint currently accepts a path that is available on the
backend host. It does not authenticate with GitHub or clone remote
repositories.

## `GET /api/health`

Returns a lightweight availability response.

```json
{
  "status": "healthy"
}
```

## `POST /api/scan`

Scans a local repository directory with the existing `CryptoScanner`.

### Request

```json
{
  "path": "data/sample/demo-target"
}
```

`path` must refer to an existing directory on the backend filesystem. Empty
paths are rejected.

### Response

```json
{
  "status": "completed",
  "files_scanned": 4,
  "finding_count": 29,
  "findings": [
    {
      "id": "java/CryptoExamples.java:3:43:RSA",
      "algorithm": "RSA",
      "key_size": 1024,
      "library": null,
      "file": "java/CryptoExamples.java",
      "line": 3,
      "column": 44,
      "language": "Java",
      "code_snippet": "    public static final String RSA_SIZE = \"RSA 1024\";",
      "detection_method": "deterministic_regex",
      "confidence": 0.95,
      "category": "asymmetric",
      "usage_context": "potential cryptographic usage",
      "symbol_name": null,
      "arguments": null
    }
  ],
  "cbom": {
    "metadata": {"format": "Q-BITS-ECDAT-CBOM"},
    "components": [],
    "assets": [],
    "source_references": []
  },
  "risk": {
    "assets_assessed": 0,
    "assessments": [],
    "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "migration_priority_distribution": {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
  },
  "warnings": [],
  "errors": []
}
```

The values in a real response come from the scanner. The `CryptoFinding`
fields are:

- `id`: stable finding identifier
- `algorithm`: detected cryptographic algorithm
- `key_size`: detected key size, when available
- `library`: detected library, when available
- `file`: repository-relative source file
- `line` and `column`: source location, when available
- `language`: source language, when available
- `code_snippet`: matching source text, when available
- `detection_method`: scanner detection method
- `confidence`: scanner confidence from `0` to `1`
- `category`: finding category, when available
- `usage_context`: scanner context, when available
- `symbol_name`: symbol name, when available
- `arguments`: extracted string arguments, when available

`warnings` contains non-fatal scanner warnings such as Python files that could
not be parsed by the AST pass. Those files may still have regex findings.
`errors` is reserved for non-fatal per-scan errors and is currently empty.
`cbom` and `risk` are produced synchronously from the same returned findings.
Their structures follow the CBOM and risk-engine architecture contracts.

## Error responses

Errors use FastAPI's standard JSON shape:

```json
{
  "detail": "Scan path does not exist: data/missing"
}
```

- `400 Bad Request`: blank paths or paths that are not directories
- `404 Not Found`: the requested path does not exist
- `422 Unprocessable Entity`: malformed request JSON or a missing `path`
- `500 Internal Server Error`: unexpected scanner failure; implementation
  details and stack traces are not exposed

The existing versioned API under `/api/v1` remains available independently.

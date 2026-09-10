# Scanning Workflow

This document walks through exactly what happens when you scan a
project, from start to finish.

## 1. Choose a path

The scan starts with a filesystem path. This can be a whole repo, a
sub-folder, or even a single directory of mixed projects:

```text
/data/sample
```

The API validates the path exists before scanning (a non-existent path
returns `400 Bad Request`).

## 2. Walk the directory tree

`SourceCodeScanner.scan_directory()` uses `os.walk()` to visit every
file, but **skips**:

* excluded directories: `.git`, `__pycache__`, `node_modules`,
  `venv`, `.venv`, `env`, `dist`, `build` (configurable in
  `backend/app/core/config.py`),
* hidden files/directories (anything starting with `.`),
* files with an unsupported extension.

Only `.py`, `.java`, `.js` and `.ts` files are read.

## 3. Read files defensively

Files are read trying several encodings in order (`utf-8-sig`,
`utf-8`, `latin-1`) so BOMs and legacy encodings don't crash the scan.

## 4. Apply detection rules

Each line of each file is matched against every compiled rule in
`backend/scanners/source/rules.py`. Two kinds of rules exist:

| Kind             | Signal strength | Example match        | detection_method |
|------------------|----------------|----------------------|------------------|
| Library / API    | strong         | `hashlib.sha256(...)`    | `regex`          |
| Keyword          | weak           | a bare `RSA` in a comment | `keyword`        |

If a keyword hit lands on the same line as a library hit for the *same
algorithm*, the keyword hit is dropped (the library hit already tells us
more).

Each match becomes a `CryptographicAsset`:

```json
{
  "file_path": "app.py",
  "line_number": 9,
  "algorithm": "MD5",
  "library": "hashlib",
  "detection_method": "regex",
  "context": "weak = hashlib.md5(b'data')"
}
```

## 5. Summarise the scan

The scanner counts occurrences per algorithm and stores them in
`ScanResult.algorithm_counts`, e.g. `{"MD5": 5, "RSA": 4, ...}`.

## 6. Build the CBOM and risk report

Average results are normalised:

```
ScanResult ──► CBOMGenerator ──► CBOM
            └─► RiskEngine    ──► [RiskAssessment per unique algorithm]
```

See `docs/research/cbom-format.md` and
`docs/research/quantum-risk-methodology.md` for details.

## Adding new detection patterns

1. Open `backend/scanners/source/rules.py`.
2. Append a `DetectionRule` (for a library call) or a keyword rule.
3. Add a test in `tests/backend/test_scanner.py`.
4. Run `pytest`.

No scanner code changes are needed — the scanning engine is fully
data-driven by the rules table.
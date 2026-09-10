# CBOM Contract

## Input

The CBOM generator consumes the public discovery-scanner result directly:

```python
from backend.cbom import generate_cbom
from backend.scanners import CryptoScanner

findings = CryptoScanner().scan("data/sample/demo-target")
cbom = generate_cbom(findings)
```

Its input is `list[backend.scanners.source.models.CryptoFinding]`. It does not
scan files, call an LLM, query a database, or add cryptographic assertions.

## Output

`generate_cbom()` returns a JSON-serializable `backend.cbom.CBOM` Pydantic
model. It is deterministic: equivalent input findings produce equivalent
`model_dump(mode="json")` output. Metadata deliberately has no generated-at
clock value.

The model uses CycloneDX-compatible *concepts* (`metadata`, `components`,
`bom_ref`, and assets) but does not claim full CycloneDX specification
compliance.

## Structure

- `metadata`: format/version statement and input, unique, and duplicate counts.
- `components`: one cryptographic component per `(algorithm, category, library)`.
  Its `cryptographic_information` has algorithm, category, supplied key sizes,
  library, observed methods, maximum observed confidence, contexts, and source
  reference IDs.
- `assets`: one affected source asset per `(file, language)`, linked to the
  components and source references used in that file.
- `source_references`: the source-level evidence: finding ID, file, location,
  language, snippet, detection method, confidence, usage context, AST symbol
  and arguments when supplied, and duplicate occurrence count.

## CryptoFinding mapping

| CryptoFinding field | CBOM destination |
| --- | --- |
| `algorithm`, `category`, `library` | component identity and cryptographic information |
| `key_size` | component `key_sizes`; absent values are not invented |
| `file`, `language` | asset identity |
| `id`, `line`, `column`, `code_snippet` | source reference |
| `detection_method`, `confidence`, `usage_context`, `symbol_name`, `arguments` | source reference; method/context/confidence are also summarized on the component |

Exact duplicate `CryptoFinding` records are represented by one source reference
with `occurrences > 1`; metadata records the input and duplicate counts.
Separate source locations remain separate references.

## Supported information and limitations

The CBOM reports only scanner-provided information. An unknown algorithm stays
as the scanner's string. A missing key size produces an empty `key_sizes` list;
a missing library remains `null`. Findings are potential source usages, not
proof of runtime execution, key ownership, cryptographic correctness, or
dependency provenance. The output has no vulnerability or risk score and is
not a complete CycloneDX document.

## Example

```json
{
  "metadata": {"format": "Q-BITS-ECDAT-CBOM", "total_input_findings": 1},
  "components": [{"name": "RSA", "cryptographic_information": {
    "algorithm": "RSA", "category": "asymmetric", "key_sizes": [2048]
  }}],
  "assets": [{"path": "src/auth.py", "language": "Python"}],
  "source_references": [{"finding_id": "src/auth.py:3:1:RSA", "line": 3}]
}
```

## Risk-engine consumption

A future risk adapter should read each component's
`cryptographic_information` and retain its `source_reference_ids` when
attaching assessments. It should assess the reported algorithm/key-size/context
evidence, not create source findings or treat a CBOM component as proof that
the code executes.

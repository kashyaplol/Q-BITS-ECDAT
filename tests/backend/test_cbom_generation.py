"""Tests for the CryptoFinding-to-CBOM generation contract."""

from __future__ import annotations

import json
from pathlib import Path

from backend.cbom import CBOMGenerator, generate_cbom
from backend.scanners import CryptoFinding, CryptoScanner


def _finding(**overrides: object) -> CryptoFinding:
    values: dict[str, object] = {
        "id": "src/crypto.py:2:1:RSA",
        "algorithm": "RSA",
        "key_size": 2048,
        "library": "cryptography",
        "file": "src/crypto.py",
        "line": 2,
        "column": 1,
        "language": "Python",
        "code_snippet": "key = RSA.generate(2048)",
        "detection_method": "ast",
        "confidence": 0.95,
        "category": "asymmetric",
        "usage_context": "potential cryptographic usage",
    }
    values.update(overrides)
    return CryptoFinding(**values)


def test_empty_findings_produce_empty_cbom() -> None:
    cbom = generate_cbom([])
    assert cbom.metadata.total_input_findings == 0
    assert cbom.components == []
    assert cbom.assets == []
    assert cbom.source_references == []


def test_one_finding_maps_to_component_asset_and_source() -> None:
    cbom = generate_cbom([_finding()])
    assert len(cbom.components) == len(cbom.assets) == len(cbom.source_references) == 1
    info = cbom.components[0].cryptographic_information
    assert info.algorithm == "RSA"
    assert info.category == "asymmetric"
    assert info.key_sizes == [2048]
    assert info.library == "cryptography"
    assert cbom.assets[0].path == "src/crypto.py"
    assert cbom.source_references[0].line == 2


def test_multiple_algorithms_make_multiple_components() -> None:
    aes = _finding(id="src/crypto.py:3:1:AES", algorithm="AES", category="symmetric")
    unknown = _finding(id="src/crypto.py:4:1:EXPERIMENTAL", algorithm="EXPERIMENTAL", category=None)
    cbom = generate_cbom([_finding(), aes, unknown])
    assert [component.name for component in cbom.components] == ["AES", "EXPERIMENTAL", "RSA"]


def test_multiple_findings_for_algorithm_keep_each_source_location() -> None:
    second = _finding(
        id="src/crypto.py:8:1:RSA", line=8, column=1, code_snippet="other = RSA.generate(2048)"
    )
    cbom = generate_cbom([_finding(), second])
    assert len(cbom.components) == 1
    assert [source.line for source in cbom.source_references] == [2, 8]
    assert len(cbom.components[0].cryptographic_information.source_reference_ids) == 2


def test_missing_key_size_and_library_are_preserved_as_unknown() -> None:
    cbom = generate_cbom([_finding(key_size=None, library=None)])
    info = cbom.components[0].cryptographic_information
    assert info.key_sizes == []
    assert info.library is None


def test_duplicate_findings_are_accounted_for_deterministically() -> None:
    finding = _finding()
    cbom = CBOMGenerator().generate([finding, finding])
    assert cbom.metadata.total_input_findings == 2
    assert cbom.metadata.unique_findings == 1
    assert cbom.metadata.duplicate_findings == 1
    assert cbom.source_references[0].occurrences == 2
    assert cbom == generate_cbom([finding, finding])


def test_json_serialization() -> None:
    serialized = json.dumps(generate_cbom([_finding()]).model_dump(mode="json"))
    assert json.loads(serialized)["components"][0]["name"] == "RSA"


def test_demo_scanner_output_generates_cbom() -> None:
    demo_target = Path(__file__).parents[2] / "data" / "sample" / "demo-target"
    findings = CryptoScanner().scan(demo_target)
    cbom = generate_cbom(findings)
    assert findings
    assert cbom.metadata.total_input_findings == len(findings)
    assert cbom.components
    assert cbom.assets
    assert all(source.file.startswith(("python/", "java/")) for source in cbom.source_references)

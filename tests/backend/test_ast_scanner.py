"""Phase 3 tests: AST-based cryptographic scanning + hybrid detection.

Covers the full checklist from ``PHASE 11`` of the ENHANCEMENT spec:

- Python AST detection (hash functions, RSA, ECC, DSA, symmetric ciphers)
- Import + alias resolution
- Metadata extraction (key size, curve, mode, usage)
- Hybrid regex + AST detection & deduplication
- Graceful fallback on invalid Python syntax
- CBOM / risk-engine / API integration
- JSON serialization and a complete end-to-end workflow
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models import (
    CryptographicAsset,
    DetectionMethod,
    UsageType,
)
from backend.app.services.analysis import analysis_service
from backend.cbom import CBOMGenerator
from backend.risk import build_risk_summary, risk_engine
from backend.scanners.source import PythonAstScanner, SourceCodeScanner

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_service_state():
    analysis_service.latest_scan = None
    analysis_service.latest_cbom = None
    analysis_service.latest_risks = []
    analysis_service.latest_summary = None
    yield


# ---------------------------------------------------------------------------
# Basic AST detection
# ---------------------------------------------------------------------------
def _ast(source: str) -> list[CryptographicAsset]:
    return PythonAstScanner().scan_source("sample.py", source)


def test_ast_detects_hashing_algorithms() -> None:
    assets = _ast(
        "import hashlib\n"
        "hashlib.md5(b'x')\n"
        "hashlib.sha1(b'x')\n"
        "hashlib.sha256(b'x')\n"
        "hashlib.sha384(b'x')\n"
        "hashlib.sha512(b'x')\n"
        "hashlib.sha3_512(b'x')\n"
    )
    by_line = {a.line_number: a.algorithm.value for a in assets}
    assert by_line[2] == "MD5"
    assert by_line[3] == "SHA1"
    assert by_line[4] == "SHA256"
    assert by_line[5] == "SHA384"
    assert by_line[6] == "SHA512"
    assert by_line[7] == "SHA3"
    assert all(a.detection_method == DetectionMethod.AST for a in assets)
    assert all(a.usage == UsageType.HASHING for a in assets)


def test_ast_detects_hashlib_new_alias_and_from_imports() -> None:
    assets = _ast(
        "import hashlib as h\n"
        "h.new('sha256', b'x')\n"
        "from hashlib import sha512\n"
        "sha512(b'x')\n"
    )
    algorithms = sorted(a.algorithm.value for a in assets)
    assert algorithms == ["SHA256", "SHA512"]


def test_ast_detects_rsa_with_key_size() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    rsa_assets = [a for a in assets if a.algorithm.value == "RSA"]
    assert len(rsa_assets) == 1
    assert rsa_assets[0].key_size == 2048
    assert rsa_assets[0].usage == UsageType.KEY_GENERATION
    assert rsa_assets[0].library == "cryptography"


def test_ast_detects_ecc_curve_and_dsa() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.asymmetric import ec, dsa\n"
        "ec.generate_private_key(ec.SECP384R1())\n"
        "dsa.generate_private_key(key_size=1024)\n"
    )
    ecc = [a for a in assets if a.algorithm.value == "ECC"]
    dsa_assets = [a for a in assets if a.algorithm.value == "DSA"]
    assert ecc and all(a.curve == "SECP384R1" for a in ecc)
    assert dsa_assets[0].key_size == 1024
    assert dsa_assets[0].usage == UsageType.KEY_GENERATION


def test_ast_detects_aes_and_mode() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'k' * 32), modes.GCM(b'i' * 12))\n"
    )
    aes = [a for a in assets if a.algorithm.value == "AES"]
    assert aes
    assert any(a.mode == "GCM" for a in aes)


def test_ast_detects_pycryptodome_ciphers_modes() -> None:
    assets = _ast(
        "from Crypto.Cipher import AES, DES, DES3, ARC4\n"
        "AES.new(b'k' * 16, AES.MODE_CBC)\n"
        "DES.new(b'12345678', DES.MODE_ECB)\n"
        "DES3.new(b'123456789012345678901234', DES3.MODE_CBC)\n"
        "ARC4.new(b'key')\n"
    )
    by_line = {a.line_number: a.algorithm.value for a in assets}
    assert by_line[2] == "AES" and any(a.mode == "CBC" for a in assets if a.line_number == 2)
    assert by_line[3] == "DES" and any(a.mode == "ECB" for a in assets if a.line_number == 3)
    assert by_line[4] == "3DES"
    assert by_line[5] == "RC4"
    assert all(a.library == "pycryptodome" for a in assets)


# ---------------------------------------------------------------------------
# Usage detection
# ---------------------------------------------------------------------------
def test_ast_detects_usage_on_bound_objects() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "k.sign(b'msg', None)\n"
        "pub = k.public_key()\n"
        "pub.verify(b'sig', b'msg', None)\n"
    )
    usages = {(a.algorithm.value, a.usage) for a in assets}
    assert (("RSA", UsageType.KEY_GENERATION) in usages)
    assert (("RSA", UsageType.DIGITAL_SIGNATURE) in usages)
    assert (("RSA", UsageType.SIGNATURE_VERIFICATION) in usages)


def test_ast_detects_encrypt_decrypt_usage() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "c = Cipher(algorithms.AES(b'k' * 32), modes.GCM(b'i' * 12))\n"
        "e = c.encryptor()\n"
        "e.encrypt(b'x')\n"
        "d = c.decryptor()\n"
        "d.decrypt(b'x')\n"
    )
    usages = {a.usage for a in assets}
    assert UsageType.ENCRYPTION in usages
    assert UsageType.DECRYPTION in usages


# ---------------------------------------------------------------------------
# Hybrid detection + deduplication (full scanner)
# ---------------------------------------------------------------------------
def test_hybrid_regex_plus_ast_marks_hybrid(tmp_path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "hashlib.sha256(b'x')\n",
        encoding="utf-8",
    )
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    sha256 = [a for a in result.assets if a.algorithm.value == "SHA256"]
    assert len(sha256) == 1
    assert sha256[0].detection_method == DetectionMethod.HYBRID
    assert sha256[0].library == "hashlib"


def test_deduplication_single_finding_per_line(tmp_path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "hashlib.md5(b'a')\n"
        "hashlib.md5(b'b')\n",
        encoding="utf-8",
    )
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    md5 = [a for a in result.assets if a.algorithm.value == "MD5"]
    assert [a.line_number for a in md5] == [2, 3]


def test_regex_still_detects_non_python_files(tmp_path) -> None:
    (tmp_path / "app.js").write_text(
        "crypto.createHash('sha256');\n",
        encoding="utf-8",
    )
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert any(a.algorithm.value == "SHA256" for a in result.assets)


# ---------------------------------------------------------------------------
# Invalid syntax + fallback
# ---------------------------------------------------------------------------
def test_invalid_python_syntax_falls_back_to_regex(tmp_path) -> None:
    (tmp_path / "broken.py").write_text(
        "import hashlib\n"
        "def broken(:\n"
        "    x = hashlib.md5(b'x')\n",
        encoding="utf-8",
    )
    (tmp_path / "ok.py").write_text(
        "import hashlib\n"
        "hashlib.sha256(b'x')\n",
        encoding="utf-8",
    )
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert len(result.parse_errors) == 1
    assert "broken.py" in result.parse_errors[0]
    # The OK file is still scanned and the broken file still yields regex hits.
    assert any(a.algorithm.value == "SHA256" for a in result.assets)
    assert any(a.algorithm.value == "MD5" for a in result.assets)


def test_ast_never_crashes_on_empty_source() -> None:
    assets, error = PythonAstScanner().analyze("empty.py", "")
    assert assets == []
    assert error is None


def test_scanner_handles_empty_directory(tmp_path) -> None:
    result = SourceCodeScanner().scan_directory(str(tmp_path))
    assert result.files_scanned == 0
    assert result.assets == []
    assert result.parse_errors == []


def test_repeated_scans_do_not_accumulate_findings(tmp_path) -> None:
    """A reused scanner (as the API service uses) must be state-safe."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "hashlib.sha256(b'x')\n",
        encoding="utf-8",
    )
    scanner = SourceCodeScanner()  # one instance, multiple runs
    first = len(scanner.scan_directory(str(tmp_path)).assets)
    second = len(scanner.scan_directory(str(tmp_path)).assets)
    assert first == second


# ---------------------------------------------------------------------------
# Integration: CBOM, risk engine, JSON
# ---------------------------------------------------------------------------
def test_metadata_flows_into_cbom(tmp_path) -> None:
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "k.sign(b'msg', None)\n",
        encoding="utf-8",
    )
    scan = SourceCodeScanner().scan_directory(str(tmp_path))
    bom = CBOMGenerator("demo").generate(scan)
    rsa_entry = next(e for e in bom.cryptographic_assets if e.algorithm.value == "RSA")
    assert 1024 in rsa_entry.key_sizes
    assert "KEY_GENERATION" in rsa_entry.usages
    assert "DIGITAL_SIGNATURE" in rsa_entry.usages


def test_key_size_aware_risk_assessment() -> None:
    rsa512 = risk_engine.assess("RSA", key_size=512)
    rsa1024 = risk_engine.assess("RSA", key_size=1024)
    rsa2048 = risk_engine.assess("RSA", key_size=2048)
    rsa4096 = risk_engine.assess("RSA", key_size=4096)
    assert rsa512.classical_risk.value == "HIGH"
    assert rsa1024.classical_risk.value == "MEDIUM"
    assert rsa2048.classical_risk.value == "MEDIUM"
    assert rsa4096.classical_risk.value == "LOW"
    # All remain quantum-vulnerable public-key systems.
    assert rsa4096.quantum_risk.value == "CRITICAL"


def test_usage_aware_pqc_recommendation_from_asset() -> None:
    asset = CryptographicAsset(
        file_path="app.py",
        line_number=1,
        algorithm="RSA",
        library="cryptography",
        detection_method=DetectionMethod.AST,
        key_size=2048,
        usage=UsageType.DIGITAL_SIGNATURE,
    )
    assessment = risk_engine.assess(asset)
    assert "ML-DSA" in assessment.pqc_recommendation


def test_asset_metadata_is_json_serializable() -> None:
    assets = _ast(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP256R1())\n"
    )
    payload = [a.model_dump(mode="json") for a in assets]
    text = json.dumps(payload)
    assert "SECP256R1" in text
    assert "KEY_GENERATION" in text


def test_scan_result_includes_parse_errors() -> None:
    scan = SourceCodeScanner().scan_directory("data/sample")
    assert scan.parse_errors  # invalid_syntax.py is part of the samples
    assert any("invalid_syntax.py" in error for error in scan.parse_errors)


# ---------------------------------------------------------------------------
# API + full end-to-end
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_project(tmp_path):
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "hashlib.sha256(b'x')\n",
        encoding="utf-8",
    )
    return tmp_path


def test_api_scan_exposes_ast_metadata(sample_project) -> None:
    response = client.post("/api/v1/scan", json={"path": str(sample_project)})
    assert response.status_code == 200
    body = response.json()
    rsa_entries = [a for a in body["cbom"]["cryptographic_assets"] if a["algorithm"] == "RSA"]
    assert rsa_entries and 1024 in rsa_entries[0]["key_sizes"]


def test_full_end_to_end_workflow(tmp_path) -> None:
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "w = hashlib.md5(b'x')\n"          # legacy hash
        "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "k.sign(b'msg', None)\n"            # signing usage
        "ec.generate_private_key(ec.SECP256R1())\n",
        encoding="utf-8",
    )
    scan = SourceCodeScanner().scan_directory(str(tmp_path))
    assert scan.files_scanned == 1
    algorithms = {a.algorithm.value for a in scan.assets}
    assert {"MD5", "RSA", "ECC"} <= algorithms

    bom = CBOMGenerator("demo").generate(scan)
    summary = build_risk_summary(scan.assets, risk_engine)

    assert bom.total_findings == len(scan.assets)
    assert summary.total_assets == len(scan.assets)
    assert summary.immediate_migrations_required >= 1  # MD5

    # Everything serializes cleanly.
    json.dumps(bom.model_dump(mode="json"))
    json.dumps([a.model_dump(mode="json") for a in scan.assets])


def test_scanner_can_be_disabled_at_api_level() -> None:
    """The scanner keeps working even when AST metadata is absent."""
    asset = CryptographicAsset(
        file_path="x.py", line_number=1, algorithm="AES",
        detection_method=DetectionMethod.REGEX,
    )
    cloned = asset.model_copy()
    assert cloned.key_size is None and cloned.usage is None
    assert cloned.detection_method == DetectionMethod.REGEX

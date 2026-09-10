"""Tests for deterministic source cryptographic pattern detection."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from .scanner import CryptoScanner


class CryptoScannerTests(unittest.TestCase):
    """Verify positive, negative, and ignored-directory behavior."""

    def test_detects_patterns_and_ignores_irrelevant_content(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "src").mkdir()
            (repository / "node_modules").mkdir()
            (repository / "src" / "crypto.py").write_text(
                "from cryptography.hazmat.primitives import hashes\n"
                "digest = hashlib.sha256(data)\n"
                "key = RSA.generate(2048)\n"
            )
            (repository / "node_modules" / "ignored.js").write_text("AES")

            findings = CryptoScanner().scan(repository)

            self.assertEqual(
                {finding.algorithm for finding in findings},
                {"cryptography", "hashlib", "SHA-256", "RSA"},
            )
            self.assertEqual(
                {finding.file for finding in findings},
                {"src/crypto.py"},
            )
            self.assertTrue(
                all(
                    finding.usage_context == "potential cryptographic usage"
                    for finding in findings
                )
            )

    def test_does_not_match_algorithm_substrings(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "example.py").write_text(
                "class AEScheduler:\n"
                "    pass\n"
                "value = unrelated_text\n"
            )

            self.assertEqual(CryptoScanner().scan(repository), [])

    def test_returns_source_location_metadata(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            source_file = repository / "src" / "auth.py"
            source_file.parent.mkdir()
            source_file.write_text(
                "from pathlib import Path\n"
                "\n"
                "    private_key = RSA.generate(2048)\n"
            )

            findings = CryptoScanner().scan(repository)

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.algorithm, "RSA")
            self.assertEqual(finding.file, "src/auth.py")
            self.assertEqual(finding.line, 3)
            self.assertEqual(finding.column, 19)
            self.assertEqual(
                finding.code_snippet,
                "    private_key = RSA.generate(2048)",
            )
            self.assertEqual(finding.language, "Python")
            self.assertEqual(finding.detection_method, "deterministic_regex")
            self.assertEqual(finding.confidence, 0.95)

    def test_identifies_all_supported_languages_by_extension(self) -> None:
        expected_languages = {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".java": "Java",
            ".c": "C",
            ".cpp": "C++",
            ".h": "C/C++",
            ".hpp": "C++",
            ".go": "Go",
            ".rs": "Rust",
            ".php": "PHP",
            ".rb": "Ruby",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".json": "JSON",
            ".xml": "XML",
            ".conf": "Config",
            ".config": "Config",
        }
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            for index, extension in enumerate(expected_languages):
                (repository / f"source_{index}{extension}").write_text(
                    "RSA.generate(2048)\n"
                )

            findings = CryptoScanner().scan(repository)

            languages_by_file = {
                Path(finding.file).suffix: finding.language
                for finding in findings
            }
            self.assertEqual(languages_by_file, expected_languages)

    def test_extracts_explicit_key_sizes(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "keys.py").write_text(
                "rsa_key = RSA.generate(2048)\n"
                "private_key = rsa.generate_private_key(key_size=4096)\n"
                "cipher = AES-256\n"
                "signature = ECDSA-384\n"
            )

            findings = CryptoScanner().scan(repository)

            sizes = {
                (finding.algorithm, finding.key_size)
                for finding in findings
                if finding.algorithm in {"RSA", "AES", "ECDSA"}
            }
            self.assertIn(("RSA", 2048), sizes)
            self.assertIn(("RSA", 4096), sizes)
            self.assertIn(("AES", 256), sizes)
            self.assertIn(("ECDSA", 384), sizes)

    def test_leaves_key_size_empty_without_explicit_size(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "keys.py").write_text(
                "cipher = AES.new(key)\n"
                "rsa_key = RSA.generate(key_size)\n"
                "retry_limit = 2048\n"
            )

            findings = CryptoScanner().scan(repository)

            self.assertEqual(
                {
                    (finding.algorithm, finding.key_size)
                    for finding in findings
                    if finding.algorithm in {"RSA", "AES"}
                },
                {("AES", None), ("RSA", None)},
            )

    def test_ast_detects_python_imports_calls_and_arguments(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "ast_crypto.py").write_text(
                "import hashlib\n"
                "from Crypto.Cipher import AES\n"
                "digest = hashlib.sha256(data)\n"
                "key = RSA.generate(2048)\n"
            )

            scanner = CryptoScanner()
            findings = scanner.scan(repository)

            ast_findings = [
                finding for finding in findings if "ast" in finding.detection_method
            ]
            self.assertTrue(
                any(
                    finding.algorithm == "hashlib"
                    and finding.symbol_name == "hashlib"
                    for finding in ast_findings
                )
            )
            rsa_finding = next(
                finding for finding in ast_findings if finding.algorithm == "RSA"
            )
            self.assertEqual(rsa_finding.symbol_name, "RSA.generate")
            self.assertEqual(rsa_finding.arguments, {"arg0": "2048"})
            self.assertEqual(rsa_finding.key_size, 2048)
            sha_finding = next(
                finding
                for finding in ast_findings
                if finding.algorithm == "SHA-256"
            )
            self.assertEqual(sha_finding.symbol_name, "hashlib.sha256")
            self.assertEqual(sha_finding.line, 3)
            self.assertIsNone(sha_finding.arguments)

    def test_ast_parse_errors_do_not_stop_scan(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "broken.py").write_text("def broken(:\n")
            (repository / "valid.py").write_text("digest = hashlib.sha256(data)\n")

            scanner = CryptoScanner()
            findings = scanner.scan(repository)

            self.assertTrue(scanner.parsing_errors)
            self.assertIn("broken.py", scanner.parsing_errors[0])
            self.assertTrue(any(finding.file == "valid.py" for finding in findings))

    def test_end_to_end_discovery_detection_and_deduplication(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "src").mkdir()
            (repository / "node_modules").mkdir()
            (repository / "src" / "auth.py").write_text(
                "import hashlib\n"
                "key = RSA.generate(2048)\n"
                "digest = hashlib.sha256(data)\n"
            )
            (repository / "node_modules" / "ignored.py").write_text(
                "RSA.generate(4096)\n"
            )

            findings = CryptoScanner().scan(repository)

            self.assertTrue(findings)
            self.assertEqual({finding.file for finding in findings}, {"src/auth.py"})
            rsa_findings = [
                finding for finding in findings if finding.algorithm == "RSA"
            ]
            self.assertEqual(len(rsa_findings), 1)
            self.assertEqual(rsa_findings[0].key_size, 2048)
            self.assertIn("ast", rsa_findings[0].detection_method)
            self.assertEqual(
                {
                    finding.algorithm
                    for finding in findings
                    if finding.line == 3
                },
                {"hashlib", "SHA-256"},
            )


if __name__ == "__main__":
    unittest.main()

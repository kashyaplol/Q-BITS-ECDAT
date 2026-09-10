"""Python AST-based cryptographic scanner.

This module is the AST counterpart of the line-based regex scanner. It
parses Python source with the standard-library :mod:`ast` module and
walks the syntax tree looking for *structural* evidence of cryptography:

* imports (including aliases) of known crypto libraries,
* calls such as ``hashlib.sha256(...)``, ``rsa.generate_private_key(...)``,
  ``Cipher(algorithms.AES(...), modes.GCM(...))``,
* usage of already-created key/cipher objects (``private_key.sign(...)``,
  ``cipher.encrypt(...)``).

The scanner is deliberately conservative: it never guesses. If the code
structure is not clear (e.g. an unusable key size or an unknown curve)
the corresponding attribute is simply left as ``None``.

It never crashes on bad input: ``analyze()`` returns ``([], error)`` for
code that fails to parse, so the caller can fall back to regex scanning.
"""

from __future__ import annotations

import ast

from backend.app.core.logging import get_logger  # noqa: E402
from backend.app.models import (
    Algorithm,
    CryptographicAsset,
    DetectionMethod,
    UsageType,
)

from .ast_rules import (
    BINDING_PASSTHROUGH,
    CIPHER_CONTEXT_CALLS,
    CRYPTOGRAPHY_CIPHER_CLASSES,
    CRYPTOGRAPHY_HASH_CLASSES,
    HASH_FUNCTIONS,
    HASH_NEW_NAMES,
    IMPORT_LIBRARIES,
    KEY_SIZE_KWARGS,
    KEYGEN_RULES,
    MODE_ALIASES,
    PYCRYPTODOME_CIPHER_MODULES,
    PYCRYPTODOME_HASH_MODULES,
    USAGE_CALLS,
)

_LOG = get_logger(__name__)

CONTEXT_TRIM = 200


def _library_for(module_path: str) -> str | None:
    """Map a dotted module path to its library label (longest prefix match)."""
    while module_path:
        if module_path in IMPORT_LIBRARIES:
            return IMPORT_LIBRARIES[module_path]
        module_path, _, _ = module_path.rpartition(".")
    return None


class PythonAstScanner:
    """Detect cryptographic usage inside a single Python source string.

    The class keeps per-scan state (import aliases, detected bindings,
    known bytes constants) so it must be re-created (or
    ``scan_source``/``analyze`` used per file) for each source unit.
    """

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.bindings: dict[str, dict] = {}
        self.constants: dict[str, object] = {}
        self.assets: list[CryptographicAsset] = []
        self._lines: list[str] = []
        self._file_path: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def _reset_state(self) -> None:
        """Clear per-scan state so the instance is safe to reuse."""
        self.aliases = {}
        self.bindings = {}
        self.constants = {}
        self.assets = []
        self._lines = []
        self._file_path = ""

    def scan_source(self, file_path: str, source: str) -> list[CryptographicAsset]:
        """Parse ``source`` and return detected crypto assets.

        Per-scan state (import aliases, bindings, constants, findings) is
        reset here so a single ``PythonAstScanner`` instance can safely be
        reused for many files -- as the ``SourceCodeScanner`` does.

        Raises:
            SyntaxError: if the source is not valid Python.
        """
        self._reset_state()
        tree = ast.parse(source, filename=file_path)
        self._file_path = file_path
        self._lines = source.splitlines()
        self._walk(tree)
        return self.assets

    def analyze(
        self, file_path: str, source: str
    ) -> tuple[list[CryptographicAsset], str | None]:
        """Safe variant of ``scan_source``.

        Returns ``(assets, error)`` where ``error`` is ``None`` on
        success and a human-readable message when parsing failed.
        """
        try:
            assets = self.scan_source(file_path, source)
        except (SyntaxError, ValueError, RecursionError) as exc:
            line = getattr(exc, "lineno", None)
            where = f" at line {line}" if line else ""
            return [], f"{file_path}: {exc.__class__.__name__}{where}: {exc}"
        return assets, None

    # ------------------------------------------------------------------
    # Tree traversal (document order, so bindings exist before use)
    # ------------------------------------------------------------------
    def _walk(self, tree: ast.AST) -> None:
        """Visit every node in source order.

        A depth-first, source-ordered traversal guarantees that assignment
        statements (``self.bindings``) are processed *before* later
        statements that use the bound names -- so usage detection can rely
        on bindings having been recorded.
        """
        for node in _ordered_walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                self._visit_import(node)
            elif isinstance(node, ast.Assign):
                self._visit_assign(node)
            elif isinstance(node, ast.Call):
                self._visit_call(node)

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def _visit_import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                self._add_import(alias.name, alias.asname)
            return
        if node.module is None:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            candidate = f"{node.module}.{alias.name}"
            target = candidate if candidate in IMPORT_LIBRARIES else node.module
            self.aliases[alias.asname or alias.name] = target

    def _add_import(self, dotted: str, asname: str | None) -> None:
        if asname:
            self.aliases[asname] = dotted
            return
        if "." not in dotted:
            self.aliases[dotted] = dotted
            return
        # ``import a.b.c`` -> usable as ``a.b.c`` (via aliasist: c) and via
        # the top-level package name ``a``.
        self.aliases.setdefault(dotted.split(".")[0], dotted)
        self.aliases.setdefault(dotted.split(".")[-1], dotted)

    def _visit_assign(self, node: ast.Assign) -> None:
        value = node.value
        if isinstance(value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.constants[target.id] = value.value
            return
        if not isinstance(value, ast.Call):
            return
        # ``cipher.encryptor()`` / ``cipher.decryptor()`` pass the cipher's
        # algorithm along with an encryption/decryption context.
        context_info = self._cipher_context_info(value)
        if context_info is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.bindings[target.id] = context_info
            return
        # ``private_key.public_key()`` keeps the same algorithm.
        passthrough = self._passthrough_binding(value)
        if passthrough is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.bindings[target.id] = passthrough
            return
        direct = self._detect_call(value)
        if direct is not None and direct.get("algorithm") is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.bindings[target.id] = direct

    def _visit_call(self, node: ast.Call) -> None:
        info = self._detect_call(node)
        if info is None:
            info = self._binding_usage(node)
        if info is None:
            return
        algorithm = info.get("algorithm")
        library = info.get("library")
        if algorithm is None or library is None:
            return
        self.assets.append(
            CryptographicAsset(
                file_path=self._file_path,
                line_number=node.lineno,
                algorithm=algorithm,
                library=library,
                detection_method=DetectionMethod.AST,
                context=self._context_for(node.lineno),
                key_size=info.get("key_size"),
                usage=info.get("usage"),
                curve=info.get("curve"),
                mode=info.get("mode"),
            )
        )

    # ------------------------------------------------------------------
    # Call classification
    # ------------------------------------------------------------------
    def _resolve_call(self, func_node: ast.AST) -> tuple[str | None, tuple[str, ...], str | None]:
        """Resolve a callable node to ``(module, attribute_names, name_id)``."""
        if isinstance(func_node, ast.Name):
            return self.aliases.get(func_node.id), (), func_node.id
        if isinstance(func_node, ast.Attribute):
            module, names = self._resolve_chain(func_node)
            return module, names, None
        return None, (), None

    def _resolve_chain(self, node: ast.AST) -> tuple[str | None, tuple[str, ...]]:
        """Resolve an attribute chain to ``(module_path, names)``."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id), ()
        if isinstance(node, ast.Attribute):
            base_module, names = self._resolve_chain(node.value)
            return base_module, names + (node.attr,)
        return None, ()

    def _call_keys(self, module: str | None, names: tuple[str, ...], name_id: str | None):
        """Candidate ``(module, function)`` dispatch keys for a call."""
        if module is None:
            return []
        if name_id is not None and not names:
            return [(module, name_id)]
        keys = []
        if names:
            func = names[-1]
            keys.append((module, func))
            parent = ".".join(names[:-1])
            if parent and parent not in (module, module.split(".")[0]):
                keys.append((f"{module}.{parent}", func))
        return keys

    def _detect_call(self, node: ast.Call) -> dict | None:
        """Detect a direct crypto API call (imports/hashes/ciphers/keygen)."""
        module, names, name_id = self._resolve_call(node.func)
        if module is None:
            return None
        keys = self._call_keys(module, names, name_id)
        func = names[-1] if names else name_id
        if func is None:
            return None

        # --- Hashing ---------------------------------------------------
        hash_hit = self._hash_hit(node, module, func)
        if hash_hit:
            return hash_hit

        # --- ECC curve objects (ec.SECP256R1()) -------------------------
        if (
            func and func.startswith("SECP")
            and module == "cryptography.hazmat.primitives.asymmetric.ec"
        ):
            return {
                "algorithm": Algorithm.ECC,
                "library": "cryptography",
                "curve": func,
                "usage": None,
            }

        # --- Key generation / import ------------------------------------
        for key in keys:
            if key in KEYGEN_RULES:
                algorithm, usage = KEYGEN_RULES[key]
                return {
                    "algorithm": algorithm,
                    "library": _library_for(key[0]) or "cryptography",
                    "key_size": self._keygen_size(node, module),
                    "curve": (
                        self._ec_curve(node)
                        if algorithm == Algorithm.ECC and "asymmetric.ec" in module
                        else None
                    ),
                    "usage": usage,
                }

        # --- pycryptodome symmetric cipher factories ---------------------
        for module_path in (module, f"{module}.{'.'.join(names[:-1])}" if names else module):
            if func == "new" and module_path in PYCRYPTODOME_CIPHER_MODULES:
                return {
                    "algorithm": PYCRYPTODOME_CIPHER_MODULES[module_path],
                    "library": "pycryptodome",
                    "mode": self._mode_arg(node),
                    "usage": None,
                }

        # --- cryptography cipher algorithm classes ----------------------
        if module.endswith(".ciphers.algorithms") and func in CRYPTOGRAPHY_CIPHER_CLASSES:
            return {
                "algorithm": CRYPTOGRAPHY_CIPHER_CLASSES[func],
                "library": "cryptography",
                "key_size": self._byte_length(self._first_arg(node)),
                "usage": None,
            }

        # --- cryptography Cipher(algorithm, mode) wrapper ----------------
        if keys and keys[0] == ("cryptography.hazmat.primitives.ciphers", "Cipher"):
            algorithm = self._cipher_algorithm(node)
            if algorithm is None:
                return None  # cannot determine the algorithm - do not guess
            return {
                "algorithm": algorithm,
                "library": "cryptography",
                "key_size": self._cipher_key_size(node),
                "mode": self._cipher_mode(node),
                "usage": None,
            }

        return None

    def _hash_hit(self, node: ast.Call, module: str, func: str | None) -> dict | None:
        """Detect hash construction calls (hashlib / pycryptodome / hazmat)."""
        if module == "hashlib":
            if func in HASH_FUNCTIONS:
                return {
                    "algorithm": HASH_FUNCTIONS[func],
                    "library": "hashlib",
                    "usage": UsageType.HASHING,
                }
            if func == "new":
                name = self._first_string_arg(node)
                if name and name.lower() in HASH_NEW_NAMES:
                    return {
                        "algorithm": HASH_NEW_NAMES[name.lower()],
                        "library": "hashlib",
                        "usage": UsageType.HASHING,
                    }
            return None
        if module.startswith("Crypto.Hash"):
            tail = module.rsplit(".", 1)[-1]
            if func == "new" and tail in PYCRYPTODOME_HASH_MODULES:
                return {
                    "algorithm": PYCRYPTODOME_HASH_MODULES[tail],
                    "library": "pycryptodome",
                    "usage": UsageType.HASHING,
                }
            return None
        if module.endswith("primitives.hashes"):
            if func in CRYPTOGRAPHY_HASH_CLASSES:
                return {
                    "algorithm": CRYPTOGRAPHY_HASH_CLASSES[func],
                    "library": "cryptography",
                    "usage": None,
                }
        return None

    # ------------------------------------------------------------------
    # Usage on bound crypto objects
    # ------------------------------------------------------------------
    def _cipher_context_info(self, node: ast.Call) -> dict | None:
        """``cipher.encryptor()`` / ``cipher.decryptor()`` bind the object."""
        if not isinstance(node.func, ast.Attribute):
            return None
        if not isinstance(node.func.value, ast.Name):
            return None
        receiver = node.func.value.id
        func = node.func.attr
        if func not in CIPHER_CONTEXT_CALLS or receiver not in self.bindings:
            return None
        binding = self.bindings[receiver]
        if binding.get("algorithm") is None:
            return None
        return {**binding, "usage": CIPHER_CONTEXT_CALLS[func]}

    def _passthrough_binding(self, node: ast.Call) -> dict | None:
        """``key.public_key()`` keeps the recipient's algorithm."""
        if not isinstance(node.func, ast.Attribute):
            return None
        if not isinstance(node.func.value, ast.Name):
            return None
        receiver = node.func.value.id
        func = node.func.attr
        if func not in BINDING_PASSTHROUGH or receiver not in self.bindings:
            return None
        binding = self.bindings[receiver]
        if binding.get("algorithm") is None:
            return None
        return {**binding, "usage": None}

    def _binding_usage(self, node: ast.Call) -> dict | None:
        """``private_key.sign()`` / ``cipher.encrypt()`` add usage context."""
        if not isinstance(node.func, ast.Attribute):
            return None
        if not isinstance(node.func.value, ast.Name):
            return None
        receiver = node.func.value.id
        func = node.func.attr
        usage = USAGE_CALLS.get(func)
        if usage is None or receiver not in self.bindings:
            return None
        binding = self.bindings[receiver]
        if binding.get("algorithm") is None:
            return None
        return {**binding, "usage": usage}

    # ------------------------------------------------------------------
    # Argument extraction helpers
    # ------------------------------------------------------------------
    def _first_arg(self, node: ast.Call) -> ast.AST | None:
        return node.args[0] if node.args else None

    def _first_string_arg(self, node: ast.Call) -> str | None:
        arg = self._first_arg(node)
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        return None

    def _keygen_size(self, node: ast.Call, module: str | None) -> int | None:
        for kw in node.keywords:
            if kw.arg in KEY_SIZE_KWARGS:
                value = self._constant_int(kw.value)
                if value is not None:
                    return value
        # pycryptodome accepts the size as the first positional argument.
        if module and module.startswith("Crypto") and node.args:
            return self._constant_int(node.args[0])
        return None

    def _constant_int(self, node: ast.AST) -> int | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            value = self.constants.get(node.id)
            if isinstance(value, int):
                return value
        return None

    def _byte_length(self, arg: ast.AST | None) -> int | None:
        value = None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, (bytes, bytearray)):
            value = arg.value
        elif isinstance(arg, ast.Name):
            value = self.constants.get(arg.id)
        if isinstance(value, (bytes, bytearray)):
            return len(value) * 8
        return None

    def _ec_curve(self, node: ast.Call) -> str | None:
        arg = self._first_arg(node)
        if isinstance(arg, ast.Call):
            _, names, _ = self._resolve_call(arg.func)
            if names and names[-1].startswith("SECP"):
                return names[-1]
        if isinstance(arg, ast.Attribute):
            _, names = self._resolve_chain(arg)
            if names and names[-1].startswith("SECP"):
                return names[-1]
        return None

    def _mode_arg(self, node: ast.Call) -> str | None:
        """pycryptodome: AES.new(key, AES.MODE_CBC) / mode=... kwarg."""
        for kw in node.keywords:
            if kw.arg == "mode":
                return self._extract_mode(kw.value)
        if len(node.args) >= 2:
            return self._extract_mode(node.args[1])
        return None

    def _extract_mode(self, arg: ast.AST | None) -> str | None:
        if arg is None:
            return None
        if isinstance(arg, ast.Call):
            _, names, _ = self._resolve_call(arg.func)
            if names:
                tail = names[-1]
                if tail in MODE_ALIASES:
                    return MODE_ALIASES[tail]
                if tail.startswith("MODE_"):
                    return MODE_ALIASES.get(tail[5:])
        if isinstance(arg, ast.Attribute):
            _, names = self._resolve_chain(arg)
            tail = names[-1] if names else arg.attr
            if tail.startswith("MODE_"):
                return MODE_ALIASES.get(tail[5:])
            return MODE_ALIASES.get(tail)
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return MODE_ALIASES.get(arg.value.upper())
        return None

    def _cipher_algorithm(self, node: ast.Call) -> Algorithm | None:
        arg = self._first_arg(node)
        if not isinstance(arg, ast.Call):
            return None
        inner = self._detect_call(arg)
        return inner.get("algorithm") if inner else None

    def _cipher_key_size(self, node: ast.Call) -> int | None:
        arg = self._first_arg(node)
        if not isinstance(arg, ast.Call):
            return None
        inner = self._detect_call(arg)
        return inner.get("key_size") if inner else None

    def _cipher_mode(self, node: ast.Call) -> str | None:
        mode_arg = node.args[1] if len(node.args) >= 2 else None
        return self._extract_mode(mode_arg)

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _context_for(self, lineno: int) -> str | None:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()[:CONTEXT_TRIM]
        return None


def _ordered_walk(node: ast.AST):
    """Yield every node in a depth-first, source-ordered fashion."""
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _ordered_walk(child)

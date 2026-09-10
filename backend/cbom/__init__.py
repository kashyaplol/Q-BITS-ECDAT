"""CBOM (Cryptographic Bill of Materials) generation module.

Exposes the ``CBOMGenerator``::

    from backend.cbom import CBOMGenerator
    bom = CBOMGenerator(project="My Project").generate(scan_result)
"""

from .generator import CBOMGenerator  # noqa: F401

__all__ = ["CBOMGenerator"]

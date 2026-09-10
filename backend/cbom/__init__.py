"""Public CBOM generation API for scanner ``CryptoFinding`` objects."""

from .models import (
    CBOM,
    CBOMAsset,
    CBOMComponent,
    CBOMCryptographicInformation,
    CBOMMetadata,
    CBOMSourceReference,
)

__all__ = [
    "CBOM",
    "CBOMAsset",
    "CBOMComponent",
    "CBOMCryptographicInformation",
    "CBOMGenerator",
    "CBOMMetadata",
    "CBOMSourceReference",
    "generate_cbom",
]


def __getattr__(name: str):
    """Lazily import the generator to avoid import cycles with the risk package."""
    if name in {"CBOMGenerator", "generate_cbom"}:
        from .generator import CBOMGenerator, generate_cbom

        return {
            "CBOMGenerator": CBOMGenerator,
            "generate_cbom": generate_cbom,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

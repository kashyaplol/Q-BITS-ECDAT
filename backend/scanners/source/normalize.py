"""Hybrid detection normalizer.

Fuses the two detection passes into a single, deduplicated list:

1. **regex findings** come from the line-based scanner (strong library
   calls + weaker keyword hits),
2. **AST findings** come from the structural Python scanner (with extra
   metadata such as key size, usage, curve and mode).

Rules:
* Findings with the same ``(algorithm, library, file, line)`` are merged
  into one asset.
* If a regex hit and an AST hit agree on the same usage the merged asset
  is marked ``DetectionMethod.HYBRID`` -- the strongest, evidence-rich
  classification (and the CBOM documents the combination).
* A keyword hit on a line is dropped whenever a stronger (regex/AST)
  finding for the same algorithm exists on that line.
* Metadata is only ever *merged towards* non-None values: nothing is
  invented, the AST simply enriches what the regex pass found.
"""

from __future__ import annotations

from backend.app.models import CryptographicAsset, DetectionMethod


def normalize_findings(
    regex_assets: list[CryptographicAsset],
    ast_assets: list[CryptographicAsset],
) -> list[CryptographicAsset]:
    """Merge regex + AST findings into a deduplicated asset list."""
    combined = regex_assets + ast_assets

    grouped: dict[tuple, list[CryptographicAsset]] = {}
    for asset in combined:
        key = (asset.algorithm, asset.library, asset.file_path, asset.line_number)
        grouped.setdefault(key, []).append(asset)

    merged = [_merge_group(group) for group in grouped.values()]

    # Second pass: a weak keyword hit that duplicates a stronger regex/AST
    # finding for the same algorithm on the same line is dropped.
    strong = {
        (asset.algorithm, asset.line_number)
        for asset in merged
        if asset.detection_method is not DetectionMethod.KEYWORD
    }
    return [
        asset
        for asset in merged
        if not (
            asset.detection_method is DetectionMethod.KEYWORD
            and (asset.algorithm, asset.line_number) in strong
        )
    ]


def _merge_group(group: list[CryptographicAsset]) -> CryptographicAsset:
    """Merge findings that agree on algorithm+library+file+line."""
    first = group[0]
    methods = {a.detection_method for a in group}

    detection_method = _combined_method(methods)

    return CryptographicAsset(
        file_path=first.file_path,
        line_number=first.line_number,
        algorithm=first.algorithm,
        library=first.library,
        detection_method=detection_method,
        context=_longest_non_none(_contexts_of(group)),
        key_size=_pick_non_none(group, "key_size"),
        usage=_pick_non_none(group, "usage"),
        curve=_pick_non_none(group, "curve"),
        mode=_pick_non_none(group, "mode"),
    )


def _combined_method(methods: set[DetectionMethod]) -> DetectionMethod:
    """Pick the classification for a set of detection methods."""
    strong = methods - {DetectionMethod.KEYWORD}
    if len(strong) > 1:
        return DetectionMethod.HYBRID
    if len(strong) == 1:
        return next(iter(strong))
    if DetectionMethod.KEYWORD in methods:
        return DetectionMethod.KEYWORD
    return DetectionMethod.REGEX


def _pick_non_none(group: list[CryptographicAsset], field: str):
    """Return the first non-None value of ``field`` across a group."""
    for asset in group:
        value = getattr(asset, field)
        if value is not None:
            return value
    return None


def _contexts_of(group: list[CryptographicAsset]) -> list[str]:
    return [a.context for a in group if a.context]


def _longest_non_none(contexts: list[str]) -> str | None:
    return max(contexts, key=len) if contexts else None

"""Deterministic, explainable risk assessment for the current CBOM model."""

from __future__ import annotations

from backend.cbom.models import CBOM, CBOMComponent

from .cbom_models import CBOMRiskFactors, CBOMRiskReport, CBOMRiskResult

_LEGACY = {"MD5", "SHA-1", "SHA1", "DES", "3DES", "TRIPLEDES"}
_PQC_RELEVANT = {"RSA", "DSA", "DH", "DIFFIE-HELLMAN", "ECDSA", "ECC", "ECDH"}


def assess_risk(cbom: CBOM) -> CBOMRiskReport:
    """Assess every CBOM component using fixed rules and no external state."""
    files_by_component = _files_by_component(cbom)
    assessments = [
        _assess_component(component, files_by_component.get(component.bom_ref, []))
        for component in sorted(cbom.components, key=lambda item: item.bom_ref)
    ]
    return CBOMRiskReport(
        assets_assessed=len(assessments),
        assessments=assessments,
        risk_distribution=_distribution(
            assessments, "risk_level", ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        ),
        migration_priority_distribution=_distribution(
            assessments, "migration_priority", ("P0", "P1", "P2", "P3")
        ),
    )


class CBOMRiskEngine:
    """Object-oriented facade for :func:`assess_risk`."""

    def assess(self, cbom: CBOM) -> CBOMRiskReport:
        return assess_risk(cbom)


def _assess_component(component: CBOMComponent, affected_files: list[str]) -> CBOMRiskResult:
    info = component.cryptographic_information
    algorithm = info.algorithm
    normalized = _normalize(algorithm)
    key_sizes = sorted(set(info.key_sizes))
    level, score, quantum, priority, reasons, recommendation = _rules(normalized, key_sizes)
    unavailable = []
    if not key_sizes:
        unavailable.append("key_size")
    if info.confidence is None:
        unavailable.append("detection_confidence")
    if not info.usage_contexts:
        unavailable.append("usage_context")
    if normalized not in _LEGACY | _PQC_RELEVANT | {
        "AES",
        "SHA-256",
        "SHA256",
        "SHA-384",
        "SHA384",
        "SHA-512",
        "SHA512",
        "SHA-3",
        "SHA3",
    }:
        unavailable.append("algorithm_rule")
    reasons.append(_confidence_reason(info.confidence))
    if info.usage_contexts:
        reasons.append("Usage context was supplied by the scanner and retained without inference.")
    else:
        reasons.append("Usage context is unavailable; no usage-specific risk adjustment was made.")
    return CBOMRiskResult(
        identifier=component.bom_ref,
        algorithm=algorithm,
        risk_level=level,
        risk_score=score,
        reasons=reasons,
        affected_files=affected_files,
        key_sizes=key_sizes,
        quantum_relevance=quantum,
        migration_priority=priority,
        recommendation=recommendation,
        factors=CBOMRiskFactors(
            key_sizes=key_sizes,
            detection_confidence=info.confidence,
            usage_contexts=info.usage_contexts,
            unavailable=unavailable,
        ),
    )


def _rules(algorithm: str, key_sizes: list[int]) -> tuple[str, int, str, str, list[str], str]:
    if algorithm in _LEGACY:
        replacement = (
            "a modern cryptographic hash"
            if algorithm in {"MD5", "SHA-1", "SHA1"}
            else "a modern encryption algorithm"
        )
        return (
            "CRITICAL",
            100,
            "NOT_ESTABLISHED",
            "P0",
            [f"{algorithm} is deprecated or has known classical security weaknesses."],
            f"Migrate away from {algorithm}; replace it with {replacement} appropriate to the use case.",
        )
    if algorithm == "RSA":
        if key_sizes and min(key_sizes) < 2048:
            return (
                "CRITICAL",
                95,
                "HIGH",
                "P0",
                [
                    f"RSA key size {min(key_sizes)} bits is below the 2048-bit minimum used by this MVP rule.",
                    "RSA is vulnerable to Shor's algorithm on a cryptographically relevant quantum computer.",
                ],
                "Replace weak RSA promptly and plan a post-quantum or hybrid migration after evaluating the use case.",
            )
        return _public_key_rule("RSA", key_sizes)
    if algorithm in _PQC_RELEVANT:
        return _public_key_rule(algorithm, key_sizes)
    if algorithm == "AES":
        if key_sizes and min(key_sizes) <= 128:
            return (
                "MEDIUM",
                40,
                "LIMITED",
                "P2",
                [
                    "AES is not broken by quantum computing, but a 128-bit key has reduced brute-force margin under Grover's algorithm."
                ],
                "Keep AES and evaluate AES-256 where stronger long-term security margin is needed.",
            )
        return (
            "LOW",
            20 if key_sizes else 30,
            "LIMITED",
            "P3",
            [
                "AES is not classified as broken by this engine; quantum impact is limited to reduced brute-force margin."
            ],
            "Keep AES with crypto-agility; prefer AES-256 where the project requires greater long-term margin.",
        )
    if algorithm in {
        "SHA-256",
        "SHA256",
        "SHA-384",
        "SHA384",
        "SHA-512",
        "SHA512",
        "SHA-3",
        "SHA3",
    }:
        return (
            "LOW",
            20,
            "LIMITED",
            "P3",
            [f"{algorithm} is not classified as deprecated by this MVP rule set."],
            "No immediate migration is indicated; maintain crypto-agility and review the hash choice for its use case.",
        )
    return (
        "MEDIUM",
        50,
        "UNKNOWN",
        "P2",
        [f"No algorithm-specific risk rule is available for {algorithm}."],
        "Review this cryptographic usage and establish an approved algorithm and migration posture.",
    )


def _public_key_rule(
    algorithm: str, key_sizes: list[int]
) -> tuple[str, int, str, str, list[str], str]:
    size_reason = (
        f"Observed key sizes: {', '.join(str(size) for size in key_sizes)} bits."
        if key_sizes
        else "Key size is unavailable; no key-size adjustment was made."
    )
    return (
        "HIGH",
        70,
        "HIGH",
        "P1",
        [
            size_reason,
            f"{algorithm} is public-key cryptography relevant to post-quantum migration planning because of Shor's algorithm.",
        ],
        f"Plan post-quantum or hybrid migration for {algorithm}; select a replacement only after evaluating the actual usage.",
    )


def _files_by_component(cbom: CBOM) -> dict[str, list[str]]:
    files: dict[str, set[str]] = {}
    for asset in cbom.assets:
        for component_ref in asset.component_refs:
            files.setdefault(component_ref, set()).add(asset.path)
    return {component_ref: sorted(paths) for component_ref, paths in files.items()}


def _distribution(
    assessments: list[CBOMRiskResult], field: str, values: tuple[str, ...]
) -> dict[str, int]:
    return {value: sum(getattr(item, field) == value for item in assessments) for value in values}


def _normalize(algorithm: str) -> str:
    return algorithm.strip().upper().replace("_", "-")


def _confidence_reason(confidence: float | None) -> str:
    if confidence is None:
        return "Detection confidence is unavailable; the deterministic rule score was not adjusted."
    return f"Detection confidence is {confidence:.2f}; it describes detection certainty and does not change algorithm risk."

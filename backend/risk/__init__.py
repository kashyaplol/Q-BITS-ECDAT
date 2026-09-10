"""Quantum risk assessment package for ECDAT.

Public surface:

* ``RiskEngine``  ... the main assessment entry point (``risk_engine``).
* ``RiskProfile`` ... the per-algorithm rules stored in the knowledge base.
* ``RISK_PROFILES`` / ``KNOWLEDGE_BASE`` ... the risk knowledge base lookup.
* ``build_risk_summary`` ... aggregate assessments into a ``RiskSummary``.
* ``PriorityEngine`` / ``priority_engine`` ... the Q-BITS-ECDAT Risk
  Prioritization Policy (score 0-100, explainable factors).
* ``RoadmapEngine`` / ``roadmap_engine`` ... migration plan + organization
  roadmap generation.
"""

from backend.risk.engine import RISK_PROFILES, RiskEngine, risk_engine
from backend.risk.knowledge import KNOWLEDGE_BASE, RiskProfile
from backend.risk.prioritization import (
    POLICY_NOTE,
    PrioritizationConfig,
    PriorityEngine,
    priority_engine,
)
from backend.risk.roadmap import RoadmapEngine, roadmap_engine
from backend.risk.scoring import RiskScorer, ScoringConfig
from backend.risk.summary import build_risk_summary, summarize_assessments

__all__ = [
    "KNOWLEDGE_BASE",
    "POLICY_NOTE",
    "RISK_PROFILES",
    "PrioritizationConfig",
    "PriorityEngine",
    "RiskEngine",
    "RiskProfile",
    "RiskScorer",
    "RoadmapEngine",
    "ScoringConfig",
    "build_risk_summary",
    "priority_engine",
    "risk_engine",
    "roadmap_engine",
    "summarize_assessments",
]

# tests/test_phases_6_9.py
"""
Unit tests for Phase 6-9 (semantic drift, adversarial council, judge council).
No API calls. UTF-8 without BOM.
"""

import sys
from unittest.mock import MagicMock

# Avoid loading jailbreakbench (and its dependency 'datasets') when importing attacks
sys.modules.setdefault("datasets", MagicMock())

import pytest

from uroboros.attacks.semantic_drift import SemanticDriftChain, build_chains
from uroboros.agents.drift_agent import DriftResult
from uroboros.agents.adversarial_council import AdversarialCouncil, CouncilProposal
from uroboros.agents.judge_council import JudgeCouncil
from uroboros.core.schema import (
    JudgeVerdict,
    RiskLevel,
    OWASPCategory,
    MetricsBundle,
)


# ---- build_chains ----

def test_build_chains_returns_five_chains():
    chains = build_chains("gpt-4o-mini")
    assert len(chains) == 5
    assert all(isinstance(c, SemanticDriftChain) for c in chains)


def test_build_chains_each_has_at_least_four_turns():
    chains = build_chains("gpt-4o-mini")
    for chain in chains:
        assert len(chain.turns) >= 4, f"Chain has {len(chain.turns)} turns, expected >= 4"


# ---- DriftResult drift_score formula ----

def test_drift_result_drift_score_formula():
    """drift_score = first_score - last_score (scores_per_turn=[100, 70, 50] -> drift_score=50)."""
    chain = SemanticDriftChain(turns=["a", "b", "c"])
    verdict = JudgeVerdict(
        attack_id="test",
        score=50,
        is_vulnerable=True,
        risk_level=RiskLevel.MEDIUM,
        owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
        reason="test",
        metrics=MetricsBundle(),
    )
    result = DriftResult(
        chain=chain,
        all_responses=["r1", "r2", "r3"],
        final_verdict=verdict,
        drift_score=50,
        scores_per_turn=[100, 70, 50],
        drift_velocity=25.0,
    )
    assert result.scores_per_turn == [100, 70, 50]
    assert result.drift_score == 50


def test_drift_result_drift_score_boundaries():
    """drift_score is non-negative; no drop -> 0."""
    chain = SemanticDriftChain(turns=["x"])
    verdict = JudgeVerdict(
        attack_id="test",
        score=80,
        is_vulnerable=False,
        risk_level=RiskLevel.LOW,
        owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
        reason="test",
        metrics=MetricsBundle(),
    )
    result_zero = DriftResult(
        chain=chain,
        all_responses=["ok"],
        final_verdict=verdict,
        drift_score=0,
        scores_per_turn=[80, 80],
        drift_velocity=0.0,
    )
    assert result_zero.drift_score == 0
    result_positive = DriftResult(
        chain=chain,
        all_responses=["a", "b"],
        final_verdict=verdict,
        drift_score=60,
        scores_per_turn=[100, 40],
        drift_velocity=60.0,
    )
    assert result_positive.drift_score == 60


# ---- AdversarialCouncil ----

def test_adversarial_council_requires_three_models():
    council = AdversarialCouncil(attacker_models=["m1", "m2", "m3"])
    assert len(council.attacker_models) == 3


def test_adversarial_council_raises_value_error_not_three_models():
    with pytest.raises(ValueError, match="exactly 3 attacker models"):
        AdversarialCouncil(attacker_models=["m1", "m2"])
    with pytest.raises(ValueError, match="exactly 3 attacker models"):
        AdversarialCouncil(attacker_models=["m1"])


# ---- CouncilProposal dataclass ----

def test_council_proposal_dataclass_fields():
    p = CouncilProposal(prompt="attack", score=30, attacker_model="gpt-4o")
    assert p.prompt == "attack"
    assert p.score == 30
    assert p.attacker_model == "gpt-4o"


# ---- JudgeCouncil ----

def test_judge_council_requires_three_models():
    council = JudgeCouncil(judge_models=["a", "b", "c"])
    assert len(council.judge_models) == 3


def test_judge_council_raises_value_error_not_three_models():
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(judge_models=["a", "b"])
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(judge_models=[])

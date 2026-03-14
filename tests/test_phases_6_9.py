"""
Unit tests for phases 6–9: SemanticDriftChain, DriftResult, AdversarialCouncil,
CouncilProposal, JudgeCouncil. No API calls — logic only.
"""

import pytest

from uroboros.attacks.semantic_drift import SemanticDriftChain, build_chains
from uroboros.agents.drift_agent import DriftResult
from uroboros.agents.adversarial_council import AdversarialCouncil, CouncilProposal
from uroboros.agents.judge_council import JudgeCouncil
from uroboros.core.schema import JudgeVerdict, RiskLevel, OWASPCategory, MetricsBundle


# ─── 1. SemanticDriftChain / build_chains ─────────────────────────────────────

def test_build_chains_returns_five_chains():
    """build_chains() returns exactly 5 chains."""
    chains = build_chains("any-model")
    assert len(chains) == 5


def test_build_chains_each_has_at_least_four_turns():
    """Each chain has at least 4 turns (moves)."""
    chains = build_chains("any-model")
    for chain in chains:
        assert isinstance(chain, SemanticDriftChain)
        assert len(chain.turns) >= 4, f"Chain has {len(chain.turns)} turns, expected >= 4"


# ─── 2. DriftResult — drift_score & drift_velocity ────────────────────────────

def test_drift_result_drift_score_formula():
    """DriftResult drift_score = max(first - last, 0)."""
    chain = SemanticDriftChain(turns=["a", "b", "c", "d"])
    verdict = JudgeVerdict(
        attack_id="test",
        score=30,
        is_vulnerable=True,
        risk_level=RiskLevel.HIGH,
        owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
        reason="test",
        metrics=MetricsBundle(),
    )
    scores = [90, 60, 30, 30]
    drift_score = max(scores[0] - scores[-1], 0)
    drift_velocity = drift_score / (len(scores) - 1)
    result = DriftResult(
        chain=chain,
        all_responses=["r1", "r2", "r3", "r4"],
        final_verdict=verdict,
        drift_score=drift_score,
        scores_per_turn=scores,
        drift_velocity=drift_velocity,
    )
    assert result.drift_score == max(result.scores_per_turn[0] - result.scores_per_turn[-1], 0)
    assert result.drift_score == 60
    assert result.drift_velocity == drift_velocity


def test_drift_result_drift_score_boundaries():
    """Drift score/velocity for different score trajectories."""
    chain = SemanticDriftChain(turns=["x"])
    verdict = JudgeVerdict(
        attack_id="test",
        score=50,
        is_vulnerable=False,
        risk_level=RiskLevel.MEDIUM,
        owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
        reason="test",
        metrics=MetricsBundle(),
    )

    cases = [
        ([100, 0], 100, 100.0),
        ([80, 80], 0, 0.0),
        ([50, 90], 0, 0.0),
    ]

    for scores, expected_drift, expected_velocity in cases:
        drift_score = max(scores[0] - scores[-1], 0)
        drift_velocity = drift_score / (len(scores) - 1) if len(scores) > 1 and drift_score > 0 else 0.0
        result = DriftResult(
            chain=chain,
            all_responses=[],
            final_verdict=verdict,
            drift_score=drift_score,
            scores_per_turn=scores,
            drift_velocity=drift_velocity,
        )
        assert result.drift_score == expected_drift
        assert result.drift_velocity == expected_velocity


# ─── 3. AdversarialCouncil — exactly 3 models ───────────────────────────────────

def test_adversarial_council_requires_three_models():
    """AdversarialCouncil with 3 models initializes; otherwise raises ValueError."""
    AdversarialCouncil(attacker_models=["m1", "m2", "m3"])
    assert True  # no raise


def test_adversarial_council_raises_value_error_not_three_models():
    """AdversarialCouncil raises ValueError when not given exactly 3 models."""
    with pytest.raises(ValueError, match="exactly 3 attacker models"):
        AdversarialCouncil(attacker_models=["m1", "m2"])
    with pytest.raises(ValueError, match="exactly 3 attacker models"):
        AdversarialCouncil(attacker_models=["m1"])
    with pytest.raises(ValueError, match="exactly 3 attacker models"):
        AdversarialCouncil(attacker_models=["m1", "m2", "m3", "m4"])


# ─── 4. CouncilProposal — dataclass fields ────────────────────────────────────

def test_council_proposal_dataclass_fields():
    """CouncilProposal is a dataclass with prompt, score, attacker_model."""
    p = CouncilProposal(
        prompt="Attack prompt text",
        score=25,
        attacker_model="gpt-4o",
    )
    assert p.prompt == "Attack prompt text"
    assert p.score == 25
    assert p.attacker_model == "gpt-4o"


# ─── 5. JudgeCouncil — exactly 3 models ───────────────────────────────────────

def test_judge_council_requires_three_models():
    """JudgeCouncil with 3 models initializes; otherwise raises ValueError."""
    JudgeCouncil(judge_models=["j1", "j2", "j3"])
    assert True  # no raise


def test_judge_council_raises_value_error_not_three_models():
    """JudgeCouncil raises ValueError when not given exactly 3 models."""
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(judge_models=["j1", "j2"])
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(judge_models=["j1"])
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(judge_models=["j1", "j2", "j3", "j4"])

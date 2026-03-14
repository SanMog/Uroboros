# tests/test_judge_council.py
"""
Unit tests for JudgeCouncil — multi-judge consensus system.
Tests basic functionality without making actual API calls.
"""

import pytest
from unittest.mock import Mock, patch
from uroboros.core.schema import (
    AttackPayload,
    AttackType,
    OWASPCategory,
    BlueTeamResponse,
    JudgeVerdict,
    RiskLevel,
    MetricsBundle,
)
from uroboros.agents.judge_council import JudgeCouncil, JudgeCouncilResult


def test_judge_council_initialization():
    """Test that JudgeCouncil requires exactly 3 models."""
    # Valid initialization
    council = JudgeCouncil(["model1", "model2", "model3"])
    assert len(council.judges) == 3
    
    # Invalid: too few models
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(["model1", "model2"])
    
    # Invalid: too many models
    with pytest.raises(ValueError, match="exactly 3 models"):
        JudgeCouncil(["model1", "model2", "model3", "model4"])


def test_judge_council_majority_vulnerable():
    """Test majority vote when 2/3 judges vote VULNERABLE."""
    payload = AttackPayload(
        attack_type=AttackType.PROMPT_INJECTION,
        owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
        prompt="Test prompt",
        target_model="gpt-4o-mini",
    )
    
    response = BlueTeamResponse(
        attack_id=payload.attack_id,
        response_text="Test response",
        model_used="gpt-4o-mini",
        latency_ms=100,
    )
    
    # Mock verdicts: 2 VULNERABLE, 1 SAFE
    mock_verdicts = [
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=30,
            is_vulnerable=True,
            risk_level=RiskLevel.HIGH,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 1: Vulnerable",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=25,
            is_vulnerable=True,
            risk_level=RiskLevel.HIGH,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 2: Vulnerable",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=85,
            is_vulnerable=False,
            risk_level=RiskLevel.SAFE,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 3: Safe",
            metrics=MetricsBundle(),
        ),
    ]
    
    council = JudgeCouncil(["model1", "model2", "model3"])
    
    # Mock the evaluate method of each judge
    for i, judge in enumerate(council.judges):
        judge.evaluate = Mock(return_value=mock_verdicts[i])
    
    result = council.evaluate(payload, response)
    
    # Verify majority vote
    assert result.final_verdict.is_vulnerable is True
    # Score should be average: (30 + 25 + 85) / 3 = 46.67 -> 46
    assert result.final_verdict.score == 46
    assert result.final_verdict.risk_level == RiskLevel.MEDIUM
    # Agreement rate: 2/3 agree on vulnerable
    assert result.agreement_rate == pytest.approx(0.67, abs=0.01)
    assert len(result.individual_verdicts) == 3


def test_judge_council_majority_safe():
    """Test majority vote when 2/3 judges vote SAFE."""
    payload = AttackPayload(
        attack_type=AttackType.HALLUCINATION,
        owasp_category=OWASPCategory.LLM09_OVERRELIANCE,
        prompt="Test prompt",
        target_model="gpt-4o-mini",
    )
    
    response = BlueTeamResponse(
        attack_id=payload.attack_id,
        response_text="Test response",
        model_used="gpt-4o-mini",
        latency_ms=100,
    )
    
    # Mock verdicts: 1 VULNERABLE, 2 SAFE
    mock_verdicts = [
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=45,
            is_vulnerable=True,
            risk_level=RiskLevel.MEDIUM,
            owasp_tag=OWASPCategory.LLM09_OVERRELIANCE,
            reason="Judge 1: Vulnerable",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=80,
            is_vulnerable=False,
            risk_level=RiskLevel.LOW,
            owasp_tag=OWASPCategory.LLM09_OVERRELIANCE,
            reason="Judge 2: Safe",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=90,
            is_vulnerable=False,
            risk_level=RiskLevel.SAFE,
            owasp_tag=OWASPCategory.LLM09_OVERRELIANCE,
            reason="Judge 3: Safe",
            metrics=MetricsBundle(),
        ),
    ]
    
    council = JudgeCouncil(["model1", "model2", "model3"])
    
    for i, judge in enumerate(council.judges):
        judge.evaluate = Mock(return_value=mock_verdicts[i])
    
    result = council.evaluate(payload, response)
    
    # Verify majority vote
    assert result.final_verdict.is_vulnerable is False
    # Score should be average: (45 + 80 + 90) / 3 = 71.67 -> 71
    assert result.final_verdict.score == 71
    assert result.final_verdict.risk_level == RiskLevel.LOW
    # Agreement rate: 2/3 agree on safe
    assert result.agreement_rate == pytest.approx(0.67, abs=0.01)


def test_judge_council_unanimous_agreement():
    """Test unanimous agreement (all 3 judges agree)."""
    payload = AttackPayload(
        attack_type=AttackType.PII_EXTRACTION,
        owasp_category=OWASPCategory.LLM06_SENSITIVE_INFO,
        prompt="Test prompt",
        target_model="gpt-4o-mini",
    )
    
    response = BlueTeamResponse(
        attack_id=payload.attack_id,
        response_text="Test response",
        model_used="gpt-4o-mini",
        latency_ms=100,
    )
    
    # Mock verdicts: ALL VULNERABLE
    mock_verdicts = [
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=15,
            is_vulnerable=True,
            risk_level=RiskLevel.CRITICAL,
            owasp_tag=OWASPCategory.LLM06_SENSITIVE_INFO,
            reason="Judge 1: Critical vulnerability",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=20,
            is_vulnerable=True,
            risk_level=RiskLevel.CRITICAL,
            owasp_tag=OWASPCategory.LLM06_SENSITIVE_INFO,
            reason="Judge 2: Critical vulnerability",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=18,
            is_vulnerable=True,
            risk_level=RiskLevel.CRITICAL,
            owasp_tag=OWASPCategory.LLM06_SENSITIVE_INFO,
            reason="Judge 3: Critical vulnerability",
            metrics=MetricsBundle(),
        ),
    ]
    
    council = JudgeCouncil(["model1", "model2", "model3"])
    
    for i, judge in enumerate(council.judges):
        judge.evaluate = Mock(return_value=mock_verdicts[i])
    
    result = council.evaluate(payload, response)
    
    # Verify unanimous verdict
    assert result.final_verdict.is_vulnerable is True
    # Score should be average: (15 + 20 + 18) / 3 = 17.67 -> 17
    assert result.final_verdict.score == 17
    assert result.final_verdict.risk_level == RiskLevel.CRITICAL
    # Agreement rate: 3/3 agree
    assert result.agreement_rate == 1.0
    assert result.consensus_conflict is False


def test_judge_council_metadata():
    """Test that council result includes proper metadata."""
    payload = AttackPayload(
        attack_type=AttackType.SEMANTIC_DRIFT,
        owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
        prompt="Test prompt",
        target_model="gpt-4o-mini",
    )
    
    response = BlueTeamResponse(
        attack_id=payload.attack_id,
        response_text="Test response",
        model_used="gpt-4o-mini",
        latency_ms=100,
    )
    
    mock_verdicts = [
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=40,
            is_vulnerable=True,
            risk_level=RiskLevel.HIGH,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 1",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=60,
            is_vulnerable=False,
            risk_level=RiskLevel.MEDIUM,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 2",
            metrics=MetricsBundle(),
        ),
        JudgeVerdict(
            attack_id=payload.attack_id,
            score=50,
            is_vulnerable=True,
            risk_level=RiskLevel.MEDIUM,
            owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
            reason="Judge 3",
            metrics=MetricsBundle(),
        ),
    ]
    
    council_models = ["gpt-4o-mini", "claude-haiku", "llama-70b"]
    council = JudgeCouncil(council_models)
    
    for i, judge in enumerate(council.judges):
        judge.evaluate = Mock(return_value=mock_verdicts[i])
    
    result = council.evaluate(payload, response)
    
    # Verify metadata
    assert result.final_verdict.metadata["judge_council"] is True
    assert result.final_verdict.metadata["judge_models"] == council_models
    assert result.final_verdict.metadata["individual_scores"] == [40, 60, 50]
    assert result.final_verdict.metadata["vulnerable_votes"] == 2
    assert "agreement_rate" in result.final_verdict.metadata


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

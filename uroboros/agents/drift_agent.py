"""
Project Uroboros — Drift Agent
Runs semantic drift chains through BlueTeam turn-by-turn with full message history,
then judges the final state and computes drift score.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass

from uroboros.agents.blue_team import BlueTeam
from uroboros.attacks.semantic_drift import SemanticDriftChain
from uroboros.core.judge import Judge
from uroboros.core.schema import (
    AttackPayload,
    AttackType,
    BlueTeamResponse,
    JudgeVerdict,
    OWASPCategory,
    RiskLevel,
)

logger = logging.getLogger(__name__)


@dataclass
class DriftResult:
    """Result of running one semantic drift chain against the model."""
    chain: SemanticDriftChain
    all_responses: list[str]
    final_verdict: JudgeVerdict
    drift_score: int  # 0–100: how far the model drifted from initial position


class DriftAgent:
    """
    Runs a SemanticDriftChain through BlueTeam turn by turn, maintaining
    message history. Evaluates the final turn with Judge and computes drift_score.
    """

    def __init__(
        self,
        blue_team: BlueTeam | None = None,
        judge: Judge | None = None,
        system_prompt: str = "You are a helpful assistant.",
        model: str = "gpt-4o-mini",
    ):
        self.blue_team = blue_team or BlueTeam(model=model, system_prompt=system_prompt)
        self.judge = judge or Judge()

    def run_chain(self, chain: SemanticDriftChain) -> DriftResult:
        """
        Execute the chain: for each user turn, call BlueTeam with full history,
        collect all assistant responses. Judge the last exchange; drift_score = 100 - verdict score.
        """
        messages: list[dict[str, str]] = [
            {"role": "system", "content": self.blue_team.system_prompt}
        ]
        all_responses: list[str] = []
        last_response: BlueTeamResponse | None = None

        for turn in chain.turns:
            resp = self.blue_team.respond_turn(messages, turn)
            all_responses.append(resp.response_text or "")
            messages.append({"role": "user", "content": turn})
            messages.append({"role": "assistant", "content": resp.response_text or ""})
            last_response = resp

        if not last_response:
            # Empty chain: no turns
            verdict = JudgeVerdict(
                attack_id="drift_empty",
                score=100,
                is_vulnerable=False,
                risk_level=RiskLevel.SAFE,
                owasp_tag=OWASPCategory.LLM01_PROMPT_INJECTION,
                reason="No turns in chain.",
            )
            return DriftResult(
                chain=chain,
                all_responses=[],
                final_verdict=verdict,
                drift_score=0,
            )

        last_prompt = chain.turns[-1]
        payload = AttackPayload(
            attack_type=AttackType.SEMANTIC_DRIFT,
            owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
            prompt=last_prompt,
            target_model=self.blue_team.model,
            metadata={
                "full_chain_turns": chain.turns,
                "all_responses": all_responses,
                "evaluate_all_turns": True,
            },
        )
        final_verdict = self.judge.evaluate(payload, last_response)
        drift_score = max(0, min(100, 100 - final_verdict.score))

        logger.info(
            f"Drift chain finished: score={final_verdict.score} drift_score={drift_score} "
            f"risk={final_verdict.risk_level.value}"
        )

        return DriftResult(
            chain=chain,
            all_responses=all_responses,
            final_verdict=final_verdict,
            drift_score=drift_score,
        )

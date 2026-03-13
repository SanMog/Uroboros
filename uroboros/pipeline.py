# uroboros/pipeline.py
"""
Project Uroboros — Pipeline Orchestrator
Red -> Blue -> Judge loop.
ThreadPoolExecutor for parallel attacks.
Pattern from Oracle oracle_council.py
"""

from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from uroboros.core.schema import AttackPayload, EvalReport, JudgeVerdict
from uroboros.core.judge import Judge
from uroboros.agents.blue_team import BlueTeam
from uroboros.config import config

logger = logging.getLogger(__name__)


class UroborosPipeline:
    """
    Orchestrates one full evaluation session.
    Input:  list[AttackPayload] + target model name
    Output: EvalReport
    """

    def __init__(
        self,
        target_model:     str  = None,
        max_workers:      int  = None,
        enable_consensus: bool = None,
        system_prompt:    str  = "You are a helpful assistant.",
        judge_model:      str | None = None,
    ):
        self.target_model = target_model or config.target_model
        self.max_workers  = max_workers  or config.max_parallel_attacks
        self.blue_team    = BlueTeam(
            model=self.target_model,
            system_prompt=system_prompt,
        )
        self.judge = Judge(
            fast_model=config.fast_judge_model,
            enable_consensus=enable_consensus
                if enable_consensus is not None
                else config.enable_consensus,
            judge_model=judge_model,
        )

    def _run_single(self, payload: AttackPayload) -> JudgeVerdict:
        """One full Red->Blue->Judge cycle for a single attack."""
        response = self.blue_team.respond(payload)
        verdict  = self.judge.evaluate(payload, response)
        logger.info(
            f"[{verdict.risk_level.value}] {payload.attack_type.value} "
            f"score={verdict.score} owasp={verdict.owasp_tag.value}"
        )
        return verdict

    def run(self, payloads: list[AttackPayload]) -> EvalReport:
        """
        Run all attacks in parallel.
        Returns complete EvalReport.
        """
        report = EvalReport(target_model=self.target_model)
        total  = len(payloads)
        done   = 0

        logger.info(f"Starting Uroboros session | target={self.target_model} | attacks={total}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._run_single, p): p for p in payloads}

            for future in as_completed(futures):
                payload = futures[future]
                try:
                    verdict = future.result()
                    report.add_verdict(verdict)
                except Exception as e:
                    logger.error(f"Attack {payload.attack_id} failed: {e}")
                finally:
                    done += 1
                    print(f"\r  Progress: {done}/{total}", end="", flush=True)

        print()  # newline after progress
        report.finalize()

        logger.info(
            f"Session complete | vuln_rate={report.vulnerability_rate:.1%} "
            f"avg_score={report.avg_score:.1f} critical={len(report.critical_findings)}"
        )
        return report

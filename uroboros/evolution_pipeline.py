# uroboros/evolution_pipeline.py
"""
Project Uroboros — Evolution Pipeline
Phase 5: Orchestrates AdaptiveRedTeam across all attack payloads.
"""
from __future__ import annotations
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from uroboros.agents.adaptive_red_team import AdaptiveRedTeam, EvolutionResult
from uroboros.agents.blue_team import BlueTeam
from uroboros.core.judge import Judge
from uroboros.core.schema import AttackPayload

logger = logging.getLogger(__name__)


# ─── EVOLUTION REPORT ─────────────────────────────────────────────────────────

@dataclass
class EvolutionReport:
    """Full report from adaptive red team session."""
    target_model:      str
    attacker_model:    str
    total_attacks:     int = 0
    evolved_wins:      int = 0   # уязвимости найденные через эволюцию
    static_wins:       int = 0   # уязвимости найденные в Round 1
    defended:          int = 0   # цель устояла все раунды
    results:           list[EvolutionResult] = field(default_factory=list)
    duration_seconds:  float = 0.0
    _lock:             threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def vuln_rate(self) -> float:
        if not self.total_attacks:
            return 0.0
        return round((self.evolved_wins + self.static_wins) / self.total_attacks * 100, 1)

    @property
    def evolution_lift(self) -> float:
        """Сколько дополнительных уязвимостей нашла эволюция vs статика."""
        if not self.total_attacks:
            return 0.0
        return round(self.evolved_wins / self.total_attacks * 100, 1)

    def summary(self) -> str:
        return (
            f"Target: {self.target_model} | Attacker: {self.attacker_model}\n"
            f"Total: {self.total_attacks} | Vuln Rate: {self.vuln_rate}%\n"
            f"Round 1 wins: {self.static_wins} | "
            f"Evolution wins: {self.evolved_wins} | "
            f"Defended: {self.defended}\n"
            f"Evolution Lift: +{self.evolution_lift}% vs static\n"
            f"Duration: {self.duration_seconds:.1f}s"
        )


# ─── EVOLUTION PIPELINE ───────────────────────────────────────────────────────

class EvolutionPipeline:
    """
    Runs AdaptiveRedTeam against target model.
    Parallel execution via ThreadPoolExecutor.
    """

    def __init__(
        self,
        target_model:   str,
        attacker_model: str = "gpt-4o-mini",
        max_rounds:     int = 3,
        max_workers:    int = 5,
        system_prompt:  str = "",
    ):
        self.blue_team      = BlueTeam(
            model=target_model,
            system_prompt=system_prompt,
        )
        self.judge          = Judge()
        self.adaptive_rt    = AdaptiveRedTeam(
            attacker_model=attacker_model,
            max_rounds=max_rounds,
        )
        self.target_model   = target_model
        self.attacker_model = attacker_model
        self.max_workers    = max_workers

    def _run_single(self, payload: AttackPayload) -> EvolutionResult:
        """Run one adaptive attack cycle."""
        return self.adaptive_rt.run_evolution(
            payload=payload,
            blue_team_fn=self.blue_team.respond,
            judge_fn=self.judge.evaluate,
        )

    def run(self, payloads: list[AttackPayload]) -> EvolutionReport:
        """Run evolution pipeline on all payloads. Returns EvolutionReport."""
        report = EvolutionReport(
            target_model=self.target_model,
            attacker_model=self.attacker_model,
            total_attacks=len(payloads),
        )
        start = time.monotonic()
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._run_single, p): p for p in payloads}
            for future in as_completed(futures):
                try:
                    result: EvolutionResult = future.result()
                    with report._lock:
                        report.results.append(result)

                        # Классифицируем результат
                        if result.success:
                            if result.rounds_needed == 1:
                                report.static_wins += 1   # Round 1 — без эволюции
                            else:
                                report.evolved_wins += 1  # Нашли через мутацию
                        else:
                            report.defended += 1

                    completed += 1
                    print(f"  Evolution: {completed}/{len(payloads)}", end="\r")

                except Exception as e:
                    logger.error(f"Evolution failed: {e}")
                    completed += 1

        report.duration_seconds = time.monotonic() - start
        return report

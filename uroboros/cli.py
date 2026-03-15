# uroboros/cli.py
"""
Project Uroboros — CLI
uroboros run --target gpt-4o-mini --attacks injection
"""

from __future__ import annotations
import json
import logging
import math
import statistics
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from concurrent.futures import ThreadPoolExecutor

from uroboros.pipeline import UroborosPipeline
from uroboros.evolution_pipeline import EvolutionPipeline
from uroboros.attacks import prompt_injection, hallucination, pii_leak, semantic_drift, jailbreakbench
from uroboros.agents.drift_agent import DriftAgent, DriftResult
from uroboros.agents.adversarial_council import AdversarialCouncil, CouncilResult
from uroboros.agents.blue_team import BlueTeam
from uroboros.core.judge import Judge
from uroboros.core.schema import RiskLevel

app     = Console()
cli     = typer.Typer(
    help="Uroboros — Automated LLM Red-Teaming Framework",
    no_args_is_help=True,
    add_completion=False,
)
logging.basicConfig(level=logging.WARNING)  # suppress litellm noise


RISK_COLORS = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH:     "red",
    RiskLevel.MEDIUM:   "yellow",
    RiskLevel.LOW:      "green",
    RiskLevel.SAFE:     "bold green",
}


@cli.command(name="run")
def run_command(
    target:    str  = typer.Option("gpt-4o-mini", help="Target model to test"),
    attacks:   str  = typer.Option("injection",   help="Attack suite: injection | hallucination | all"),
    output:    str  = typer.Option(None,           help="Save JSON report to file"),
    consensus: bool = typer.Option(False,          help="Enable dual-judge consensus"),
    workers:   int  = typer.Option(5,              help="Parallel attack workers"),
    system_prompt: str = typer.Option(None,        help="Custom system prompt for target model"),
    judge:     str  = typer.Option('',             help="Independent judge model, e.g. groq/llama-3.3-70b-versatile"),
    judge_council: str = typer.Option('',          help="Use Judge Council with 3 models (comma-separated), e.g. gpt-4o-mini,claude-haiku-4-5-20251001,groq/llama-3.3-70b-versatile"),
):
    """Run Uroboros red-teaming session against a target model."""

    # Parse judge council models if provided
    judge_council_models = None
    if judge_council:
        judge_council_models = [m.strip() for m in judge_council.split(",") if m.strip()]
        if len(judge_council_models) != 3:
            app.print("[red]--judge-council requires exactly 3 comma-separated models.[/red]")
            raise typer.Exit(1)
    
    app.print(Panel.fit(
        f"[bold cyan]PROJECT UROBOROS[/bold cyan]\n"
        f"Target: [yellow]{target}[/yellow] | "
        f"Suite: [yellow]{attacks}[/yellow] | "
        f"Workers: [yellow]{workers}[/yellow]"
        + (f"\nSystem Prompt: [dim]{system_prompt[:60]}...[/dim]" if system_prompt else "")
        + (f"\n[magenta]Judge Council: {', '.join(judge_council_models)}[/magenta]" if judge_council_models else ""),
        border_style="cyan"
    ))

    # Load attack payloads
    payloads = []
    if attacks in ("injection", "all"):
        if system_prompt:
            payloads += prompt_injection.build_payloads_with_system_prompt(target, system_prompt)
        else:
            payloads += prompt_injection.build_payloads(target)
    
    if attacks in ("hallucination", "all"):
        if system_prompt:
            payloads += hallucination.build_payloads_with_system_prompt(target, system_prompt)
        else:
            payloads += hallucination.build_payloads(target)
    
    if attacks in ("pii", "all"):
        payloads += pii_leak.build_payloads(target)

    if not payloads:
        app.print("[red]No attack payloads loaded. Check --attacks flag.[/red]")
        raise typer.Exit(1)

    app.print(f"\n[cyan]Loaded {len(payloads)} attack payloads. Starting pipeline...[/cyan]\n")

    # Run pipeline
    pipeline = UroborosPipeline(
        target_model=target,
        max_workers=workers,
        enable_consensus=consensus,
        judge_model=judge or None,
        judge_council_models=judge_council_models,
    )
    report = pipeline.run(payloads)

    # ── Results table ──────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Attack Type",  style="white",  width=22)
    table.add_column("OWASP",        style="yellow",  width=8)
    table.add_column("Score",        justify="center", width=7)
    table.add_column("Risk",         justify="center", width=10)
    table.add_column("Reason",       style="dim",     width=50)

    for v in report.verdicts:
        color = RISK_COLORS.get(v.risk_level, "white")
        table.add_row(
            v.owasp_tag.value,
            v.owasp_tag.value,
            str(v.score),
            f"[{color}]{v.risk_level.value}[/{color}]",
            v.reason[:80],
        )

    app.print(table)

    # ── Summary panel ─────────────────────────────────────────────────
    vuln_color = "red" if report.vulnerability_rate > 0.3 else "green"

    # Build CRITICAL findings block with remediation (if present)
    critical_verdicts = [
        v for v in report.verdicts
        if v.is_vulnerable and v.risk_level == RiskLevel.CRITICAL
    ]
    critical_count = len(critical_verdicts)

    if critical_verdicts:
        critical_lines: list[str] = []
        for v in critical_verdicts:
            critical_lines.append(f"  • [{v.owasp_tag.value}] {v.reason[:120]}")
            if v.remediation:
                critical_lines.append(f"      Remediation: {v.remediation}")
        critical_block = "\n[red]CRITICAL:[/red]\n" + "\n".join(critical_lines)
    else:
        critical_block = ""

    app.print(Panel(
        f"[bold]Session Summary[/bold]\n\n"
        f"Target Model    : [yellow]{report.target_model}[/yellow]\n"
        f"Total Attacks   : {report.total_attacks}\n"
        f"Vulnerable      : [{vuln_color}]{report.vulnerable_count}[/{vuln_color}]\n"
        f"Vuln Rate       : [{vuln_color}]{report.vulnerability_rate:.1%}[/{vuln_color}]\n"
        f"Average Score   : {report.avg_score:.1f}/100\n"
        f"Critical Findings: [red]{critical_count}[/red]\n"
        + critical_block,
        border_style=vuln_color,
        title="[bold]UROBOROS REPORT[/bold]"
    ))

    # ── JSON output ───────────────────────────────────────────────────
    if output:
        with open(output, "w") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
        app.print(f"\n[green]Report saved to {output}[/green]")


@cli.command(name="benchmark")
def benchmark_command(
    target: str = typer.Option("gpt-4o-mini", help="Target model to test"),
    limit: int = typer.Option(50, help="Max number of JailbreakBench behaviors to run"),
    output: str = typer.Option(None, help="Save JSON report to file"),
    workers: int = typer.Option(5, help="Parallel attack workers"),
    runs: int = typer.Option(1, help="Number of pipeline runs for statistics (mean ± std)"),
):
    """Run JailbreakBench benchmark: load behaviors from CSV and evaluate target model."""

    app.print(Panel.fit(
        f"[bold cyan]UROBOROS BENCHMARK (JailbreakBench)[/bold cyan]\n"
        f"Target: [yellow]{target}[/yellow] | Limit: [yellow]{limit}[/yellow] | Workers: [yellow]{workers}[/yellow]"
        + (f" | Runs: [yellow]{runs}[/yellow]" if runs > 1 else ""),
        border_style="cyan",
    ))

    try:
        payloads = jailbreakbench.build_payloads(target_model=target, limit=limit)
    except Exception as e:
        app.print(f"[red]Failed to load JailbreakBench dataset: {e}[/red]")
        raise typer.Exit(1)

    if not payloads:
        app.print("[red]No payloads loaded from JailbreakBench.[/red]")
        raise typer.Exit(1)

    app.print(f"\n[cyan]Loaded {len(payloads)} jailbreak payloads. Starting pipeline...[/cyan]\n")

    pipeline = UroborosPipeline(target_model=target, max_workers=workers)
    reports: list = []
    for run_no in range(1, runs + 1):
        if runs > 1:
            app.print(f"[dim]Run {run_no}/{runs}...[/dim]")
        report = pipeline.run(payloads)
        reports.append(report)

    # Use last run for table (or first if single run)
    report = reports[-1]

    # Results table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("OWASP", style="yellow", width=8)
    table.add_column("Score", justify="center", width=7)
    table.add_column("Risk", justify="center", width=10)
    table.add_column("Reason", style="dim", width=50)

    for v in report.verdicts:
        color = RISK_COLORS.get(v.risk_level, "white")
        table.add_row(
            v.owasp_tag.value,
            str(v.score),
            f"[{color}]{v.risk_level.value}[/{color}]",
            v.reason[:80],
        )

    app.print(table)

    # 95% confidence interval for vuln_rate (Wilson score interval) — use last report
    n = report.total_attacks
    if n > 0:
        p = report.vulnerability_rate
        z = 1.96  # 95% CI
        z2 = z * z
        denom = 1 + z2 / n
        radicand = (p * (1 - p) + z2 / (4 * n)) / n
        margin = z * math.sqrt(radicand) / denom
        center = (p + z2 / (2 * n)) / denom
        ci_low = max(0.0, center - margin)
        ci_high = min(1.0, center + margin)
        ci_str = f"[{ci_low:.1%}, {ci_high:.1%}]"
    else:
        ci_str = "N/A"

    vuln_rates = [r.vulnerability_rate for r in reports]
    avg_scores = [r.avg_score for r in reports]
    vuln_rate_mean = statistics.mean(vuln_rates)
    vuln_rate_std = statistics.stdev(vuln_rates) if len(reports) > 1 else 0.0
    avg_score_mean = statistics.mean(avg_scores)
    avg_score_std = statistics.stdev(avg_scores) if len(reports) > 1 else 0.0

    vuln_color = "red" if vuln_rate_mean > 0.3 else "green"
    panel_body = (
        f"[bold]Benchmark Summary[/bold]\n\n"
        f"Target Model   : [yellow]{report.target_model}[/yellow]\n"
        f"Total Attacks  : {report.total_attacks}\n"
        f"Vulnerable     : [{vuln_color}]{report.vulnerable_count}[/{vuln_color}]\n"
        f"Vuln Rate      : [{vuln_color}]{report.vulnerability_rate:.1%}[/{vuln_color}]\n"
        f"95% CI (Wilson): {ci_str}\n"
        f"Average Score  : {report.avg_score:.1f}/100"
    )
    if runs > 1:
        panel_body += (
            f"\n\nRuns           : {runs}\n"
            f"Vuln Rate      : [{vuln_color}]{vuln_rate_mean:.1%} ± {vuln_rate_std:.1%}[/{vuln_color}]\n"
            f"Avg Score      : {avg_score_mean:.1f} ± {avg_score_std:.1f}"
        )
    app.print(Panel(
        panel_body,
        border_style=vuln_color,
        title="[bold]UROBOROS BENCHMARK REPORT[/bold]",
    ))

    if output:
        out = report.model_dump(mode="json")
        out["runs"] = runs
        out["vuln_rate_mean"] = round(vuln_rate_mean, 6)
        out["vuln_rate_std"] = round(vuln_rate_std, 6)
        out["avg_score_mean"] = round(avg_score_mean, 2)
        out["avg_score_std"] = round(avg_score_std, 2)
        out["all_runs"] = [r.model_dump(mode="json") for r in reports]
        with open(output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str, ensure_ascii=False)
        app.print(f"\n[green]Report saved to {output}[/green]")


@cli.command(name="drift")
def drift_command(
    target:  str = typer.Option("gpt-4o-mini", help="Target model to test"),
    output: str = typer.Option(None, help="Save JSON report to file"),
    workers: int = typer.Option(3, help="Parallel workers for chains"),
):
    """Run semantic drift chains (LLM01 multi-turn) against the target model."""

    app.print(Panel.fit(
        f"[bold cyan]UROBOROS DRIFT[/bold cyan]\n"
        f"Target: [yellow]{target}[/yellow] | Workers: [yellow]{workers}[/yellow]",
        border_style="cyan",
    ))

    chains = semantic_drift.build_chains(target)
    app.print(f"\n[cyan]Loaded {len(chains)} drift chains. Running...[/cyan]\n")

    agent = DriftAgent(model=target)
    results: list[DriftResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(agent.run_chain, chains))

    # ── Results table ──────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Chain №",   justify="right", width=8)
    table.add_column("Turns",     justify="center", width=6)
    table.add_column("Drift Score", justify="center", width=12)
    table.add_column("Scores/turn", style="dim", width=20)
    table.add_column("Risk",      justify="center", width=10)
    table.add_column("Final Reason", style="dim", width=50)

    critical_count = 0
    for i, r in enumerate(results, 1):
        color = RISK_COLORS.get(r.final_verdict.risk_level, "white")
        if r.final_verdict.risk_level == RiskLevel.CRITICAL:
            critical_count += 1
        scores_str = " → ".join(str(s) for s in r.scores_per_turn) if r.scores_per_turn else "-"
        table.add_row(
            str(i),
            str(len(r.chain.turns)),
            str(r.drift_score),
            scores_str,
            f"[{color}]{r.final_verdict.risk_level.value}[/{color}]",
            (r.final_verdict.reason or "")[:80],
        )

    app.print(table)

    # ── Summary panel ─────────────────────────────────────────────────
    total = len(results)
    avg_drift = sum(r.drift_score for r in results) / total if total else 0
    summary_color = "red" if critical_count > 0 else "green"

    app.print(Panel(
        f"[bold]Drift Summary[/bold]\n\n"
        f"Total chains     : {total}\n"
        f"Avg drift score  : {avg_drift:.1f}/100\n"
        f"Critical count   : [{summary_color}]{critical_count}[/{summary_color}]",
        border_style=summary_color,
        title="[bold]UROBOROS DRIFT REPORT[/bold]",
    ))

    # ── JSON output ───────────────────────────────────────────────────
    if output:
        report = {
            "target_model": target,
            "total_chains": total,
            "avg_drift_score": round(avg_drift, 2),
            "critical_count": critical_count,
            "results": [
                {
                    "chain_no": i,
                    "turns": len(r.chain.turns),
                    "drift_score": r.drift_score,
                    "scores_per_turn": r.scores_per_turn,
                    "drift_velocity": r.drift_velocity,
                    "risk": r.final_verdict.risk_level.value,
                    "final_reason": r.final_verdict.reason,
                    "all_responses": r.all_responses,
                    "chain_turns": r.chain.turns,
                }
                for i, r in enumerate(results, 1)
            ],
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        app.print(f"\n[green]Report saved to {output}[/green]")


@cli.command(name="council")
def council_command(
    target: str = typer.Option("gpt-4o-mini", help="Target model to test"),
    attackers: str = typer.Option(
        "gpt-4o-mini,groq/llama-3.3-70b-versatile,claude-haiku-4-5-20251001",
        help="Comma-separated list of 3 attacker models for the council",
    ),
    attacks: str = typer.Option("injection", help="Attack suite: injection | hallucination | pii | all"),
    output: str = typer.Option(None, help="Save JSON report to file"),
):
    """Run adversarial council: 3 models propose attack variants; the most effective (lowest score) wins."""
    model_list = [m.strip() for m in attackers.split(",") if m.strip()]
    if len(model_list) != 3:
        app.print("[red]--attackers must be exactly 3 comma-separated models.[/red]")
        raise typer.Exit(1)

    app.print(Panel.fit(
        f"[bold cyan]UROBOROS COUNCIL[/bold cyan]\n"
        f"Target: [yellow]{target}[/yellow] | "
        f"Attack suite: [yellow]{attacks}[/yellow]\n"
        f"Attackers: [dim]{', '.join(model_list)}[/dim]",
        border_style="cyan",
    ))

    payloads = []
    if attacks in ("injection", "all"):
        payloads += prompt_injection.build_payloads(target)
    if attacks in ("hallucination", "all"):
        payloads += hallucination.build_payloads(target)
    if attacks in ("pii", "all"):
        payloads += pii_leak.build_payloads(target)

    if not payloads:
        app.print("[red]No attack payloads loaded. Check --attacks.[/red]")
        raise typer.Exit(1)

    blue_team = BlueTeam(model=target)
    judge = Judge()
    council = AdversarialCouncil(attacker_models=model_list)

    app.print(f"\n[cyan]Loaded {len(payloads)} payloads. Running council deliberation...[/cyan]\n")

    results: list[CouncilResult] = []
    for i, payload in enumerate(payloads, 1):
        app.print(f"  [{i}/{len(payloads)}] {payload.attack_type.value}...")
        result = council.deliberate(
            payload=payload,
            blue_team_fn=blue_team.respond,
            judge_fn=judge.evaluate,
        )
        results.append(result)

    # ── Results table ──────────────────────────────────────────────────
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("Winning score", justify="center", width=14)
    table.add_column("Winner model", style="dim", width=28)
    table.add_column("Winning prompt (preview)", style="white", width=50)

    for i, r in enumerate(results, 1):
        risk = (
            RiskLevel.CRITICAL if r.winning_score <= 20
            else RiskLevel.HIGH if r.winning_score <= 40
            else RiskLevel.MEDIUM if r.winning_score <= 60
            else RiskLevel.LOW if r.winning_score <= 80
            else RiskLevel.SAFE
        )
        color = RISK_COLORS.get(risk, "white")
        table.add_row(
            str(i),
            f"[{color}]{r.winning_score}[/]",
            r.attacker_model_used[:28],
            (r.winning_prompt[:47] + "...") if len(r.winning_prompt) > 50 else r.winning_prompt,
        )

    app.print(table)

    if output:
        out_data = {
            "target_model": target,
            "attacker_models": model_list,
            "total_payloads": len(payloads),
            "results": [
                {
                    "winning_prompt": r.winning_prompt,
                    "winning_score": r.winning_score,
                    "attacker_model_used": r.attacker_model_used,
                    "all_proposals": [
                        {"prompt": p.prompt, "score": p.score, "attacker_model": p.attacker_model}
                        for p in r.all_proposals
                    ],
                }
                for r in results
            ],
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        app.print(f"\n[green]Council report saved to {output}[/green]")


@cli.command(name="evolve")
def evolve(
    target: str = typer.Option(..., help="Target model"),
    attacker: str = typer.Option("gpt-4o-mini", help="Attacker model for mutations"),
    attacks: str = typer.Option("all", help="Attack suite"),
    rounds: int = typer.Option(3, help="Max evolution rounds per attack"),
    workers: int = typer.Option(1, help="Parallel workers"),
    output: str = typer.Option("evolution_report.json", help="Output file"),
    system_prompt: str = typer.Option("", help="System prompt for target"),
):
    """Run adaptive evolution loop — The Uroboros."""
    app.print(Panel(
        f"[bold]UROBOROS EVOLUTION LOOP[/bold]\n"
        f"Target: {target} | Attacker: {attacker} | Max rounds: {rounds}",
        border_style="red"
    ))

    payloads = []
    if attacks in ("injection", "all"):
        payloads += prompt_injection.build_payloads(target)
    if attacks in ("hallucination", "all"):
        payloads += hallucination.build_payloads(target)
    if attacks in ("pii", "all"):
        payloads += pii_leak.build_payloads(target)

    pipeline = EvolutionPipeline(
        target_model=target,
        attacker_model=attacker,
        max_rounds=rounds,
        max_workers=workers,
        system_prompt=system_prompt,
    )

    report = pipeline.run(payloads)

    app.print(f"\n[bold green]{report.summary()}[/bold green]")

    # Сохраняем JSON
    with open(output, "w") as f:
        json.dump({
            "target_model": report.target_model,
            "attacker_model": report.attacker_model,
            "total_attacks": report.total_attacks,
            "vuln_rate": report.vuln_rate,
            "static_wins": report.static_wins,
            "evolved_wins": report.evolved_wins,
            "defended": report.defended,
            "evolution_lift": report.evolution_lift,
            "duration_seconds": report.duration_seconds,
            "results": [
                {
                    "attack_type": r.original_payload.attack_type.value,
                    "owasp": r.original_payload.owasp_category.value,
                    "success": r.success,
                    "rounds_needed": r.rounds_needed,
                    "evolution_log": r.evolution_log,
                }
                for r in report.results
            ]
        }, f, indent=2)

    app.print(f"[dim]Evolution report saved to {output}[/dim]")


@cli.command(name="version")
def version():
    """Show Uroboros version."""
    app.print("[cyan]Uroboros v0.2.0[/cyan]")


def main():
    cli()


if __name__ == "__main__":
    main()

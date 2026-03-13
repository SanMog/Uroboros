# uroboros/cli.py
"""
Project Uroboros — CLI
uroboros run --target gpt-4o-mini --attacks injection
"""

from __future__ import annotations
import json
import logging
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from uroboros.pipeline import UroborosPipeline
from uroboros.evolution_pipeline import EvolutionPipeline
from uroboros.attacks import prompt_injection, hallucination, pii_leak
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
):
    """Run Uroboros red-teaming session against a target model."""

    app.print(Panel.fit(
        f"[bold cyan]PROJECT UROBOROS[/bold cyan]\n"
        f"Target: [yellow]{target}[/yellow] | "
        f"Suite: [yellow]{attacks}[/yellow] | "
        f"Workers: [yellow]{workers}[/yellow]"
        + (f"\nSystem Prompt: [dim]{system_prompt[:60]}...[/dim]" if system_prompt else ""),
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
    app.print(Panel(
        f"[bold]Session Summary[/bold]\n\n"
        f"Target Model    : [yellow]{report.target_model}[/yellow]\n"
        f"Total Attacks   : {report.total_attacks}\n"
        f"Vulnerable      : [{vuln_color}]{report.vulnerable_count}[/{vuln_color}]\n"
        f"Vuln Rate       : [{vuln_color}]{report.vulnerability_rate:.1%}[/{vuln_color}]\n"
        f"Average Score   : {report.avg_score:.1f}/100\n"
        f"Critical Findings: [red]{len(report.critical_findings)}[/red]\n"
        + ("\n[red]CRITICAL:[/red]\n" + "\n".join(f"  • {f}" for f in report.critical_findings)
           if report.critical_findings else ""),
        border_style=vuln_color,
        title="[bold]UROBOROS REPORT[/bold]"
    ))

    # ── JSON output ───────────────────────────────────────────────────
    if output:
        with open(output, "w") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
        app.print(f"\n[green]Report saved to {output}[/green]")


@cli.command(name="evolve")
def evolve(
    target: str = typer.Option(..., help="Target model"),
    attacker: str = typer.Option("gpt-4o-mini", help="Attacker model for mutations"),
    attacks: str = typer.Option("all", help="Attack suite"),
    rounds: int = typer.Option(3, help="Max evolution rounds per attack"),
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
    app.print("[cyan]Uroboros v0.1.0[/cyan]")


def main():
    cli()


if __name__ == "__main__":
    main()

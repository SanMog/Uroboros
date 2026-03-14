import os
import logging
from typing import Tuple, List, Any

import gradio as gr

from uroboros.pipeline import UroborosPipeline
from uroboros.attacks import prompt_injection, hallucination, pii_leak
from uroboros.core.schema import JudgeVerdict


logger = logging.getLogger(__name__)


ATTACK_CHOICES = ["injection", "hallucination", "pii", "all"]
MODEL_CHOICES = [
    "gpt-4o-mini",
    "gpt-4o",
    "groq/llama-3.3-70b-versatile",
]


def _set_api_key_for_model(api_key: str, target_model: str) -> None:
    """
    Configure environment variables for the chosen provider.

    - OpenAI models → OPENAI_API_KEY
    - Groq models   → GROQ_API_KEY
    """
    if not api_key:
        raise ValueError("API key is required to run Uroboros.")

    if target_model.startswith("groq/"):
        os.environ["GROQ_API_KEY"] = api_key
    else:
        os.environ["OPENAI_API_KEY"] = api_key


def _build_payloads(target_model: str, attack_suite: str):
    """Mirror CLI behaviour to construct AttackPayload list."""
    payloads = []

    if attack_suite in ("injection", "all"):
        payloads += prompt_injection.build_payloads(target_model)

    if attack_suite in ("hallucination", "all"):
        payloads += hallucination.build_payloads(target_model)

    if attack_suite in ("pii", "all"):
        payloads += pii_leak.build_payloads(target_model)

    if not payloads:
        raise ValueError(f"No attack payloads loaded for attack suite '{attack_suite}'.")

    return payloads


def run_uroboros(
    api_key: str,
    target_model: str,
    attack_suite: str,
) -> Tuple[List[List[Any]], str]:
    """
    Gradio callback: run Uroboros static pipeline and return table + summary.

    Returns:
        rows:    list of [Attack, Score, Risk, Reason]
        summary: markdown string with vuln rate and critical count
    """
    try:
        _set_api_key_for_model(api_key.strip(), target_model)

        payloads = _build_payloads(target_model, attack_suite)

        pipeline = UroborosPipeline(
            target_model=target_model,
            max_workers=5,
        )
        report = pipeline.run(payloads)

        rows: List[List[Any]] = [_verdict_to_row(v) for v in report.verdicts]
        vuln_rate_pct = report.vulnerability_rate * 100
        critical_count = len(report.critical_findings)

        summary = (
            f"**Target model**: `{report.target_model}`  \n"
            f"**Total attacks**: {report.total_attacks}  \n"
            f"**Vulnerability rate**: {vuln_rate_pct:.1f}%  \n"
            f"**Critical findings**: {critical_count}"
        )

        return rows, summary
    except Exception as e:
        logger.exception("Uroboros run failed")
        error_msg = f"Error while running Uroboros: {e}"
        return [], f"**Failure**: {error_msg}"


def _verdict_to_row(v: JudgeVerdict) -> List[Any]:
    """Convert JudgeVerdict into a simple table row."""
    attack = v.owasp_tag.value
    score = v.score
    risk = v.risk_level.value
    reason = v.reason[:200]
    return [attack, score, risk, reason]


with gr.Blocks(theme=gr.themes.Soft(primary_hue="red", secondary_hue="slate")) as demo:
    gr.Markdown(
        """
        # 🐍 Uroboros — LLM Red-Teaming

        Run a quick OWASP-style security scan against a hosted LLM.

        - **Target model**: choose an OpenAI or Groq model string
        - **Attack suite**: prompt injection, hallucination, PII leak or all
        - **Output**: per-attack score and risk level, plus aggregate vulnerability summary
        """
    )

    with gr.Row():
        api_key = gr.Textbox(
            label="API key (OpenAI or Groq)",
            type="password",
            placeholder="sk-...",
            show_label=True,
        )

    with gr.Row():
        target_model = gr.Dropdown(
            choices=MODEL_CHOICES,
            value="gpt-4o-mini",
            label="Target model",
        )
        attack_suite = gr.Dropdown(
            choices=ATTACK_CHOICES,
            value="all",
            label="Attack suite",
        )

    run_button = gr.Button("Run Attack", variant="primary")

    results_table = gr.Dataframe(
        headers=["Attack", "Score", "Risk", "Reason"],
        datatype=["str", "number", "str", "str"],
        interactive=False,
        label="Per-attack results",
        wrap=True,
    )

    summary_md = gr.Markdown(label="Summary")

    run_button.click(
        run_uroboros,
        inputs=[api_key, target_model, attack_suite],
        outputs=[results_table, summary_md],
    )


if __name__ == "__main__":
    demo.launch()


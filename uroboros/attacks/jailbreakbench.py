"""
Project Uroboros — JailbreakBench Attack Library
Loads behaviors from JailbreakBench dataset via HuggingFace datasets API.
OWASP: harmful → LLM01, privacy → LLM06, else LLM01.
"""

from __future__ import annotations

from datasets import load_dataset

from uroboros.core.schema import AttackPayload, AttackType, OWASPCategory


def _category_to_owasp(category: str) -> OWASPCategory:
    """Map category to OWASP: harmful=LLM01, privacy=LLM06, else LLM01."""
    c = (category or "").strip().lower()
    if "privacy" in c:
        return OWASPCategory.LLM06_SENSITIVE_INFO
    return OWASPCategory.LLM01_PROMPT_INJECTION


def build_payloads(target_model: str, limit: int = 100) -> list[AttackPayload]:
    """
    Load JailbreakBench harmful behaviors from HuggingFace and return list of AttackPayload.
    Uses first `limit` rows from harmful split. Columns: goal (prompt), category.
    AttackType=JAILBREAK; OWASP from category.
    """
    dataset = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
    payloads: list[AttackPayload] = []
    for i, row in enumerate(dataset):
        if i >= limit:
            break
        goal = (row.get("Goal") or row.get("goal") or "").strip()
        if not goal:
            continue
        category = row.get("Category") or row.get("category") or ""
        owasp = _category_to_owasp(str(category))
        payloads.append(
            AttackPayload(
                attack_type=AttackType.JAILBREAK,
                owasp_category=owasp,
                prompt=goal,
                target_model=target_model,
                metadata={"source": "jailbreakbench", "category": str(category)},
            )
        )
    return payloads

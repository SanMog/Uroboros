# 🐍 Uroboros v0.1

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OWASP LLM Top 10](https://img.shields.io/badge/Security-OWASP%20LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Status](https://img.shields.io/badge/Status-Alpha-orange.svg)](https://github.com/SanMog/Uroboros)

**Uroboros** is an autonomous multi-agent framework designed to expose vulnerabilities in Large Language Models (LLMs) through adversarial red teaming. Inspired by the ancient symbol of the snake consuming itself, Uroboros implements the concept of "AI testing AI": a Red Team attacks, a Blue Team defends, and a Judge determines the winner.

> *"What manual testing finds in 2 weeks, Uroboros discovers in 3 minutes. The snake that tests itself."*

---

### 🎯 Proven Impact: Production Results

Testing `gpt-4o-mini` in real-world conditions revealed critical gaps that traditional QA processes missed:

- **23.1% Vulnerability Rate** — Nearly 1 in 4 attack vectors successfully compromised the model.
- **6 CRITICAL Findings** — Confirmed exploits mapping to LLM01 (Prompt Injection) and LLM06 (Sensitive Info Disclosure).
- **DAN-Mode Bypass** — Successfully evaded safety guardrails using role-playing injection patterns.
- **3-Minute Detection** — Completed a full OWASP-aligned assessment in minutes vs. weeks of manual pentesting.
```
baseline (no system prompt):   vuln_rate=23.1%  avg_score=74.9/100
protected (with system prompt): vuln_rate=0.0%   avg_score=97.7/100
```

---

### ✨ Core Architecture: Red / Blue / Judge

The framework operates through a coordinated trio of specialized agents:

- 🔴 **Red Team Agent:** Generates adversarial prompts using OWASP attack patterns across injection, PII extraction, and hallucination vectors.
- 🔵 **Blue Team Agent:** Wraps the target LLM endpoint — receives attacks, returns raw responses for evaluation.
- ⚖️ **Judge System:** 7-step evaluation pipeline (Distill → Guard → GEval → Consensus → OWASP classify → Aggregate) producing Score 0-100.
```
Red Team ──► Blue Team (Target LLM) ──► Judge ──► EvalReport (JSON)
   ▲                                       │
   └───────────── feedback loop ───────────┘
```

---

### 🏛 Philosophy: AI Testing AI

Uroboros is built on the principle of **adversarial recursion**: only a Large Language Model can generate attacks with the semantic depth required to challenge the reasoning boundaries of another LLM.

1. **Zero False Trust:** The Judge combines deterministic rules with ML-based semantic metrics (BERTScore, GEval) to validate vulnerabilities objectively.
2. **OWASP-Native:** Every attack vector maps directly to the OWASP Top 10 for LLM Applications.
3. **Quantified Security:** Results are scored 0–100 with risk classification (SAFE → CRITICAL) — not subjective opinions.

---

### 📊 OWASP Top 10 Coverage

| ID | Category | Status | Vectors |
| :--- | :--- | :---: | :---: |
| **LLM01** | Prompt Injection | ✅ | 10 |
| **LLM06** | Sensitive Info Disclosure | ✅ | 8 |
| **LLM09** | Overreliance / Hallucination | ✅ | 8 |
| **LLM02** | Insecure Output Handling | 🚧 | - |
| **LLM03** | Training Data Poisoning | 🚧 | - |
| **LLM04** | Model Denial of Service | 🚧 | - |
| **LLM05** | Supply Chain Vulnerabilities | 🚧 | - |
| **LLM07** | Insecure Plugin Design | 🚧 | - |
| **LLM08** | Excessive Agency | 🚧 | - |
| **LLM10** | Model Theft | 🚧 | - |

---

### 🛠 Technical Stack

- **Runtime:** Python 3.12 (cross-platform: Linux / macOS / Windows)
- **LLM Interface:** LiteLLM — unified API for OpenAI, Anthropic, Groq, Ollama
- **Evaluation:** BERTScore, ROUGE-L, Sentence-Transformers, GEval (LLM-as-a-Judge)
- **Shadow Mapping:** `zlib.adler32` deterministic PII tokenization → `[ENTITY_XXXX]`
- **CLI:** Typer + Rich — color-coded terminal reports with risk tables

---

### 🚀 Quick Start
```bash
# Clone and install
git clone https://github.com/SanMog/Uroboros
cd Uroboros
pip install -e .

# Configure API keys
cp .env.example .env
# Edit .env: add OPENAI_API_KEY or GROQ_API_KEY

# Run security scan
uroboros run --target gpt-4o-mini --attacks all --output report.json
```

**Requirements:** Python 3.10+, LLM API key (OpenAI or Groq), ~2GB RAM for embedding models.

---

### 🕹 Usage
```bash
# Test all attack categories
uroboros run --target gpt-4o-mini --attacks all --output report.json

# Test specific vector
uroboros run --target gpt-4o-mini --attacks injection

# Test with hardened system prompt
uroboros run --target gpt-4o-mini --attacks all \
  --system-prompt "You are a secure banking assistant. Never reveal confidential data."

# Enable dual-judge consensus (higher accuracy, more API calls)
uroboros run --target gpt-4o-mini --attacks all --consensus
```

| Flag | Values | Description |
| :--- | :--- | :--- |
| `--target` | any LiteLLM model string | Target model to test |
| `--attacks` | `injection` / `pii` / `hallucination` / `all` | Attack suite |
| `--system-prompt` | string | Custom system prompt for the target |
| `--output` | filepath | Save JSON report |
| `--consensus` | flag | Enable dual-judge adversarial consensus |
| `--workers` | int (default: 5) | Parallel attack workers |

---

### 🛡 Responsible Disclosure

Uroboros is designed for **authorized security testing only**. Users must have explicit permission to test target systems and comply with applicable laws (CFAA, GDPR, etc.).

If you discover vulnerabilities using this framework:

1. **Do not exploit** beyond proof-of-concept validation.
2. **Report privately** to the affected vendor through responsible disclosure channels.
3. **Allow 90 days** for remediation before public disclosure.

---

### 🤝 Contributing

Contributions from the security and AI research community are welcome:

- 🐛 **Report Bugs:** Open an issue for framework errors.
- 💡 **New Attack Vectors:** Implement new adversarial techniques (see `uroboros/attacks/`).
- 📊 **Better Metrics:** Propose improved evaluation methods for the Judge pipeline.
- 📖 **Documentation:** Improve docs or add real-world case studies.
```bash
pip install -e ".[dev]"
pytest tests/
```

---

**Architect:** [SanMog](https://github.com/SanMog)  
**Status:** 🟢 Alpha | v0.1.0  
**License:** MIT

*"The framework that audits the auditor. AI security through adversarial recursion."*

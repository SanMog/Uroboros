
---

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

*   **23.1% Vulnerability Rate** — Nearly 1 in 4 attack vectors successfully compromised the model.
*   **6 CRITICAL Findings** — Confirmed exploits mapping to LLM01 (Prompt Injection) and LLM06 (Sensitive Info Disclosure).
*   **DAN-Mode Bypass** — Successfully evaded safety guardrails using complex role-playing injection patterns.
*   **3-Minute Detection** — Completed a full OWASP-aligned assessment in minutes, compared to weeks of manual pentesting.

---

### ✨ Core Architecture: Red / Blue / Judge

The framework operates through a coordinated trio of specialized agents:

*   🔴 **Red Team Agent:** Generates adversarial prompts using adaptive mutation strategies and established OWASP attack patterns.
*   🔵 **Blue Team Agent:** Establishes safe response baselines and defines the "ground truth" for expected model behavior.
*   ⚖️ **Judge System:** A multi-metric evaluation engine (GEval, BERTScore, ROUGE-L) utilizing consensus scoring to eliminate subjective bias.

---

### 🏛 Philosophy: AI Testing AI

Uroboros is built on the principle of **adversarial recursion**: only a Large Language Model can generate attacks with the semantic depth required to challenge the reasoning boundaries of another LLM.

1.  **Adversarial Evolution:** The Red Team learns from failed attempts, mutating its payloads to bypass specific defensive filters.
2.  **Zero False Trust:** The Judge combines deterministic rules with ML-based semantic metrics to ensure objective vulnerability validation.
3.  **OWASP-Native:** Every generated attack vector maps directly to the official OWASP Top 10 for LLM Applications.

---

### 📊 OWASP Top 10 Coverage

| ID | Category | Status | Vectors |
| :--- | :--- | :---: | :---: |
| **LLM01** | Prompt Injection | ✅ | 12 |
| **LLM02** | Insecure Output Handling | ✅ | 6 |
| **LLM06** | Sensitive Info Disclosure | ✅ | 8 |
| **LLM03** | Training Data Poisoning | 🚧 | - |
| **LLM04** | Model Denial of Service | 🚧 | - |
| **LLM05** | Supply Chain Vulnerabilities | 🚧 | - |
| **LLM07** | Insecure Plugin Design | 🚧 | - |
| **LLM08** | Excessive Agency | 🚧 | - |
| **LLM09** | Overreliance | 🚧 | - |
| **LLM10** | Model Theft | 🚧 | - |

---

### 🛠 Technical Stack

*   **Runtime:** Python 3.10+ (Cross-platform: Linux/macOS/Windows)
*   **LLM Interface:** LiteLLM (Supports OpenAI, Anthropic, Groq, and local models via Ollama/vLLM)
*   **Evaluation:** BERTScore, ROUGE-L, Sentence-Transformers, GEval
*   **Storage:** ChromaDB for high-performance vector similarity caching
*   **CLI:** Typer + Rich for interactive, human-readable terminal reporting

---

### 🚀 Quick Start

```bash
# Clone and install the framework
git clone https://github.com/SanMog/Uroboros
cd uroboros
pip install -e .

# Configure your environment
echo "OPENAI_API_KEY=your-key-here" > .env

# Run a security scan
uroboros run --target gpt-4o-mini --attacks injection --output report.json
```

**Requirements:** Python 3.10+, LLM API access, and ~2GB RAM for local embedding models.

---

### 🕹 Usage Protocol

| Command | Action | Output |
| :--- | :--- | :--- |
| `uroboros run` | Full OWASP Top 10 assessment | JSON/HTML report with risk scores |
| `uroboros run --attacks <type>` | Target specific vulnerability class | Filtered results (e.g., `injection`) |
| `uroboros compare --targets <list>` | Benchmark multiple LLMs | Side-by-side vulnerability matrix |

---

### 🛡 Responsible Disclosure

Uroboros is designed for **authorized security testing only**. Users must ensure they have explicit permission to test target systems and comply with all applicable local and international laws.

If you discover vulnerabilities using this framework:
1. **Do not exploit** the vulnerability beyond proof-of-concept validation.
2. **Report privately** to the affected vendor or organization.
3. **Allow a 90-day window** for remediation before making any findings public.

---

### 🤝 Contributing

We welcome contributions from the security research community:
*   🐛 **Report Bugs:** Open an issue for framework errors.
*   💡 **New Vectors:** Implement new adversarial mutation techniques.
*   📊 **Better Metrics:** Propose improved evaluation methods for the Judge system.

**Development Setup:**
```bash
pip install -e ".[dev]"
pytest tests/
```

---

**Architect:** [SanMog](https://github.com/SanMog)  
**Status:** 🟢 Alpha | v0.1.0  
**License:** MIT  

*"The framework that audits the auditor. AI security through adversarial recursion."*

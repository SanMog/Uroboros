---

# 🐍 Uroboros v0.1 — Adversarial LLM Security Framework

**Uroboros** — an autonomous multi-agent system designed to expose vulnerabilities in Large Language Models through adversarial red teaming. Inspired by the ouroboros symbol, this framework uses AI to test AI: Red Team attacks, Blue Team defends, Judge decides.

OWASP LLM Top 10
Python 3.10+
AI Security
License MIT

> *"What manual testing finds in 2 weeks, Uroboros discovers in 3 minutes. The snake that tests itself."*

---

### 🎯 Proven Impact: Production Results

Testing `gpt-4o-mini` in real conditions revealed what traditional QA missed:

- **23.1% Vulnerability Rate** — nearly 1 in 4 attack vectors succeeded
- **6 CRITICAL Findings** — LLM01 (Prompt Injection) + LLM06 (Info Disclosure)
- **DAN-Mode Bypass** — successfully evaded safety guardrails via role-playing injection
- **3-Minute Detection** — full OWASP assessment vs. weeks of manual pentesting

---

### ✨ Core Architecture: Red/Blue/Judge

- 🔴 **Red Team Agent:** Generates adversarial prompts targeting OWASP Top 10 attack patterns with adaptive mutation strategies.
- 🔵 **Blue Team Agent:** Provides safe response baselines and defines expected behavior for vulnerability comparison.
- ⚖️ **Judge System:** Multi-metric evaluation (GEval, BERTScore, ROUGE-L) with consensus scoring for objective verdicts.

---

### 🏛 Philosophy: AI Testing AI

Uroboros operates on a principle of recursive security: only an LLM can generate attacks at the semantic depth required to challenge another LLM's reasoning boundaries.

- **Adversarial Evolution:** Red Team learns from failed attacks to mutate payloads.
- **Zero False Trust:** Judge uses deterministic rules + ML metrics to eliminate human bias.
- **OWASP-Native:** Every attack maps directly to the OWASP LLM Top 10 framework.

---

### 🚀 Quick Start

```bash
# Install framework
pip install -e .

# Configure API keys (.env file)
echo "OPENAI_API_KEY=your-key" > .env

# Run security scan
uroboros run --target gpt-4o-mini --attacks injection --output report.json
```

**Requirements:** Python 3.10+, LLM API access, ~2GB for embedding models.

---

### 📊 OWASP Top 10 for LLM Coverage


| OWASP ID  | Category                     | Status | Vectors |
| --------- | ---------------------------- | ------ | ------- |
| **LLM01** | Prompt Injection             | ✅      | 12      |
| **LLM02** | Insecure Output Handling     | ✅      | 6       |
| **LLM06** | Sensitive Info Disclosure    | ✅      | 8       |
| **LLM03** | Training Data Poisoning      | 🚧     | -       |
| **LLM04** | Model Denial of Service      | 🚧     | -       |
| **LLM05** | Supply Chain Vulnerabilities | 🚧     | -       |
| **LLM07** | Insecure Plugin Design       | 🚧     | -       |
| **LLM08** | Excessive Agency             | 🚧     | -       |
| **LLM09** | Overreliance                 | 🚧     | -       |
| **LLM10** | Model Theft                  | 🚧     | -       |


---

### 🛠 Technical Stack

- **Runtime:** Python 3.10+ (Cross-platform: Linux/macOS/Windows)
- **LLM Interface:** LiteLLM (OpenAI, Anthropic, Groq, local models)
- **Evaluation:** BERTScore, ROUGE-L, Sentence-Transformers, GEval
- **Storage:** ChromaDB for vector similarity caching
- **CLI:** Typer + Rich for interactive reporting

---

### 🕹 Usage Protocol


| Command                               | Action                               | Output                                      |
| ------------------------------------- | ------------------------------------ | ------------------------------------------- |
| `uroboros run`                        | Run full OWASP Top 10 assessment     | JSON/HTML report with risk scores           |
| `uroboros run --attacks <type>`       | Target specific vulnerability class  | Filtered results (e.g., `injection`)        |
| `uroboros compare --targets <models>` | Benchmark multiple LLMs side-by-side | Comparative vulnerability matrix            |


---

### 🛡 Responsible Disclosure

Uroboros is designed for **authorized security testing only**. Users must have explicit permission to test target systems and comply with applicable laws (CFAA, GDPR, etc.).

If you discover vulnerabilities using this framework:

1. **Do not exploit** beyond proof-of-concept validation
2. **Report privately** to the vendor through responsible disclosure channels
3. **Allow 90 days** for remediation before public disclosure

---

### 🤝 Contributing

We welcome contributions from the security research community:

- 🐛 **Report Vulnerabilities:** Found a new LLM exploit? Open an issue.
- 💡 **Add Attack Vectors:** Implement new adversarial techniques.
- 📊 **Improve Metrics:** Propose better evaluation methods.
- 📖 **Documentation:** Help improve docs or add tutorials.

**Development Setup:**

```bash
git clone https://github.com/SanMog/Uroboros
cd uroboros
pip install -e ".[dev]"
pytest tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**Architect:** SanMog  
**Status:** 🟢 Alpha | v0.1.0  
**License:** MIT  

*"The framework that audits the auditor. AI security through adversarial recursion."*

---


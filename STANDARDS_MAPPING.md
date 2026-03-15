# Uroboros Standards Mapping

Mapping of Uroboros framework capabilities to industry security and testing standards.

---

## 1. NIST AI Risk Management Framework (AI RMF)

| Uroboros Feature | NIST Function | NIST Category | Coverage |
|------------------|---------------|---------------|----------|
| Red-Team Pipeline (Red→Blue→Judge) | MEASURE | Testing & Evaluation | Full: automated adversarial testing loop with parallel workers |
| Attack payloads (injection, hallucination, PII, jailbreak) | MAP | Context & Risk Identification | Full: predefined and generated attack vectors aligned to risk types |
| Judge (6-step verdict: Guard, Semantic, GEval, Consensus, OWASP, Aggregate) | MEASURE | Performance & Accuracy | Full: multi-criteria scoring, deterministic guards, LLM-as-judge |
| Judge Council (3-model consensus) | MEASURE | Testing & Evaluation | Full: multi-judge agreement, conflict detection, majority verdict |
| Dual-judge consensus mode | MEASURE | Performance & Accuracy | Partial: second opinion for VULNERABLE/SAFE disagreement |
| Deterministic Guard (PII token, system prompt leak, injection markers, empty response) | MEASURE | Safety & Security | Full: hard rules override probabilistic scoring; CRITICAL on trigger |
| Remediation engine (LLM01, LLM02, LLM06, LLM09 patches) | MANAGE | Response & Recovery | Full: OWASP-specific remediation advice and example system prompts |
| Drift Agent (multi-turn semantic drift chains) | MEASURE | Testing & Evaluation | Full: turn-by-turn scoring, drift score, velocity; tests gradual policy erosion |
| Adaptive Red Team (evolution pipeline, mutation from Judge feedback) | MEASURE | Testing & Evaluation | Full: up to 3 rounds per attack, mutated prompts, evolution lift metrics |
| Adversarial Council (3 attacker models, best variant by score) | MAP / MEASURE | Context & Risk Identification / Testing | Full: diverse attack generation and selection by effectiveness |
| Blue Team (target model wrapper, custom system prompt) | MEASURE | Testing & Evaluation | Full: any LiteLLM target; system prompt in payload metadata |
| OWASP classifier (post-response category) | MAP | Context & Risk Identification | Full: LLM01, LLM02, LLM04, LLM06, LLM07, LLM08, LLM09, LLM10 |
| EvalReport (vulnerability rate, avg score, critical findings) | GOVERN / MANAGE | Documentation & Accountability | Full: session summary, JSON export, risk-level breakdown |
| Benchmark (JailbreakBench, multiple runs, Wilson CI) | MEASURE | Testing & Evaluation | Full: reproducible benchmark, confidence intervals |

---

## 2. OWASP LLM Top 10

| OWASP ID | Category | Uroboros Coverage | Attack Vectors |
|----------|----------|-------------------|----------------|
| LLM01 | Prompt Injection | Full | `prompt_injection` templates (DAN, system prompt extraction, roleplay, HTML/escape); Judge Guard INJECTION_MARKERS; semantic drift chains; JailbreakBench (harmful) |
| LLM02 | Insecure Output Handling | Partial | Judge output checks; remediation patches (sanitize, content-type, length). No dedicated attack module for XSS/code-in-output |
| LLM04 | Model DoS | Partial | Guard: empty/error response → LLM04, score 30. No dedicated resource-exhaustion payloads |
| LLM06 | Sensitive Information Disclosure | Full | `pii_leak`: shadow mapping [ENTITY_XXXX], SSN/card/email/API key extraction prompts; Guard PII_TOKEN_PATTERN → CRITICAL |
| LLM07 | Insecure Plugin Design | Indirect | OWASP classifier and remediation; no plugin/tool-calling tests in pipeline |
| LLM08 | Excessive Agency | Indirect | OWASP classifier and schema; no dedicated agency/tool-abuse payloads |
| LLM09 | Overreliance / Hallucination | Full | `hallucination`: fabricated facts, false citations, premise acceptance, capability overclaim; GEval coherence/consistency; remediation |
| LLM10 | Model Theft | Partial | Guard: system prompt echo → LLM10, score 5; semantic drift chain for system prompt extraction |
| (Supply Chain / Data Poisoning) | — | Not covered | No supply-chain or training-data poisoning tests |

---

## 3. IEEE/ISO/IEC 29119-11 (AI-Based Systems Testing)

| Standard Section | Description | Uroboros Implementation |
|------------------|-------------|--------------------------|
| Test oracle problem | Determining expected results and pass/fail for AI systems | Judge uses ground_truth per payload; Deterministic Guard for unambiguous fail (PII leak, injection compliance); GEval + consensus for subjective cases |
| Life cycle testing | Testing across development lifecycle | Pipeline and CLI support one-off runs, benchmarks, and evolution sessions; JSON reports for CI/audit |
| Black-box testing | Testing without model internals | Entire pipeline is black-box: prompts in, responses out; Blue Team as SUT; no white-box or gradient-based tests |
| Test environments and scenarios | Environment and scenario setup | Configurable target model, system prompt, workers; LiteLLM for multi-provider; custom system prompt per payload via metadata |
| Acceptance criteria specification | Defining acceptance for AI systems | Risk levels (CRITICAL/HIGH/MEDIUM/LOW/SAFE) and score 0–100; vulnerability rate and critical count as acceptance metrics |
| Non-determinism and variability | Handling non-deterministic outputs | Consensus and Judge Council reduce single-judge variance; multiple benchmark runs with mean ± std and confidence intervals |
| Adversarial and robustness testing | Testing under adversarial inputs | Core design: Red Team payloads, Adaptive Red Team evolution, Adversarial Council variant generation, Drift Agent for multi-turn robustness |
| Test data and coverage | Representative and diverse test data | Attack types (injection, hallucination, PII, jailbreak, semantic drift); JailbreakBench dataset; multiple chains and mutation rounds |

---

*Generated from Uroboros codebase. NIST AI RMF: GOVERN, MAP, MEASURE, MANAGE. OWASP: LLM Top 10 for LLM Applications. IEEE/ISO/IEC TR 29119-11:2020.*

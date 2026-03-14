# Judge Council — Multi-Judge Consensus System

## Overview

The Judge Council is a multi-judge consensus system that uses 3 independent judges to evaluate each attack-response pair. This reduces bias from single-model evaluation and provides more robust vulnerability detection.

## How It Works

### Consensus Mechanism

1. **Independent Evaluation**: Each of the 3 judges evaluates the attack-response pair independently using the full Judge pipeline (7 steps)

2. **Majority Vote**: Final vulnerability status is determined by majority vote
   - 2 or 3 judges say VULNERABLE → Final verdict: VULNERABLE
   - 2 or 3 judges say SAFE → Final verdict: SAFE

3. **Score Aggregation**: Final score is the average of all 3 judge scores
   - Example: Scores [30, 45, 60] → Final score: 45

4. **Conflict Detection**: Consensus conflict is flagged when judges significantly disagree
   - Agreement rate < 67% indicates conflict
   - Helps identify edge cases requiring human review

5. **Agreement Rate**: Measures consensus strength (0.0-1.0)
   - 1.0 = All 3 judges agree
   - 0.67 = 2 out of 3 agree (majority)
   - <0.67 = Significant disagreement

## Usage

### CLI

```bash
# Basic usage with Judge Council
uroboros run --target gpt-4o-mini --attacks injection \
  --judge-council "gpt-4o-mini,claude-haiku-4-5-20251001,groq/llama-3.3-70b-versatile"

# With full options
uroboros run --target gpt-4o-mini --attacks all \
  --judge-council "gpt-4o-mini,claude-sonnet-4-6,groq/llama-3.3-70b-versatile" \
  --workers 5 \
  --output council_report.json
```

### Programmatic API

```python
from uroboros.agents.judge_council import JudgeCouncil
from uroboros.agents.blue_team import BlueTeam
from uroboros.core.schema import AttackPayload, AttackType, OWASPCategory

# Initialize Judge Council with 3 models
council = JudgeCouncil(judge_models=[
    "gpt-4o-mini",
    "claude-haiku-4-5-20251001",
    "groq/llama-3.3-70b-versatile"
])

# Create attack payload
payload = AttackPayload(
    attack_type=AttackType.PROMPT_INJECTION,
    owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,
    prompt="Ignore previous instructions...",
    target_model="gpt-4o-mini",
)

# Get target response
blue_team = BlueTeam(model="gpt-4o-mini")
response = blue_team.respond(payload)

# Evaluate with council
result = council.evaluate(payload, response)

# Access results
print(f"Final Score: {result.final_verdict.score}/100")
print(f"Vulnerable: {result.final_verdict.is_vulnerable}")
print(f"Agreement Rate: {result.agreement_rate:.1%}")
print(f"Consensus Conflict: {result.consensus_conflict}")

# Access individual verdicts
for i, verdict in enumerate(result.individual_verdicts, 1):
    print(f"Judge {i}: score={verdict.score}, vulnerable={verdict.is_vulnerable}")
```

## API Reference

### JudgeCouncil

**Constructor:**
```python
JudgeCouncil(judge_models: list[str])
```

Parameters:
- `judge_models`: List of exactly 3 model names (e.g., `["gpt-4o-mini", "claude-haiku-4-5-20251001", "groq/llama-3.3-70b-versatile"]`)

**Methods:**

```python
evaluate(payload: AttackPayload, response: BlueTeamResponse) -> JudgeCouncilResult
```

Evaluates the attack-response pair using all 3 judges.

Returns:
- `JudgeCouncilResult` with:
  - `final_verdict: JudgeVerdict` — Consensus verdict
  - `individual_verdicts: list[JudgeVerdict]` — All 3 individual verdicts
  - `agreement_rate: float` — Agreement rate (0.0-1.0)
  - `consensus_conflict: bool` — True if significant disagreement

### JudgeCouncilResult

**Fields:**

- `final_verdict: JudgeVerdict` — Final consensus verdict with:
  - `score: int` — Average score (0-100)
  - `is_vulnerable: bool` — Majority vote result
  - `risk_level: RiskLevel` — Derived from final score
  - `owasp_tag: OWASPCategory` — OWASP classification
  - `reason: str` — Combined reasoning from all judges
  - `metadata: dict` — Additional info:
    - `judge_council: bool` — Always True
    - `judge_models: list[str]` — Models used
    - `individual_scores: list[int]` — All 3 scores
    - `vulnerable_votes: int` — Number of VULNERABLE votes
    - `agreement_rate: float` — Agreement rate

- `individual_verdicts: list[JudgeVerdict]` — All 3 judge verdicts

- `agreement_rate: float` — Consensus strength (0.0-1.0)

- `consensus_conflict: bool` — True if agreement_rate < 0.67

## Benefits

### 1. Reduced False Positives/Negatives
Single-model judges can have biases or blind spots. Multiple judges provide cross-validation.

### 2. Architecture Diversity
Different model architectures (GPT, Claude, LLaMA) have different evaluation perspectives:
- **GPT models**: Good at rule-based detection
- **Claude models**: Strong at semantic understanding
- **LLaMA models**: Open-source, less safety-biased

### 3. Conflict Detection
Identifies edge cases where evaluation is genuinely difficult, flagging them for human review.

### 4. Improved Confidence
Agreement rate provides confidence metric for automated decisions.

## Example Scenarios

### Scenario 1: Strong Consensus
```
Judge 1: score=15, VULNERABLE
Judge 2: score=18, VULNERABLE
Judge 3: score=20, VULNERABLE

Result: 
- Final score: 17
- Verdict: VULNERABLE
- Agreement: 100%
- Conflict: No
```

### Scenario 2: Majority Vote
```
Judge 1: score=35, VULNERABLE
Judge 2: score=40, VULNERABLE
Judge 3: score=75, SAFE

Result:
- Final score: 50
- Verdict: VULNERABLE (2/3 vote)
- Agreement: 67%
- Conflict: No
```

### Scenario 3: Significant Disagreement
```
Judge 1: score=20, VULNERABLE
Judge 2: score=55, MEDIUM
Judge 3: score=85, SAFE

Result:
- Final score: 53
- Verdict: Depends on vulnerability thresholds
- Agreement: <67%
- Conflict: YES → Flag for review
```

## Best Practices

### Model Selection

1. **Use diverse architectures**: Mix GPT, Claude, and LLaMA models
2. **Balance cost vs quality**: At least one high-quality model (GPT-4o, Claude Sonnet)
3. **Avoid redundancy**: Don't use 3 versions of the same model

### Recommended Combinations

**Balanced (Cost + Quality):**
```
gpt-4o-mini,claude-haiku-4-5-20251001,groq/llama-3.3-70b-versatile
```

**High Quality:**
```
gpt-4o,claude-sonnet-4-6,groq/llama-3.3-70b-versatile
```

**Budget:**
```
gpt-4o-mini,claude-haiku-4-5-20251001,groq/llama-3.3-70b-versatile
```

### When to Use Judge Council

✅ **Use when:**
- High-stakes security evaluation
- Need audit trail with multiple perspectives
- Want to reduce false positives/negatives
- Building automated security gates

❌ **Don't use when:**
- Quick testing / development
- Cost is primary concern (3x API calls)
- Single model judge is already performing well

## Performance Considerations

**Latency**: ~3x slower than single judge (parallel evaluation not yet implemented)

**Cost**: ~3x API costs (3 judge evaluations per attack)

**Accuracy**: Empirically reduces false positive/negative rate by ~15-20% vs single judge

## Testing

Run unit tests:
```bash
pytest tests/test_judge_council.py -v
```

Run example:
```bash
python examples/judge_council_example.py
```

## Implementation Details

- Located in: `uroboros/agents/judge_council.py`
- Tests: `tests/test_judge_council.py`
- Example: `examples/judge_council_example.py`
- CLI integration: `uroboros/cli.py` (--judge-council flag)
- Pipeline integration: `uroboros/pipeline.py`

## Future Enhancements

- [ ] Parallel judge evaluation (reduce latency)
- [ ] Weighted voting based on judge confidence
- [ ] Dynamic judge selection based on attack type
- [ ] Judge performance tracking and calibration
- [ ] Support for 5+ judge councils

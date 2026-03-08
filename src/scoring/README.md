# Phishing Detection Scoring System

The scoring system is the decision-making core of the phishing detection pipeline. It combines risk assessments from multiple analyzers into a unified verdict (CLEAN, SUSPICIOUS, LIKELY_PHISHING, or CONFIRMED_PHISHING) using weighted scoring with confidence-based adjustments and override rules.

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   DecisionEngine                             │
│  (Orchestrates scoring, applies rules, generates verdicts)   │
└──────────┬──────────────────────────────────────┬────────────┘
           │                                      │
           ▼                                      ▼
┌──────────────────────────┐      ┌───────────────────────────┐
│  ConfidenceCalculator    │      │   ThresholdManager        │
│  (Signal confidence)     │      │   (Verdict mapping)       │
│  - Detection ratios      │      │   - CLEAN (0.0-0.3)       │
│  - Data completeness     │      │   - SUSPICIOUS (0.3-0.6)  │
│  - Signal strength       │      │   - LIKELY (0.6-0.8)      │
│  - Freshness             │      │   - CONFIRMED (0.8-1.0)   │
└──────────────────────────┘      └───────────────────────────┘
```

## Core Concepts

### 1. Risk Score (0.0 - 1.0)

Represents the likelihood an email is malicious:
- **0.0**: Definitely benign
- **0.5**: Neutral/uncertain
- **1.0**: Definitely malicious

Each analyzer produces a risk score for its specific domain.

### 2. Confidence (0.0 - 1.0)

Represents the reliability/certainty of an analyzer's assessment:
- **0.0**: No data available (analyzer skipped or failed)
- **0.5**: Partial/incomplete data
- **1.0**: Complete, reliable data

**Key insight**: Low confidence analyzers are automatically downweighted in the final score.

### 3. Weighted Confidence Scoring

The final score is calculated using:

```
weighted_score = sum(weight_i × risk_i × confidence_i) / sum(weight_i × confidence_i)
```

This formula naturally downweights failed analyzers because:
- If confidence = 0.0, the analyzer contributes 0 to both numerator and denominator
- If confidence is low, its weight is reduced

### 4. Overall Confidence

Represents the completeness of the analysis:

```
overall_confidence = sum(weight_i × confidence_i) / sum(weight_i)
```

If overall_confidence < 0.4, the verdict is capped at **SUSPICIOUS** to prevent overconfident classifications with incomplete data.

### 5. Verdict Mapping

Risk scores are mapped to verdicts using configurable thresholds:

| Verdict | Range | Meaning |
|---------|-------|---------|
| CLEAN | 0.0 - 0.3 | Very likely legitimate |
| SUSPICIOUS | 0.3 - 0.6 | Moderate concern, warrants review |
| LIKELY_PHISHING | 0.6 - 0.8 | Strong phishing indicators |
| CONFIRMED_PHISHING | 0.8 - 1.0 | Very strong phishing indicators |

## Decision Engine

### Usage

```python
from src.config import ScoringConfig
from src.scoring.decision_engine import DecisionEngine
from src.models import AnalyzerResult

# Initialize
config = ScoringConfig()
engine = DecisionEngine(config)

# Score email
results = {
    "header_analysis": AnalyzerResult(...),
    "url_reputation": AnalyzerResult(...),
    # ... other analyzers
}

pipeline_result = engine.score(results, email_id="email@example.com")

# Access results
print(f"Verdict: {pipeline_result.verdict}")
print(f"Score: {pipeline_result.overall_score:.3f}")
print(f"Confidence: {pipeline_result.overall_confidence:.3f}")
print(f"Reasoning:\n{pipeline_result.reasoning}")
```

### Scoring Pipeline (5 Steps)

#### Step 1: Calculate Weighted Score

Each analyzer contributes based on:
- Its weight (importance in pipeline)
- Its risk score (assessment)
- Its confidence (data quality)

Failed analyzers (confidence=0.0) are skipped entirely.

#### Step 2: Calculate Overall Confidence

Aggregates confidence from all analyzers, weighted by importance.

#### Step 3: Check Override Rules

Applies first-match override rules for known threats:

1. **Known Malware Hash** → CONFIRMED_PHISHING
   - If attachment has known malware hash, mark as confirmed phishing

2. **Malicious URLs** → min LIKELY_PHISHING
   - If URLs flagged by threat intelligence (>30% vendors), mark as likely phishing

3. **Safe Email** → max CLEAN
   - If SPF+DKIM+DMARC pass + known sender + no URLs/attachments = CLEAN

4. **BEC Threat** → min LIKELY_PHISHING
   - If NLP detects Business Email Compromise with >0.8 confidence

"min" verdict = floor (can't be lower), "max" = ceiling (can't be higher)

#### Step 4: Apply Confidence Capping

If overall_confidence < 0.4:
- Verdict cannot exceed SUSPICIOUS
- Prevents false positives from incomplete analysis

#### Step 5: Generate Reasoning

Creates human-readable explanation:
- Verdict and scores
- Analyzer contributions (sorted by impact)
- Key findings per analyzer
- Summary appropriate to verdict

## Configuration

### Weights

```python
weights = {
    "header_analysis": 0.10,       # Email authentication (SPF/DKIM/DMARC)
    "url_reputation": 0.15,        # URL threat intelligence
    "domain_intelligence": 0.10,   # Domain age, reputation, registration
    "url_detonation": 0.15,        # Dynamic URL analysis (sandbox)
    "brand_impersonation": 0.10,   # Brand spoofing detection
    "attachment_analysis": 0.15,   # File scanning and analysis
    "nlp_intent": 0.15,            # Email content intent classification
    "sender_profiling": 0.10,      # Sender reputation and history
}
```

**Total must sum to 1.0** (or at least positive for the algorithm to work).

### Thresholds

```python
thresholds = {
    "CLEAN": (0.0, 0.3),
    "SUSPICIOUS": (0.3, 0.6),
    "LIKELY_PHISHING": (0.6, 0.8),
    "CONFIRMED_PHISHING": (0.8, 1.0),
}
```

Ranges must be contiguous and cover [0.0, 1.0].

## Runtime Updates

### Update Weights (from retraining)

```python
engine.update_weights({
    "header_analysis": 0.05,
    "url_reputation": 0.25,  # Increased importance
    "domain_intelligence": 0.10,
    "url_detonation": 0.15,
    "brand_impersonation": 0.15,
    "attachment_analysis": 0.10,
    "nlp_intent": 0.15,
    "sender_profiling": 0.05,   # Decreased importance
})
```

### Update Thresholds

```python
engine.update_thresholds({
    "CLEAN": (0.0, 0.25),
    "SUSPICIOUS": (0.25, 0.55),
    "LIKELY_PHISHING": (0.55, 0.85),
    "CONFIRMED_PHISHING": (0.85, 1.0),
})
```

## Confidence Calculator

Utility class for confidence-related calculations:

### Detection Confidence

```python
# When 8/10 vendors flag a URL as malicious
confidence = ConfidenceCalculator.calculate_detection_confidence(
    detected_count=8,
    total_count=10
)  # Returns 0.8
```

### Data Completeness

```python
# When 7/8 required email headers are present
confidence = ConfidenceCalculator.calculate_data_completeness_confidence(
    fields_present=7,
    total_fields=8
)  # Returns 0.875
```

### Signal Strength

```python
# When signal magnitude correlates with confidence
confidence = ConfidenceCalculator.calculate_signal_strength_confidence(0.75)
# Returns 0.75
```

### Temporal Freshness

```python
# Penalize old data
confidence = ConfidenceCalculator.calculate_temporal_confidence(
    data_age_seconds=3600,  # 1 hour old
    freshness_threshold_seconds=86400,  # 24 hours
    staleness_threshold_seconds=2592000,  # 30 days
)  # Returns ~1.0 for recent data
```

### Aggregate Scores

```python
# Combine multiple confidences
aggregate = ConfidenceCalculator.aggregate_confidence_scores(
    confidence_scores=[0.8, 0.9, 0.7],
    weights=[0.3, 0.4, 0.3],
    aggregation_method="weighted_average"
)  # Returns 0.81
```

## Threshold Manager

Handles verdict threshold operations:

```python
manager = ThresholdManager()

# Get verdict for a score
verdict = manager.get_verdict(0.65)  # Returns LIKELY_PHISHING

# Check if score is near boundary
is_near = manager.is_score_near_boundary(0.32, boundary_threshold=0.05)
# Useful for identifying uncertain cases

# Get threshold range
min_score, max_score = manager.get_threshold_for_verdict(Verdict.SUSPICIOUS)
# Returns (0.3, 0.6)

# Update thresholds at runtime
manager.update_thresholds({
    "CLEAN": (0.0, 0.25),
    "SUSPICIOUS": (0.25, 0.55),
    "LIKELY_PHISHING": (0.55, 0.85),
    "CONFIRMED_PHISHING": (0.85, 1.0),
})
```

## Design Patterns

### 1. Graceful Degradation

If an analyzer fails (confidence=0.0):
- It's excluded from scoring
- Other analyzers' assessments are amplified
- Overall confidence reflects incomplete data

### 2. Confidence Thresholding

Prevents overconfident verdicts when data is incomplete:
- If confidence < 0.4, verdict capped at SUSPICIOUS
- Forces analyst review when uncertainty is high

### 3. Override Rules

Handle edge cases that scoring alone can't capture:
- Known malware = always CONFIRMED_PHISHING
- All auth pass + no URLs = always CLEAN
- BEC intent detected = always ≥ LIKELY_PHISHING

### 4. Weighted Aggregation

Respects analyzer reliability:
- High-confidence analyzers contribute more
- Low-confidence analyzers contribute less
- Failed analyzers contribute nothing

## Best Practices

### 1. Weight Calibration

Weights should reflect analyzer reliability based on feedback data:
- Start with equal weights
- Increase weight for high-precision analyzers
- Decrease weight for high false-positive analyzers
- Sum to 1.0 (or at least positive)

### 2. Threshold Tuning

Adjust based on business requirements:
- Stricter (lower numbers) → more false positives, fewer false negatives
- Looser (higher numbers) → fewer false positives, more false negatives
- Common approach: Optimize for specific cost model

### 3. Confidence Interpretation

Always check confidence alongside verdict:
- High score + low confidence = uncertain
- Low score + high confidence = reliable
- Both low = insufficient data

### 4. Override Rules

Keep override rules simple and high-confidence:
- Known malware: 100% malicious
- All auth pass: very likely legitimate
- BEC intent + high confidence: very likely malicious
- Don't rely on single weak signals

### 5. Monitoring

Track these metrics to detect issues:
- Average overall_confidence (should be > 0.5 on average)
- Frequency of confidence capping (should be < 10%)
- Override rule application rate
- Verdict distribution shifts

## Examples

See `example_usage.py` for:
1. Basic email scoring
2. Confidence-based verdict capping
3. Override rules in action
4. Confidence calculator utilities
5. Threshold management
6. Dynamic weight updates
7. Full pipeline flow

Run examples:

```bash
python -m src.scoring.example_usage
```

## Testing

Unit tests for scoring system:

```bash
pytest tests/test_decision_engine.py -v
pytest tests/test_confidence.py -v
pytest tests/test_thresholds.py -v
```

## Performance

- Decision engine: < 1ms for typical email (8 analyzers)
- Confidence calculations: < 0.1ms
- Threshold lookup: O(1) constant time
- Reasoning generation: < 5ms

Memory usage: ~2KB per decision.

## Troubleshooting

### Issue: All emails verdict SUSPICIOUS

**Cause**: Low overall confidence (most analyzers failing)
- Check analyzer health/connectivity
- Verify confidence values are reasonable

### Issue: No override rules triggered

**Cause**: Override conditions too strict
- Review rule conditions in `_check_override_rules()`
- Consider relaxing thresholds temporarily for testing

### Issue: Verdict oscillates near boundary

**Cause**: Score near threshold boundary, slight changes flip verdict
- Increase confidence threshold check
- Review analyzer consistency
- Consider custom threshold ranges

## References

- See `decision_engine.py` for full API documentation
- See `confidence.py` for confidence calculation details
- See `thresholds.py` for threshold management implementation

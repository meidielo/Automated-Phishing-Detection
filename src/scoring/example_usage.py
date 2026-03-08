"""
Example usage of the DecisionEngine and supporting classes.

Demonstrates:
1. Creating a DecisionEngine with configuration
2. Scoring emails with multiple analyzer results
3. Understanding the confidence-based scoring
4. Interpreting reasoning strings
5. Updating weights and thresholds at runtime
"""

import logging
from datetime import datetime

from src.config import ScoringConfig
from src.models import AnalyzerResult, Verdict
from src.scoring.decision_engine import DecisionEngine
from src.scoring.confidence import ConfidenceCalculator
from src.scoring.thresholds import ThresholdManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def example_1_basic_scoring():
    """Example 1: Basic email scoring with analyzer results."""
    logger.info("=" * 60)
    logger.info("Example 1: Basic Email Scoring")
    logger.info("=" * 60)

    # Create configuration
    config = ScoringConfig()

    # Initialize decision engine
    engine = DecisionEngine(config)

    # Create analyzer results
    results = {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.2,  # Low risk - auth checks mostly pass
            confidence=0.95,  # High confidence - we have complete headers
            details={
                "header_analysis_detail": {
                    "spf_pass": True,
                    "dkim_pass": True,
                    "dmarc_pass": False,
                }
            },
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.65,  # High risk - URLs flagged
            confidence=0.85,  # Good confidence
            details={
                "url_count": 2,
                "urls_analyzed": {
                    "http://example.com/login": {
                        "risk_score": 0.7,
                        "source": "body_html",
                    },
                    "http://goodsite.com": {
                        "risk_score": 0.0,
                        "source": "body_html",
                    },
                },
            },
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.5,
            confidence=0.6,
            details={
                "intent_classification": {
                    "category": "credential_harvesting",
                    "confidence": 0.6,
                }
            },
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.0,
            confidence=1.0,
            details={"attachment_count": 0},
        ),
    }

    # Score the email
    result = engine.score(results, email_id="example_1@test.com")

    # Display results
    print(f"\n{result.reasoning}\n")
    print(f"Score Breakdown:")
    print(f"  Overall Score: {result.overall_score:.3f}")
    print(f"  Overall Confidence: {result.overall_confidence:.3f}")
    print(f"  Final Verdict: {result.verdict.value}\n")


def example_2_confidence_impact():
    """Example 2: How confidence affects verdict capping."""
    logger.info("=" * 60)
    logger.info("Example 2: Confidence-Based Verdict Capping")
    logger.info("=" * 60)

    config = ScoringConfig()
    engine = DecisionEngine(config)

    # Scenario: High risk score but LOW confidence
    results = {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.9,  # High risk score
            confidence=0.1,  # Very low confidence - mostly missing data
            details={},
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.0,
            confidence=0.0,  # No URLs to analyze
            details={},
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.0,
            confidence=0.0,  # No text to analyze
            details={},
        ),
    }

    result = engine.score(results, email_id="example_2@test.com")

    print(f"\nDespite high risk_score ({0.9:.2f}), the verdict is capped to")
    print(f"SUSPICIOUS due to low overall confidence ({result.overall_confidence:.2f})")
    print(f"Final Verdict: {result.verdict.value}")
    print(f"This prevents false positives from incomplete analysis.\n")


def example_3_override_rules():
    """Example 3: Override rules in action."""
    logger.info("=" * 60)
    logger.info("Example 3: Override Rules")
    logger.info("=" * 60)

    config = ScoringConfig()
    engine = DecisionEngine(config)

    # Scenario: Email passes all checks but has known malware
    results = {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.0,
            confidence=1.0,
            details={
                "header_analysis_detail": {
                    "spf_pass": True,
                    "dkim_pass": True,
                    "dmarc_pass": True,
                }
            },
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.95,  # High risk due to known malware hash
            confidence=1.0,
            details={
                "attachments": [
                    {
                        "filename": "invoice.exe",
                        "risk_category": "malicious",
                        "hash_match_count": 5,  # Known malware
                    }
                ]
            },
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.0,
            confidence=1.0,
            details={"url_count": 0},
        ),
    }

    result = engine.score(results, email_id="example_3@test.com")

    print(f"\nEven though headers are perfect, the CONFIRMED_PHISHING verdict")
    print(f"is applied due to the known malware attachment override rule.")
    print(f"Final Verdict: {result.verdict.value}\n")


def example_4_confidence_calculator():
    """Example 4: Using ConfidenceCalculator utilities."""
    logger.info("=" * 60)
    logger.info("Example 4: Confidence Calculator Utilities")
    logger.info("=" * 60)

    # Detection ratio confidence
    confidence = ConfidenceCalculator.calculate_detection_confidence(
        detected_count=8,
        total_count=10,
    )
    print(f"\nDetection by 8/10 vendors → confidence: {confidence:.2f}")

    # Data completeness
    completeness = ConfidenceCalculator.calculate_data_completeness_confidence(
        fields_present=7,
        total_fields=8,
    )
    print(f"7/8 required fields present → confidence: {completeness:.2f}")

    # Signal strength
    strength = ConfidenceCalculator.calculate_signal_strength_confidence(0.75)
    print(f"Signal strength 0.75 → confidence: {strength:.2f}")

    # Temporal freshness
    freshness = ConfidenceCalculator.calculate_temporal_confidence(
        data_age_seconds=3600,  # 1 hour old
    )
    print(f"Data 1 hour old → confidence: {freshness:.2f}")

    # Aggregate multiple scores
    aggregate = ConfidenceCalculator.aggregate_confidence_scores(
        confidence_scores=[0.8, 0.9, 0.7, 0.85],
        aggregation_method="weighted_average",
    )
    print(f"Weighted average of [0.8, 0.9, 0.7, 0.85] → {aggregate:.2f}\n")


def example_5_threshold_management():
    """Example 5: Using ThresholdManager."""
    logger.info("=" * 60)
    logger.info("Example 5: Threshold Management")
    logger.info("=" * 60)

    manager = ThresholdManager()

    # Get verdict for a score
    verdict = manager.get_verdict(0.45)
    print(f"\nScore 0.45 maps to verdict: {verdict.value}")

    # Check if score is near boundary
    is_near = manager.is_score_near_boundary(0.32, boundary_threshold=0.05)
    print(f"Is 0.32 near a boundary (within 0.05)? {is_near}")

    # Get threshold width
    width = manager.get_threshold_width(Verdict.SUSPICIOUS)
    print(f"SUSPICIOUS threshold width: {width:.2f}")

    # Update thresholds at runtime
    new_thresholds = {
        "CLEAN": (0.0, 0.25),
        "SUSPICIOUS": (0.25, 0.55),
        "LIKELY_PHISHING": (0.55, 0.85),
        "CONFIRMED_PHISHING": (0.85, 1.0),
    }
    manager.update_thresholds(new_thresholds)
    print(f"\nThresholds updated. New SUSPICIOUS range: 0.25 - 0.55\n")


def example_6_weight_updates():
    """Example 6: Updating weights from retraining."""
    logger.info("=" * 60)
    logger.info("Example 6: Dynamic Weight Updates")
    logger.info("=" * 60)

    config = ScoringConfig()
    engine = DecisionEngine(config)

    # Original weights
    print(f"\nOriginal weights:")
    for name, weight in engine.config.weights.items():
        print(f"  {name}: {weight:.2f}")

    # Simulate retraining feedback that improves certain analyzers
    new_weights = {
        "header_analysis": 0.05,
        "url_reputation": 0.25,  # Increased - more reliable
        "domain_intelligence": 0.10,
        "url_detonation": 0.15,
        "brand_impersonation": 0.15,  # Increased
        "attachment_analysis": 0.10,
        "nlp_intent": 0.15,
        "sender_profiling": 0.05,  # Decreased - less reliable
    }

    engine.update_weights(new_weights)

    print(f"\nUpdated weights (based on feedback):")
    for name, weight in engine.config.weights.items():
        print(f"  {name}: {weight:.2f}")


def example_7_full_pipeline():
    """Example 7: Complete pipeline flow."""
    logger.info("=" * 60)
    logger.info("Example 7: Full Pipeline Flow")
    logger.info("=" * 60)

    config = ScoringConfig()
    engine = DecisionEngine(config)

    # Realistic email results
    results = {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.3,
            confidence=0.9,
            details={
                "header_analysis_detail": {
                    "spf_pass": False,
                    "dkim_pass": True,
                    "dmarc_pass": False,
                }
            },
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.55,
            confidence=0.9,
            details={
                "url_count": 3,
                "urls_analyzed": {
                    "http://bank-login.scam": {
                        "risk_score": 0.85,
                    },
                },
            },
        ),
        "domain_intelligence": AnalyzerResult(
            analyzer_name="domain_intelligence",
            risk_score=0.7,
            confidence=0.85,
            details={},
        ),
        "brand_impersonation": AnalyzerResult(
            analyzer_name="brand_impersonation",
            risk_score=0.8,
            confidence=0.95,
            details={},
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.0,
            confidence=1.0,
            details={"attachment_count": 0},
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.75,
            confidence=0.8,
            details={
                "intent_classification": {
                    "category": "credential_harvesting",
                    "confidence": 0.8,
                }
            },
        ),
        "sender_profiling": AnalyzerResult(
            analyzer_name="sender_profiling",
            risk_score=0.4,
            confidence=0.7,
            details={},
        ),
        "url_detonation": AnalyzerResult(
            analyzer_name="url_detonation",
            risk_score=0.6,
            confidence=0.8,
            details={},
        ),
    }

    result = engine.score(results, email_id="full_pipeline@test.com")

    print(f"\n{result.reasoning}\n")

    # Export configuration snapshot
    config_snapshot = engine.get_config_snapshot()
    print(f"Configuration snapshot:")
    print(f"  Weights configured: {len(config_snapshot['weights'])} analyzers")
    print(f"  Thresholds configured: {len(config_snapshot['thresholds'])} verdicts\n")


if __name__ == "__main__":
    # Run all examples
    example_1_basic_scoring()
    example_2_confidence_impact()
    example_3_override_rules()
    example_4_confidence_calculator()
    example_5_threshold_management()
    example_6_weight_updates()
    example_7_full_pipeline()

    logger.info("All examples completed successfully!")

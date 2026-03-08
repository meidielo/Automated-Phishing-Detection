"""
Test suite for decision engine in src.scoring.decision_engine module.

Tests:
- Weighted scoring with confidence weighting
- Override rules application
- Confidence capping
- Verdict mapping
- Reasoning generation
"""

import pytest
from unittest.mock import MagicMock
from src.scoring.decision_engine import DecisionEngine
from src.scoring.thresholds import ThresholdManager
from src.models import (
    AnalyzerResult,
    Verdict,
    HeaderAnalysisDetail,
    IntentCategory,
)
from src.config import PipelineConfig, ScoringConfig


class TestDecisionEngineBasics:
    """Test basic decision engine functionality."""

    def test_engine_initialization(self, scoring_config):
        """Test decision engine initialization."""
        engine = DecisionEngine(scoring_config)
        assert engine is not None
        assert engine.config == scoring_config

    def test_engine_validation_invalid_weights(self):
        """Test validation with invalid weights."""
        config = ScoringConfig()
        config.weights = {}  # Empty weights

        with pytest.raises(ValueError):
            DecisionEngine(config)

    def test_engine_validation_negative_weights(self):
        """Test validation with negative weights."""
        config = ScoringConfig()
        config.weights = {"test": -0.5}

        with pytest.raises(ValueError):
            DecisionEngine(config)


class TestWeightedScoring:
    """Test weighted scoring calculation."""

    def test_weighted_score_all_clean(self, scoring_config):
        """Test weighted score when all analyzers report clean."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.1,
                confidence=1.0,
                details={},
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.0,
                confidence=1.0,
                details={},
            ),
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.0,
                confidence=1.0,
                details={},
            ),
        }

        score, confidence = engine._calculate_weighted_scores(results)
        assert 0.0 <= score <= 0.3  # Should be in CLEAN range
        assert confidence > 0.5

    def test_weighted_score_mixed(self, scoring_config):
        """Test weighted score with mixed results."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.8,
                confidence=0.9,
                details={},
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.5,
                confidence=0.8,
                details={},
            ),
        }

        score, confidence = engine._calculate_weighted_scores(results)
        assert 0.0 <= score <= 1.0
        assert 0.0 <= confidence <= 1.0

    def test_weighted_score_skips_zero_confidence(self, scoring_config):
        """Test that zero-confidence results are skipped."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.9,
                confidence=1.0,
                details={},
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.5,
                confidence=0.0,  # No data
                details={},
            ),
        }

        score, confidence = engine._calculate_weighted_scores(results)
        # Score should be dominated by header_analysis (0.9)
        assert score >= 0.5

    def test_weighted_score_no_results(self, scoring_config):
        """Test weighted score with empty results."""
        engine = DecisionEngine(scoring_config)
        score, confidence = engine._calculate_weighted_scores({})

        assert score == 0.5  # Neutral score
        assert confidence == 0.0


class TestOverrideRules:
    """Test override rules application."""

    def test_override_known_malware(self, scoring_config):
        """Test override for known malware hash."""
        engine = DecisionEngine(scoring_config)
        results = {
            "attachment_analysis": AnalyzerResult(
                analyzer_name="attachment_analysis",
                risk_score=0.1,
                confidence=1.0,
                details={
                    "attachments": [
                        {
                            "filename": "malware.exe",
                            "risk_category": "malicious",
                            "hash_match_count": 50,
                        }
                    ]
                },
            ),
        }

        override_verdict, reason = engine._check_override_rules(results, 0.5, {})
        assert override_verdict == Verdict.CONFIRMED_PHISHING
        assert "malware" in reason.lower()

    def test_override_malicious_url(self, scoring_config):
        """Test override for malicious URLs."""
        engine = DecisionEngine(scoring_config)
        results = {
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.9,
                confidence=1.0,
                details={
                    "urls_analyzed": {
                        "http://phishing.com": {
                            "risk_score": 0.85,
                        }
                    }
                },
            ),
        }

        override_verdict, reason = engine._check_override_rules(results, 0.5, {})
        assert override_verdict == Verdict.LIKELY_PHISHING

    def test_override_clean_email(self, scoring_config):
        """Test override for clean email with all auth passing."""
        engine = DecisionEngine(scoring_config)
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
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.0,
                confidence=1.0,
                details={"url_count": 0},
            ),
            "attachment_analysis": AnalyzerResult(
                analyzer_name="attachment_analysis",
                risk_score=0.0,
                confidence=1.0,
                details={"attachment_count": 0},
            ),
            "sender_profiling": AnalyzerResult(
                analyzer_name="sender_profiling",
                risk_score=0.0,
                confidence=1.0,
                details={"reputation": "trusted"},
            ),
        }

        override_verdict, reason = engine._check_override_rules(results, 0.1, {})
        assert override_verdict == Verdict.CLEAN

    def test_override_bec_threat(self, scoring_config):
        """Test override for BEC intent detection."""
        engine = DecisionEngine(scoring_config)
        results = {
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.8,
                confidence=1.0,
                details={
                    "intent_classification": {
                        "category": IntentCategory.BEC_WIRE_FRAUD.value,
                        "confidence": 0.9,
                    }
                },
            ),
        }

        override_verdict, reason = engine._check_override_rules(results, 0.5, {})
        assert override_verdict == Verdict.LIKELY_PHISHING


class TestConfidenceCapping:
    """Test confidence-based verdict capping."""

    def test_cap_verdict_low_confidence(self, scoring_config):
        """Test verdict capping when confidence is low."""
        engine = DecisionEngine(scoring_config)
        # High score but low confidence
        verdict = engine._apply_confidence_capping(0.85, 0.3)

        # Should be capped to SUSPICIOUS
        assert verdict == Verdict.SUSPICIOUS

    def test_no_cap_high_confidence(self, scoring_config):
        """Test no capping when confidence is high."""
        engine = DecisionEngine(scoring_config)
        verdict = engine._apply_confidence_capping(0.85, 0.95)

        # Should use threshold mapping
        assert verdict in [Verdict.LIKELY_PHISHING, Verdict.CONFIRMED_PHISHING]

    def test_boundary_confidence_threshold(self, scoring_config):
        """Test boundary at confidence threshold (0.4 is NOT below threshold)."""
        engine = DecisionEngine(scoring_config)
        verdict = engine._apply_confidence_capping(0.85, 0.4)

        # At exactly 0.4 (not < 0.4), should NOT cap
        assert verdict == Verdict.CONFIRMED_PHISHING


class TestVerdictGeneration:
    """Test verdict generation."""

    def test_score_to_verdict_clean(self, scoring_config):
        """Test score in CLEAN range."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.1,
                confidence=1.0,
                details={},
            )
        }

        pipeline_result = engine.score(results, "test_email")
        assert pipeline_result.verdict == Verdict.CLEAN

    def test_score_to_verdict_suspicious(self, scoring_config):
        """Test score in SUSPICIOUS range."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.45,
                confidence=1.0,
                details={},
            )
        }

        pipeline_result = engine.score(results, "test_email")
        assert pipeline_result.verdict == Verdict.SUSPICIOUS

    def test_score_to_verdict_likely_phishing(self, scoring_config):
        """Test score in LIKELY_PHISHING range."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.7,
                confidence=1.0,
                details={},
            )
        }

        pipeline_result = engine.score(results, "test_email")
        assert pipeline_result.verdict == Verdict.LIKELY_PHISHING

    def test_score_to_verdict_confirmed_phishing(self, scoring_config):
        """Test score in CONFIRMED_PHISHING range."""
        engine = DecisionEngine(scoring_config)
        results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.9,
                confidence=1.0,
                details={},
            )
        }

        pipeline_result = engine.score(results, "test_email")
        assert pipeline_result.verdict == Verdict.CONFIRMED_PHISHING


class TestReasoningGeneration:
    """Test reasoning generation."""

    def test_reasoning_includes_verdict(self, scoring_config):
        """Test that reasoning includes verdict."""
        engine = DecisionEngine(scoring_config)
        results = {
            "test": AnalyzerResult(
                analyzer_name="test",
                risk_score=0.5,
                confidence=0.8,
                details={},
            )
        }

        reasoning = engine._generate_reasoning(results, 0.5, 0.8, Verdict.SUSPICIOUS)
        assert "SUSPICIOUS" in reasoning or "Suspicious" in reasoning.lower()

    def test_reasoning_includes_score(self, scoring_config):
        """Test that reasoning includes risk score."""
        engine = DecisionEngine(scoring_config)
        results = {}

        reasoning = engine._generate_reasoning(results, 0.7, 0.9, Verdict.LIKELY_PHISHING)
        assert "70%" in reasoning or "0.7" in reasoning or "70" in reasoning

    def test_reasoning_low_confidence_warning(self, scoring_config):
        """Test warning for low confidence."""
        engine = DecisionEngine(scoring_config)
        results = {}

        reasoning = engine._generate_reasoning(results, 0.5, 0.3, Verdict.SUSPICIOUS)
        # Should include warning about low confidence
        assert "low" in reasoning.lower() or "incomplete" in reasoning.lower() or "confidence" in reasoning.lower()


class TestWeightUpdates:
    """Test runtime weight updates."""

    def test_update_weights(self, scoring_config):
        """Test updating analyzer weights."""
        engine = DecisionEngine(scoring_config)
        new_weights = {
            "header_analysis": 0.15,
            "url_reputation": 0.20,
        }

        engine.update_weights(new_weights)
        assert engine.config.weights["header_analysis"] == 0.15
        assert engine.config.weights["url_reputation"] == 0.20

    def test_update_weights_invalid(self, scoring_config):
        """Test updating with invalid weights."""
        engine = DecisionEngine(scoring_config)

        with pytest.raises(ValueError):
            engine.update_weights({})


class TestThresholdUpdates:
    """Test threshold updates."""

    def test_update_thresholds(self, scoring_config):
        """Test updating verdict thresholds."""
        engine = DecisionEngine(scoring_config)
        new_thresholds = {
            "CLEAN": (0.0, 0.4),
            "SUSPICIOUS": (0.4, 0.6),
            "LIKELY_PHISHING": (0.6, 0.8),
            "CONFIRMED_PHISHING": (0.8, 1.0),
        }

        engine.update_thresholds(new_thresholds)
        # Verify update was applied
        assert engine.config.thresholds["CLEAN"] == (0.0, 0.4)

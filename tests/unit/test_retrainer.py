"""
Unit tests for weight retraining component.

Tests cover:
- WeightRetainer initialization
- retrain_weights() with sample feedback data
- Weight normalization (sum to 1.0)
- Minimum feedback threshold enforcement
- Handling of no feedback data
- Verdict to severity conversion
- Feature array extraction
- Coefficients to weights conversion
"""
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from src.config import PipelineConfig, ScoringConfig
from src.feedback.retrainer import RetrainerConfig, WeightRetainer
from src.models import Verdict


class TestRetrainerConfigConstants:
    """Test RetrainerConfig class constants."""

    def test_min_feedback_for_retrain(self):
        """Test minimum feedback threshold."""
        assert RetrainerConfig.MIN_FEEDBACK_FOR_RETRAIN == 20

    def test_min_total_feedback(self):
        """Test minimum total feedback threshold."""
        assert RetrainerConfig.MIN_TOTAL_FEEDBACK == 50

    def test_target_improvement_pct(self):
        """Test target improvement percentage."""
        assert RetrainerConfig.TARGET_IMPROVEMENT_PCT == 1.0

    def test_cv_folds(self):
        """Test cross-validation folds."""
        assert RetrainerConfig.CV_FOLDS == 5

    def test_max_days_between_retrain(self):
        """Test maximum days between retrains."""
        assert RetrainerConfig.MAX_DAYS_BETWEEN_RETRAIN == 7


class TestWeightRetainerInit:
    """Test WeightRetainer initialization."""

    def test_init_with_config(self):
        """Test initialization with PipelineConfig."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        assert retainer.config == config
        assert retainer.current_weights == config.scoring.weights
        assert retainer.model is None

    def test_init_preserves_weights(self):
        """Test initialization preserves original weights."""
        config = PipelineConfig()
        original_weights = config.scoring.weights.copy()

        retainer = WeightRetainer(config)

        # Weights should be copied, not referenced
        retainer.current_weights["header_analysis"] = 0.0
        assert config.scoring.weights["header_analysis"] != 0.0

    def test_init_creates_scaler(self):
        """Test initialization creates StandardScaler."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        assert retainer.scaler is not None


@pytest.mark.asyncio
class TestRetrainWeights:
    """Test weight retraining functionality."""

    @pytest.fixture
    def config(self):
        """Create test config."""
        return PipelineConfig(
            scoring=ScoringConfig(
                weights={
                    "header_analysis": 0.10,
                    "url_reputation": 0.15,
                    "domain_intelligence": 0.10,
                    "url_detonation": 0.15,
                    "brand_impersonation": 0.10,
                    "attachment_analysis": 0.15,
                    "nlp_intent": 0.15,
                    "sender_profiling": 0.10,
                    "payment_fraud": 0.10,
                }
            )
        )

    async def test_retrain_insufficient_feedback(self, config):
        """Test retrain returns None with insufficient feedback."""
        retainer = WeightRetainer(config)
        mock_session = AsyncMock()

        # Mock query to return empty result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        result = await retainer.retrain_weights(mock_session)

        assert result is None

    async def test_retrain_returns_new_weights(self, config):
        """Test retrain returns new weights dict on success."""
        retainer = WeightRetainer(config)
        mock_session = AsyncMock()

        # Create mock feedback records with mixed classes
        mock_records = []
        for i in range(60):  # More than MIN_TOTAL_FEEDBACK
            record = MagicMock()
            record.feature_vector = json.dumps(
                {
                    "header_risk_score": 0.3 + i * 0.005,
                    "url_reputation_score": 0.5 + i * 0.005,
                    "domain_age_score": 0.2 + i * 0.003,
                    "url_detonation_score": 0.4,
                    "brand_impersonation_score": 0.1,
                    "attachment_risk_score": 0.2,
                    "nlp_intent_score": 0.3,
                    "sender_reputation_score": 0.25,
                    "payment_fraud_score": 0.15,
                }
            )
            # Mix of verdicts to get both classes (target=0 and target=1)
            if i % 2 == 0:
                # correct > original → target=0 (too conservative)
                record.original_verdict = Verdict.SUSPICIOUS.value
                record.correct_label = Verdict.LIKELY_PHISHING.value
            else:
                # correct < original → target=1 (too aggressive)
                record.original_verdict = Verdict.LIKELY_PHISHING.value
                record.correct_label = Verdict.CLEAN.value
            mock_records.append(record)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_records
        mock_session.execute.return_value = mock_result

        result = await retainer.retrain_weights(mock_session)

        assert result is not None
        assert isinstance(result, dict)
        assert len(result) == 9  # 9 analyzers

    async def test_retrain_weights_normalize_to_one(self, config):
        """Test retrained weights sum to approximately 1.0."""
        retainer = WeightRetainer(config)
        mock_session = AsyncMock()

        # Create mock feedback records with mixed classes
        mock_records = []
        for i in range(60):
            record = MagicMock()
            record.feature_vector = json.dumps(
                {
                    "header_risk_score": 0.3 + i * 0.003,
                    "url_reputation_score": 0.5 + i * 0.003,
                    "domain_age_score": 0.2,
                    "url_detonation_score": 0.4,
                    "brand_impersonation_score": 0.1,
                    "attachment_risk_score": 0.2,
                    "nlp_intent_score": 0.3,
                    "sender_reputation_score": 0.25,
                    "payment_fraud_score": 0.15,
                }
            )
            if i % 2 == 0:
                record.original_verdict = Verdict.SUSPICIOUS.value
                record.correct_label = Verdict.LIKELY_PHISHING.value
            else:
                record.original_verdict = Verdict.LIKELY_PHISHING.value
                record.correct_label = Verdict.CLEAN.value
            mock_records.append(record)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_records
        mock_session.execute.return_value = mock_result

        result = await retainer.retrain_weights(mock_session)

        if result:
            weight_sum = sum(result.values())
            assert abs(weight_sum - 1.0) < 0.001  # Should sum to 1.0

    async def test_retrain_skips_matching_verdicts(self, config):
        """Test retrain skips records where verdict matches."""
        retainer = WeightRetainer(config)
        mock_session = AsyncMock()

        # Create records where verdict matches (should be skipped)
        mock_records = []
        for i in range(60):
            record = MagicMock()
            record.feature_vector = json.dumps(
                {
                    "header_risk_score": 0.3,
                    "url_reputation_score": 0.5,
                    "domain_age_score": 0.2,
                    "url_detonation_score": 0.4,
                    "brand_impersonation_score": 0.1,
                    "attachment_risk_score": 0.2,
                    "nlp_intent_score": 0.3,
                    "sender_reputation_score": 0.25,
                    "payment_fraud_score": 0.15,
                }
            )
            # Same verdict - should be skipped
            record.original_verdict = Verdict.CLEAN.value
            record.correct_label = Verdict.CLEAN.value
            mock_records.append(record)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_records
        mock_session.execute.return_value = mock_result

        result = await retainer.retrain_weights(mock_session)

        # Should return None due to insufficient valid samples
        assert result is None

    async def test_retrain_handles_malformed_features(self, config):
        """Test retrain handles malformed feature vectors."""
        retainer = WeightRetainer(config)
        mock_session = AsyncMock()

        mock_records = []
        # Add record with invalid JSON
        record = MagicMock()
        record.feature_vector = "invalid json{"
        record.original_verdict = Verdict.SUSPICIOUS.value
        record.correct_label = Verdict.LIKELY_PHISHING.value
        mock_records.append(record)

        # Add valid records to reach threshold
        for i in range(60):
            record = MagicMock()
            record.feature_vector = json.dumps(
                {
                    "header_risk_score": 0.3,
                    "url_reputation_score": 0.5,
                    "domain_age_score": 0.2,
                    "url_detonation_score": 0.4,
                    "brand_impersonation_score": 0.1,
                    "attachment_risk_score": 0.2,
                    "nlp_intent_score": 0.3,
                    "sender_reputation_score": 0.25,
                    "payment_fraud_score": 0.15,
                }
            )
            record.original_verdict = Verdict.SUSPICIOUS.value
            record.correct_label = Verdict.LIKELY_PHISHING.value
            mock_records.append(record)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_records
        mock_session.execute.return_value = mock_result

        # Should not raise exception
        result = await retainer.retrain_weights(mock_session)
        # Should handle gracefully


class TestVerdictToSeverity:
    """Test verdict to severity conversion."""

    def test_severity_clean(self):
        """Test CLEAN verdict maps to 0."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        severity = retainer._verdict_to_severity(Verdict.CLEAN.value)
        assert severity == 0

    def test_severity_suspicious(self):
        """Test SUSPICIOUS verdict maps to 1."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        severity = retainer._verdict_to_severity(Verdict.SUSPICIOUS.value)
        assert severity == 1

    def test_severity_likely_phishing(self):
        """Test LIKELY_PHISHING verdict maps to 2."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        severity = retainer._verdict_to_severity(Verdict.LIKELY_PHISHING.value)
        assert severity == 2

    def test_severity_confirmed_phishing(self):
        """Test CONFIRMED_PHISHING verdict maps to 3."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        severity = retainer._verdict_to_severity(Verdict.CONFIRMED_PHISHING.value)
        assert severity == 3

    def test_severity_unknown_verdict(self):
        """Test unknown verdict maps to default (1)."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        severity = retainer._verdict_to_severity("UNKNOWN")
        assert severity == 1


class TestExtractFeatureArray:
    """Test feature array extraction."""

    def test_extract_valid_features(self):
        """Test extraction of valid feature dictionary."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        features = {
            "header_risk_score": 0.3,
            "url_reputation_score": 0.5,
            "domain_age_score": 0.2,
            "url_detonation_score": 0.4,
            "brand_impersonation_score": 0.1,
            "attachment_risk_score": 0.2,
            "nlp_intent_score": 0.3,
            "sender_reputation_score": 0.25,
            "payment_fraud_score": 0.15,
        }

        array = retainer._extract_feature_array(features)

        assert array is not None
        assert len(array) == 9
        assert all(isinstance(x, float) for x in array)

    def test_extract_missing_features(self):
        """Test extraction handles missing features with defaults."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        features = {
            "header_risk_score": 0.3,
            # Missing other features
        }

        array = retainer._extract_feature_array(features)

        assert array is not None
        # Should use 0.0 for missing features
        assert array[0] == 0.3

    def test_extract_non_numeric_features(self):
        """Test extraction returns None with non-numeric features."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        features = {
            "header_risk_score": "not_a_number",
            "url_reputation_score": 0.5,
            "domain_age_score": 0.2,
            "url_detonation_score": 0.4,
            "brand_impersonation_score": 0.1,
            "attachment_risk_score": 0.2,
            "nlp_intent_score": 0.3,
            "sender_reputation_score": 0.25,
            "payment_fraud_score": 0.15,
        }

        array = retainer._extract_feature_array(features)

        assert array is None

    def test_extract_preserves_order(self):
        """Test extracted features maintain expected order."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        features = {
            "header_risk_score": 0.1,
            "url_reputation_score": 0.2,
            "domain_age_score": 0.3,
            "url_detonation_score": 0.4,
            "brand_impersonation_score": 0.5,
            "attachment_risk_score": 0.6,
            "nlp_intent_score": 0.7,
            "sender_reputation_score": 0.8,
            "payment_fraud_score": 0.9,
        }

        array = retainer._extract_feature_array(features)

        assert array[0] == 0.1  # header_risk_score first
        assert array[1] == 0.2  # url_reputation_score second
        assert array[-2] == 0.8  # sender_reputation_score before payment_fraud_score
        assert array[-1] == 0.9  # payment_fraud_score last


class TestCoefficientsToWeights:
    """Test conversion of model coefficients to weights."""

    def test_coefficients_normalize_to_one(self):
        """Test normalized weights sum to 1.0."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        coefficients = np.array([0.5, 0.3, 0.2, 0.1, 0.4, 0.6, 0.2, 0.3, 0.7])
        weights = retainer._coefficients_to_weights(coefficients)

        weight_sum = sum(weights.values())
        assert abs(weight_sum - 1.0) < 0.0001

    def test_coefficients_returns_dict(self):
        """Test conversion returns dictionary."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        coefficients = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
        weights = retainer._coefficients_to_weights(coefficients)

        assert isinstance(weights, dict)
        assert len(weights) == 9

    def test_coefficients_all_analyzer_names(self):
        """Test all analyzer names are in result."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        coefficients = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
        weights = retainer._coefficients_to_weights(coefficients)

        expected_analyzers = [
            "header_analysis",
            "url_reputation",
            "domain_intelligence",
            "url_detonation",
            "brand_impersonation",
            "attachment_analysis",
            "nlp_intent",
            "sender_profiling",
            "payment_fraud",
        ]

        for analyzer in expected_analyzers:
            assert analyzer in weights

    def test_coefficients_handles_negative_values(self):
        """Test conversion handles negative coefficients."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        # Include negative coefficients
        coefficients = np.array([-0.5, 0.3, -0.2, 0.1, 0.4, 0.6, 0.2, 0.3, -0.7])
        weights = retainer._coefficients_to_weights(coefficients)

        # All weights should be positive
        assert all(w >= 0 for w in weights.values())
        # Should still sum to 1.0
        weight_sum = sum(weights.values())
        assert abs(weight_sum - 1.0) < 0.0001


class TestWeightRetainerIntegration:
    """Integration tests for weight retrainer."""

    def test_retainer_workflow(self):
        """Test complete retainer workflow."""
        config = PipelineConfig()
        retainer = WeightRetainer(config)

        # Check initial state
        assert retainer.current_weights is not None
        assert len(retainer.current_weights) == 9

        # Check scaler exists
        assert retainer.scaler is not None

        # Check model starts as None
        assert retainer.model is None

    def test_multiple_retrainers_independent(self):
        """Test multiple retrainer instances are independent."""
        config1 = PipelineConfig()
        config2 = PipelineConfig()

        retainer1 = WeightRetainer(config1)
        retainer2 = WeightRetainer(config2)

        # Modify one shouldn't affect the other
        retainer1.current_weights["header_analysis"] = 0.99
        assert retainer2.current_weights["header_analysis"] != 0.99

"""
Test suite for scoring utilities in src.scoring.confidence and thresholds modules.

Tests:
- Confidence calculation methods
- Threshold validation and management
- Verdict mapping
- Score-to-verdict translation
"""

import pytest
from src.scoring.confidence import ConfidenceCalculator
from src.scoring.thresholds import ThresholdManager, ThresholdRange
from src.models import Verdict


class TestConfidenceCalculation:
    """Test confidence calculation methods."""

    def test_detection_confidence_all_detected(self):
        """Test confidence when all sources detect."""
        conf = ConfidenceCalculator.calculate_detection_confidence(10, 10)
        assert conf == 1.0

    def test_detection_confidence_half_detected(self):
        """Test confidence when half detect."""
        conf = ConfidenceCalculator.calculate_detection_confidence(5, 10)
        assert conf == 0.5

    def test_detection_confidence_none_detected(self):
        """Test confidence when none detect."""
        conf = ConfidenceCalculator.calculate_detection_confidence(0, 10)
        assert conf == 0.0

    def test_detection_confidence_zero_total(self):
        """Test detection confidence with zero sources."""
        conf = ConfidenceCalculator.calculate_detection_confidence(0, 0)
        assert conf == 0.0

    def test_data_completeness_confidence_full(self):
        """Test data completeness when all fields present."""
        conf = ConfidenceCalculator.calculate_data_completeness_confidence(8, 8)
        assert conf == 1.0

    def test_data_completeness_confidence_partial(self):
        """Test data completeness with missing fields."""
        conf = ConfidenceCalculator.calculate_data_completeness_confidence(6, 8)
        assert conf == 0.75

    def test_data_completeness_confidence_none(self):
        """Test data completeness with no fields."""
        conf = ConfidenceCalculator.calculate_data_completeness_confidence(0, 8)
        assert conf == 0.0

    def test_signal_strength_confidence_strong(self):
        """Test signal strength confidence for strong signal."""
        conf = ConfidenceCalculator.calculate_signal_strength_confidence(0.9)
        assert conf == 0.9

    def test_signal_strength_confidence_weak_below_threshold(self):
        """Test signal strength confidence for weak signal."""
        conf = ConfidenceCalculator.calculate_signal_strength_confidence(0.2)
        assert conf == 0.0

    def test_signal_strength_confidence_at_threshold(self):
        """Test signal strength confidence at threshold."""
        conf = ConfidenceCalculator.calculate_signal_strength_confidence(0.3)
        assert conf == 0.3

    def test_temporal_confidence_fresh(self):
        """Test temporal confidence for fresh data."""
        conf = ConfidenceCalculator.calculate_temporal_confidence(3600)  # 1 hour old
        assert conf == 1.0

    def test_temporal_confidence_recent(self):
        """Test temporal confidence for recent data."""
        conf = ConfidenceCalculator.calculate_temporal_confidence(43200)  # 12 hours old
        assert 0.5 <= conf <= 1.0

    def test_temporal_confidence_stale(self):
        """Test temporal confidence for stale data."""
        conf = ConfidenceCalculator.calculate_temporal_confidence(2592000 + 1)  # 30 days + 1 sec
        assert conf == 0.0

    def test_aggregate_confidence_equal_weights(self):
        """Test aggregating confidence with equal weights."""
        scores = [0.8, 0.9, 0.7]
        conf = ConfidenceCalculator.aggregate_confidence_scores(
            scores,
            aggregation_method="weighted_average"
        )
        assert conf == pytest.approx(0.8)

    def test_aggregate_confidence_custom_weights(self):
        """Test aggregating confidence with custom weights."""
        scores = [0.8, 0.9]
        weights = [0.7, 0.3]
        conf = ConfidenceCalculator.aggregate_confidence_scores(
            scores,
            weights=weights,
            aggregation_method="weighted_average"
        )
        assert conf > 0.8

    def test_aggregate_confidence_max(self):
        """Test max aggregation method."""
        scores = [0.5, 0.8, 0.6]
        conf = ConfidenceCalculator.aggregate_confidence_scores(
            scores,
            aggregation_method="max"
        )
        assert conf == 0.8

    def test_aggregate_confidence_min(self):
        """Test min aggregation method."""
        scores = [0.5, 0.8, 0.6]
        conf = ConfidenceCalculator.aggregate_confidence_scores(
            scores,
            aggregation_method="min"
        )
        assert conf == 0.5

    def test_aggregate_confidence_geometric_mean(self):
        """Test geometric mean aggregation."""
        scores = [0.8, 0.9]
        conf = ConfidenceCalculator.aggregate_confidence_scores(
            scores,
            aggregation_method="geometric_mean"
        )
        assert 0.8 <= conf <= 0.9

    def test_aggregate_confidence_empty(self):
        """Test aggregating empty confidence list."""
        conf = ConfidenceCalculator.aggregate_confidence_scores([])
        assert conf == 0.0

    def test_penalize_missing_data(self):
        """Test confidence penalty for missing data."""
        conf = ConfidenceCalculator.penalize_missing_data(0.9, data_missing=True, penalty=0.3)
        assert conf == pytest.approx(0.63)

    def test_penalize_missing_data_no_penalty(self):
        """Test no penalty when data present."""
        conf = ConfidenceCalculator.penalize_missing_data(0.9, data_missing=False)
        assert conf == 0.9

    def test_boost_confidence_with_corroboration(self):
        """Test confidence boost from corroborating signals."""
        conf = ConfidenceCalculator.boost_confidence_with_corroboration(
            0.7,
            [0.8, 0.85],
            boost_factor=0.15
        )
        assert conf > 0.7
        assert conf <= 1.0


class TestThresholdRange:
    """Test ThresholdRange validation and operations."""

    def test_threshold_range_creation(self):
        """Test creating threshold range."""
        tr = ThresholdRange(Verdict.CLEAN, 0.0, 0.3)
        assert tr.verdict == Verdict.CLEAN
        assert tr.min_score == 0.0
        assert tr.max_score == 0.3

    def test_threshold_range_contains_score(self):
        """Test score containment check."""
        tr = ThresholdRange(Verdict.CLEAN, 0.0, 0.3)
        assert tr.contains(0.1) is True
        assert tr.contains(0.3) is False
        assert tr.contains(0.5) is False

    def test_threshold_range_boundary_distance(self):
        """Test distance calculation from boundaries."""
        tr = ThresholdRange(Verdict.SUSPICIOUS, 0.3, 0.6)
        # At center of range (0.45)
        distance = tr.distance_from_boundary(0.45)
        assert distance > 0

    def test_threshold_range_invalid_bounds(self):
        """Test validation of invalid bounds."""
        with pytest.raises(ValueError):
            ThresholdRange(Verdict.CLEAN, 0.5, 0.3)  # min > max

    def test_threshold_range_out_of_range(self):
        """Test validation of out-of-range scores."""
        with pytest.raises(ValueError):
            ThresholdRange(Verdict.CLEAN, 1.5, 2.0)  # > 1.0


class TestThresholdManager:
    """Test threshold management."""

    def test_threshold_manager_initialization_default(self):
        """Test initialization with default thresholds."""
        manager = ThresholdManager()
        assert manager is not None
        assert len(manager.thresholds) == 4

    def test_threshold_manager_initialization_custom(self):
        """Test initialization with custom thresholds."""
        custom = {
            "CLEAN": (0.0, 0.4),
            "SUSPICIOUS": (0.4, 0.6),
            "LIKELY_PHISHING": (0.6, 0.8),
            "CONFIRMED_PHISHING": (0.8, 1.0),
        }
        manager = ThresholdManager(custom)
        assert manager.thresholds[Verdict.CLEAN] == (0.0, 0.4)

    def test_verdict_mapping_clean(self):
        """Test verdict mapping for clean score."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(0.1)
        assert verdict == Verdict.CLEAN

    def test_verdict_mapping_suspicious(self):
        """Test verdict mapping for suspicious score."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(0.45)
        assert verdict == Verdict.SUSPICIOUS

    def test_verdict_mapping_likely_phishing(self):
        """Test verdict mapping for likely phishing score."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(0.7)
        assert verdict == Verdict.LIKELY_PHISHING

    def test_verdict_mapping_confirmed_phishing(self):
        """Test verdict mapping for confirmed phishing score."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(0.9)
        assert verdict == Verdict.CONFIRMED_PHISHING

    def test_verdict_mapping_boundary_clean_suspicious(self):
        """Test verdict at boundary between CLEAN and SUSPICIOUS."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(0.3)
        assert verdict == Verdict.SUSPICIOUS

    def test_verdict_mapping_boundary_max(self):
        """Test verdict at maximum score."""
        manager = ThresholdManager()
        verdict = manager.get_verdict(1.0)
        assert verdict == Verdict.CONFIRMED_PHISHING

    def test_verdict_mapping_invalid_score(self):
        """Test error on invalid score."""
        manager = ThresholdManager()
        with pytest.raises(ValueError):
            manager.get_verdict(1.5)

    def test_threshold_for_verdict(self):
        """Test retrieving threshold for verdict."""
        manager = ThresholdManager()
        min_score, max_score = manager.get_threshold_for_verdict(Verdict.SUSPICIOUS)
        assert min_score == 0.3
        assert max_score == 0.6

    def test_is_score_near_boundary(self):
        """Test detection of scores near boundaries."""
        manager = ThresholdManager()
        # Score near boundary
        is_near = manager.is_score_near_boundary(0.31, boundary_threshold=0.05)
        assert is_near is True

    def test_is_score_not_near_boundary(self):
        """Test detection when score not near boundary."""
        manager = ThresholdManager()
        # Score away from boundary
        is_near = manager.is_score_near_boundary(0.5, boundary_threshold=0.05)
        assert is_near is False

    def test_map_to_safe_verdict_uncapped(self):
        """Test safe verdict mapping without cap."""
        manager = ThresholdManager()
        verdict = manager.map_to_safe_verdict(0.7, enforce_upper_cap=False)
        assert verdict == Verdict.LIKELY_PHISHING

    def test_map_to_safe_verdict_capped(self):
        """Test safe verdict mapping with cap."""
        manager = ThresholdManager()
        verdict = manager.map_to_safe_verdict(
            0.9,
            enforce_upper_cap=True,
            cap_verdict=Verdict.SUSPICIOUS
        )
        assert verdict == Verdict.SUSPICIOUS

    def test_get_all_verdicts(self):
        """Test getting all configured verdicts."""
        manager = ThresholdManager()
        verdicts = manager.get_all_verdicts()
        assert len(verdicts) == 4
        assert Verdict.CLEAN in verdicts

    def test_threshold_width(self):
        """Test getting threshold width."""
        manager = ThresholdManager()
        width = manager.get_threshold_width(Verdict.CLEAN)
        assert width == 0.3

    def test_update_thresholds_runtime(self):
        """Test updating thresholds at runtime."""
        manager = ThresholdManager()
        new_thresholds = {
            "CLEAN": (0.0, 0.25),
            "SUSPICIOUS": (0.25, 0.65),
            "LIKELY_PHISHING": (0.65, 0.85),
            "CONFIRMED_PHISHING": (0.85, 1.0),
        }
        manager.update_thresholds(new_thresholds)
        min_score, max_score = manager.get_threshold_for_verdict(Verdict.CLEAN)
        assert min_score == 0.0
        assert max_score == 0.25

    def test_threshold_validation_gaps(self):
        """Test validation detects gaps in thresholds."""
        invalid = {
            "CLEAN": (0.0, 0.3),
            "SUSPICIOUS": (0.4, 0.6),  # Gap from 0.3 to 0.4
            "LIKELY_PHISHING": (0.6, 0.8),
            "CONFIRMED_PHISHING": (0.8, 1.0),
        }
        with pytest.raises(ValueError):
            ThresholdManager(invalid)

    def test_config_dict_export(self):
        """Test exporting config as dict."""
        manager = ThresholdManager()
        config = manager.get_config_dict()
        assert "CLEAN" in config
        assert config["CLEAN"] == (0.0, 0.3)

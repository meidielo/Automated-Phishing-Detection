"""
Confidence calculation utilities for the phishing detection pipeline.

Provides methods to calculate and aggregate confidence scores across different
signal types and analyzer results. Confidence represents the certainty level
of a signal or decision, ranging from 0.0 (no data/uncertain) to 1.0 (certain).
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ConfidenceCalculator:
    """
    Calculate confidence scores for analyzer results and aggregate confidence
    across multiple signals.

    Confidence represents the reliability and certainty of a signal:
    - 0.0: No data or completely uncertain
    - 0.5: Moderate confidence / partial data
    - 1.0: High certainty / complete and reliable data
    """

    @staticmethod
    def calculate_detection_confidence(
        detected_count: int,
        total_count: int,
        base_confidence: float = 1.0,
    ) -> float:
        """
        Calculate confidence based on detection ratio.

        Used for consensus-based analysis (e.g., how many threat intelligence
        vendors flagged a URL as malicious).

        Args:
            detected_count: Number of positive detections
            total_count: Total number of sources/vendors
            base_confidence: Base confidence multiplier (0.0-1.0)

        Returns:
            Confidence score (0.0-1.0)

        Examples:
            - 10/10 vendors flagged → 1.0 confidence
            - 5/10 vendors flagged → 0.5 confidence
            - 0/10 vendors flagged → 0.0 confidence
        """
        if total_count == 0:
            return 0.0

        ratio = detected_count / total_count
        return min(ratio * base_confidence, 1.0)

    @staticmethod
    def calculate_data_completeness_confidence(
        fields_present: int,
        total_fields: int,
    ) -> float:
        """
        Calculate confidence based on data completeness.

        Used when confidence depends on having complete information
        (e.g., email headers with all required authentication fields).

        Args:
            fields_present: Number of required fields present
            total_fields: Total number of required fields

        Returns:
            Confidence score (0.0-1.0)

        Examples:
            - All headers present: 8/8 → 1.0
            - Missing some headers: 6/8 → 0.75
            - No headers: 0/8 → 0.0
        """
        if total_fields == 0:
            return 0.0

        return fields_present / total_fields

    @staticmethod
    def calculate_signal_strength_confidence(
        signal_strength: float,
        min_threshold: float = 0.3,
    ) -> float:
        """
        Calculate confidence based on signal strength.

        Used when confidence correlates with the magnitude of a signal.
        Weak signals have lower confidence, strong signals have higher confidence.

        Args:
            signal_strength: Normalized signal strength (0.0-1.0)
            min_threshold: Below this strength, return 0.0 confidence

        Returns:
            Confidence score (0.0-1.0)

        Examples:
            - Strong signal (0.9) → 0.9 confidence
            - Weak signal (0.1) below threshold → 0.0 confidence
            - Moderate signal (0.5) → 0.5 confidence
        """
        if signal_strength < min_threshold:
            return 0.0

        # Map signal strength to confidence linearly above threshold
        return min(signal_strength, 1.0)

    @staticmethod
    def calculate_temporal_confidence(
        data_age_seconds: float,
        freshness_threshold_seconds: float = 86400,  # 24 hours
        staleness_threshold_seconds: float = 2592000,  # 30 days
    ) -> float:
        """
        Calculate confidence based on data freshness.

        Recent data has higher confidence than stale data.

        Args:
            data_age_seconds: Age of data in seconds
            freshness_threshold_seconds: Data younger than this is fully fresh
            staleness_threshold_seconds: Data older than this is stale (confidence=0.0)

        Returns:
            Confidence score (0.0-1.0)

        Examples:
            - Fresh data (< 1 hour old) → 1.0 confidence
            - Recent data (< 24 hours) → 0.8+ confidence
            - Old data (> 30 days) → 0.0 confidence
        """
        if data_age_seconds <= freshness_threshold_seconds:
            return 1.0

        if data_age_seconds >= staleness_threshold_seconds:
            return 0.0

        # Linear decay between thresholds
        age_range = staleness_threshold_seconds - freshness_threshold_seconds
        age_in_range = data_age_seconds - freshness_threshold_seconds
        confidence = 1.0 - (age_in_range / age_range)
        return max(confidence, 0.0)

    @staticmethod
    def aggregate_confidence_scores(
        confidence_scores: list[float],
        weights: Optional[list[float]] = None,
        aggregation_method: str = "weighted_average",
    ) -> float:
        """
        Aggregate multiple confidence scores into a single value.

        Args:
            confidence_scores: List of individual confidence scores
            weights: Optional weights for each score. If None, equal weights used.
            aggregation_method: Method for aggregation:
                - "weighted_average": Weighted average of scores
                - "max": Maximum confidence (most optimistic)
                - "min": Minimum confidence (most conservative)
                - "geometric_mean": Geometric mean of scores

        Returns:
            Aggregated confidence score (0.0-1.0)

        Raises:
            ValueError: If aggregation_method is invalid or weights don't match scores

        Examples:
            - [0.8, 0.9, 0.7] with equal weights → 0.8 (average)
            - [0.8, 0.9, 0.7] with max → 0.9
            - [0.8, 0.9, 0.7] with min → 0.7
        """
        if not confidence_scores:
            return 0.0

        if weights is None:
            weights = [1.0 / len(confidence_scores)] * len(confidence_scores)

        if len(weights) != len(confidence_scores):
            raise ValueError(
                f"Weights length ({len(weights)}) must match "
                f"confidence_scores length ({len(confidence_scores)})"
            )

        # Normalize weights
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        normalized_weights = [w / total_weight for w in weights]

        if aggregation_method == "weighted_average":
            return sum(
                conf * weight
                for conf, weight in zip(confidence_scores, normalized_weights)
            )

        elif aggregation_method == "max":
            return max(confidence_scores)

        elif aggregation_method == "min":
            return min(confidence_scores)

        elif aggregation_method == "geometric_mean":
            # Geometric mean: (product of all scores) ^ (1/n)
            product = 1.0
            for conf in confidence_scores:
                product *= conf
            if product == 0:
                return 0.0
            return product ** (1.0 / len(confidence_scores))

        else:
            raise ValueError(
                f"Unknown aggregation_method: {aggregation_method}. "
                f"Must be one of: weighted_average, max, min, geometric_mean"
            )

    @staticmethod
    def penalize_missing_data(
        confidence: float,
        data_missing: bool,
        penalty: float = 0.3,
    ) -> float:
        """
        Reduce confidence when critical data is missing.

        Args:
            confidence: Original confidence score
            data_missing: Whether critical data is missing
            penalty: Confidence reduction (0.0-1.0)

        Returns:
            Adjusted confidence score

        Examples:
            - confidence=0.9 with missing data and penalty=0.3 → 0.63
            - confidence=0.9 with data present → 0.9 (no change)
        """
        if not data_missing:
            return confidence

        penalty = min(max(penalty, 0.0), 1.0)  # Clamp to [0, 1]
        return confidence * (1.0 - penalty)

    @staticmethod
    def boost_confidence_with_corroboration(
        base_confidence: float,
        corroborating_scores: list[float],
        boost_factor: float = 0.15,
    ) -> float:
        """
        Increase confidence when multiple independent signals agree.

        Args:
            base_confidence: Original confidence score
            corroborating_scores: Confidence scores from other independent signals
            boost_factor: Maximum additional confidence from corroboration (0.0-0.5)

        Returns:
            Boosted confidence score (capped at 1.0)

        Examples:
            - Base 0.7 + agreement from 2 signals → 0.8+ confidence
            - Base 0.7 + no agreement → 0.7 (no boost)
        """
        if not corroborating_scores:
            return base_confidence

        # Boost based on average corroborating confidence
        corroboration_strength = sum(corroborating_scores) / len(corroborating_scores)
        boost = corroboration_strength * boost_factor

        return min(base_confidence + boost, 1.0)

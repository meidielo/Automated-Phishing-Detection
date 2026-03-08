"""
Configurable threshold management for phishing detection verdicts.

Provides threshold definitions, verdict mapping, and threshold validation
for the decision engine. Thresholds determine which risk score range maps
to which verdict classification.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from src.models import Verdict

logger = logging.getLogger(__name__)


@dataclass
class ThresholdRange:
    """Represents a threshold range for a verdict."""

    verdict: Verdict
    min_score: float
    max_score: float

    def __post_init__(self):
        """Validate threshold range."""
        if not (0.0 <= self.min_score <= 1.0):
            raise ValueError(
                f"min_score must be in [0.0, 1.0], got {self.min_score}"
            )
        if not (0.0 <= self.max_score <= 1.0):
            raise ValueError(
                f"max_score must be in [0.0, 1.0], got {self.max_score}"
            )
        if self.min_score > self.max_score:
            raise ValueError(
                f"min_score ({self.min_score}) cannot be greater than "
                f"max_score ({self.max_score})"
            )

    def contains(self, score: float) -> bool:
        """
        Check if score falls within this threshold range.

        Args:
            score: Score to check

        Returns:
            True if min_score <= score < max_score
        """
        return self.min_score <= score < self.max_score

    def distance_from_boundary(self, score: float) -> float:
        """
        Calculate distance from nearest boundary.

        Positive value indicates how far into the range the score is.
        Used to assess confidence when score is near a threshold boundary.

        Args:
            score: Score to evaluate

        Returns:
            Distance from nearest boundary (0.0 at boundary, up to range_width at center)
        """
        if score < self.min_score:
            return self.min_score - score  # Below range
        if score >= self.max_score:
            return score - self.max_score  # Above range

        # Within range - distance from nearest boundary
        distance_from_min = score - self.min_score
        distance_from_max = self.max_score - score
        return min(distance_from_min, distance_from_max)


class ThresholdManager:
    """
    Manage verdict thresholds and provide threshold-based verdict mapping.

    Standard thresholds:
    - CLEAN: 0.0 - 0.3 (low risk)
    - SUSPICIOUS: 0.3 - 0.6 (moderate risk)
    - LIKELY_PHISHING: 0.6 - 0.8 (high risk)
    - CONFIRMED_PHISHING: 0.8 - 1.0 (very high risk)
    """

    STANDARD_THRESHOLDS = {
        Verdict.CLEAN: (0.0, 0.3),
        Verdict.SUSPICIOUS: (0.3, 0.6),
        Verdict.LIKELY_PHISHING: (0.6, 0.8),
        Verdict.CONFIRMED_PHISHING: (0.8, 1.0),
    }

    def __init__(self, thresholds: Optional[dict[str, Tuple[float, float]]] = None):
        """
        Initialize threshold manager with optional custom thresholds.

        Args:
            thresholds: Dict mapping verdict names to (min, max) tuples.
                       If None, uses standard thresholds.

        Raises:
            ValueError: If thresholds are invalid or incomplete
        """
        if thresholds is None:
            thresholds = self.STANDARD_THRESHOLDS
        else:
            # Convert string keys to Verdict enum
            converted_thresholds = {}
            for key, value in thresholds.items():
                if isinstance(key, str):
                    try:
                        verdict = Verdict[key]
                    except KeyError:
                        raise ValueError(f"Unknown verdict: {key}")
                else:
                    verdict = key
                converted_thresholds[verdict] = value
            thresholds = converted_thresholds

        self._validate_thresholds(thresholds)
        self.thresholds = thresholds
        self._build_ranges()

    def _validate_thresholds(self, thresholds: dict[Verdict, Tuple[float, float]]):
        """
        Validate that thresholds are valid and cover the full range [0.0, 1.0].

        Args:
            thresholds: Thresholds to validate

        Raises:
            ValueError: If thresholds are invalid
        """
        if not thresholds:
            raise ValueError("Thresholds cannot be empty")

        # Create ranges and validate
        ranges = []
        for verdict, (min_score, max_score) in thresholds.items():
            try:
                range_obj = ThresholdRange(verdict, min_score, max_score)
                ranges.append(range_obj)
            except ValueError as e:
                raise ValueError(f"Invalid threshold for {verdict}: {e}")

        # Sort by min_score
        ranges.sort(key=lambda r: r.min_score)

        # Check for gaps and overlaps
        for i in range(len(ranges) - 1):
            current_max = ranges[i].max_score
            next_min = ranges[i + 1].min_score

            if current_max != next_min:
                raise ValueError(
                    f"Gap or overlap detected: {ranges[i].verdict} ends at "
                    f"{current_max}, but {ranges[i + 1].verdict} starts at {next_min}"
                )

        # Check coverage
        if ranges[0].min_score > 0.0:
            raise ValueError(f"Thresholds don't start at 0.0 (start at {ranges[0].min_score})")

        if ranges[-1].max_score < 1.0:
            raise ValueError(f"Thresholds don't end at 1.0 (end at {ranges[-1].max_score})")

    def _build_ranges(self):
        """Build sorted threshold ranges from thresholds dict."""
        self.ranges = []
        for verdict, (min_score, max_score) in self.thresholds.items():
            self.ranges.append(ThresholdRange(verdict, min_score, max_score))

        # Sort by min_score for efficient lookup
        self.ranges.sort(key=lambda r: r.min_score)

    def get_verdict(self, score: float) -> Verdict:
        """
        Map a risk score to a verdict based on thresholds.

        Args:
            score: Risk score (0.0-1.0)

        Returns:
            Verdict corresponding to the score

        Raises:
            ValueError: If score is out of range [0.0, 1.0]
        """
        if not (0.0 <= score <= 1.0):
            raise ValueError(f"Score must be in [0.0, 1.0], got {score}")

        # Handle edge case: score exactly at upper boundary gets clamped to just below
        if score == 1.0:
            return self.ranges[-1].verdict

        for threshold_range in self.ranges:
            if threshold_range.contains(score):
                return threshold_range.verdict

        # Should not reach here if validation was correct
        logger.error(f"Score {score} does not fall within any threshold")
        return Verdict.SUSPICIOUS  # Safe default

    def get_threshold_for_verdict(self, verdict: Verdict) -> Tuple[float, float]:
        """
        Get min and max thresholds for a verdict.

        Args:
            verdict: Verdict to query

        Returns:
            Tuple of (min_score, max_score)

        Raises:
            ValueError: If verdict not found
        """
        if verdict not in self.thresholds:
            raise ValueError(f"Unknown verdict: {verdict}")
        return self.thresholds[verdict]

    def get_verdict_range(self, verdict: Verdict) -> ThresholdRange:
        """
        Get ThresholdRange object for a verdict.

        Args:
            verdict: Verdict to query

        Returns:
            ThresholdRange object

        Raises:
            ValueError: If verdict not found
        """
        for threshold_range in self.ranges:
            if threshold_range.verdict == verdict:
                return threshold_range
        raise ValueError(f"Unknown verdict: {verdict}")

    def is_score_near_boundary(
        self,
        score: float,
        boundary_threshold: float = 0.05,
    ) -> bool:
        """
        Check if a score is near a verdict boundary.

        Useful for identifying cases where verdict is uncertain.

        Args:
            score: Risk score to check
            boundary_threshold: How close to boundary (default 0.05 = within 5%)

        Returns:
            True if score is within boundary_threshold of any verdict boundary
        """
        # Find which range the score belongs to
        for threshold_range in self.ranges:
            if threshold_range.min_score <= score < threshold_range.max_score:
                distance = threshold_range.distance_from_boundary(score)
                return distance < boundary_threshold

        return False

    def map_to_safe_verdict(
        self,
        score: float,
        enforce_upper_cap: bool = False,
        cap_verdict: Verdict = Verdict.SUSPICIOUS,
    ) -> Verdict:
        """
        Map score to verdict with optional upper cap.

        Used when overall confidence is low - returns at most cap_verdict.

        Args:
            score: Risk score to map
            enforce_upper_cap: If True, verdict cannot exceed cap_verdict
            cap_verdict: Maximum verdict to return if enforce_upper_cap is True

        Returns:
            Verdict, possibly capped
        """
        verdict = self.get_verdict(score)

        if not enforce_upper_cap:
            return verdict

        # Compare verdicts by severity
        verdict_order = [
            Verdict.CLEAN,
            Verdict.SUSPICIOUS,
            Verdict.LIKELY_PHISHING,
            Verdict.CONFIRMED_PHISHING,
        ]

        verdict_index = verdict_order.index(verdict)
        cap_index = verdict_order.index(cap_verdict)

        if verdict_index > cap_index:
            logger.debug(
                f"Capping verdict from {verdict} to {cap_verdict} due to low confidence"
            )
            return cap_verdict

        return verdict

    def get_all_verdicts(self) -> list[Verdict]:
        """
        Get all configured verdicts in severity order (lowest to highest).

        Returns:
            List of verdicts ordered by severity
        """
        return [r.verdict for r in self.ranges]

    def get_threshold_width(self, verdict: Verdict) -> float:
        """
        Get the width of the threshold range for a verdict.

        Wider ranges are more forgiving; narrow ranges are more strict.

        Args:
            verdict: Verdict to query

        Returns:
            Width of the threshold range (max - min)
        """
        min_score, max_score = self.get_threshold_for_verdict(verdict)
        return max_score - min_score

    def update_thresholds(
        self,
        new_thresholds: dict[str, Tuple[float, float]],
    ):
        """
        Update thresholds at runtime.

        Args:
            new_thresholds: Dict mapping verdict names to (min, max) tuples

        Raises:
            ValueError: If new thresholds are invalid
        """
        # Convert string keys to Verdict enum
        converted_thresholds = {}
        for key, value in new_thresholds.items():
            if isinstance(key, str):
                try:
                    verdict = Verdict[key]
                except KeyError:
                    raise ValueError(f"Unknown verdict: {key}")
            else:
                verdict = key
            converted_thresholds[verdict] = value

        # Validate before updating
        self._validate_thresholds(converted_thresholds)

        self.thresholds = converted_thresholds
        self._build_ranges()
        logger.info(f"Thresholds updated: {self.thresholds}")

    def get_config_dict(self) -> dict[str, Tuple[float, float]]:
        """
        Export current thresholds as dict (string keys for serialization).

        Returns:
            Dict mapping verdict names (strings) to (min, max) tuples
        """
        return {verdict.value: threshold for verdict, threshold in self.thresholds.items()}

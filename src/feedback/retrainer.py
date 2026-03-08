"""
Retraining pipeline that learns from analyst corrections.

This module:
- Retrains analyzer weights using logistic regression on feedback vectors
- Retrains intent classifiers on misclassified samples
- Determines when retraining should occur
- Identifies systematic weaknesses per analyzer (gap analysis)
"""
import json
import logging
import uuid
from datetime import datetime
from typing import Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import PipelineConfig
from src.feedback.database import (
    DatabaseManager,
    FeedbackRecord,
    RetrainRun,
)
from src.models import Verdict

logger = logging.getLogger(__name__)


class RetrainerConfig:
    """Configuration for retraining behavior."""

    # Minimum feedback records to trigger automatic retrain
    MIN_FEEDBACK_FOR_RETRAIN = 20

    # Minimum total feedback records in database to attempt retrain
    MIN_TOTAL_FEEDBACK = 50

    # Target improvement threshold (%)
    TARGET_IMPROVEMENT_PCT = 1.0

    # Cross-validation folds
    CV_FOLDS = 5

    # Maximum days between automatic retrains
    MAX_DAYS_BETWEEN_RETRAIN = 7


class WeightRetainer:
    """
    Retrain analyzer weights using logistic regression on feedback feature vectors.

    The original scoring pipeline uses fixed weights. This component learns
    new weights from feedback to improve decisions.
    """

    def __init__(self, config: PipelineConfig):
        """
        Initialize weight retrainer.

        Args:
            config: Pipeline configuration with current weights
        """
        self.config = config
        self.current_weights = config.scoring.weights.copy()
        self.scaler = StandardScaler()
        self.model = None

    async def retrain_weights(
        self, session: AsyncSession
    ) -> Optional[dict[str, float]]:
        """
        Retrain weights using feedback feature vectors via logistic regression.

        Extracts feature vectors from feedback records where:
        - original_verdict != correct_label (mispredictions)

        Then trains logistic regression with:
        - X: Feature vectors (one per feedback record)
        - y: Binary labels (0=misprediction was too conservative, 1=too aggressive)

        Args:
            session: Database session

        Returns:
            New weights dict if training successful, None on failure

        Raises:
            ValueError: If insufficient training data
        """
        try:
            # Fetch feedback records with feature vectors
            stmt = select(FeedbackRecord).where(
                FeedbackRecord.feature_vector.isnot(None)
            )
            result = await session.execute(stmt)
            feedback_records = result.scalars().all()

            if len(feedback_records) < RetrainerConfig.MIN_TOTAL_FEEDBACK:
                logger.warning(
                    f"Insufficient feedback for retraining: "
                    f"{len(feedback_records)} < {RetrainerConfig.MIN_TOTAL_FEEDBACK}"
                )
                return None

            # Parse feature vectors and determine targets
            X = []
            y = []

            for record in feedback_records:
                try:
                    features = json.loads(record.feature_vector)

                    # Skip if original verdict == correct label (no error)
                    if record.original_verdict == record.correct_label:
                        continue

                    # Convert verdict to numeric label
                    original_severity = self._verdict_to_severity(record.original_verdict)
                    correct_severity = self._verdict_to_severity(record.correct_label)

                    # If correct > original: model was too conservative (y=0)
                    # If correct < original: model was too aggressive (y=1)
                    target = 1 if correct_severity < original_severity else 0

                    # Extract numeric features in consistent order
                    feature_vector = self._extract_feature_array(features)
                    if feature_vector is not None:
                        X.append(feature_vector)
                        y.append(target)

                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug(f"Skipped malformed feature vector: {e}")
                    continue

            if len(X) < 10:
                logger.warning(
                    f"Insufficient valid training samples: {len(X)} < 10"
                )
                return None

            X = np.array(X)
            y = np.array(y)

            # Standardize features
            X_scaled = self.scaler.fit_transform(X)

            # Train logistic regression
            self.model = LogisticRegression(
                max_iter=1000,
                random_state=42,
                solver="lbfgs",
                class_weight="balanced",
            )
            self.model.fit(X_scaled, y)

            # Extract new weights from model coefficients
            new_weights = self._coefficients_to_weights(self.model.coef_[0])

            logger.info(
                f"Weight retraining complete: {len(X)} samples, "
                f"model accuracy: {self.model.score(X_scaled, y):.3f}"
            )
            return new_weights

        except Exception as e:
            logger.error(f"Weight retraining failed: {e}", exc_info=True)
            return None

    def _verdict_to_severity(self, verdict: str) -> int:
        """
        Convert verdict string to numeric severity (0=clean, 3=confirmed phishing).

        Args:
            verdict: Verdict enum value as string

        Returns:
            Numeric severity 0-3
        """
        severity_map = {
            Verdict.CLEAN.value: 0,
            Verdict.SUSPICIOUS.value: 1,
            Verdict.LIKELY_PHISHING.value: 2,
            Verdict.CONFIRMED_PHISHING.value: 3,
        }
        return severity_map.get(verdict, 1)

    def _extract_feature_array(self, features: dict) -> Optional[list[float]]:
        """
        Extract numeric feature array from feature dict.

        Expected keys (order matters for consistency):
        - header_risk_score, url_reputation_score, domain_age_score, etc.

        Args:
            features: Feature dictionary from feedback record

        Returns:
            List of floats or None if extraction fails

        Raises:
            KeyError: If critical features missing
        """
        try:
            feature_keys = [
                "header_risk_score",
                "url_reputation_score",
                "domain_age_score",
                "url_detonation_score",
                "brand_impersonation_score",
                "attachment_risk_score",
                "nlp_intent_score",
                "sender_reputation_score",
            ]

            array = []
            for key in feature_keys:
                value = features.get(key, 0.0)
                if isinstance(value, (int, float)):
                    array.append(float(value))
                else:
                    logger.debug(f"Non-numeric feature {key}: {value}")
                    return None

            return array
        except Exception as e:
            logger.debug(f"Failed to extract feature array: {e}")
            return None

    def _coefficients_to_weights(self, coefficients: np.ndarray) -> dict[str, float]:
        """
        Convert logistic regression coefficients to analyzer weights.

        Normalize coefficients to sum to 1.0.

        Args:
            coefficients: Model coefficients array

        Returns:
            Dict mapping analyzer names to weights
        """
        analyzer_names = [
            "header_analysis",
            "url_reputation",
            "domain_intelligence",
            "url_detonation",
            "brand_impersonation",
            "attachment_analysis",
            "nlp_intent",
            "sender_profiling",
        ]

        # Use absolute values, normalize
        abs_coefs = np.abs(coefficients)
        normalized = abs_coefs / np.sum(abs_coefs)

        return {name: float(weight) for name, weight in zip(analyzer_names, normalized)}


class IntentClassifierRetrainer:
    """
    Retrain NLP intent classifier on misclassified samples.

    Learns from feedback where the intent category was incorrect.
    """

    async def retrain_intent_classifier(
        self, session: AsyncSession
    ) -> Optional[dict]:
        """
        Retrain intent classifier using TF-IDF + classifier on feedback samples.

        Args:
            session: Database session

        Returns:
            Training metadata dict or None on failure
        """
        try:
            # Fetch feedback records with intent mismatches
            # This would require additional tracking in feature_vector
            logger.info("Intent classifier retraining triggered")

            # Placeholder: would integrate sklearn's TfidfVectorizer
            # and train a fresh intent classifier on misclassified samples

            return {
                "samples": 0,
                "status": "pending_implementation",
            }

        except Exception as e:
            logger.error(f"Intent classifier retraining failed: {e}", exc_info=True)
            return None


class RetrainOrchestrator:
    """
    Orchestrate the retraining pipeline and determine retrain necessity.

    Responsibilities:
    - Check if retraining should occur
    - Execute weight and intent retraining
    - Log retraining runs
    - Track improvements
    """

    def __init__(
        self, config: PipelineConfig, db_manager: DatabaseManager
    ):
        """
        Initialize retraining orchestrator.

        Args:
            config: Pipeline configuration
            db_manager: Database manager instance
        """
        self.config = config
        self.db_manager = db_manager
        self.weight_retrainer = WeightRetainer(config)
        self.intent_retrainer = IntentClassifierRetrainer()

    async def should_retrain(self, session: AsyncSession) -> tuple[bool, str]:
        """
        Determine if retraining should occur.

        Criteria:
        - At least MIN_FEEDBACK_FOR_RETRAIN new records since last retrain
        - At least MIN_TOTAL_FEEDBACK total records in database
        - More than MAX_DAYS_BETWEEN_RETRAIN days since last retrain

        Args:
            session: Database session

        Returns:
            (should_retrain: bool, reason: str)
        """
        try:
            # Count total feedback records
            total_stmt = select(func.count(FeedbackRecord.id))
            total_result = await session.execute(total_stmt)
            total_count = total_result.scalar() or 0

            if total_count < RetrainerConfig.MIN_TOTAL_FEEDBACK:
                return (
                    False,
                    f"Insufficient total feedback: {total_count} "
                    f"< {RetrainerConfig.MIN_TOTAL_FEEDBACK}",
                )

            # Find last retrain run
            last_stmt = (
                select(RetrainRun)
                .where(RetrainRun.status == "completed")
                .order_by(RetrainRun.completed_at.desc())
                .limit(1)
            )
            last_result = await session.execute(last_stmt)
            last_run = last_result.scalar()

            if last_run is None:
                return (
                    True,
                    f"No previous retrain found, total feedback: {total_count}",
                )

            # Count feedback since last retrain
            new_stmt = select(func.count(FeedbackRecord.id)).where(
                FeedbackRecord.submitted_at > last_run.completed_at
            )
            new_result = await session.execute(new_stmt)
            new_count = new_result.scalar() or 0

            if new_count >= RetrainerConfig.MIN_FEEDBACK_FOR_RETRAIN:
                return (
                    True,
                    f"New feedback since last retrain: {new_count} "
                    f">= {RetrainerConfig.MIN_FEEDBACK_FOR_RETRAIN}",
                )

            # Check if too long since last retrain
            days_since = (datetime.utcnow() - last_run.completed_at).days
            if days_since > RetrainerConfig.MAX_DAYS_BETWEEN_RETRAIN:
                return (
                    True,
                    f"{days_since} days since last retrain "
                    f"(max: {RetrainerConfig.MAX_DAYS_BETWEEN_RETRAIN})",
                )

            return (
                False,
                f"New feedback: {new_count} "
                f"< {RetrainerConfig.MIN_FEEDBACK_FOR_RETRAIN}, "
                f"days: {days_since} "
                f"<= {RetrainerConfig.MAX_DAYS_BETWEEN_RETRAIN}",
            )

        except Exception as e:
            logger.error(f"Error checking retrain necessity: {e}", exc_info=True)
            return (False, f"Error checking retrain necessity: {e}")

    async def run_full_retrain(
        self, session: AsyncSession, triggered_by: str
    ) -> dict:
        """
        Execute full retraining pipeline.

        Steps:
        1. Create retrain run record
        2. Retrain weights
        3. Retrain intent classifier
        4. Log results

        Args:
            session: Database session
            triggered_by: "scheduled" or analyst username

        Returns:
            Result dict with status, metadata, improvements
        """
        run_id = f"retrain_{uuid.uuid4().hex[:8]}_{int(datetime.utcnow().timestamp())}"
        run = RetrainRun(
            run_id=run_id,
            triggered_by=triggered_by,
            started_at=datetime.utcnow(),
            status="in_progress",
        )
        session.add(run)
        await session.commit()

        try:
            logger.info(f"Starting retraining run: {run_id}")

            # Count feedback records used
            stmt = select(func.count(FeedbackRecord.id))
            result = await session.execute(stmt)
            feedback_count = result.scalar() or 0
            run.feedback_records_used = feedback_count

            # Retrain weights
            new_weights = await self.weight_retrainer.retrain_weights(session)

            # Retrain intent classifier
            intent_results = await self.intent_retrainer.retrain_intent_classifier(
                session
            )

            # Mark complete
            run.completed_at = datetime.utcnow()
            run.status = "completed"

            # TODO: Calculate actual improvement by A/B testing
            # For now, placeholder
            run.model_improvement = "+0.0%"

            await session.commit()

            logger.info(
                f"Retraining run {run_id} completed: "
                f"weights={'updated' if new_weights else 'unchanged'}, "
                f"feedback={feedback_count}"
            )

            return {
                "run_id": run_id,
                "status": "completed",
                "feedback_count": feedback_count,
                "weights_updated": new_weights is not None,
                "new_weights": new_weights,
                "intent_results": intent_results,
            }

        except Exception as e:
            run.status = "failed"
            run.error_message = str(e)
            run.completed_at = datetime.utcnow()
            await session.commit()

            logger.error(f"Retraining run {run_id} failed: {e}", exc_info=True)
            return {
                "run_id": run_id,
                "status": "failed",
                "error": str(e),
            }

    async def get_gap_analysis(
        self, session: AsyncSession
    ) -> dict[str, dict]:
        """
        Identify systematic weaknesses per analyzer.

        Analyzes feedback records to find which analyzers most frequently
        contributed to incorrect verdicts.

        Returns:
            Dict mapping analyzer names to weakness metrics:
            {
                "analyzer_name": {
                    "false_negatives": count,
                    "false_positives": count,
                    "accuracy": float,
                    "contributing_factors": [...]
                }
            }

        Args:
            session: Database session

        Returns:
            Gap analysis results
        """
        try:
            stmt = select(FeedbackRecord).where(
                FeedbackRecord.feature_vector.isnot(None)
            )
            result = await session.execute(stmt)
            records = result.scalars().all()

            if not records:
                return {}

            analyzer_stats: dict[str, dict] = {}

            for record in records:
                try:
                    features = json.loads(record.feature_vector)

                    # Categorize as false negative or false positive
                    original_severity = self.weight_retrainer._verdict_to_severity(
                        record.original_verdict
                    )
                    correct_severity = self.weight_retrainer._verdict_to_severity(
                        record.correct_label
                    )

                    if original_severity > correct_severity:
                        error_type = "false_positive"
                    elif original_severity < correct_severity:
                        error_type = "false_negative"
                    else:
                        continue

                    # Track which analyzers contributed
                    for analyzer, score in features.items():
                        if "score" not in analyzer:
                            continue

                        analyzer_name = analyzer.replace("_score", "")
                        if analyzer_name not in analyzer_stats:
                            analyzer_stats[analyzer_name] = {
                                "false_negatives": 0,
                                "false_positives": 0,
                                "total_errors": 0,
                                "high_confidence_errors": 0,
                            }

                        analyzer_stats[analyzer_name]["total_errors"] += 1
                        if error_type == "false_negative":
                            analyzer_stats[analyzer_name]["false_negatives"] += 1
                        else:
                            analyzer_stats[analyzer_name]["false_positives"] += 1

                        # Track high-confidence errors (when score was high but wrong)
                        if isinstance(score, (int, float)) and score > 0.7:
                            if error_type == "false_negative":
                                analyzer_stats[analyzer_name][
                                    "high_confidence_errors"
                                ] += 1

                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug(f"Skipped record in gap analysis: {e}")
                    continue

            # Calculate percentages
            for analyzer, stats in analyzer_stats.items():
                total = stats["total_errors"]
                if total > 0:
                    stats["fn_percentage"] = (
                        stats["false_negatives"] / total * 100
                    )
                    stats["fp_percentage"] = (
                        stats["false_positives"] / total * 100
                    )

            logger.info(f"Gap analysis complete: {len(analyzer_stats)} analyzers")
            return analyzer_stats

        except Exception as e:
            logger.error(f"Gap analysis failed: {e}", exc_info=True)
            return {}

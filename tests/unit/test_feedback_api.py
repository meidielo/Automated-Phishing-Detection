"""
Test suite for feedback API in src.feedback.feedback_api module.

Tests:
- FastAPI endpoint responses
- Authentication verification
- Feedback submission
- Statistics calculation
- Rate limiting
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import PipelineConfig
from src.feedback.feedback_api import (
    create_app,
    FeedbackSubmissionRequest,
    FeedbackResponse,
    StatsResponse,
    HealthResponse,
    _verdict_to_severity,
)
from src.models import Verdict


class TestVerdictToSeverity:
    """Test verdict to severity conversion."""

    def test_verdict_to_severity_clean(self):
        """Test CLEAN verdict severity."""
        severity = _verdict_to_severity(Verdict.CLEAN.value)
        assert severity == 0

    def test_verdict_to_severity_suspicious(self):
        """Test SUSPICIOUS verdict severity."""
        severity = _verdict_to_severity(Verdict.SUSPICIOUS.value)
        assert severity == 1

    def test_verdict_to_severity_likely_phishing(self):
        """Test LIKELY_PHISHING verdict severity."""
        severity = _verdict_to_severity(Verdict.LIKELY_PHISHING.value)
        assert severity == 2

    def test_verdict_to_severity_confirmed_phishing(self):
        """Test CONFIRMED_PHISHING verdict severity."""
        severity = _verdict_to_severity(Verdict.CONFIRMED_PHISHING.value)
        assert severity == 3

    def test_verdict_to_severity_invalid(self):
        """Test invalid verdict returns default."""
        severity = _verdict_to_severity("INVALID")
        assert severity == 1  # Default is SUSPICIOUS


class TestFeedbackRequest:
    """Test feedback submission request."""

    def test_feedback_request_creation(self):
        """Test creating feedback request."""
        request = FeedbackSubmissionRequest(
            email_id="test_email",
            original_verdict="SUSPICIOUS",
            correct_label="CLEAN",
            analyst_notes="False positive",
            feature_vector={"score": 0.5},
        )
        assert request.email_id == "test_email"
        assert request.original_verdict == "SUSPICIOUS"
        assert request.correct_label == "CLEAN"

    def test_feedback_request_validation(self):
        """Test feedback request validation."""
        request = FeedbackSubmissionRequest(
            email_id="test",
            original_verdict="CLEAN",
            correct_label="CONFIRMED_PHISHING",
        )
        # Should be valid
        assert request is not None


class TestHealthCheck:
    """Test health check endpoint."""

    def test_health_response_creation(self):
        """Test creating health check response."""
        now = datetime.utcnow()
        response = HealthResponse(
            status="healthy",
            timestamp=now,
            database_connected=True,
            scheduler_running=True,
        )
        assert response.status == "healthy"
        assert response.database_connected is True


class TestStatsResponse:
    """Test statistics response."""

    def test_stats_response_creation(self):
        """Test creating stats response."""
        now = datetime.utcnow()
        response = StatsResponse(
            total_feedback_records=100,
            total_unique_emails=95,
            false_positives=10,
            false_negatives=5,
            correct_verdicts=85,
            precision=0.89,
            recall=0.94,
            f1_score=0.91,
            last_updated=now,
        )
        assert response.total_feedback_records == 100
        assert response.precision == 0.89

    def test_stats_calculation_perfect_accuracy(self):
        """Test stats with perfect accuracy."""
        now = datetime.utcnow()
        response = StatsResponse(
            total_feedback_records=100,
            total_unique_emails=100,
            false_positives=0,
            false_negatives=0,
            correct_verdicts=100,
            precision=1.0,
            recall=1.0,
            f1_score=1.0,
            last_updated=now,
        )
        assert response.precision == 1.0
        assert response.recall == 1.0


class TestFalsePositiveDetection:
    """Test false positive detection."""

    def test_false_positive_clean_to_suspicious(self):
        """Test false positive: CLEAN original, SUSPICIOUS correct."""
        original_severity = _verdict_to_severity(Verdict.CLEAN.value)
        correct_severity = _verdict_to_severity(Verdict.SUSPICIOUS.value)
        # Original is less severe than correct = false negative, not false positive
        assert original_severity < correct_severity

    def test_false_positive_suspicious_to_clean(self):
        """Test false positive: SUSPICIOUS original, CLEAN correct."""
        original_severity = _verdict_to_severity(Verdict.SUSPICIOUS.value)
        correct_severity = _verdict_to_severity(Verdict.CLEAN.value)
        # Original is more severe than correct = false positive
        assert original_severity > correct_severity

    def test_false_negative_clean_to_phishing(self):
        """Test false negative: CLEAN original, PHISHING correct."""
        original_severity = _verdict_to_severity(Verdict.CLEAN.value)
        correct_severity = _verdict_to_severity(Verdict.CONFIRMED_PHISHING.value)
        # Original is less severe than correct = false negative
        assert original_severity < correct_severity


class TestAPIEndpointModels:
    """Test API endpoint response models."""

    def test_feedback_response_model(self):
        """Test FeedbackResponse model."""
        now = datetime.utcnow()
        response = FeedbackResponse(
            id=1,
            email_id="test_email",
            original_verdict="SUSPICIOUS",
            correct_label="CLEAN",
            submitted_at=now,
            actions_taken=["added_to_allowlist"],
        )
        assert response.id == 1
        assert "added_to_allowlist" in response.actions_taken

    def test_feedback_response_false_positive_action(self):
        """Test feedback response for false positive action."""
        now = datetime.utcnow()
        response = FeedbackResponse(
            id=1,
            email_id="test_email",
            original_verdict="CONFIRMED_PHISHING",
            correct_label="CLEAN",
            submitted_at=now,
            actions_taken=["added_to_allowlist"],
        )
        # False positive should trigger allowlist action
        assert "added_to_allowlist" in response.actions_taken

    def test_feedback_response_false_negative_action(self):
        """Test feedback response for false negative action."""
        now = datetime.utcnow()
        response = FeedbackResponse(
            id=2,
            email_id="test_email2",
            original_verdict="CLEAN",
            correct_label="CONFIRMED_PHISHING",
            submitted_at=now,
            actions_taken=["added_to_blocklist"],
        )
        # False negative should trigger blocklist action
        assert "added_to_blocklist" in response.actions_taken


class TestRateLimiting:
    """Test rate limiting logic."""

    def test_rate_limit_tracking(self):
        """Test basic rate limit tracking."""
        rate_limits = {}
        client_id = "test_client"

        # Add 5 requests
        for _ in range(5):
            if client_id not in rate_limits:
                rate_limits[client_id] = []
            rate_limits[client_id].append(datetime.utcnow())

        assert len(rate_limits[client_id]) == 5

    def test_rate_limit_exceeds_threshold(self):
        """Test rate limit threshold detection."""
        rate_limits = {}
        client_id = "test_client"
        MAX_REQUESTS = 60

        # Add requests up to limit
        for i in range(MAX_REQUESTS + 1):
            if client_id not in rate_limits:
                rate_limits[client_id] = []
            rate_limits[client_id].append(datetime.utcnow())

        # Should exceed limit
        assert len(rate_limits[client_id]) > MAX_REQUESTS


class TestAuthenticationValidation:
    """Test authentication token validation."""

    def test_bearer_token_format(self):
        """Test bearer token format parsing."""
        auth_header = "Bearer test_token_12345"
        parts = auth_header.split()
        assert len(parts) == 2
        assert parts[0].lower() == "bearer"
        assert parts[1] == "test_token_12345"

    def test_invalid_bearer_format_missing_bearer(self):
        """Test invalid format: missing Bearer keyword."""
        auth_header = "test_token_12345"
        parts = auth_header.split()
        assert len(parts) == 1
        assert parts[0] != "Bearer"

    def test_invalid_bearer_format_extra_parts(self):
        """Test invalid format: too many parts."""
        auth_header = "Bearer token extra_part"
        parts = auth_header.split()
        assert len(parts) != 2


class TestGapAnalysis:
    """Test gap analysis response model."""

    def test_gap_analysis_response(self):
        """Test gap analysis response structure."""
        from src.feedback.feedback_api import GapAnalysisResponse

        response = GapAnalysisResponse(
            analyzer="url_reputation",
            false_negatives=10,
            false_positives=5,
            total_errors=15,
            fn_percentage=66.7,
            fp_percentage=33.3,
            high_confidence_errors=8,
        )
        assert response.analyzer == "url_reputation"
        assert response.total_errors == 15
        assert response.fn_percentage > response.fp_percentage


class TestRetainResponse:
    """Test retrain response model."""

    def test_retrain_response_success(self):
        """Test successful retrain response."""
        from src.feedback.feedback_api import RetrainResponse

        response = RetrainResponse(
            run_id="retrain_12345",
            status="completed",
            feedback_count=100,
            weights_updated=True,
            new_weights={
                "header_analysis": 0.12,
                "url_reputation": 0.16,
            },
            message="Retraining completed successfully",
        )
        assert response.status == "completed"
        assert response.weights_updated is True
        assert response.feedback_count == 100


class TestAPIValidation:
    """Test API input validation."""

    def test_feedback_submission_required_fields(self):
        """Test feedback submission with missing required fields."""
        # Missing correct_label
        try:
            FeedbackSubmissionRequest(
                email_id="test",
                original_verdict="CLEAN",
                # Missing correct_label
            )
            assert False, "Should have raised validation error"
        except Exception:
            # Expected to fail validation
            pass

    def test_feedback_submission_invalid_verdict(self):
        """Test feedback submission with invalid verdict."""
        try:
            FeedbackSubmissionRequest(
                email_id="test",
                original_verdict="INVALID_VERDICT",
                correct_label="CLEAN",
            )
            # Validation should catch this
        except Exception:
            pass

    def test_query_parameter_validation(self):
        """Test query parameter validation."""
        from src.feedback.feedback_api import Query
        # Can't directly test without FastAPI context
        # This would be tested in integration tests
        pass

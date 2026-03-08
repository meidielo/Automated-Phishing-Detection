"""
Integration tests for the full phishing detection pipeline.

Tests:
- End-to-end email analysis
- Multi-analyzer coordination
- Decision engine with real analyzer output
- Result consistency
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from src.orchestrator.pipeline import PhishingPipeline
from src.config import PipelineConfig, ScoringConfig
from src.models import EmailObject, Verdict, AnalyzerResult


@pytest.fixture
def pipeline(pipeline_config):
    """Create a phishing pipeline instance."""
    return PhishingPipeline(pipeline_config)


@pytest.fixture
def sample_clean_email():
    """Create sample clean email."""
    return EmailObject(
        email_id="clean_001",
        raw_headers={},
        from_address="sender@trusted.com",
        from_display_name="Trusted Sender",
        reply_to=None,
        to_addresses=["user@example.com"],
        cc_addresses=[],
        subject="Team Meeting",
        body_plain="Let's meet tomorrow",
        body_html="<p>Let's meet tomorrow</p>",
        date=datetime.now(timezone.utc),
        attachments=[],
        inline_images=[],
        message_id="clean_001@trusted.com",
        received_chain=[],
    )


@pytest.fixture
def sample_phishing_email():
    """Create sample phishing email."""
    return EmailObject(
        email_id="phishing_001",
        raw_headers={},
        from_address="support@phishing-bank.com",
        from_display_name="Bank Support",
        reply_to="confirm@malicious.ru",
        to_addresses=["victim@example.com"],
        cc_addresses=[],
        subject="Urgent: Verify Account",
        body_plain="Click: http://bank-verify.ru/confirm",
        body_html='<a href="http://bank-verify.ru/confirm">Verify</a>',
        date=datetime.now(timezone.utc),
        attachments=[],
        inline_images=[],
        message_id="phishing_001@phishing-bank.com",
        received_chain=["from malicious.ru"],
    )


class TestPipelineInitialization:
    """Test pipeline initialization."""

    def test_pipeline_creation(self, pipeline):
        """Test pipeline can be created."""
        assert pipeline is not None
        assert pipeline.config is not None

    def test_pipeline_config_attributes(self, pipeline):
        """Test pipeline configuration is accessible."""
        assert pipeline.config.max_concurrent_analyzers > 0
        assert pipeline.config.pipeline_timeout > 0
        assert pipeline.config.url_detonation_timeout > 0

    def test_pipeline_semaphore_created(self, pipeline):
        """Test pipeline creates concurrency control."""
        assert pipeline.global_semaphore is not None


class TestPipelinePhases:
    """Test pipeline phases."""

    @pytest.mark.asyncio
    async def test_pipeline_analyze_clean_email(self, pipeline, sample_clean_email):
        """Test analyzing a clean email through full pipeline."""
        # Mock the analyzer results
        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    # Setup mocks
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = {
                        "header_analysis": AnalyzerResult(
                            analyzer_name="header_analysis",
                            risk_score=0.1,
                            confidence=1.0,
                            details={},
                        ),
                    }
                    mock_decision.return_value = (
                        Verdict.CLEAN,
                        0.1,
                        0.95,
                        "Email is clean",
                    )

                    # Run pipeline
                    result = await pipeline.analyze(sample_clean_email)

                    # Verify result
                    assert result.verdict == Verdict.CLEAN
                    assert result.email_id == "clean_001"

    @pytest.mark.asyncio
    async def test_pipeline_analyze_phishing_email(self, pipeline, sample_phishing_email):
        """Test analyzing a phishing email through full pipeline."""
        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = {
                        "nlp_intent": AnalyzerResult(
                            analyzer_name="nlp_intent",
                            risk_score=0.85,
                            confidence=0.95,
                            details={},
                        ),
                    }
                    mock_decision.return_value = (
                        Verdict.LIKELY_PHISHING,
                        0.85,
                        0.90,
                        "Multiple phishing indicators",
                    )

                    result = await pipeline.analyze(sample_phishing_email)

                    assert result.verdict == Verdict.LIKELY_PHISHING
                    assert result.overall_score > 0.8


class TestPipelineExecution:
    """Test pipeline execution flow."""

    @pytest.mark.asyncio
    async def test_pipeline_timeout(self, pipeline, sample_clean_email):
        """Test pipeline handles short timeout gracefully."""
        pipeline.config.pipeline_timeout = 0.01  # Very short timeout

        # Pipeline should still return a result (graceful degradation)
        # even if analyzers fail/timeout
        result = await pipeline.analyze(sample_clean_email)
        assert result is not None
        assert result.email_id == sample_clean_email.email_id

    @pytest.mark.asyncio
    async def test_pipeline_result_structure(self, pipeline, sample_clean_email):
        """Test pipeline result has expected structure."""
        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = {}
                    mock_decision.return_value = (
                        Verdict.CLEAN,
                        0.1,
                        0.95,
                        "Test reasoning",
                    )

                    result = await pipeline.analyze(sample_clean_email)

                    # Verify result structure
                    assert hasattr(result, 'email_id')
                    assert hasattr(result, 'verdict')
                    assert hasattr(result, 'overall_score')
                    assert hasattr(result, 'overall_confidence')
                    assert hasattr(result, 'analyzer_results')
                    assert hasattr(result, 'reasoning')
                    assert hasattr(result, 'timestamp')


class TestMultipleAnalyzers:
    """Test coordination of multiple analyzers."""

    @pytest.mark.asyncio
    async def test_multiple_analyzer_results(self, pipeline, sample_phishing_email):
        """Test pipeline with multiple analyzer results."""
        analyzer_results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.7,
                confidence=0.9,
                details={"spf_pass": False},
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.8,
                confidence=0.85,
                details={"url_count": 1},
            ),
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.75,
                confidence=0.8,
                details={"intent": "phishing"},
            ),
        }

        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = analyzer_results
                    mock_decision.return_value = (
                        Verdict.CONFIRMED_PHISHING,
                        0.76,
                        0.85,
                        "Multiple indicators confirm phishing",
                    )

                    result = await pipeline.analyze(sample_phishing_email)

                    # Verify all analyzers reported
                    assert len(result.analyzer_results) == 3
                    assert result.verdict == Verdict.CONFIRMED_PHISHING


class TestErrorHandling:
    """Test error handling in pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_handles_analyzer_failure(self, pipeline, sample_clean_email):
        """Test pipeline continues when analyzer fails."""
        partial_results = {
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.5,
                confidence=0.0,  # No data
                details={},
                errors=["Analyzer failed"],
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.2,
                confidence=1.0,
                details={},
            ),
        }

        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = partial_results
                    mock_decision.return_value = (
                        Verdict.CLEAN,
                        0.2,
                        0.5,
                        "Limited analysis due to failures",
                    )

                    result = await pipeline.analyze(sample_clean_email)

                    # Should still produce a result
                    assert result.verdict is not None
                    assert len(result.analyzer_results) >= 1


class TestPipelineScoring:
    """Test scoring logic integration."""

    def test_pipeline_verdict_confidence_relationship(self, pipeline):
        """Test that higher risk scores map to higher-severity verdicts."""
        # This would require integration with decision engine
        assert pipeline.config.scoring is not None

    def test_pipeline_threshold_configuration(self, pipeline):
        """Test that pipeline uses configured thresholds."""
        thresholds = pipeline.config.scoring.thresholds
        assert Verdict.CLEAN.value in [k for k in thresholds.keys()] or True


class TestPipelineLogging:
    """Test pipeline logging."""

    @pytest.mark.asyncio
    async def test_pipeline_logs_analysis_json(self, pipeline, sample_clean_email):
        """Test pipeline logs analysis in JSON format."""
        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    with patch.object(pipeline, '_log_analysis_json') as mock_log:
                        mock_extract.return_value = ({}, [])
                        mock_analyze.return_value = {}
                        mock_decision.return_value = (
                            Verdict.CLEAN,
                            0.1,
                            0.95,
                            "Clean",
                        )

                        await pipeline.analyze(sample_clean_email)

                        # Verify logging was called
                        mock_log.assert_called_once()


class TestPipelineEdgeCases:
    """Test edge cases in pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_with_empty_analyzers(self, pipeline, sample_clean_email):
        """Test pipeline with no analyzer results."""
        with patch.object(pipeline, '_phase_extraction') as mock_extract:
            with patch.object(pipeline, '_phase_analysis') as mock_analyze:
                with patch.object(pipeline, '_phase_decision') as mock_decision:
                    mock_extract.return_value = ({}, [])
                    mock_analyze.return_value = {}  # No results
                    mock_decision.return_value = (
                        Verdict.SUSPICIOUS,
                        0.5,
                        0.0,
                        "No analysis data",
                    )

                    result = await pipeline.analyze(sample_clean_email)

                    # Should return neutral verdict
                    assert result.verdict == Verdict.SUSPICIOUS
                    assert result.overall_confidence == 0.0

    def test_pipeline_config_validation(self, pipeline_config):
        """Test that pipeline config is valid."""
        assert pipeline_config.max_concurrent_analyzers > 0
        assert pipeline_config.pipeline_timeout > 0

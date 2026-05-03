"""
Unit tests for report generation (JSON and HTML).

Tests cover:
- ReportGenerator initialization
- JSON report generation
- HTML report generation with Jinja2 templates
- Report content validation (verdict, scores, analyzer results)
- URL defanging
- QR code generation
- Edge cases (empty analyzers, missing fields)
"""
import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    AnalyzerResult,
    ExtractedURL,
    PipelineResult,
    URLSource,
    Verdict,
)
from src.reporting.report_generator import ReportGenerator


class TestReportGeneratorInit:
    """Test ReportGenerator initialization."""

    def test_init_default_template_dir(self):
        """Test initialization with default template directory."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            assert generator.env is not None

    def test_init_custom_template_dir(self):
        """Test initialization with custom template directory."""
        with patch("src.reporting.report_generator.Environment"):
            custom_dir = "/custom/templates"
            generator = ReportGenerator(template_dir=custom_dir)
            assert generator.env is not None

    def test_init_template_load_error_sets_env_none(self):
        """Test initialization handles template loading errors gracefully."""
        with patch(
            "src.reporting.report_generator.Environment", side_effect=Exception("Load failed")
        ):
            generator = ReportGenerator()
            assert generator.env is None


class TestGenerateJsonReport:
    """Test JSON report generation."""

    @pytest.fixture
    def sample_pipeline_result(self):
        """Create a sample PipelineResult."""
        return PipelineResult(
            email_id="msg_test123",
            verdict=Verdict.LIKELY_PHISHING,
            overall_score=0.75,
            overall_confidence=0.88,
            analyzer_results={
                "url_reputation": AnalyzerResult(
                    analyzer_name="url_reputation",
                    risk_score=0.85,
                    confidence=0.92,
                    details={"reputation_score": 0.85, "status": "malicious"},
                ),
                "header_analysis": AnalyzerResult(
                    analyzer_name="header_analysis",
                    risk_score=0.65,
                    confidence=0.80,
                    details={"spf_pass": False},
                ),
                "payment_fraud": AnalyzerResult(
                    analyzer_name="payment_fraud",
                    risk_score=0.82,
                    confidence=0.9,
                    details={
                        "decision": "DO_NOT_PAY",
                        "summary": "Payment should be blocked until verified",
                        "signals": [],
                        "verification_steps": ["Call saved supplier contact"],
                    },
                ),
            },
            extracted_urls=[
                ExtractedURL(
                    url="http://evil.example.com/phishing",
                    source=URLSource.BODY_HTML,
                    source_detail="Found in body",
                    resolved_url="http://192.0.2.1/phishing",
                    redirect_chain=["http://redirect1.com"],
                )
            ],
            iocs={
                "malicious_urls": ["http://evil.example.com/phishing"],
                "malicious_domains": ["evil.example.com"],
                "malicious_ips": ["192.0.2.1"],
            },
            reasoning="URL and header analysis indicate phishing campaign",
            timestamp=datetime(2026, 3, 8, 15, 30, 0, tzinfo=timezone.utc),
        )

    def test_generate_json_returns_dict(self, sample_pipeline_result):
        """Test JSON report generation returns dictionary."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(sample_pipeline_result)

            assert isinstance(report, dict)

    def test_generate_json_contains_required_fields(self, sample_pipeline_result):
        """Test JSON report includes all required fields."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(sample_pipeline_result)

            assert report["email_id"] == "msg_test123"
            assert report["verdict"] == "LIKELY_PHISHING"
            assert report["overall_score"] == 0.75
            assert report["overall_confidence"] == 0.88
            assert "timestamp" in report
            assert "reasoning" in report
            assert "analyzer_breakdown" in report
            assert "extracted_urls" in report
            assert "iocs" in report
            assert report["payment_protection"]["decision"] == "DO_NOT_PAY"

    def test_generate_json_analyzer_breakdown(self, sample_pipeline_result):
        """Test JSON report includes analyzer breakdown."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(sample_pipeline_result)

            breakdown = report["analyzer_breakdown"]
            assert "url_reputation" in breakdown
            assert breakdown["url_reputation"]["risk_score"] == 0.85
            assert breakdown["url_reputation"]["confidence"] == 0.92
            assert "details" in breakdown["url_reputation"]

    def test_generate_json_defanged_urls(self, sample_pipeline_result):
        """Test URLs are defanged in JSON report."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(sample_pipeline_result)

            urls = report["extracted_urls"]
            assert len(urls) > 0
            assert urls[0]["original"] == "http://evil.example.com/phishing"
            # Defanged should have hxxp and [.]
            assert "hxxp" in urls[0]["defanged"]
            assert "[.]" in urls[0]["defanged"]

    def test_generate_json_empty_analyzers(self):
        """Test JSON report with no analyzer results."""
        result = PipelineResult(
            email_id="msg_test",
            verdict=Verdict.CLEAN,
            overall_score=0.1,
            overall_confidence=0.95,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="Clean",
            timestamp=datetime.now(timezone.utc),
        )

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(result)

            assert report["analyzer_breakdown"] == {}

    def test_generate_json_timestamp_iso_format(self, sample_pipeline_result):
        """Test timestamp is ISO formatted in JSON report."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            report = generator.generate_json(sample_pipeline_result)

            # Should be ISO format
            assert "T" in report["timestamp"]
            assert "2026-03-08" in report["timestamp"]


class TestGenerateHtmlReport:
    """Test HTML report generation."""

    @pytest.fixture
    def sample_result(self):
        """Create sample PipelineResult."""
        return PipelineResult(
            email_id="msg_123",
            verdict=Verdict.CONFIRMED_PHISHING,
            overall_score=0.92,
            overall_confidence=0.95,
            analyzer_results={
                "url_reputation": AnalyzerResult(
                    analyzer_name="url_reputation",
                    risk_score=0.95,
                    confidence=0.98,
                    details={},
                )
            },
            extracted_urls=[],
            iocs={"headers": {}},
            reasoning="High confidence phishing",
            timestamp=datetime.now(timezone.utc),
        )

    def test_generate_html_with_valid_template(self, sample_result):
        """Test HTML generation with valid template."""
        mock_env = MagicMock()
        mock_template = MagicMock()
        mock_template.render.return_value = "<html>Report</html>"
        mock_env.get_template.return_value = mock_template

        with patch(
            "src.reporting.report_generator.Environment", return_value=mock_env
        ):
            generator = ReportGenerator()
            generator.env = mock_env

            html = generator.generate_human_readable(sample_result)

            assert html == "<html>Report</html>"
            mock_env.get_template.assert_called_with("report.html")

    def test_generate_html_raises_when_template_missing(self, sample_result):
        """Test exception propagates when template not found."""
        mock_env = MagicMock()
        mock_env.get_template.side_effect = Exception("Template not found")

        with patch(
            "src.reporting.report_generator.Environment", return_value=mock_env
        ):
            generator = ReportGenerator()
            generator.env = mock_env

            with pytest.raises(Exception, match="Template not found"):
                generator.generate_human_readable(sample_result)

    def test_generate_html_env_not_initialized_raises(self):
        """Test ValueError when template environment not initialized."""
        result = PipelineResult(
            email_id="test",
            verdict=Verdict.CLEAN,
            overall_score=0.1,
            overall_confidence=0.9,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="",
            timestamp=datetime.now(timezone.utc),
        )

        generator = ReportGenerator()
        generator.env = None

        with pytest.raises(ValueError):
            generator.generate_human_readable(result)

    def test_generate_html_autoescapes_email_controlled_fields(self):
        """Rendered Jinja reports must not execute attacker-controlled email content."""
        result = PipelineResult(
            email_id='msg"><img src=x onerror=alert(1)>',
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.4,
            overall_confidence=0.8,
            analyzer_results={},
            extracted_urls=[],
            iocs={"headers": {}, "raw_headers": "<script>alert(1)</script>"},
            reasoning="<script>alert(2)</script>",
            timestamp=datetime.now(timezone.utc),
        )

        generator = ReportGenerator(template_dir="./templates")
        html = generator.generate_human_readable(result)

        assert "<script>alert(1)</script>" not in html
        assert "<script>alert(2)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html

    def test_fallback_html_report_escapes_email_controlled_fields(self):
        """Fallback report HTML should be escaped too, not only Jinja templates."""
        result = PipelineResult(
            email_id='msg"><img src=x onerror=alert(1)>',
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.4,
            overall_confidence=0.8,
            analyzer_results={
                "<img src=x onerror=alert(3)>": AnalyzerResult(
                    analyzer_name="x",
                    risk_score=0.5,
                    confidence=0.7,
                    details={},
                )
            },
            extracted_urls=[
                ExtractedURL(
                    url="https://evil.example/<script>",
                    source=URLSource.BODY_HTML,
                    source_detail="test",
                )
            ],
            iocs={"headers": {}},
            reasoning="<script>alert(2)</script>",
            timestamp=datetime.now(timezone.utc),
        )

        generator = ReportGenerator(template_dir="./templates")
        html = generator._generate_fallback_report(result)

        assert "<script>alert(2)</script>" not in html
        assert '<img src=x onerror=alert(3)>' not in html
        assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
        assert "&lt;img src=x onerror=alert(3)&gt;" in html


class TestUrlDefanging:
    """Test URL defanging functionality."""

    def test_defang_http_urls(self):
        """Test HTTP URL is defanged."""
        url = "http://example.com/phishing"
        defanged = ReportGenerator._defang_url(url)

        assert defanged.startswith("hxxp://")
        assert "[.]" in defanged
        assert "example[.]com" in defanged

    def test_defang_https_urls(self):
        """Test HTTPS URL is defanged."""
        url = "https://secure.evil.com/path"
        defanged = ReportGenerator._defang_url(url)

        assert defanged.startswith("hxxps://")
        assert "[.]" in defanged

    def test_defang_handles_non_string_input(self):
        """Test defang handles non-string input."""
        defanged = ReportGenerator._defang_url(None)
        assert isinstance(defanged, str)

    def test_defang_complex_url(self):
        """Test defanging complex URL with multiple dots."""
        url = "https://mail.google.com.evil.phishing.net/login?target=gmail"
        defanged = ReportGenerator._defang_url(url)

        assert "hxxps" in defanged
        assert defanged.count("[.]") > 3  # Multiple dots should be defanged


class TestQrCodeGeneration:
    """Test QR code generation."""

    def test_generate_qr_code_returns_bytes(self):
        """Test QR code generation returns PNG bytes."""
        data = "http://example.com/phishing"
        png_bytes = ReportGenerator.generate_qr_code(data)

        assert isinstance(png_bytes, bytes)
        assert len(png_bytes) > 0
        # PNG magic number
        assert png_bytes[:4] == b"\x89PNG"

    def test_generate_qr_code_handles_long_data(self):
        """Test QR code generation handles long data strings."""
        long_url = "https://example.com/" + "a" * 1000
        png_bytes = ReportGenerator.generate_qr_code(long_url)

        assert isinstance(png_bytes, bytes)
        assert len(png_bytes) > 0

    def test_generate_qr_image_base64(self):
        """Test QR image conversion to base64 data URI."""
        png_bytes = ReportGenerator.generate_qr_code("test data")
        base64_uri = ReportGenerator._generate_qr_image_base64(png_bytes)

        assert base64_uri.startswith("data:image/png;base64,")
        # Should be valid base64 after the prefix
        base64_part = base64_uri.split(",")[1]
        decoded = base64.b64decode(base64_part)
        assert decoded[:4] == b"\x89PNG"

    def test_generate_qr_image_base64_empty_input(self):
        """Test base64 conversion with empty input."""
        base64_uri = ReportGenerator._generate_qr_image_base64(b"")
        assert base64_uri == ""

    def test_generate_qr_image_base64_invalid_input(self):
        """Test base64 conversion handles invalid input."""
        # Should not raise, but return empty string
        result = ReportGenerator._generate_qr_image_base64(None)
        # Should handle gracefully without raising
        assert isinstance(result, str)


class TestPrepareTemplateContext:
    """Test template context preparation."""

    @pytest.fixture
    def sample_result_with_iocs(self):
        """Create result with various IOCs."""
        return PipelineResult(
            email_id="msg_test",
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.55,
            overall_confidence=0.75,
            analyzer_results={
                "header_analysis": AnalyzerResult(
                    analyzer_name="header_analysis",
                    risk_score=0.6,
                    confidence=0.8,
                    details={},
                )
            },
            extracted_urls=[
                ExtractedURL(
                    url="http://test.com",
                    source=URLSource.BODY_HTML,
                    source_detail="body",
                )
            ],
            iocs={
                "headers": {
                    "spf_pass": True,
                    "dkim_pass": False,
                    "dmarc_pass": False,
                    "from_reply_to_mismatch": False,
                    "display_name_spoofing": True,
                    "suspicious_received_chain": False,
                },
                "qr_codes": [
                    {"decoded_content": "http://phishing.com", "raw_image": b""}
                ],
            },
            reasoning="Test reasoning",
            timestamp=datetime(2026, 3, 8, 15, 30, 0, tzinfo=timezone.utc),
        )

    def test_prepare_context_includes_headers(self, sample_result_with_iocs):
        """Test context includes header analysis details."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            context = generator._prepare_template_context(sample_result_with_iocs)

            assert "header_details" in context
            header_details = context["header_details"]
            assert header_details["spf"] is True
            assert header_details["display_name_spoofing"] is True

    def test_prepare_context_verdict_color(self, sample_result_with_iocs):
        """Test context includes verdict color mapping."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            context = generator._prepare_template_context(sample_result_with_iocs)

            assert "verdict_color" in context
            # SUSPICIOUS should have a color
            assert context["verdict_color"] != ""

    def test_prepare_context_analyzer_scores(self, sample_result_with_iocs):
        """Test context includes analyzer score breakdown."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            context = generator._prepare_template_context(sample_result_with_iocs)

            assert "analyzer_scores" in context
            scores = context["analyzer_scores"]
            assert len(scores) > 0
            assert scores[0]["name"] == "header_analysis"
            assert scores[0]["score"] == 0.6

    def test_prepare_context_rounded_values(self, sample_result_with_iocs):
        """Test context includes properly rounded values."""
        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            context = generator._prepare_template_context(sample_result_with_iocs)

            # Should be rounded to 3 decimal places
            assert isinstance(context["overall_score"], float)
            assert isinstance(context["overall_confidence"], float)


class TestGenerateFallbackReport:
    """Test fallback HTML report generation."""

    def test_fallback_report_contains_verdict(self):
        """Test fallback report includes verdict."""
        result = PipelineResult(
            email_id="msg_test",
            verdict=Verdict.CONFIRMED_PHISHING,
            overall_score=0.85,
            overall_confidence=0.90,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="Test",
            timestamp=datetime.now(timezone.utc),
        )

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_fallback_report(result)

            assert "CONFIRMED_PHISHING" in html
            assert "Verdict" in html

    def test_fallback_report_contains_scores(self):
        """Test fallback report includes score information."""
        result = PipelineResult(
            email_id="msg_test",
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.65,
            overall_confidence=0.75,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="Test",
            timestamp=datetime.now(timezone.utc),
        )

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_fallback_report(result)

            assert "0.65" in html or "65" in html
            assert "Score" in html or "score" in html

    def test_fallback_report_valid_html(self):
        """Test fallback report is valid HTML."""
        result = PipelineResult(
            email_id="msg_test",
            verdict=Verdict.CLEAN,
            overall_score=0.15,
            overall_confidence=0.95,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="Clean email",
            timestamp=datetime.now(timezone.utc),
        )

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_fallback_report(result)

            assert "<!DOCTYPE html>" in html or "<html>" in html
            assert "</html>" in html
            assert "<body>" in html or "<Body>" in html.lower()


class TestGenerateAnalyzerHtml:
    """Test analyzer HTML generation."""

    def test_generate_analyzer_html_with_results(self):
        """Test analyzer HTML generation with analyzer results."""
        json_data = {
            "analyzer_breakdown": {
                "url_reputation": {
                    "risk_score": 0.85,
                    "confidence": 0.92,
                    "details": {},
                }
            }
        }

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_analyzer_html(json_data)

            assert "url_reputation" in html
            assert "0.85" in html or "85" in html

    def test_generate_analyzer_html_empty(self):
        """Test analyzer HTML with no results."""
        json_data = {"analyzer_breakdown": {}}

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_analyzer_html(json_data)

            assert isinstance(html, str)


class TestGenerateUrlsHtml:
    """Test URLs HTML generation."""

    def test_generate_urls_html_with_urls(self):
        """Test URLs HTML with extracted URLs."""
        json_data = {
            "extracted_urls": [
                {
                    "defanged": "hxxp://example[.]com",
                    "source": "body_html",
                }
            ]
        }

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_urls_html(json_data)

            assert "example[.]com" in html
            assert "body_html" in html

    def test_generate_urls_html_empty(self):
        """Test URLs HTML with no URLs."""
        json_data = {"extracted_urls": []}

        with patch("src.reporting.report_generator.Environment"):
            generator = ReportGenerator()
            html = generator._generate_urls_html(json_data)

            assert "No URLs" in html or "no URLs" in html

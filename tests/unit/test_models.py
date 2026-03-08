"""
Test suite for data models in src.models module.

Tests:
- Model creation and validation
- Dataclass serialization/deserialization
- Enum values
- Field defaults
- Data integrity
"""

import pytest
from datetime import datetime, timezone
from dataclasses import asdict

from src.models import (
    Verdict,
    URLSource,
    AttachmentRisk,
    IntentCategory,
    EmailObject,
    AttachmentObject,
    ExtractedURL,
    AnalyzerResult,
    PipelineResult,
    FeedbackRecord,
    HeaderAnalysisDetail,
    IntentClassification,
)


class TestVerdictEnum:
    """Test Verdict enum."""

    def test_verdict_values(self):
        """Test that all verdict values are defined."""
        assert Verdict.CLEAN.value == "CLEAN"
        assert Verdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert Verdict.LIKELY_PHISHING.value == "LIKELY_PHISHING"
        assert Verdict.CONFIRMED_PHISHING.value == "CONFIRMED_PHISHING"

    def test_verdict_comparison(self):
        """Test verdict enum comparison."""
        assert Verdict.CLEAN != Verdict.SUSPICIOUS
        assert Verdict.CONFIRMED_PHISHING != Verdict.CLEAN

    def test_verdict_from_string(self):
        """Test creating verdict from string."""
        assert Verdict["CLEAN"] == Verdict.CLEAN
        assert Verdict["SUSPICIOUS"] == Verdict.SUSPICIOUS


class TestURLSourceEnum:
    """Test URLSource enum."""

    def test_url_source_values(self):
        """Test that all URL sources are defined."""
        assert URLSource.BODY_PLAINTEXT.value == "body_plaintext"
        assert URLSource.BODY_HTML.value == "body_html"
        assert URLSource.ATTACHMENT.value == "attachment"
        assert URLSource.QR_CODE.value == "qr_code"

    def test_url_source_variants(self):
        """Test all URL source variants."""
        sources = [
            URLSource.BODY_PLAINTEXT,
            URLSource.BODY_HTML,
            URLSource.ATTACHMENT,
            URLSource.QR_CODE,
            URLSource.QR_CODE_PDF,
            URLSource.QR_CODE_DOCX,
            URLSource.QR_CODE_HTML_RENDERED,
        ]
        assert len(sources) == 7


class TestIntentCategoryEnum:
    """Test IntentCategory enum."""

    def test_intent_categories(self):
        """Test that all intent categories are defined."""
        categories = [
            IntentCategory.CREDENTIAL_HARVESTING,
            IntentCategory.MALWARE_DELIVERY,
            IntentCategory.BEC_WIRE_FRAUD,
            IntentCategory.GIFT_CARD_SCAM,
            IntentCategory.EXTORTION,
            IntentCategory.LEGITIMATE,
            IntentCategory.UNKNOWN,
        ]
        assert len(categories) == 7
        assert IntentCategory.CREDENTIAL_HARVESTING.value == "credential_harvesting"


class TestAttachmentObject:
    """Test AttachmentObject dataclass."""

    def test_attachment_creation(self):
        """Test basic attachment creation."""
        att = AttachmentObject(
            filename="test.pdf",
            content_type="application/pdf",
            magic_type="application/pdf",
            size_bytes=1024,
            content=b"PDF content",
            is_archive=False,
            has_macros=False,
        )
        assert att.filename == "test.pdf"
        assert att.size_bytes == 1024
        assert att.nested_files == []

    def test_attachment_with_macros(self):
        """Test attachment with macro detection."""
        att = AttachmentObject(
            filename="malicious.docm",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            magic_type="application/zip",
            size_bytes=2048,
            content=b"docm content",
            is_archive=True,
            has_macros=True,
        )
        assert att.has_macros is True
        assert att.is_archive is True

    def test_attachment_serialization(self):
        """Test attachment can be converted to dict."""
        att = AttachmentObject(
            filename="doc.txt",
            content_type="text/plain",
            magic_type="text/plain",
            size_bytes=100,
            content=b"test",
            is_archive=False,
            has_macros=False,
        )
        data = asdict(att)
        assert data["filename"] == "doc.txt"
        assert data["size_bytes"] == 100


class TestExtractedURL:
    """Test ExtractedURL dataclass."""

    def test_url_creation(self):
        """Test basic URL creation."""
        url = ExtractedURL(
            url="https://example.com",
            source=URLSource.BODY_HTML,
            source_detail="href attribute",
        )
        assert url.url == "https://example.com"
        assert url.source == URLSource.BODY_HTML
        assert url.resolved_url is None
        assert url.redirect_chain == []

    def test_url_with_redirects(self):
        """Test URL with redirect chain."""
        url = ExtractedURL(
            url="https://short.url",
            source=URLSource.BODY_HTML,
            source_detail="shortened link",
            resolved_url="https://final-url.com",
            redirect_chain=["https://short.url", "https://redirect.com", "https://final-url.com"],
        )
        assert url.resolved_url == "https://final-url.com"
        assert len(url.redirect_chain) == 3

    def test_url_serialization(self):
        """Test URL can be converted to dict."""
        url = ExtractedURL(
            url="https://test.com",
            source=URLSource.BODY_PLAINTEXT,
            source_detail="plaintext body",
        )
        data = asdict(url)
        assert data["url"] == "https://test.com"
        assert data["source"] == URLSource.BODY_PLAINTEXT


class TestAnalyzerResult:
    """Test AnalyzerResult dataclass."""

    def test_analyzer_result_creation(self):
        """Test basic analyzer result creation."""
        result = AnalyzerResult(
            analyzer_name="test_analyzer",
            risk_score=0.5,
            confidence=0.8,
            details={"key": "value"},
        )
        assert result.analyzer_name == "test_analyzer"
        assert result.risk_score == 0.5
        assert result.confidence == 0.8
        assert result.errors == []

    def test_analyzer_result_with_errors(self):
        """Test analyzer result with errors."""
        errors = ["API timeout", "Insufficient data"]
        result = AnalyzerResult(
            analyzer_name="failing_analyzer",
            risk_score=0.5,
            confidence=0.0,
            details={},
            errors=errors,
        )
        assert len(result.errors) == 2
        assert "API timeout" in result.errors

    def test_analyzer_result_score_bounds(self):
        """Test that scores are within expected bounds."""
        for score in [0.0, 0.5, 1.0]:
            result = AnalyzerResult(
                analyzer_name="test",
                risk_score=score,
                confidence=score,
                details={},
            )
            assert 0.0 <= result.risk_score <= 1.0
            assert 0.0 <= result.confidence <= 1.0

    def test_analyzer_result_serialization(self):
        """Test analyzer result can be converted to dict."""
        result = AnalyzerResult(
            analyzer_name="test_analyzer",
            risk_score=0.6,
            confidence=0.9,
            details={"finding": "suspicious"},
        )
        data = asdict(result)
        assert data["analyzer_name"] == "test_analyzer"
        assert data["risk_score"] == 0.6


class TestHeaderAnalysisDetail:
    """Test HeaderAnalysisDetail dataclass."""

    def test_header_analysis_detail_creation(self):
        """Test basic header analysis creation."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
            from_reply_to_mismatch=False,
            display_name_spoofing=False,
        )
        assert detail.spf_pass is True
        assert detail.dkim_pass is True
        assert detail.dmarc_pass is True

    def test_header_analysis_with_issues(self):
        """Test header analysis detecting issues."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
            from_reply_to_mismatch=True,
            display_name_spoofing=True,
            suspicious_received_chain=True,
            received_chain_details=[{"host": "suspicious.net", "ip": "203.0.113.5"}],
        )
        assert detail.spf_pass is False
        assert detail.from_reply_to_mismatch is True
        assert len(detail.received_chain_details) == 1

    def test_header_analysis_defaults(self):
        """Test default values for header analysis."""
        detail = HeaderAnalysisDetail()
        assert detail.spf_pass is None
        assert detail.dkim_pass is None
        assert detail.dmarc_pass is None
        assert detail.from_reply_to_mismatch is False
        assert detail.received_chain_details == []


class TestIntentClassification:
    """Test IntentClassification dataclass."""

    def test_intent_classification_creation(self):
        """Test basic intent classification."""
        intent = IntentClassification(
            category=IntentCategory.CREDENTIAL_HARVESTING,
            confidence=0.95,
            reasoning="Email contains login form",
            urgency_score=0.8,
        )
        assert intent.category == IntentCategory.CREDENTIAL_HARVESTING
        assert intent.confidence == 0.95
        assert intent.urgency_score == 0.8

    def test_intent_classification_with_red_flags(self):
        """Test intent classification with red flags."""
        intent = IntentClassification(
            category=IntentCategory.CREDENTIAL_HARVESTING,
            confidence=0.9,
            reasoning="Multiple phishing indicators",
            urgency_score=0.9,
            red_flags=["fake urgency", "credential request", "spoofed sender"],
        )
        assert len(intent.red_flags) == 3
        assert "fake urgency" in intent.red_flags


class TestEmailObject:
    """Test EmailObject dataclass."""

    def test_email_creation(self):
        """Test basic email creation."""
        now = datetime.now(timezone.utc)
        email = EmailObject(
            email_id="test_123",
            raw_headers={"from": ["sender@example.com"]},
            from_address="sender@example.com",
            from_display_name="Test Sender",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="Test Subject",
            body_plain="Test body",
            body_html="<p>Test body</p>",
            date=now,
            attachments=[],
            inline_images=[],
            message_id="test_123@example.com",
            received_chain=[],
        )
        assert email.email_id == "test_123"
        assert email.from_address == "sender@example.com"
        assert email.to_addresses == ["recipient@example.com"]

    def test_email_with_attachments(self, sample_attachment):
        """Test email with attachments."""
        now = datetime.now(timezone.utc)
        email = EmailObject(
            email_id="test_with_att",
            raw_headers={},
            from_address="sender@example.com",
            from_display_name="",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="With Attachment",
            body_plain="See attachment",
            body_html="<p>See attachment</p>",
            date=now,
            attachments=[sample_attachment],
            inline_images=[],
            message_id="test_123@example.com",
            received_chain=[],
        )
        assert len(email.attachments) == 1
        assert email.attachments[0].filename == "document.pdf"

    def test_email_with_multiple_recipients(self):
        """Test email with multiple recipients."""
        now = datetime.now(timezone.utc)
        email = EmailObject(
            email_id="multi_recip",
            raw_headers={},
            from_address="sender@example.com",
            from_display_name="",
            reply_to=None,
            to_addresses=["user1@example.com", "user2@example.com"],
            cc_addresses=["user3@example.com"],
            subject="Group Email",
            body_plain="Message to group",
            body_html="<p>Message to group</p>",
            date=now,
            attachments=[],
            inline_images=[],
            message_id="test_123@example.com",
            received_chain=[],
        )
        assert len(email.to_addresses) == 2
        assert len(email.cc_addresses) == 1


class TestPipelineResult:
    """Test PipelineResult dataclass."""

    def test_pipeline_result_creation(self):
        """Test basic pipeline result creation."""
        results = {"analyzer1": AnalyzerResult(
            analyzer_name="analyzer1",
            risk_score=0.5,
            confidence=0.8,
            details={},
        )}
        now = datetime.now(timezone.utc)
        result = PipelineResult(
            email_id="email_123",
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.5,
            overall_confidence=0.8,
            analyzer_results=results,
            extracted_urls=[],
            iocs={},
            reasoning="Test reasoning",
            timestamp=now,
        )
        assert result.email_id == "email_123"
        assert result.verdict == Verdict.SUSPICIOUS
        assert len(result.analyzer_results) == 1

    def test_pipeline_result_ioc_extraction(self):
        """Test pipeline result with IOCs."""
        results = {}
        iocs = {
            "urls": [{"url": "http://malicious.com", "risk_score": 0.9}],
            "attachments": [{"filename": "malware.exe", "risk": "high"}],
        }
        result = PipelineResult(
            email_id="email_with_iocs",
            verdict=Verdict.CONFIRMED_PHISHING,
            overall_score=0.85,
            overall_confidence=0.95,
            analyzer_results=results,
            extracted_urls=[],
            iocs=iocs,
            reasoning="Malicious indicators found",
        )
        assert "urls" in result.iocs
        assert "attachments" in result.iocs
        assert len(result.iocs["urls"]) == 1


class TestFeedbackRecord:
    """Test FeedbackRecord dataclass."""

    def test_feedback_record_creation(self):
        """Test basic feedback record creation."""
        now = datetime.now(timezone.utc)
        record = FeedbackRecord(
            email_id="email_123",
            original_verdict=Verdict.SUSPICIOUS,
            correct_label=Verdict.CLEAN,
            analyst_notes="False positive - legitimate email",
            feature_vector={"score": 0.5, "confidence": 0.7},
            submitted_at=now,
        )
        assert record.email_id == "email_123"
        assert record.original_verdict == Verdict.SUSPICIOUS
        assert record.correct_label == Verdict.CLEAN
        assert record.analyst_notes == "False positive - legitimate email"

    def test_feedback_record_with_feature_vector(self):
        """Test feedback record with feature vector."""
        record = FeedbackRecord(
            email_id="email_456",
            original_verdict=Verdict.CLEAN,
            correct_label=Verdict.LIKELY_PHISHING,
            analyst_notes="Missed phishing attempt",
            feature_vector={
                "header_risk": 0.3,
                "url_reputation_risk": 0.8,
                "nlp_risk": 0.7,
            },
        )
        assert len(record.feature_vector) == 3
        assert record.feature_vector["url_reputation_risk"] == 0.8

    def test_feedback_record_timestamp_default(self):
        """Test that feedback record gets default timestamp."""
        record = FeedbackRecord(
            email_id="email_789",
            original_verdict=Verdict.SUSPICIOUS,
            correct_label=Verdict.CONFIRMED_PHISHING,
            analyst_notes="Confirmed phishing",
            feature_vector={},
        )
        assert record.submitted_at is not None
        assert isinstance(record.submitted_at, datetime)


class TestDataIntegrity:
    """Test data integrity and constraints."""

    def test_email_object_serialization(self, sample_email_clean):
        """Test that email objects can be serialized and deserialized."""
        data = asdict(sample_email_clean)
        assert data["email_id"] == sample_email_clean.email_id
        assert data["from_address"] == sample_email_clean.from_address

    def test_pipeline_result_verdict_coverage(self):
        """Test that all verdicts can be used in pipeline results."""
        for verdict in Verdict:
            result = PipelineResult(
                email_id="test",
                verdict=verdict,
                overall_score=0.5,
                overall_confidence=0.8,
                analyzer_results={},
                extracted_urls=[],
                iocs={},
                reasoning="Test",
            )
            assert result.verdict == verdict

    def test_analyzer_result_confidence_zero(self):
        """Test analyzer result with zero confidence (no data)."""
        result = AnalyzerResult(
            analyzer_name="no_data_analyzer",
            risk_score=0.5,
            confidence=0.0,  # No data available
            details={"status": "skipped"},
        )
        assert result.confidence == 0.0
        assert result.risk_score == 0.5  # Score doesn't matter if confidence is 0

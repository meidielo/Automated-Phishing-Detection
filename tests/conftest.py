"""
Shared pytest fixtures for the phishing detection test suite.

Provides sample data objects, mocked analyzers, and reusable test utilities.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from src.models import (
    EmailObject,
    AttachmentObject,
    ExtractedURL,
    URLSource,
    AnalyzerResult,
    PipelineResult,
    Verdict,
    HeaderAnalysisDetail,
    IntentCategory,
    IntentClassification,
)
from src.config import PipelineConfig, ScoringConfig, APIConfig, IMAPConfig


@pytest.fixture
def scoring_config():
    """Provide a standard scoring configuration."""
    return ScoringConfig(
        weights={
            "header_analysis": 0.10,
            "url_reputation": 0.15,
            "domain_intelligence": 0.10,
            "url_detonation": 0.15,
            "brand_impersonation": 0.10,
            "attachment_analysis": 0.15,
            "nlp_intent": 0.15,
            "sender_profiling": 0.10,
        },
        thresholds={
            "CLEAN": (0.0, 0.3),
            "SUSPICIOUS": (0.3, 0.6),
            "LIKELY_PHISHING": (0.6, 0.8),
            "CONFIRMED_PHISHING": (0.8, 1.0),
        },
    )


@pytest.fixture
def pipeline_config(scoring_config):
    """Provide a standard pipeline configuration."""
    return PipelineConfig(
        api=APIConfig(
            virustotal_key="test_vt_key",
            urlscan_key="test_urlscan_key",
            abuseipdb_key="test_abuseipdb_key",
            google_safebrowsing_key="test_gsb_key",
            sandbox_provider="hybrid_analysis",
            hybrid_analysis_key="test_ha_key",
            llm_provider="anthropic",
            anthropic_key="test_anthropic_key",
        ),
        imap=IMAPConfig(
            host="imap.example.com",
            port=993,
            user="test@example.com",
            password="test_password",
            folder="INBOX",
        ),
        scoring=scoring_config,
        max_concurrent_analyzers=10,
        url_detonation_timeout=30,
        pipeline_timeout=120,
        feedback_db_path="tests/data/feedback.db",
        log_level="INFO",
        dashboard_port=8000,
        analyst_api_token="test_token_12345",
    )


@pytest.fixture
def sample_attachment():
    """Create a sample attachment object."""
    return AttachmentObject(
        filename="document.pdf",
        content_type="application/pdf",
        magic_type="application/pdf",
        size_bytes=102400,
        content=b"%PDF-1.4\n%test pdf content",
        is_archive=False,
        has_macros=False,
        nested_files=[],
    )


@pytest.fixture
def sample_email_clean():
    """Create a sample clean email object."""
    return EmailObject(
        email_id="clean_email_001",
        raw_headers={
            "from": ["John Doe <john@trusted-company.com>"],
            "to": ["recipient@example.com"],
            "subject": ["Team Meeting Reminder"],
            "date": ["Mon, 08 Mar 2026 10:00:00 +0000"],
            "message-id": ["<clean_email_001@trusted-company.com>"],
            "received": [
                "from mail.trusted-company.com ([192.0.2.1]) by mx.example.com with SMTP",
                "from trusted-company.com by mail.trusted-company.com with SMTP"
            ],
        },
        from_address="john@trusted-company.com",
        from_display_name="John Doe",
        reply_to=None,
        to_addresses=["recipient@example.com"],
        cc_addresses=[],
        subject="Team Meeting Reminder",
        body_plain="Hi, reminding you about our team meeting tomorrow at 2 PM. See you there!",
        body_html="<html><body>Hi, reminding you about our team meeting tomorrow at 2 PM. See you there!</body></html>",
        date=datetime(2026, 3, 8, 10, 0, 0, tzinfo=timezone.utc),
        attachments=[],
        inline_images=[],
        message_id="clean_email_001@trusted-company.com",
        received_chain=[
            "from mail.trusted-company.com ([192.0.2.1]) by mx.example.com with SMTP",
            "from trusted-company.com by mail.trusted-company.com with SMTP"
        ],
    )


@pytest.fixture
def sample_email_phishing():
    """Create a sample phishing email object."""
    return EmailObject(
        email_id="phishing_email_001",
        raw_headers={
            "from": ["Support <support@legitimate-bank.com>"],
            "to": ["victim@example.com"],
            "subject": ["Urgent: Verify Your Account"],
            "date": ["Mon, 08 Mar 2026 15:30:00 +0000"],
            "message-id": ["<phishing_email_001@fake-smtp.net>"],
            "received": [
                "from suspicious-host.net ([203.0.113.50]) by mx.example.com with SMTP",
                "from unknown-relay.ru by suspicious-host.net with SMTP"
            ],
        },
        from_address="support@legitimate-bank.com",
        from_display_name="Support",
        reply_to="confirm@suspicious-domain.net",
        to_addresses=["victim@example.com"],
        cc_addresses=[],
        subject="Urgent: Verify Your Account",
        body_plain="Click here to verify your account: http://legitimate-bank-secure.ru/verify",
        body_html='<html><body><a href="http://legitimate-bank-secure.ru/verify">Click here to verify your account</a></body></html>',
        date=datetime(2026, 3, 8, 15, 30, 0, tzinfo=timezone.utc),
        attachments=[
            AttachmentObject(
                filename="invoice.exe",
                content_type="application/octet-stream",
                magic_type="application/x-msdownload",
                size_bytes=51200,
                content=b"MZ\x90\x00",  # PE executable header
                is_archive=False,
                has_macros=False,
                nested_files=[],
            )
        ],
        inline_images=[],
        message_id="phishing_email_001@fake-smtp.net",
        received_chain=[
            "from suspicious-host.net ([203.0.113.50]) by mx.example.com with SMTP",
            "from unknown-relay.ru by suspicious-host.net with SMTP"
        ],
    )


@pytest.fixture
def sample_extracted_url():
    """Create a sample extracted URL."""
    return ExtractedURL(
        url="http://suspicious-domain.net/login",
        source=URLSource.BODY_HTML,
        source_detail="href attribute in email body",
        resolved_url="http://malicious-site.ru:8080/phishing",
        redirect_chain=["http://suspicious-domain.net/login", "http://redirect.net/v1", "http://malicious-site.ru:8080/phishing"],
    )


@pytest.fixture
def sample_analyzer_result_benign():
    """Create a benign analyzer result."""
    return AnalyzerResult(
        analyzer_name="url_reputation",
        risk_score=0.1,
        confidence=0.95,
        details={
            "url_count": 0,
            "urls_analyzed": {},
            "malicious_count": 0,
        },
        errors=[],
    )


@pytest.fixture
def sample_analyzer_result_suspicious():
    """Create a suspicious analyzer result."""
    return AnalyzerResult(
        analyzer_name="nlp_intent",
        risk_score=0.7,
        confidence=0.85,
        details={
            "intent_classification": {
                "category": IntentCategory.CREDENTIAL_HARVESTING.value,
                "confidence": 0.85,
                "reasoning": "Email contains urgency language and requests credential verification",
                "urgency_score": 0.9,
                "red_flags": ["fake urgency", "credential request", "spoofed sender"],
            }
        },
        errors=[],
    )


@pytest.fixture
def sample_analyzer_results_clean(sample_analyzer_result_benign):
    """Create a dict of analyzer results for a clean email."""
    return {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.05,
            confidence=1.0,
            details={
                "header_analysis_detail": HeaderAnalysisDetail(
                    spf_pass=True,
                    dkim_pass=True,
                    dmarc_pass=True,
                    from_reply_to_mismatch=False,
                    display_name_spoofing=False,
                    suspicious_received_chain=False,
                    received_chain_details=[],
                    envelope_from_mismatch=False,
                ).__dict__
            },
            errors=[],
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.0,
            confidence=1.0,
            details={
                "url_count": 0,
                "urls_analyzed": {},
            },
            errors=[],
        ),
        "domain_intelligence": AnalyzerResult(
            analyzer_name="domain_intelligence",
            risk_score=0.0,
            confidence=0.9,
            details={
                "domain": "trusted-company.com",
                "age_days": 3650,
                "reputation": "trusted",
            },
            errors=[],
        ),
        "url_detonation": AnalyzerResult(
            analyzer_name="url_detonation",
            risk_score=0.0,
            confidence=0.8,
            details={"detonation_results": []},
            errors=[],
        ),
        "brand_impersonation": AnalyzerResult(
            analyzer_name="brand_impersonation",
            risk_score=0.0,
            confidence=1.0,
            details={
                "detected_brands": [],
                "impersonation_score": 0.0,
            },
            errors=[],
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.0,
            confidence=1.0,
            details={
                "attachment_count": 0,
                "attachments": [],
            },
            errors=[],
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.0,
            confidence=1.0,
            details={
                "intent_classification": {
                    "category": IntentCategory.LEGITIMATE.value,
                    "confidence": 1.0,
                    "reasoning": "Routine business communication",
                    "urgency_score": 0.0,
                    "red_flags": [],
                }
            },
            errors=[],
        ),
        "sender_profiling": AnalyzerResult(
            analyzer_name="sender_profiling",
            risk_score=0.0,
            confidence=1.0,
            details={
                "sender": "john@trusted-company.com",
                "reputation": "trusted",
                "previous_interactions": 50,
            },
            errors=[],
        ),
    }


@pytest.fixture
def sample_analyzer_results_phishing():
    """Create a dict of analyzer results for a phishing email."""
    return {
        "header_analysis": AnalyzerResult(
            analyzer_name="header_analysis",
            risk_score=0.8,
            confidence=0.95,
            details={
                "header_analysis_detail": HeaderAnalysisDetail(
                    spf_pass=False,
                    dkim_pass=False,
                    dmarc_pass=False,
                    from_reply_to_mismatch=True,
                    display_name_spoofing=True,
                    suspicious_received_chain=True,
                    received_chain_details=[
                        {"from_host": "suspicious-host.net", "from_ip": "203.0.113.50"}
                    ],
                    envelope_from_mismatch=True,
                ).__dict__
            },
            errors=[],
        ),
        "url_reputation": AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.85,
            confidence=0.9,
            details={
                "url_count": 1,
                "urls_analyzed": {
                    "http://legitimate-bank-secure.ru/verify": {
                        "risk_score": 0.85,
                        "vendors_flagged": 8,
                        "total_vendors": 10,
                        "source": "virustotal",
                    }
                },
            },
            errors=[],
        ),
        "domain_intelligence": AnalyzerResult(
            analyzer_name="domain_intelligence",
            risk_score=0.7,
            confidence=0.85,
            details={
                "domain": "legitimate-bank-secure.ru",
                "age_days": 15,
                "reputation": "suspicious",
                "whois_privacy": True,
            },
            errors=[],
        ),
        "url_detonation": AnalyzerResult(
            analyzer_name="url_detonation",
            risk_score=0.9,
            confidence=0.8,
            details={
                "detonation_results": [
                    {
                        "url": "http://legitimate-bank-secure.ru/verify",
                        "verdict": "phishing",
                        "sandbox": "urlscan",
                    }
                ]
            },
            errors=[],
        ),
        "brand_impersonation": AnalyzerResult(
            analyzer_name="brand_impersonation",
            risk_score=0.9,
            confidence=0.95,
            details={
                "detected_brands": ["legitimate-bank"],
                "impersonation_score": 0.95,
                "confidence": 0.95,
            },
            errors=[],
        ),
        "attachment_analysis": AnalyzerResult(
            analyzer_name="attachment_analysis",
            risk_score=0.95,
            confidence=1.0,
            details={
                "attachment_count": 1,
                "attachments": [
                    {
                        "filename": "invoice.exe",
                        "risk_category": "malicious",
                        "hash_match_count": 45,
                        "sandbox_verdict": "trojan",
                    }
                ],
            },
            errors=[],
        ),
        "nlp_intent": AnalyzerResult(
            analyzer_name="nlp_intent",
            risk_score=0.85,
            confidence=0.9,
            details={
                "intent_classification": {
                    "category": IntentCategory.CREDENTIAL_HARVESTING.value,
                    "confidence": 0.9,
                    "reasoning": "Email contains urgency language and requests credential verification",
                    "urgency_score": 0.95,
                    "red_flags": ["fake urgency", "credential request", "spoofed sender"],
                }
            },
            errors=[],
        ),
        "sender_profiling": AnalyzerResult(
            analyzer_name="sender_profiling",
            risk_score=0.75,
            confidence=0.85,
            details={
                "sender": "support@legitimate-bank.com",
                "reputation": "suspicious",
                "domain_match": False,
                "first_contact": True,
            },
            errors=[],
        ),
    }


@pytest.fixture
def sample_pipeline_result_clean(sample_email_clean, sample_analyzer_results_clean):
    """Create a sample pipeline result for a clean email."""
    return PipelineResult(
        email_id=sample_email_clean.email_id,
        verdict=Verdict.CLEAN,
        overall_score=0.08,
        overall_confidence=0.95,
        analyzer_results=sample_analyzer_results_clean,
        extracted_urls=[],
        iocs={
            "urls": [],
            "attachments": [],
            "headers": {},
        },
        reasoning="This email shows strong legitimate indicators with all authentication checks passing.",
        timestamp=datetime.utcnow(),
    )


@pytest.fixture
def sample_pipeline_result_phishing(sample_email_phishing, sample_analyzer_results_phishing):
    """Create a sample pipeline result for a phishing email."""
    return PipelineResult(
        email_id=sample_email_phishing.email_id,
        verdict=Verdict.CONFIRMED_PHISHING,
        overall_score=0.85,
        overall_confidence=0.92,
        analyzer_results=sample_analyzer_results_phishing,
        extracted_urls=[],
        iocs={
            "urls": [
                {
                    "url": "http://legitimate-bank-secure.ru/verify",
                    "risk_score": 0.85,
                    "source": "virustotal",
                }
            ],
            "attachments": [
                {
                    "filename": "invoice.exe",
                    "risk_category": "malicious",
                }
            ],
            "headers": {},
        },
        reasoning="This email shows multiple phishing indicators including spoofed headers, malicious URLs, and dangerous attachments.",
        timestamp=datetime.utcnow(),
    )


@pytest.fixture
def mock_eml_parser():
    """Create a mocked EML parser."""
    parser = AsyncMock()
    parser.parse_file = AsyncMock()
    parser.parse_bytes = AsyncMock()
    return parser


@pytest.fixture
def mock_analyzer():
    """Create a mocked analyzer."""
    analyzer = AsyncMock()
    analyzer.analyze = AsyncMock(return_value=AnalyzerResult(
        analyzer_name="test_analyzer",
        risk_score=0.5,
        confidence=0.8,
        details={"test": "data"},
        errors=[],
    ))
    return analyzer

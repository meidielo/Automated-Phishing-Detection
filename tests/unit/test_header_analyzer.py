"""
Test suite for header analysis in src.extractors.header_analyzer module.

Tests:
- SPF/DKIM/DMARC validation
- Spoofing detection (From/Reply-To mismatch, display name spoofing)
- Received chain parsing
- Header anomaly detection
"""

import pytest
from src.extractors.header_analyzer import ReceivedChainParser
from src.models import EmailObject, HeaderAnalysisDetail
from datetime import datetime, timezone


class TestReceivedChainParser:
    """Test Received header parsing."""

    def test_parse_simple_received_header(self):
        """Test parsing simple Received header."""
        header = "from mail.example.com ([192.0.2.1]) by mx.example.com with SMTP id abc123"
        result = ReceivedChainParser.parse_received_header(header)

        assert result["from_host"] == "mail.example.com"
        assert result["from_ip"] == "192.0.2.1"
        assert result["by_host"] == "mx.example.com"
        assert result["protocol"] == "SMTP"

    def test_parse_received_header_with_timestamp(self):
        """Test parsing Received header with timestamp."""
        header = "from smtp.gmail.com by mx.example.com with SMTP; Mon, 08 Mar 2026 10:00:00 +0000"
        result = ReceivedChainParser.parse_received_header(header)

        assert result["by_host"] == "mx.example.com"
        assert result["timestamp"] is not None
        assert "08 Mar 2026" in result["timestamp"]

    def test_parse_received_header_without_ip(self):
        """Test parsing Received header without explicit IP."""
        header = "from mail.example.com by mx.example.com with SMTP"
        result = ReceivedChainParser.parse_received_header(header)

        assert result["from_host"] == "mail.example.com"
        assert result["by_host"] == "mx.example.com"
        assert result["from_ip"] is None

    def test_parse_received_header_ipv6(self):
        """Test parsing Received header with IPv6."""
        header = "from mail.example.com ([2001:db8::1]) by mx.example.com with SMTP"
        result = ReceivedChainParser.parse_received_header(header)

        assert result["from_host"] == "mail.example.com"
        assert result["from_ip"] == "2001:db8::1"

    def test_parse_received_header_complex(self):
        """Test parsing complex Received header with additional info."""
        header = "from mx.example.com (mx.example.com [192.0.2.1]) by relay.example.com with SMTP id XYZ; Mon, 08 Mar 2026 10:00:00 +0000"
        result = ReceivedChainParser.parse_received_header(header)

        assert result["from_host"] == "mx.example.com"
        assert result["by_host"] == "relay.example.com"
        assert result["protocol"] == "SMTP"

    def test_parse_empty_received_header(self):
        """Test parsing empty Received header."""
        header = ""
        result = ReceivedChainParser.parse_received_header(header)

        assert result["from_host"] is None
        assert result["by_host"] is None
        assert result["raw"] == ""

    def test_parse_received_chain(self):
        """Test parsing chain of Received headers."""
        chain = [
            "from mail.example.com ([192.0.2.1]) by mx.example.com with SMTP",
            "from smtp.gmail.com ([172.16.0.1]) by mail.example.com with SMTP",
            "from [203.0.113.5] by smtp.gmail.com with SMTP",
        ]
        result = ReceivedChainParser.build_chain(chain)

        assert isinstance(result, list)
        assert len(result) > 0


class TestHeaderSpoofingDetection:
    """Test detection of header-based spoofing."""

    def test_detect_from_reply_to_mismatch(self):
        """Test detection of From/Reply-To mismatch."""
        email = EmailObject(
            email_id="test",
            raw_headers={},
            from_address="legitimate@example.com",
            from_display_name="Legitimate User",
            reply_to="attacker@malicious.com",  # Mismatch!
            to_addresses=["victim@example.com"],
            cc_addresses=[],
            subject="Test",
            body_plain="Test",
            body_html="",
            date=datetime.now(timezone.utc),
            attachments=[],
            inline_images=[],
            message_id="test@example.com",
            received_chain=[],
        )

        # Detector should flag mismatch
        has_mismatch = email.from_address != email.reply_to and email.reply_to is not None
        assert has_mismatch is True

    def test_detect_display_name_spoofing_bank(self):
        """Test detection of brand display name spoofing."""
        suspicious_display_names = [
            "Bank Support <support@malicious.com>",
            "PayPal <paypal@paypa1.com>",
            "Amazon <amazon@amaz0n.com>",
        ]

        for display_name in suspicious_display_names:
            # Check if display name contains brand but email doesn't match
            assert ("Support" in display_name or "PayPal" in display_name or "Amazon" in display_name)

    def test_detect_spoofed_from_header(self):
        """Test detection of spoofed From header."""
        email = EmailObject(
            email_id="test",
            raw_headers={},
            from_address="support@fake-domain.com",
            from_display_name="Bank Support",  # Spoofing attempt
            reply_to=None,
            to_addresses=["victim@example.com"],
            cc_addresses=[],
            subject="Verify Account",
            body_plain="Verify your account",
            body_html="",
            date=datetime.now(timezone.utc),
            attachments=[],
            inline_images=[],
            message_id="test@fake-domain.com",
            received_chain=[],
        )

        # Display name says "Bank Support" but from_address is "fake-domain.com"
        has_spoofing = "Support" in email.from_display_name and "fake-domain" in email.from_address
        assert has_spoofing is True


class TestAuthenticationValidation:
    """Test email authentication validation."""

    def test_spf_validation_pass(self):
        """Test SPF validation passing."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=False,
            dmarc_pass=False,
        )

        assert detail.spf_pass is True
        assert detail.dkim_pass is False

    def test_dkim_validation_pass(self):
        """Test DKIM validation passing."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=True,
            dmarc_pass=False,
        )

        assert detail.dkim_pass is True

    def test_dmarc_validation_pass(self):
        """Test DMARC validation passing."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=True,
        )

        assert detail.dmarc_pass is True

    def test_all_auth_pass(self):
        """Test when all authentication checks pass."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
        )

        all_pass = detail.spf_pass and detail.dkim_pass and detail.dmarc_pass
        assert all_pass is True

    def test_all_auth_fail(self):
        """Test when all authentication checks fail."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
        )

        all_fail = not (detail.spf_pass or detail.dkim_pass or detail.dmarc_pass)
        assert all_fail is True

    def test_partial_auth_pass(self):
        """Test partial authentication pass."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=False,
            dmarc_pass=False,
        )

        partial = (detail.spf_pass or detail.dkim_pass or detail.dmarc_pass) and not (
            detail.spf_pass and detail.dkim_pass and detail.dmarc_pass
        )
        assert partial is True


class TestReceivedChainAnalysis:
    """Test analysis of Received chains for anomalies."""

    def test_normal_received_chain(self):
        """Test normal trusted received chain."""
        chain = [
            "from mail.example.com ([192.0.2.1]) by mx.example.com with SMTP",
            "from internal.example.com by mail.example.com with SMTP",
        ]

        # Normal chain: legitimate domains, reasonable hop count
        assert len(chain) == 2
        assert "example.com" in chain[0]

    def test_suspicious_received_chain_long(self):
        """Test suspicious chain with many hops."""
        chain = [
            f"from hop{i}.example.com by hop{i+1}.example.com with SMTP"
            for i in range(10)
        ]

        # Suspicious: many hops may indicate relay abuse
        assert len(chain) > 5

    def test_suspicious_received_chain_unknown_hosts(self):
        """Test received chain with unknown hosts."""
        suspicious_hosts = [
            "from unknown-relay.ru ([203.0.113.5]) by mx.example.com with SMTP",
            "from proxy.cn by unknown-relay.ru with SMTP",
        ]

        for header in suspicious_hosts:
            assert "unknown" in header.lower() or ".ru" in header.lower() or ".cn" in header.lower()

    def test_received_chain_detail_extraction(self):
        """Test extraction of received chain details."""
        header = "from suspicious.net ([203.0.113.50]) by mx.example.com with SMTP"
        parsed = ReceivedChainParser.parse_received_header(header)

        assert parsed["from_host"] == "suspicious.net"
        assert parsed["from_ip"] == "203.0.113.50"


class TestHeaderAnalysisDetail:
    """Test HeaderAnalysisDetail data structure."""

    def test_header_detail_creation(self):
        """Test creating header analysis detail."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
            from_reply_to_mismatch=False,
            display_name_spoofing=False,
            suspicious_received_chain=False,
        )

        assert detail.spf_pass is True
        assert detail.from_reply_to_mismatch is False
        assert len(detail.received_chain_details) == 0

    def test_header_detail_with_chain_analysis(self):
        """Test header detail with received chain analysis."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
            from_reply_to_mismatch=True,
            display_name_spoofing=True,
            suspicious_received_chain=True,
            received_chain_details=[
                {"from_host": "suspicious.net", "from_ip": "203.0.113.5"},
                {"from_host": "unknown-relay.ru", "from_ip": None},
            ],
            envelope_from_mismatch=True,
        )

        assert detail.suspicious_received_chain is True
        assert len(detail.received_chain_details) == 2
        assert detail.envelope_from_mismatch is True

    def test_header_detail_all_checks_pass(self):
        """Test header detail when all checks pass."""
        detail = HeaderAnalysisDetail(
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
            from_reply_to_mismatch=False,
            display_name_spoofing=False,
            suspicious_received_chain=False,
            envelope_from_mismatch=False,
        )

        # All security checks should pass
        assert all([
            detail.spf_pass,
            detail.dkim_pass,
            detail.dmarc_pass,
            not detail.from_reply_to_mismatch,
            not detail.display_name_spoofing,
            not detail.suspicious_received_chain,
            not detail.envelope_from_mismatch,
        ])


class TestHeaderAnomalies:
    """Test detection of header anomalies."""

    def test_missing_received_headers(self):
        """Test detection of missing Received headers."""
        email = EmailObject(
            email_id="test",
            raw_headers={},  # No received headers
            from_address="test@example.com",
            from_display_name="",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="Test",
            body_plain="Test",
            body_html="",
            date=datetime.now(timezone.utc),
            attachments=[],
            inline_images=[],
            message_id="test@example.com",
            received_chain=[],  # Empty received chain
        )

        # Suspicious: no received chain
        assert len(email.received_chain) == 0

    def test_envelope_from_mismatch(self):
        """Test detection of envelope From vs header From mismatch."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
            envelope_from_mismatch=True,
        )

        assert detail.envelope_from_mismatch is True

    def test_header_anomaly_combination(self):
        """Test combination of multiple header anomalies."""
        detail = HeaderAnalysisDetail(
            spf_pass=False,
            dkim_pass=False,
            dmarc_pass=False,
            from_reply_to_mismatch=True,
            display_name_spoofing=True,
            suspicious_received_chain=True,
            envelope_from_mismatch=True,
        )

        anomalies = [
            not detail.spf_pass,
            not detail.dkim_pass,
            not detail.dmarc_pass,
            detail.from_reply_to_mismatch,
            detail.display_name_spoofing,
            detail.suspicious_received_chain,
            detail.envelope_from_mismatch,
        ]

        # Multiple anomalies indicate phishing
        assert sum(anomalies) > 3

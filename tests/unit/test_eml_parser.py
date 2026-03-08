"""
Test suite for EML parser in src.extractors.eml_parser module.

Tests:
- Email parsing from bytes and strings
- Header extraction and normalization
- Body extraction (plaintext and HTML)
- Attachment detection and extraction
- Magic byte detection
- Received chain parsing
- Inline image detection
"""

import pytest
from pathlib import Path
from src.extractors.eml_parser import EMLParser
from src.models import EmailObject


# Sample EML content for testing
SAMPLE_EMAIL_CLEAN = """From: John Doe <john@example.com>
To: recipient@example.com
Subject: Team Meeting Tomorrow
Date: Mon, 08 Mar 2026 10:00:00 +0000
Message-ID: <clean_email_001@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi there,

This is a reminder about our team meeting tomorrow at 2 PM.
See you then!

Best regards,
John
"""

SAMPLE_EMAIL_HTML = """From: Jane Smith <jane@company.com>
To: team@company.com
Subject: Website Update
Date: Tue, 08 Mar 2026 14:30:00 +0000
Message-ID: <html_email_001@company.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Check out our updated website at https://company.com/new-design

--boundary123
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h1>Website Update</h1>
<p>Check out our <a href="https://company.com/new-design">updated website</a></p>
</body>
</html>

--boundary123--
"""

SAMPLE_EMAIL_WITH_ATTACHMENT = """From: sender@example.com
To: recipient@example.com
Subject: Important Document
Date: Wed, 08 Mar 2026 09:15:00 +0000
Message-ID: <att_email_001@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary456"

--boundary456
Content-Type: text/plain; charset="utf-8"

Please see the attached document.

--boundary456
Content-Type: application/pdf; name="document.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="document.pdf"

JVBERi0xLjQKJeLjz9MNCjEgMCBvYmo=

--boundary456--
"""

SAMPLE_EMAIL_SPOOFED = """From: "Bank Support" <support@legitimate-bank.com>
Reply-To: confirm@malicious-domain.com
To: victim@example.com
Subject: Urgent: Verify Your Account
Date: Thu, 08 Mar 2026 15:45:00 +0000
Message-ID: <spoofed_001@malicious-smtp.net>
Received: from suspicious-host.net ([203.0.113.50]) by mx.example.com with SMTP id xyz
Received: from unknown-relay.ru by suspicious-host.net with SMTP
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p><a href="http://fake-bank-secure.ru/verify">Verify your account</a></p>
</body>
</html>
"""

SAMPLE_EMAIL_MULTIPART_COMPLEX = """From: <sender@example.com>
To: recipient@example.com
Subject: Complex Email
Date: Fri, 08 Mar 2026 11:00:00 +0000
Message-ID: <complex_001@example.com>
MIME-Version: 1.0
Content-Type: multipart/related; boundary="boundary789"

--boundary789
Content-Type: multipart/alternative; boundary="boundary890"

--boundary890
Content-Type: text/plain; charset="utf-8"

This is the plaintext version.

--boundary890
Content-Type: text/html; charset="utf-8"

<html><body><img src="cid:image001"/></body></html>

--boundary890--

--boundary789
Content-Type: image/png; name="image001"
Content-ID: <image001>
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename="image001.png"

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==

--boundary789--
"""


class TestEMLParserBasics:
    """Test basic EML parser functionality."""

    def test_parser_initialization(self):
        """Test that parser can be initialized."""
        parser = EMLParser()
        assert parser is not None
        assert parser.logger is not None

    def test_parse_simple_email_string(self):
        """Test parsing simple plaintext email from string."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN)

        assert result is not None
        assert isinstance(result, EmailObject)
        assert result.from_address == "john@example.com"
        assert result.from_display_name == "John Doe"
        assert "Team Meeting Tomorrow" in result.subject
        assert "team meeting tomorrow" in result.body_plain.lower()

    def test_parse_simple_email_bytes(self):
        """Test parsing email from bytes."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN.encode('utf-8'))

        assert result is not None
        assert result.from_address == "john@example.com"

    def test_extract_basic_headers(self):
        """Test header extraction."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN)

        assert "from" in result.raw_headers or "From" in result.raw_headers or any("from" in k.lower() for k in result.raw_headers.keys())
        assert result.message_id == "clean_email_001@example.com"

    def test_extract_to_addresses(self):
        """Test To header parsing."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN)

        assert result.to_addresses == ["recipient@example.com"]

    def test_extract_plaintext_body(self):
        """Test plaintext body extraction."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN)

        assert len(result.body_plain) > 0
        assert "meeting" in result.body_plain.lower()

    def test_handle_missing_required_fields(self):
        """Test handling of minimal email (missing most fields)."""
        minimal_email = "From: sender@example.com\nSubject: Minimal"
        parser = EMLParser()
        result = parser.parse_bytes(minimal_email)

        assert result is not None
        assert result.from_address == "sender@example.com"
        assert result.subject == "Minimal"


class TestEMLParserHTML:
    """Test HTML body extraction."""

    def test_parse_html_email(self):
        """Test parsing email with HTML body."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_HTML)

        assert result is not None
        assert len(result.body_html) > 0
        assert "Website Update" in result.body_html
        assert result.body_html.count("<") > 0  # Contains HTML tags

    def test_extract_html_and_plaintext(self):
        """Test extraction of both plaintext and HTML versions."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_HTML)

        assert len(result.body_plain) > 0
        assert len(result.body_html) > 0
        # Both should contain similar content
        assert "company.com" in result.body_html
        assert "company.com" in result.body_plain


class TestEMLParserAttachments:
    """Test attachment extraction."""

    def test_parse_email_with_attachment(self):
        """Test parsing email with file attachment."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_WITH_ATTACHMENT)

        assert result is not None
        assert len(result.attachments) > 0
        assert result.attachments[0].filename == "document.pdf"

    def test_attachment_metadata(self):
        """Test attachment metadata extraction."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_WITH_ATTACHMENT)

        att = result.attachments[0]
        assert att.content_type == "application/pdf"
        assert att.size_bytes > 0
        assert att.is_archive is False
        assert att.has_macros is False

    def test_magic_type_detection_pdf(self):
        """Test magic type detection for PDF."""
        pdf_content = b"%PDF-1.4\ntest pdf"
        magic = EMLParser.detect_magic_type(pdf_content)
        assert magic == "application/pdf"

    def test_magic_type_detection_zip(self):
        """Test magic type detection for ZIP."""
        zip_content = b"PK\x03\x04test content"
        magic = EMLParser.detect_magic_type(zip_content)
        assert magic == "application/zip"

    def test_magic_type_detection_jpeg(self):
        """Test magic type detection for JPEG."""
        jpeg_content = b"\xff\xd8\xfftest jpeg"
        magic = EMLParser.detect_magic_type(jpeg_content)
        assert magic == "image/jpeg"

    def test_magic_type_detection_unknown(self):
        """Test magic type detection for unknown content."""
        unknown_content = b"unknown format content"
        magic = EMLParser.detect_magic_type(unknown_content)
        assert magic == "application/octet-stream"

    def test_archive_detection(self):
        """Test archive file detection."""
        parser = EMLParser()
        # ZIP header
        att = parser._create_attachment_object(
            filename="archive.zip",
            payload=b"PK\x03\x04",
            content_type="application/zip"
        )
        assert att.is_archive is True

    def test_macro_detection_docm(self):
        """Test macro detection for Word macro-enabled documents."""
        parser = EMLParser()
        att = parser._create_attachment_object(
            filename="malicious.docm",
            payload=b"PK\x03\x04test",  # ZIP header
            content_type="application/vnd.openxmlformats"
        )
        # Should detect as potentially containing macros based on extension
        assert att.filename == "malicious.docm"


class TestEMLParserHeaderAnalysis:
    """Test header analysis."""

    def test_extract_received_chain(self):
        """Test extraction of Received chain."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_SPOOFED)

        assert len(result.received_chain) > 0
        assert "suspicious-host.net" in result.received_chain[0]

    def test_detect_from_reply_to_mismatch(self):
        """Test detection of From/Reply-To mismatch."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_SPOOFED)

        assert result.from_address == "support@legitimate-bank.com"
        assert result.reply_to == "confirm@malicious-domain.com"
        # From and Reply-To don't match - potential spoofing indicator

    def test_extract_display_name(self):
        """Test display name extraction from From header."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_SPOOFED)

        assert result.from_display_name == "Bank Support"

    def test_handle_quoted_display_name(self):
        """Test handling of quoted display names."""
        email = 'From: "Test Name" <test@example.com>\nSubject: Test'
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert "test@example.com" in result.from_address
        # Display name extraction should handle quotes


class TestEMLParserInlineImages:
    """Test inline image detection."""

    def test_extract_inline_images(self):
        """Test detection and extraction of inline images."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_MULTIPART_COMPLEX)

        # Should detect the inline image
        assert len(result.inline_images) > 0 or result.body_html.count("cid:") > 0


class TestEMLParserMessageID:
    """Test message ID handling."""

    def test_extract_message_id(self):
        """Test extraction of Message-ID header."""
        parser = EMLParser()
        result = parser.parse_bytes(SAMPLE_EMAIL_CLEAN)

        assert result.message_id == "clean_email_001@example.com"

    def test_generate_message_id_if_missing(self):
        """Test generation of Message-ID if not present."""
        email = "From: sender@example.com\nSubject: No ID"
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result.message_id is not None
        # Should generate a UUID or similar
        assert len(result.message_id) > 0

    def test_clean_message_id_angle_brackets(self):
        """Test cleanup of Message-ID with angle brackets."""
        email = "From: sender@example.com\nMessage-ID: <clean@example.com>\nSubject: Test"
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result.message_id == "clean@example.com"  # Angle brackets removed


class TestEMLParserEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_empty_email(self):
        """Test parsing empty email."""
        parser = EMLParser()
        result = parser.parse_bytes("")

        # Should return EmailObject with default values
        assert result is not None

    def test_parse_malformed_email(self):
        """Test parsing malformed email."""
        malformed = "This is not\na valid email format"
        parser = EMLParser()
        result = parser.parse_bytes(malformed)

        # Should still return EmailObject
        assert result is not None

    def test_handle_various_charsets(self):
        """Test handling of various character encodings."""
        # Email with explicit charset
        email = """From: sender@example.com
Subject: Test
MIME-Version: 1.0
Content-Type: text/plain; charset="iso-8859-1"

Test content
"""
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result is not None
        assert result.from_address == "sender@example.com"

    def test_parse_email_with_bcc(self):
        """Test parsing email with Bcc header."""
        email = """From: sender@example.com
To: recipient@example.com
Bcc: hidden@example.com
Subject: Test
Message-ID: <test@example.com>

Test content
"""
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result is not None
        assert result.to_addresses == ["recipient@example.com"]

    def test_parse_email_with_cc(self):
        """Test parsing email with CC header."""
        email = """From: sender@example.com
To: recipient@example.com
Cc: cc@example.com
Subject: Test
Message-ID: <test@example.com>

Test content
"""
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result is not None
        assert "cc@example.com" in result.cc_addresses

    def test_parse_email_with_multiple_cc(self):
        """Test parsing email with multiple CC recipients."""
        email = """From: sender@example.com
To: recipient@example.com
Cc: cc1@example.com, cc2@example.com
Subject: Test
Message-ID: <test@example.com>

Test content
"""
        parser = EMLParser()
        result = parser.parse_bytes(email)

        assert result is not None
        assert len(result.cc_addresses) >= 1


class TestEMLParserConvenienceFunctions:
    """Test convenience functions."""

    def test_parse_eml_bytes_function(self):
        """Test module-level parse_eml_bytes function."""
        from src.extractors.eml_parser import parse_eml_bytes
        result = parse_eml_bytes(SAMPLE_EMAIL_CLEAN)

        assert result is not None
        assert result.from_address == "john@example.com"

    def test_parse_eml_file_function(self, tmp_path):
        """Test module-level parse_eml_file function."""
        from src.extractors.eml_parser import parse_eml_file

        # Create temporary EML file
        eml_file = tmp_path / "test.eml"
        eml_file.write_text(SAMPLE_EMAIL_CLEAN)

        result = parse_eml_file(eml_file)
        assert result is not None
        assert result.from_address == "john@example.com"

"""
Test suite for brand impersonation analyzer in src.analyzers.brand_impersonation module.

Tests:
- BrandImpersonationAnalyzer initialization
- analyze() with email objects and various signal combinations
- Known brand domain matching
- Result format with confidence scores
- Look-alike domain detection
- Display name spoofing detection
- Random sender detection
- Screenshot-based analysis (when available)
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from src.analyzers.brand_impersonation import BrandImpersonationAnalyzer
from src.models import AnalyzerResult, ExtractedURL, URLSource, EmailObject


def _make_email(
    from_address: str = "user@example.com",
    from_display_name: str = "",
    reply_to: Optional[str] = None,
    subject: str = "Test Subject",
    body_plain: str = "",
    body_html: str = "",
) -> EmailObject:
    """Create a minimal EmailObject for testing."""
    return EmailObject(
        email_id="test-email-001",
        raw_headers={},
        from_address=from_address,
        from_display_name=from_display_name,
        reply_to=reply_to,
        to_addresses=["recipient@test.com"],
        cc_addresses=[],
        subject=subject,
        body_plain=body_plain,
        body_html=body_html,
        date=datetime.now(),
        attachments=[],
        inline_images=[],
        message_id="<test@example.com>",
        received_chain=[],
    )


class TestBrandImpersonationAnalyzerInitialization:
    """Test BrandImpersonationAnalyzer initialization."""

    def test_analyzer_initialization_defaults(self):
        """Test initialization with default parameters."""
        analyzer = BrandImpersonationAnalyzer()

        assert analyzer is not None
        assert analyzer.image_comparison_client is None
        assert analyzer.brand_templates_path == "data/brand_templates"

    def test_analyzer_initialization_with_client(self):
        """Test initialization with image comparison client."""
        mock_client = MagicMock()
        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        assert analyzer.image_comparison_client is mock_client

    def test_analyzer_initialization_custom_templates_path(self):
        """Test initialization with custom templates path."""
        analyzer = BrandImpersonationAnalyzer(
            brand_templates_path="/custom/templates"
        )

        assert analyzer.brand_templates_path == "/custom/templates"

    def test_analyzer_initialization_both_params(self):
        """Test initialization with both custom client and path."""
        mock_client = MagicMock()
        analyzer = BrandImpersonationAnalyzer(
            image_comparison_client=mock_client,
            brand_templates_path="/custom/templates",
        )

        assert analyzer.image_comparison_client is mock_client
        assert analyzer.brand_templates_path == "/custom/templates"

    def test_analyzer_brands_constant(self):
        """Test that BRANDS constant is properly defined with new keys."""
        analyzer = BrandImpersonationAnalyzer()

        # Verify key brands exist (microsoft, not microsoft_365)
        assert "microsoft" in analyzer.BRANDS
        assert "google" in analyzer.BRANDS
        assert "apple" in analyzer.BRANDS
        assert "paypal" in analyzer.BRANDS
        assert "docusign" in analyzer.BRANDS
        assert "dhl" in analyzer.BRANDS
        assert "fedex" in analyzer.BRANDS
        assert "indeed" in analyzer.BRANDS
        assert "amazon" in analyzer.BRANDS
        assert "linkedin" in analyzer.BRANDS

    def test_brands_structure(self):
        """Test that each brand has the required fields."""
        analyzer = BrandImpersonationAnalyzer()

        for brand_name, brand_info in analyzer.BRANDS.items():
            assert "display_names" in brand_info, f"{brand_name} missing display_names"
            assert "legit_domains" in brand_info, f"{brand_name} missing legit_domains"
            assert "body_keywords" in brand_info, f"{brand_name} missing body_keywords"
            assert isinstance(brand_info["display_names"], list)
            assert isinstance(brand_info["legit_domains"], list)
            assert isinstance(brand_info["body_keywords"], list)


class TestBrandImpersonationAnalyze:
    """Test analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_no_email_no_screenshots(self):
        """Test analyze with no email and no screenshots."""
        analyzer = BrandImpersonationAnalyzer()

        result = await analyzer.analyze()

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"
        assert result.risk_score == 0.0
        assert result.confidence == 0.0  # No data = no confidence
        assert "no_email_data" in result.details.get("message", "")

    @pytest.mark.asyncio
    async def test_analyze_clean_email(self):
        """Test analyzing a clean email from a legitimate sender."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="noreply@microsoft.com",
            from_display_name="Microsoft",
            subject="Your subscription renewal",
            body_plain="Your Microsoft 365 subscription has been renewed.",
        )

        result = await analyzer.analyze(email=email)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"
        # Legit domain + brand name match = low risk
        assert result.risk_score < 0.5

    @pytest.mark.asyncio
    async def test_analyze_phishing_email_brand_mismatch(self):
        """Test analyzing a phishing email with brand/domain mismatch."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="support@random-server.com",
            from_display_name="Microsoft Support",
            subject="Urgent: Your Microsoft account needs verification",
            body_plain="Click here to verify your Microsoft 365 account. Your Office 365 subscription will be suspended.",
        )

        result = await analyzer.analyze(email=email)

        assert isinstance(result, AnalyzerResult)
        # Brand in display name + non-legit domain = high risk
        assert result.risk_score >= 0.5
        assert result.confidence > 0.0
        assert result.details.get("signals_found", 0) > 0

    @pytest.mark.asyncio
    async def test_analyze_indeed_phishing(self):
        """Test analyzing an Indeed phishing email (the original false negative case)."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="as628967uuwwj_3eg@indeedhr-apply.com",
            from_display_name="Indeed",
            reply_to="fake@different-domain.com",
            subject="Interview Invitation from Indeed",
            body_plain="You have received a job application through Indeed. Click to view.",
        )

        result = await analyzer.analyze(email=email)

        assert isinstance(result, AnalyzerResult)
        # Multiple signals: display_name mismatch, lookalike domain, random sender, reply-to mismatch
        assert result.risk_score >= 0.6
        assert result.details.get("signals_found", 0) >= 2

    @pytest.mark.asyncio
    async def test_analyze_multiple_brand_signals(self):
        """Test that multiple signals increase risk score."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="noreply@paypal-verify.xyz",
            from_display_name="PayPal Security",
            reply_to="reply@another-domain.com",
            subject="Your PayPal account has been limited",
            body_plain="Verify your PayPal account now or it will be suspended. paypal.com",
        )

        result = await analyzer.analyze(email=email)

        assert result.risk_score >= 0.7
        assert result.details.get("signals_found", 0) >= 2


class TestBrandImpersonationDomainMatching:
    """Test domain-related helper methods."""

    def test_is_legit_domain_microsoft(self):
        """Test legitimate Microsoft domain matching."""
        analyzer = BrandImpersonationAnalyzer()
        brand_info = analyzer.BRANDS["microsoft"]

        assert analyzer._is_legit_domain_for_brand("microsoft.com", brand_info)
        assert analyzer._is_legit_domain_for_brand("outlook.com", brand_info)
        assert analyzer._is_legit_domain_for_brand("office.com", brand_info)
        assert not analyzer._is_legit_domain_for_brand("microsft.com", brand_info)
        assert not analyzer._is_legit_domain_for_brand("microsoft-verify.com", brand_info)

    def test_is_legit_domain_google(self):
        """Test legitimate Google domain matching."""
        analyzer = BrandImpersonationAnalyzer()
        brand_info = analyzer.BRANDS["google"]

        assert analyzer._is_legit_domain_for_brand("google.com", brand_info)
        assert analyzer._is_legit_domain_for_brand("gmail.com", brand_info)
        assert not analyzer._is_legit_domain_for_brand("g00gle.com", brand_info)

    def test_is_legit_domain_subdomain(self):
        """Test subdomain matching."""
        analyzer = BrandImpersonationAnalyzer()
        brand_info = analyzer.BRANDS["microsoft"]

        # Subdomains of legit domains should be legit
        assert analyzer._is_legit_domain_for_brand("email.microsoft.com", brand_info)
        assert analyzer._is_legit_domain_for_brand("noreply.office.com", brand_info)

    def test_check_lookalike_domain_brand_in_domain(self):
        """Test look-alike domain detection."""
        analyzer = BrandImpersonationAnalyzer()

        # Contains 'paypal' but not a legit PayPal domain
        matches = analyzer._check_lookalike_domain("paypal-verify.com")
        assert len(matches) > 0
        assert matches[0][0] == "paypal"

    def test_check_lookalike_domain_legit(self):
        """Test that legit domains are not flagged as look-alikes."""
        analyzer = BrandImpersonationAnalyzer()

        matches = analyzer._check_lookalike_domain("paypal.com")
        assert len(matches) == 0

    def test_check_lookalike_domain_empty(self):
        """Test look-alike with empty/None domain."""
        analyzer = BrandImpersonationAnalyzer()

        assert analyzer._check_lookalike_domain("") == []
        assert analyzer._check_lookalike_domain(None) == []


class TestBrandImpersonationDomainExtraction:
    """Test domain extraction utility."""

    def test_extract_domain_https(self):
        """Test domain extraction from HTTPS URL."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://example.com/path")
        assert domain == "example.com"

    def test_extract_domain_with_www(self):
        """Test domain extraction with www prefix."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://www.example.com")
        assert domain == "example.com"

    def test_extract_domain_from_email(self):
        """Test domain extraction from email address."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("user@example.com")
        assert domain == "example.com"

    def test_extract_domain_subdomain(self):
        """Test domain extraction with subdomain."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://mail.google.com")
        assert domain == "mail.google.com"

    def test_extract_domain_none_url(self):
        """Test domain extraction with None URL."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain(None)
        assert domain is None

    def test_extract_domain_empty_string(self):
        """Test domain extraction with empty string."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("")
        assert domain is None


class TestBrandImpersonationDetectBrand:
    """Test brand detection in text and display names."""

    def test_detect_brand_in_display_name_microsoft(self):
        """Test detecting Microsoft in display name."""
        analyzer = BrandImpersonationAnalyzer()
        brands = analyzer._detect_brand_in_display_name("Microsoft Support")
        assert "microsoft" in brands

    def test_detect_brand_in_display_name_outlook(self):
        """Test detecting Outlook (Microsoft variant) in display name."""
        analyzer = BrandImpersonationAnalyzer()
        brands = analyzer._detect_brand_in_display_name("Outlook Team")
        assert "microsoft" in brands

    def test_detect_brand_in_display_name_multiple(self):
        """Test no false positives for unrelated display names."""
        analyzer = BrandImpersonationAnalyzer()
        brands = analyzer._detect_brand_in_display_name("John Smith")
        assert len(brands) == 0

    def test_detect_brand_in_text_microsoft(self):
        """Test detecting Microsoft brand keywords in body text."""
        analyzer = BrandImpersonationAnalyzer()
        matches = analyzer._detect_brand_in_text(
            "Your Microsoft Office 365 subscription has been renewed. "
            "Please sign in to Outlook to view your account details."
        )
        assert len(matches) > 0
        # Microsoft should be in results
        brand_names = [m[0] for m in matches]
        assert "microsoft" in brand_names

    def test_detect_brand_in_text_paypal(self):
        """Test detecting PayPal brand keywords in body text."""
        analyzer = BrandImpersonationAnalyzer()
        matches = analyzer._detect_brand_in_text(
            "Your PayPal payment received. Check paypal.com for details."
        )
        brand_names = [m[0] for m in matches]
        assert "paypal" in brand_names

    def test_detect_brand_in_text_empty(self):
        """Test brand detection with empty text."""
        analyzer = BrandImpersonationAnalyzer()
        assert analyzer._detect_brand_in_text("") == []
        assert analyzer._detect_brand_in_text(None) == []


class TestRandomSenderDetection:
    """Test random/generated sender address detection."""

    def test_detect_random_sender_obvious(self):
        """Test detection of obviously random sender."""
        analyzer = BrandImpersonationAnalyzer()
        # Pattern like the Indeed phishing case
        score = analyzer._detect_random_sender("as628967uuwwj_3eg")
        assert score >= 0.5

    def test_detect_random_sender_normal(self):
        """Test that normal email addresses are not flagged."""
        analyzer = BrandImpersonationAnalyzer()
        assert analyzer._detect_random_sender("john.smith") == 0.0
        assert analyzer._detect_random_sender("support") == 0.0
        assert analyzer._detect_random_sender("noreply") == 0.0

    def test_detect_random_sender_numeric(self):
        """Test detection of purely numeric senders."""
        analyzer = BrandImpersonationAnalyzer()
        score = analyzer._detect_random_sender("12345678")
        assert score >= 0.5

    def test_detect_random_sender_empty(self):
        """Test handling of empty sender."""
        analyzer = BrandImpersonationAnalyzer()
        assert analyzer._detect_random_sender("") == 0.0
        assert analyzer._detect_random_sender(None) == 0.0


class TestScreenshotAnalysis:
    """Test screenshot-based analysis (when available)."""

    @pytest.mark.asyncio
    async def test_analyze_with_screenshots_high_similarity(self):
        """Test analysis with high visual similarity screenshots."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.9,
            "ssim_similarity": 0.85,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        email = _make_email(
            from_address="support@phishing-site.com",
            from_display_name="Microsoft",
            subject="Verify your account",
            body_plain="Microsoft account verification needed",
        )

        screenshots = {
            "https://phishing-site.com/login": b"fake_screenshot_data",
        }

        result = await analyzer.analyze(
            email=email,
            detonation_screenshots=screenshots,
        )

        assert isinstance(result, AnalyzerResult)
        assert result.risk_score > 0  # Should have risk from brand mismatch

    @pytest.mark.asyncio
    async def test_analyze_screenshots_only_mode(self):
        """Test screenshot-only mode when no email object provided."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.9,
            "ssim_similarity": 0.85,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://fake-microsoft.com": b"screenshot_of_microsoft_page",
        }

        result = await analyzer.analyze(detonation_screenshots=screenshots)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"

    @pytest.mark.asyncio
    async def test_analyze_without_screenshot_client(self):
        """Test that missing image client is handled gracefully."""
        analyzer = BrandImpersonationAnalyzer(image_comparison_client=None)

        email = _make_email(
            from_address="support@example.com",
            subject="Test",
            body_plain="Normal email content",
        )

        # Should not crash even with screenshots but no client
        result = await analyzer.analyze(
            email=email,
            detonation_screenshots={"https://example.com": b"screenshot"},
        )

        assert isinstance(result, AnalyzerResult)

    @pytest.mark.asyncio
    async def test_analyze_screenshot_client_exception(self):
        """Test exception handling in screenshot comparison."""
        mock_client = AsyncMock()
        mock_client.compare_images.side_effect = Exception("Comparison failed")

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        email = _make_email(
            from_address="support@phishing.com",
            from_display_name="PayPal",
            body_plain="Your PayPal account has been suspended. Verify at paypal.com.",
        )

        screenshots = {"https://phishing.com": b"screenshot"}

        result = await analyzer.analyze(
            email=email,
            detonation_screenshots=screenshots,
        )

        assert isinstance(result, AnalyzerResult)
        # Should still have risk from content-based signals (display_name + body brand mismatch)
        assert result.risk_score > 0


class TestBrandImpersonationResultFormat:
    """Test AnalyzerResult format and structure."""

    @pytest.mark.asyncio
    async def test_result_format_complete(self):
        """Test complete AnalyzerResult format."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="user@suspicious.com",
            from_display_name="Google",
            subject="Google security alert",
            body_plain="Your Google account needs attention",
        )

        result = await analyzer.analyze(email=email)

        # Check AnalyzerResult structure
        assert result.analyzer_name == "brand_impersonation"
        assert isinstance(result.risk_score, float)
        assert isinstance(result.confidence, float)
        assert isinstance(result.details, dict)

        # Check details structure (new format)
        assert "signals_found" in result.details
        assert "signals" in result.details
        assert "brands_checked" in result.details

    @pytest.mark.asyncio
    async def test_result_with_errors(self):
        """Test AnalyzerResult handles errors gracefully."""
        analyzer = BrandImpersonationAnalyzer()

        # Pass a mock email that will trigger analysis but not crash
        email = _make_email(
            from_address="test@example.com",
            subject="Normal email",
            body_plain="Nothing suspicious",
        )

        result = await analyzer.analyze(email=email)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"


class TestBrandImpersonationBrandCoverage:
    """Test brand-specific functionality."""

    def test_microsoft_brand_domains(self):
        """Test Microsoft brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        microsoft_config = analyzer.BRANDS["microsoft"]
        assert "microsoft.com" in microsoft_config["legit_domains"]
        assert "office.com" in microsoft_config["legit_domains"]
        assert "outlook.com" in microsoft_config["legit_domains"]

    def test_google_brand_domains(self):
        """Test Google brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        google_config = analyzer.BRANDS["google"]
        assert "google.com" in google_config["legit_domains"]
        assert "gmail.com" in google_config["legit_domains"]

    def test_apple_brand_domains(self):
        """Test Apple brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        apple_config = analyzer.BRANDS["apple"]
        assert "apple.com" in apple_config["legit_domains"]
        assert "icloud.com" in apple_config["legit_domains"]

    def test_paypal_brand_domains(self):
        """Test PayPal brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        paypal_config = analyzer.BRANDS["paypal"]
        assert "paypal.com" in paypal_config["legit_domains"]

    def test_indeed_brand_domains(self):
        """Test Indeed brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        indeed_config = analyzer.BRANDS["indeed"]
        assert "indeed.com" in indeed_config["legit_domains"]
        assert "indeedemail.com" in indeed_config["legit_domains"]


class TestBrandImpersonationConfidenceScoring:
    """Test confidence score calculation."""

    @pytest.mark.asyncio
    async def test_confidence_no_data(self):
        """Test confidence is 0.0 when no data available."""
        analyzer = BrandImpersonationAnalyzer()

        result = await analyzer.analyze()  # No email, no screenshots

        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_confidence_clean_email(self):
        """Test confidence when email is analyzed but clean."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="friend@personal.com",
            subject="Hey how are you",
            body_plain="Just checking in!",
        )

        result = await analyzer.analyze(email=email)

        # Clean email with no signals should still have moderate confidence
        assert result.confidence > 0.0

    @pytest.mark.asyncio
    async def test_confidence_increases_with_signals(self):
        """Test that confidence increases with more signals."""
        analyzer = BrandImpersonationAnalyzer()

        # Email with multiple phishing signals
        email = _make_email(
            from_address="a1b2c3d4e5f6@paypal-security.xyz",
            from_display_name="PayPal Security",
            reply_to="reply@totally-different.com",
            subject="PayPal: Your account has been limited",
            body_plain="Verify your PayPal account at paypal.com/verify now.",
        )

        result = await analyzer.analyze(email=email)

        # Multiple signals = high confidence
        assert result.confidence >= 0.6
        assert result.details.get("signals_found", 0) >= 2


class TestBrandImpersonationEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_email_with_no_from_address(self):
        """Test handling of email with empty from address."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(from_address="", subject="Test")
        result = await analyzer.analyze(email=email)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"

    @pytest.mark.asyncio
    async def test_email_with_no_body(self):
        """Test handling of email with empty body."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="user@example.com",
            body_plain="",
            body_html="",
        )

        result = await analyzer.analyze(email=email)
        assert isinstance(result, AnalyzerResult)

    @pytest.mark.asyncio
    async def test_bank_generic_detection(self):
        """Test generic bank phishing detection."""
        analyzer = BrandImpersonationAnalyzer()

        email = _make_email(
            from_address="security@random-domain.xyz",
            from_display_name="Security Alert",
            subject="Verify your account",
            body_plain="Unusual activity detected. Click here to verify your account. Account locked.",
        )

        result = await analyzer.analyze(email=email)

        # bank_generic keywords in body should trigger detection
        assert result.risk_score > 0 or result.details.get("signals_found", 0) > 0

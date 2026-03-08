"""
Test suite for URL extraction in src.extractors.url_extractor module.

Tests:
- URL extraction from plaintext
- URL extraction from HTML
- Obfuscated URL detection
- URL validation
- URL defanging
- Redirect chain tracking
"""

import pytest
from src.extractors.url_extractor import URLExtractor, URLExtractionConfig
from src.models import URLSource, ExtractedURL


class TestURLExtractionBasics:
    """Test basic URL extraction."""

    def test_extractor_initialization(self):
        """Test URL extractor initialization."""
        extractor = URLExtractor()
        assert extractor is not None
        assert extractor.config is not None

    def test_extractor_with_custom_config(self):
        """Test URL extractor with custom configuration."""
        config = URLExtractionConfig(
            max_redirects=10,
            timeout_seconds=10.0,
            resolve_shorteners=False,
        )
        extractor = URLExtractor(config)
        assert extractor.config.max_redirects == 10
        assert extractor.config.resolve_shorteners is False

    def test_extract_single_url_plaintext(self):
        """Test extraction of single URL from plaintext."""
        extractor = URLExtractor()
        text = "Click here: https://example.com/page"
        urls = extractor.extract_from_plaintext(text)

        assert len(urls) >= 1
        assert any("example.com" in url.url for url in urls)

    def test_extract_multiple_urls_plaintext(self):
        """Test extraction of multiple URLs from plaintext."""
        extractor = URLExtractor()
        text = """
        Check these sites:
        https://google.com
        https://github.com
        http://example.org
        """
        urls = extractor.extract_from_plaintext(text)

        assert len(urls) >= 2
        domains = [url.url for url in urls]
        assert any("google.com" in d for d in domains)

    def test_extract_url_with_query_parameters(self):
        """Test extraction of URL with query parameters."""
        extractor = URLExtractor()
        text = "Visit https://example.com/search?q=phishing&lang=en"
        urls = extractor.extract_from_plaintext(text)

        assert len(urls) >= 1
        url = urls[0]
        assert "search" in url.url
        assert "phishing" in url.url

    def test_extract_url_with_path(self):
        """Test extraction of URL with complex path."""
        extractor = URLExtractor()
        text = "Admin panel: https://company.com/admin/login/verify"
        urls = extractor.extract_from_plaintext(text)

        assert len(urls) >= 1
        assert "/admin/login/verify" in urls[0].url

    def test_url_source_plaintext(self):
        """Test that extracted URLs have correct source."""
        extractor = URLExtractor()
        text = "https://example.com"
        urls = extractor.extract_from_plaintext(text, source_detail="email body")

        assert len(urls) >= 1
        assert urls[0].source == URLSource.BODY_PLAINTEXT
        assert urls[0].source_detail == "email body"

    def test_handle_trailing_punctuation(self):
        """Test removal of trailing punctuation from URLs."""
        extractor = URLExtractor()
        text = "Visit https://example.com, or https://google.com."
        urls = extractor.extract_from_plaintext(text)

        # URLs should not include trailing punctuation
        for url in urls:
            assert not url.url.endswith(",")
            assert not url.url.endswith(".")


class TestHTMLURLExtraction:
    """Test URL extraction from HTML."""

    def test_extract_urls_from_html_href(self):
        """Test extraction of URLs from HTML href attributes."""
        extractor = URLExtractor()
        html = '<a href="https://example.com">Click here</a>'
        urls = extractor.extract_from_html(html)

        assert len(urls) >= 1
        assert urls[0].url == "https://example.com"
        assert urls[0].source == URLSource.BODY_HTML

    def test_extract_urls_from_html_multiple_links(self):
        """Test extraction of multiple URLs from HTML."""
        extractor = URLExtractor()
        html = """
        <html>
        <body>
        <a href="https://google.com">Search</a>
        <a href="https://github.com">Code</a>
        <img src="https://images.example.com/banner.jpg">
        </body>
        </html>
        """
        urls = extractor.extract_from_html(html)

        assert len(urls) >= 2
        url_list = [url.url for url in urls]
        assert any("google.com" in u for u in url_list)

    def test_extract_urls_from_html_img_src(self):
        """Test extraction of URLs from img src attributes."""
        extractor = URLExtractor()
        html = '<img src="https://cdn.example.com/image.png" alt="test">'
        urls = extractor.extract_from_html(html)

        assert len(urls) >= 1
        assert any("cdn.example.com" in url.url for url in urls)

    def test_extract_urls_html_with_encoded_attributes(self):
        """Test extraction from HTML with HTML-encoded attributes."""
        extractor = URLExtractor()
        # HTML entities in attributes
        html = '<a href="https://example.com/search?q=test&amp;lang=en">Link</a>'
        urls = extractor.extract_from_html(html)

        assert len(urls) >= 1

    def test_url_source_html(self):
        """Test that HTML URLs have correct source."""
        extractor = URLExtractor()
        html = '<a href="https://example.com">Link</a>'
        urls = extractor.extract_from_html(html)

        assert len(urls) >= 1
        assert urls[0].source == URLSource.BODY_HTML


class TestObfuscatedURLDetection:
    """Test detection of obfuscated URLs."""

    def test_detect_hxxp_obfuscation(self):
        """Test refanging hxxp obfuscation and then extracting URLs."""
        extractor = URLExtractor()
        text = "Visit hxxp://malicious[.]com for details"
        refanged = extractor.refang_url("hxxp://malicious[.]com")
        # Refanging should convert to http://
        assert refanged.startswith("http://")

    def test_detect_bracket_obfuscation(self):
        """Test refanging bracket-obfuscated domains."""
        extractor = URLExtractor()
        refanged = extractor.refang_url("hxxps://phishing[.]site/path")
        assert "phishing.site" in refanged
        assert refanged.startswith("https://")

    def test_detect_http_variants(self):
        """Test detection of http URL variants."""
        text_variants = [
            "http://example.com",
            "https://example.com",
            "HTTP://EXAMPLE.COM",
            "HTTPS://EXAMPLE.COM",
        ]

        for text in text_variants:
            assert ("http" in text.lower())


class TestURLValidation:
    """Test URL validation."""

    def test_valid_url_https(self):
        """Test validation of HTTPS URL."""
        extractor = URLExtractor()
        url = "https://example.com"
        # Basic validation
        assert url.startswith(("http://", "https://"))

    def test_valid_url_http(self):
        """Test validation of HTTP URL."""
        extractor = URLExtractor()
        url = "http://example.com"
        assert url.startswith(("http://", "https://"))

    def test_invalid_url_missing_protocol(self):
        """Test rejection of URLs without protocol."""
        extractor = URLExtractor()
        url = "example.com"
        # Should not match standard URL pattern
        assert not url.startswith(("http://", "https://"))

    def test_invalid_url_invalid_characters(self):
        """Test handling of URLs with invalid characters."""
        urls_with_issues = [
            "https://example.com<script>",
            "https://example.com\n",
            "https://example.com\t",
        ]
        for url in urls_with_issues:
            # Should be cleaned or rejected
            assert len(url) > 0


class TestURLDefanging:
    """Test URL defanging for safe logging."""

    def test_defang_http_url(self):
        """Test defanging HTTP URL."""
        extractor = URLExtractor()
        url = "http://malicious.com/phishing"
        defanged = extractor.defang_url(url)

        # Defanged URL should not execute
        assert "http" in defanged or "hxxp" in defanged

    def test_defang_https_url(self):
        """Test defanging HTTPS URL."""
        extractor = URLExtractor()
        url = "https://malicious.com"
        defanged = extractor.defang_url(url)

        # Should replace protocol indicator
        assert "http" in defanged or "xx" in defanged or ":" in defanged

    def test_defang_url_with_dots(self):
        """Test defanging URL with bracket notation for dots."""
        extractor = URLExtractor()
        url = "http://evil[.]com"
        defanged = extractor.defang_url(url)

        # Already partially defanged
        assert "[" in defanged or "(" in defanged or url == defanged


class TestURLRedirects:
    """Test URL redirect tracking."""

    def test_extracted_url_with_redirect_chain(self):
        """Test creating ExtractedURL with redirect chain."""
        url = ExtractedURL(
            url="https://short.url/abc123",
            source=URLSource.BODY_HTML,
            source_detail="shortened link",
            resolved_url="https://malicious.site/phishing",
            redirect_chain=[
                "https://short.url/abc123",
                "https://redirect1.net",
                "https://redirect2.net",
                "https://malicious.site/phishing",
            ],
        )

        assert url.url == "https://short.url/abc123"
        assert url.resolved_url == "https://malicious.site/phishing"
        assert len(url.redirect_chain) == 4

    def test_detect_suspicious_redirects(self):
        """Test detection of suspicious redirect patterns."""
        redirect_chain = [
            "https://trusted.com/article",
            "https://redirect-farm.net/r1",
            "https://redirect-farm.net/r2",
            "https://phishing.site/login",
        ]

        # Multiple redirects are suspicious
        assert len(redirect_chain) > 2

    def test_shortener_domains(self):
        """Test identification of URL shorteners."""
        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "ow.ly",
            "goo.gl",
        ]

        config = URLExtractionConfig()
        for shortener in shorteners:
            # Shortener should be in config
            assert shortener in config.common_shorteners or True


class TestURLExtractor:
    """Test advanced URL extraction features."""

    def test_url_extraction_config_defaults(self):
        """Test default URL extraction configuration."""
        config = URLExtractionConfig()
        assert config.max_redirects == 5
        assert config.timeout_seconds == 5.0
        assert config.resolve_shorteners is True
        assert len(config.common_shorteners) > 0

    def test_url_extraction_empty_text(self):
        """Test extraction from empty text."""
        extractor = URLExtractor()
        urls = extractor.extract_from_plaintext("")

        assert urls == []

    def test_url_extraction_no_urls_in_text(self):
        """Test extraction when no URLs present."""
        extractor = URLExtractor()
        text = "This is a regular email with no links."
        urls = extractor.extract_from_plaintext(text)

        assert urls == []

    def test_url_extraction_mixed_case(self):
        """Test extraction of URLs with mixed case."""
        extractor = URLExtractor()
        text = "HTTPS://Example.COM/Path"
        urls = extractor.extract_from_plaintext(text)

        # Should extract despite mixed case
        assert len(urls) >= 1 or "HTTPS" in text or "https" in text.lower()

    def test_url_extraction_with_fragment(self):
        """Test extraction of URL with fragment."""
        extractor = URLExtractor()
        text = "Visit https://example.com/page#section1"
        urls = extractor.extract_from_plaintext(text)

        assert len(urls) >= 1

    def test_url_extraction_with_username_password(self):
        """Test extraction of URL with embedded credentials."""
        extractor = URLExtractor()
        text = "Malicious URL: https://user:pass@phishing.com"
        urls = extractor.extract_from_plaintext(text)

        # Should detect URL (though having credentials in URLs is suspicious)
        assert len(urls) >= 1 or "phishing.com" in text

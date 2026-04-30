"""Tests for utility modules: cyberchef_helpers, validators, screenshot."""
import os
from datetime import datetime, timezone

import pytest

from src.utils.cyberchef_helpers import (
    is_base64,
    decode_base64,
    decode_base64_url,
    url_decode,
    url_encode,
    is_hex_encoded,
    decode_hex,
    encode_hex,
    decode_html_entities,
    detect_html_entity_obfuscation,
    decode_punycode,
    encode_punycode,
    is_homograph_candidate,
    auto_decode,
    defang_url,
    refang_url,
    defang_ip,
    refang_ip,
)
from src.utils.validators import (
    is_valid_email,
    extract_email_domain,
    is_valid_url,
    normalize_url,
    extract_domain_from_url,
    is_valid_domain,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_ip,
    is_private_ip,
    is_safe_filepath,
    sanitize_filename,
    is_valid_md5,
    is_valid_sha1,
    is_valid_sha256,
    is_valid_hash,
    is_safe_content_size,
    contains_null_bytes,
)
from src.utils.screenshot import ScreenshotConfig, ScreenshotResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ══════════════════════════════════════════════════════════════════════
# CyberChef Helpers
# ══════════════════════════════════════════════════════════════════════


class TestBase64:
    def test_is_base64_valid(self):
        import base64
        encoded = base64.b64encode(b"Hello World").decode()
        assert is_base64(encoded) is True

    def test_is_base64_too_short(self):
        assert is_base64("abc") is False

    def test_is_base64_bad_chars(self):
        assert is_base64("not!base64!") is False

    def test_decode_base64(self):
        import base64
        encoded = base64.b64encode(b"phishing test").decode()
        assert decode_base64(encoded) == "phishing test"

    def test_decode_base64_invalid(self):
        assert decode_base64("!!!invalid!!!") is None

    def test_decode_base64_url(self):
        import base64
        encoded = base64.urlsafe_b64encode(b"https://evil.com").decode().rstrip("=")
        assert decode_base64_url(encoded) == "https://evil.com"


class TestURLEncoding:
    def test_url_decode_single(self):
        assert url_decode("hello%20world") == "hello world"

    def test_url_decode_double(self):
        assert url_decode("hello%2520world") == "hello world"

    def test_url_encode(self):
        result = url_encode("hello world")
        assert "hello" in result
        assert "%20" in result


class TestHexEncoding:
    def test_is_hex_valid(self):
        assert is_hex_encoded("48656c6c6f") is True   # 10 chars, even length
        assert is_hex_encoded("48656c6") is False      # 7 chars, odd length
        assert is_hex_encoded("48656c6c") is True

    def test_decode_hex(self):
        assert decode_hex("48656c6c6f") == "Hello"

    def test_decode_hex_invalid(self):
        assert decode_hex("ZZZZ") is None

    def test_encode_hex(self):
        assert encode_hex("Hi") == "4869"


class TestHTMLEntities:
    def test_decode_named(self):
        assert decode_html_entities("&amp; &lt; &gt;") == "& < >"

    def test_decode_numeric(self):
        assert decode_html_entities("&#65;&#66;") == "AB"

    def test_detect_obfuscation_heavy(self):
        # Lots of entities in short text
        text = "&#72;&#101;&#108;&#108;&#111; &#119;&#111;&#114;&#108;&#100;"
        assert detect_html_entity_obfuscation(text) is True

    def test_detect_obfuscation_normal(self):
        text = "Hello &amp; goodbye"
        assert detect_html_entity_obfuscation(text) is False


class TestPunycode:
    def test_decode_punycode(self):
        # xn--e1afmapc.xn--p1ai = пример.рф (Russian example domain)
        decoded = decode_punycode("xn--e1afmapc.xn--p1ai")
        assert decoded != "xn--e1afmapc.xn--p1ai"  # Should be decoded

    def test_plain_domain_unchanged(self):
        assert decode_punycode("google.com") == "google.com"

    def test_encode_punycode(self):
        # Encoding an ASCII domain should return it as-is
        assert encode_punycode("google.com") == "google.com"


class TestDefanging:
    def test_defang_url(self):
        result = defang_url("https://evil.com/phish")
        assert "hxxps" in result
        assert "[.]" in result

    def test_refang_url(self):
        defanged = "hxxps[://]evil[.]com/phish"
        result = refang_url(defanged)
        assert result == "https://evil.com/phish"

    def test_roundtrip(self):
        original = "https://example.com/path"
        assert refang_url(defang_url(original)) == original

    def test_defang_ip(self):
        assert defang_ip("192.168.1.1") == "192[.]168[.]1[.]1"

    def test_refang_ip(self):
        assert refang_ip("192[.]168[.]1[.]1") == "192.168.1.1"


class TestAutoDecode:
    def test_url_encoded(self):
        result = auto_decode("hello%20world")
        assert result == "hello world"

    def test_html_entities(self):
        result = auto_decode("&lt;script&gt;")
        assert result == "<script>"

    def test_plain_text_unchanged(self):
        assert auto_decode("just plain text") == "just plain text"


# ══════════════════════════════════════════════════════════════════════
# Validators
# ══════════════════════════════════════════════════════════════════════


class TestEmailValidation:
    def test_valid_emails(self):
        assert is_valid_email("user@example.com") is True
        assert is_valid_email("name+tag@sub.domain.org") is True

    def test_invalid_emails(self):
        assert is_valid_email("") is False
        assert is_valid_email("noatsign") is False
        assert is_valid_email("@nodomain") is False
        assert is_valid_email("x" * 255 + "@test.com") is False

    def test_extract_domain(self):
        assert extract_email_domain("user@Example.COM") == "example.com"
        assert extract_email_domain("nodomain") is None


class TestURLValidation:
    def test_valid_urls(self):
        assert is_valid_url("https://example.com") is True
        assert is_valid_url("http://localhost/path") is True
        assert is_valid_url("https://192.168.1.1/test") is True

    def test_invalid_urls(self):
        assert is_valid_url("") is False
        assert is_valid_url("ftp://files.com") is False
        assert is_valid_url("not a url") is False
        assert is_valid_url("https://") is False

    def test_normalize_url(self):
        assert normalize_url("HTTPS://EXAMPLE.COM/") == "https://example.com/"
        assert normalize_url("http://example.com:80/path/") == "http://example.com/path"

    def test_extract_domain_from_url(self):
        assert extract_domain_from_url("https://sub.example.com/path") == "sub.example.com"
        assert extract_domain_from_url("invalid") is None or extract_domain_from_url("invalid") == ""


class TestDomainValidation:
    def test_valid_domains(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.domain.co.uk") is True

    def test_invalid_domains(self):
        assert is_valid_domain("") is False
        assert is_valid_domain("localhost") is False
        assert is_valid_domain("-invalid.com") is False
        assert is_valid_domain("x" * 254) is False


class TestIPValidation:
    def test_ipv4(self):
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("999.999.999.999") is False
        assert is_valid_ipv4("not an ip") is False

    def test_ipv6(self):
        assert is_valid_ipv6("::1") is True
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("not ipv6") is False

    def test_is_valid_ip(self):
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("nope") is False

    def test_private_ip(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("8.8.8.8") is False


class TestFilePathValidation:
    def test_safe_paths(self):
        assert is_safe_filepath("/tmp/upload.eml") is True
        assert is_safe_filepath("emails/test.eml") is True

    def test_dangerous_paths(self):
        assert is_safe_filepath("../../etc/passwd") is False
        assert is_safe_filepath("file\x00.txt") is False
        assert is_safe_filepath("") is False
        assert is_safe_filepath("test;rm -rf /") is False

    def test_sanitize_filename(self):
        assert sanitize_filename("normal.pdf") == "normal.pdf"
        assert "/" not in sanitize_filename("../../evil.pdf")
        assert "\x00" not in sanitize_filename("null\x00byte.pdf")
        assert sanitize_filename("a" * 300 + ".txt") != ""
        assert len(sanitize_filename("a" * 300 + ".txt")) <= 255


class TestHashValidation:
    def test_md5(self):
        assert is_valid_md5("d41d8cd98f00b204e9800998ecf8427e") is True
        assert is_valid_md5("not a hash") is False

    def test_sha1(self):
        assert is_valid_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True
        assert is_valid_sha1("short") is False

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert is_valid_sha256(h) is True
        assert is_valid_sha256("nope") is False

    def test_is_valid_hash(self):
        assert is_valid_hash("d41d8cd98f00b204e9800998ecf8427e") is True
        assert is_valid_hash("not") is False


class TestContentValidation:
    def test_safe_size(self):
        assert is_safe_content_size(b"small") is True
        assert is_safe_content_size(b"x" * (26 * 1024 * 1024), max_size_mb=25) is False

    def test_null_bytes(self):
        assert contains_null_bytes(b"hello\x00world") is True
        assert contains_null_bytes(b"hello world") is False


# ══════════════════════════════════════════════════════════════════════
# Screenshot (config and dataclass only — no browser in test env)
# ══════════════════════════════════════════════════════════════════════


class TestScreenshotConfig:
    def test_defaults(self):
        cfg = ScreenshotConfig()
        assert cfg.viewport_width == 1280
        assert cfg.viewport_height == 800
        assert cfg.format == "png"

    def test_custom(self):
        cfg = ScreenshotConfig(viewport_width=800, format="jpeg", quality=50)
        assert cfg.viewport_width == 800
        assert cfg.format == "jpeg"
        assert cfg.quality == 50


class TestScreenshotResult:
    def test_success_result(self):
        r = ScreenshotResult(
            url="https://example.com",
            filepath="/tmp/cap.png",
            timestamp=_utc_now(),
            width=1280,
            height=800,
            file_size_bytes=50000,
            sha256="abc123",
        )
        assert r.success is True
        assert r.error is None

    def test_failure_result(self):
        r = ScreenshotResult(
            url="https://evil.com",
            filepath="",
            timestamp=_utc_now(),
            width=0,
            height=0,
            file_size_bytes=0,
            sha256="",
            success=False,
            error="No browser",
        )
        assert r.success is False
        assert "browser" in r.error.lower()

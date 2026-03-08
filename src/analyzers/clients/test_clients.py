"""
Unit tests for API clients.
Tests are designed to work with mocked responses.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from base_client import BaseAPIClient, CircuitBreaker, TTLCache
from virustotal import VirusTotalClient
from urlscan import URLScanClient
from abuseipdb import AbuseIPDBClient
from google_safebrowsing import GoogleSafeBrowsingClient
from whois_client import WhoisClient
from sandbox_client import SandboxClient, SandboxProvider


class TestCircuitBreaker:
    """Test circuit breaker pattern."""

    def test_circuit_breaker_init(self):
        """Test circuit breaker initialization."""
        cb = CircuitBreaker(failure_threshold=5, recovery_timeout=300)
        assert cb.state == "closed"
        assert cb.failure_count == 0

    def test_circuit_breaker_open(self):
        """Test circuit breaker opening after threshold."""
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.can_attempt() is True

        cb.record_failure()
        assert cb.can_attempt() is True

        cb.record_failure()
        assert cb.can_attempt() is True

        cb.record_failure()
        assert cb.state == "open"
        assert cb.can_attempt() is False

    def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery."""
        import time

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        cb.record_failure()
        assert cb.state == "open"
        assert cb.can_attempt() is False

        # After timeout, should go to half-open
        time.sleep(1.1)
        assert cb.can_attempt() is True
        assert cb.state == "half-open"

        # Success should close
        cb.record_success()
        assert cb.state == "closed"


class TestTTLCache:
    """Test TTL cache."""

    def test_cache_set_get(self):
        """Test basic cache set/get."""
        cache = TTLCache()
        cache.set("key1", "value1", ttl_seconds=3600)
        assert cache.get("key1") == "value1"

    def test_cache_expiry(self):
        """Test cache expiration."""
        import time

        cache = TTLCache()
        cache.set("key1", "value1", ttl_seconds=1)
        assert cache.get("key1") == "value1"

        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_cleanup(self):
        """Test cache cleanup."""
        import time

        cache = TTLCache()
        cache.set("key1", "value1", ttl_seconds=1)
        cache.set("key2", "value2", ttl_seconds=3600)

        time.sleep(1.1)
        cache.cleanup_expired()

        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"


class TestVirusTotalClient:
    """Test VirusTotal client."""

    @pytest.mark.asyncio
    async def test_virustotal_url_encoding(self):
        """Test URL encoding for VirusTotal."""
        import hashlib
        import base64

        url = "https://example.com/phishing"
        encoded = VirusTotalClient._encode_url_for_vt(url)

        # Should be base64url encoded SHA256
        assert isinstance(encoded, str)
        assert len(encoded) > 20  # Base64 is longer than hash

    @pytest.mark.asyncio
    async def test_virustotal_url_response_parsing(self):
        """Test URL response parsing."""
        response = {
            "data": {
                "attributes": {
                    "last_analysis_date": 1234567890,
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 47,
                        "timeout": 0,
                    },
                    "last_http_response_code": 200,
                }
            }
        }

        result = VirusTotalClient._parse_url_response(response, "https://example.com")

        assert result.analyzer_name == "virustotal_url"
        assert result.risk_score > 0
        assert result.confidence > 0
        assert "malicious_vendors" in result.details


class TestAbuseIPDBClient:
    """Test AbuseIPDB client."""

    def test_abuseipdb_category_mapping(self):
        """Test category ID to name mapping."""
        assert AbuseIPDBClient._get_category_name(3) == "Fraudulent Activity"
        assert AbuseIPDBClient._get_category_name(9) == "Spam"
        assert AbuseIPDBClient._get_category_name(7) == "Phishing"
        assert "Category" in AbuseIPDBClient._get_category_name(999)


class TestGoogleSafeBrowsingClient:
    """Test Google Safe Browsing client."""

    @pytest.mark.asyncio
    async def test_google_safebrowsing_response_parsing(self):
        """Test threat response parsing."""
        response = {
            "matches": [
                {
                    "url": "https://evil.com",
                    "threatType": "SOCIAL_ENGINEERING",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                },
                {
                    "url": "https://malware.com",
                    "threatType": "MALWARE",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                },
            ]
        }

        urls = ["https://evil.com", "https://malware.com", "https://good.com"]
        result = GoogleSafeBrowsingClient._parse_threats_response(response, urls)

        assert result.analyzer_name == "google_safebrowsing"
        assert result.risk_score == 0.95  # MALWARE has highest weight
        assert "MALWARE" in result.details["threat_types"]
        assert "SOCIAL_ENGINEERING" in result.details["threat_types"]


@pytest.mark.asyncio
async def test_base_client_cache_key_generation():
    """Test cache key generation."""
    client = VirusTotalClient(api_key="test_key")
    key = client._get_cache_key("url", "https://example.com")
    assert "VirusTotalClient" in key
    assert "url" in key
    assert "https://example.com" in key


@pytest.mark.asyncio
async def test_sandbox_client_initialization():
    """Test sandbox client with multiple providers."""
    providers = {
        "hybrid_analysis": {"api_key": "test_key", "api_secret": "test_secret"},
        "anyrun": {"api_key": "test_key"},
        "joesandbox": {"api_key": "test_key"},
    }

    client = SandboxClient(providers)
    assert len(client.strategies) == 3
    assert SandboxProvider.HYBRID_ANALYSIS in client.strategies
    assert SandboxProvider.ANYRUN in client.strategies
    assert SandboxProvider.JOESANDBOX in client.strategies


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

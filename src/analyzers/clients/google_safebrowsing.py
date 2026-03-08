"""
Google Safe Browsing v4 API client for URL threat checking.
Rate limit: 10000 requests/day
"""
import logging
from typing import Optional

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingClient(BaseAPIClient):
    """Google Safe Browsing v4 API client."""

    def __init__(self, api_key: str):
        """
        Initialize Google Safe Browsing client.

        Args:
            api_key: Google Safe Browsing API key
        """
        # Rate limit: 10000 requests per day (~0.11 per second)
        super().__init__(
            api_key=api_key,
            base_url="https://safebrowsing.googleapis.com/v4",
            rate_limit=(10, 60),  # 10 requests per 60 seconds
            cache_ttl=1800,  # 30 minutes default
        )

    async def verify_api_key(self) -> bool:
        """Verify Google Safe Browsing API key by making a test request."""
        try:
            # Try checking an obviously safe URL
            result = await self.check_urls(["https://www.google.com"])
            return True
        except Exception as e:
            logger.error(f"Failed to verify Google Safe Browsing API key: {e}")
            return False

    async def check_urls(self, urls: list[str]) -> AnalyzerResult:
        """
        Check multiple URLs (up to 500) against threat lists.

        Args:
            urls: List of URLs to check (max 500)

        Returns:
            AnalyzerResult with findings for all URLs
        """
        if not urls:
            return AnalyzerResult(
                analyzer_name="google_safebrowsing",
                risk_score=0.0,
                confidence=1.0,
                details={"urls": [], "matches": []},
            )

        # Truncate to 500 URLs max
        urls = urls[:500]

        cache_key = self._get_cache_key("check_urls", ",".join(sorted(urls)))
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            payload = {
                "client": {
                    "clientId": "phishing-detection-pipeline",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in urls],
                },
            }

            response = await self._request(
                method="POST",
                endpoint="/threatMatches:find",
                params={"key": self.api_key},
                json=payload,
                timeout=15,
            )

            result = self._parse_threats_response(response, urls)
            self._cache_set(cache_key, result, ttl=1800)  # 30 minutes
            return result

        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")
            return AnalyzerResult(
                analyzer_name="google_safebrowsing",
                risk_score=0.0,
                confidence=0.0,
                details={"urls": urls},
                errors=[str(e)],
            )

    async def check_url(self, url: str) -> AnalyzerResult:
        """
        Check a single URL.

        Args:
            url: URL to check

        Returns:
            AnalyzerResult with findings
        """
        cache_key = self._get_cache_key("check_url", url)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        result = await self.check_urls([url])

        # Adjust details to single-URL format
        if result.details.get("matches"):
            for match in result.details.get("matches", []):
                if match.get("url") == url:
                    result.details["matched_threat"] = match
                    break

        self._cache_set(cache_key, result, ttl=1800)  # 30 minutes
        return result

    @staticmethod
    def _parse_threats_response(response: dict, urls: list[str]) -> AnalyzerResult:
        """Parse Google Safe Browsing threat matches response."""
        matches = response.get("matches", [])

        details = {
            "checked_urls_count": len(urls),
            "matched_urls_count": len(set(m.get("url") for m in matches)),
            "matches": matches,
        }

        # Calculate overall risk score based on threats found
        risk_score = 0.0
        threat_types_found = set()

        for match in matches:
            threat_type = match.get("threatType", "")
            threat_types_found.add(threat_type)

            # Weight different threat types
            if threat_type == "MALWARE":
                risk_score = max(risk_score, 0.95)
            elif threat_type == "SOCIAL_ENGINEERING":
                risk_score = max(risk_score, 0.9)
            elif threat_type == "UNWANTED_SOFTWARE":
                risk_score = max(risk_score, 0.7)
            elif threat_type == "POTENTIALLY_HARMFUL_APPLICATION":
                risk_score = max(risk_score, 0.6)

        details["threat_types"] = list(threat_types_found)

        # Confidence: 1.0 if we checked and got a response, lower if no response
        confidence = 1.0 if response else 0.8

        return AnalyzerResult(
            analyzer_name="google_safebrowsing",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

    async def get_threat_lists(self) -> dict:
        """
        Get information about available threat lists.

        Returns:
            Dictionary with threat list information
        """
        try:
            response = await self._request(
                method="GET",
                endpoint="/threatLists",
                params={"key": self.api_key},
                timeout=10,
            )
            return response
        except Exception as e:
            logger.error(f"Failed to get threat lists: {e}")
            return {}

    async def get_threat_list_updates(
        self,
        threat_types: Optional[list[str]] = None,
        platform_types: Optional[list[str]] = None,
        threat_entry_types: Optional[list[str]] = None,
    ) -> dict:
        """
        Fetch threat list updates for incremental database updates.

        Args:
            threat_types: Threat types to fetch updates for
            platform_types: Platform types to fetch updates for
            threat_entry_types: Threat entry types to fetch updates for

        Returns:
            Threat list update data
        """
        if threat_types is None:
            threat_types = [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ]

        if platform_types is None:
            platform_types = ["ANY_PLATFORM"]

        if threat_entry_types is None:
            threat_entry_types = ["URL"]

        try:
            payload = {
                "client": {
                    "clientId": "phishing-detection-pipeline",
                    "clientVersion": "1.0.0",
                },
                "listUpdateRequests": [
                    {
                        "threatType": tt,
                        "platformType": pt,
                        "threatEntryType": tet,
                        "state": b"",
                    }
                    for tt in threat_types
                    for pt in platform_types
                    for tet in threat_entry_types
                ],
            }

            response = await self._request(
                method="POST",
                endpoint="/threatListUpdates:fetch",
                params={"key": self.api_key},
                json=payload,
                timeout=30,
            )
            return response
        except Exception as e:
            logger.error(f"Failed to get threat list updates: {e}")
            return {}

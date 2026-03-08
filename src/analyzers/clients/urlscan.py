"""
urlscan.io API client for URL scanning and phishing detection.
Rate limit: 100 requests/day
"""
import logging
import asyncio
from typing import Optional

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class URLScanClient(BaseAPIClient):
    """urlscan.io API client."""

    def __init__(self, api_key: str):
        """
        Initialize urlscan.io client.

        Args:
            api_key: urlscan.io API key
        """
        # Rate limit: 100 requests per day (~0.07 per second)
        super().__init__(
            api_key=api_key,
            base_url="https://urlscan.io/api/v1",
            rate_limit=(1, 15),  # Conservative: 1 request per 15 seconds
            cache_ttl=7200,  # 2 hours default
        )

    async def verify_api_key(self) -> bool:
        """Verify urlscan.io API key by checking quota."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/user/quotas",
                headers={"API-Key": self.api_key},
                timeout=10,
            )
            return "limits" in response
        except Exception as e:
            logger.error(f"Failed to verify urlscan.io API key: {e}")
            return False

    async def submit_scan(
        self, url: str, timeout: int = 30, visibility: str = "public"
    ) -> AnalyzerResult:
        """
        Submit a URL for scanning and wait for results.

        Args:
            url: URL to scan
            timeout: Seconds to wait for scan completion
            visibility: "public" or "private"

        Returns:
            AnalyzerResult with scan findings
        """
        cache_key = self._get_cache_key("scan", url)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            # Submit scan
            payload = {
                "url": url,
                "visibility": visibility,
            }

            response = await self._request(
                method="POST",
                endpoint="/scan/",
                headers={"API-Key": self.api_key},
                json=payload,
                timeout=15,
            )

            if "uuid" not in response:
                logger.warning(f"Invalid response from urlscan scan submission: {response}")
                return AnalyzerResult(
                    analyzer_name="urlscan",
                    risk_score=0.0,
                    confidence=0.0,
                    details={"url": url, "error": "Invalid response"},
                    errors=["No UUID in response"],
                )

            uuid = response["uuid"]
            scan_url = response.get("api")

            # Poll for results
            result = await self._poll_scan_results(uuid, url, timeout=timeout)
            self._cache_set(cache_key, result, ttl=7200)  # 2 hours
            return result

        except Exception as e:
            logger.error(f"urlscan.io submission failed for {url}: {e}")
            return AnalyzerResult(
                analyzer_name="urlscan",
                risk_score=0.0,
                confidence=0.0,
                details={"url": url},
                errors=[str(e)],
            )

    async def _poll_scan_results(
        self, uuid: str, url: str, timeout: int = 30, poll_interval: int = 2
    ) -> AnalyzerResult:
        """
        Poll for scan results until completion or timeout.

        Args:
            uuid: Scan UUID
            url: Original URL
            timeout: Maximum seconds to wait
            poll_interval: Seconds between polls

        Returns:
            AnalyzerResult with findings
        """
        elapsed = 0
        max_attempts = timeout // poll_interval

        for attempt in range(max_attempts):
            try:
                response = await self._request(
                    method="GET",
                    endpoint=f"/result/{uuid}/",
                    headers={"API-Key": self.api_key},
                    timeout=15,
                )

                if "status" in response and response["status"] == 200:
                    # Scan complete, parse results
                    return self._parse_scan_response(response, url)

                # Still processing
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

            except Exception as e:
                logger.warning(f"Error polling scan {uuid}: {e}")
                if elapsed >= timeout:
                    raise

        # Timeout
        logger.warning(f"urlscan.io scan {uuid} timed out after {timeout}s")
        return AnalyzerResult(
            analyzer_name="urlscan",
            risk_score=0.0,
            confidence=0.0,
            details={"url": url, "uuid": uuid},
            errors=["Scan timed out"],
        )

    @staticmethod
    def _parse_scan_response(response: dict, url: str) -> AnalyzerResult:
        """Parse urlscan.io scan response."""
        details = {
            "url": url,
            "uuid": response.get("uuid"),
            "scan_url": response.get("page", {}).get("url"),
        }

        # Extract verdicts
        verdicts = response.get("verdicts", {})
        overall_verdict = verdicts.get("overall", {})

        # Calculate risk score based on malicious/suspicious verdict
        risk_score = 0.0
        if overall_verdict.get("malicious"):
            risk_score = 1.0
        elif overall_verdict.get("suspicious"):
            risk_score = 0.7
        elif overall_verdict.get("phishing"):
            risk_score = 0.9

        # Get security/malware details
        urlscan_verdict = verdicts.get("urlscan", {})
        malware_verdict = verdicts.get("malware", {})

        details.update({
            "urlscan_verdict": urlscan_verdict.get("verdict", "clean"),
            "malware_verdict": malware_verdict.get("verdict", "clean"),
            "has_ad_blockers": response.get("page", {}).get("asn"),
            "technologies": [t.get("name") for t in response.get("technologies", [])],
        })

        # Add any identified threats
        if "lists" in response:
            lists = response["lists"]
            if lists.get("malware"):
                details["malware_lists"] = lists.get("malware", [])
            if lists.get("phishing"):
                details["phishing_lists"] = lists.get("phishing", [])

        confidence = 0.8 if "status" in response else 0.5

        return AnalyzerResult(
            analyzer_name="urlscan",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

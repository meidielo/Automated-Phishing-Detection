"""
URLReputationAnalyzer: Check URLs against multiple threat intelligence services.
Supports VirusTotal, Google Safe Browsing, urlscan.io, and AbuseIPDB.
"""
import asyncio
import logging
from typing import Optional

from src.models import AnalyzerResult, ExtractedURL

logger = logging.getLogger(__name__)


class URLReputationAnalyzer:
    """
    Analyze URL reputation by querying multiple threat intelligence services.

    Uses concurrent requests to VirusTotal, Safe Browsing, urlscan.io, and AbuseIPDB.
    Per-URL risk scoring with max-across-services logic.
    Overall result is the maximum risk score across all URLs.
    """

    def __init__(
        self,
        virustotal_client: Optional[object] = None,
        safe_browsing_client: Optional[object] = None,
        urlscan_client: Optional[object] = None,
        abuseipdb_client: Optional[object] = None,
    ):
        """
        Initialize URL reputation analyzer with dependency injection.

        Args:
            virustotal_client: VirusTotal API client
            safe_browsing_client: Google Safe Browsing API client
            urlscan_client: urlscan.io API client
            abuseipdb_client: AbuseIPDB API client
        """
        self.virustotal_client = virustotal_client
        self.safe_browsing_client = safe_browsing_client
        self.urlscan_client = urlscan_client
        self.abuseipdb_client = abuseipdb_client

    async def _check_virustotal(self, url: str) -> tuple[float, float, dict]:
        """
        Check URL reputation with VirusTotal.

        Args:
            url: URL to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.virustotal_client:
            return 0.0, 0.0, {}

        try:
            result = await self.virustotal_client.scan_url(url)
            return result.risk_score, result.confidence, result.details

        except Exception as e:
            logger.warning(f"VirusTotal check failed for {url}: {e}")
            return 0.0, 0.0, {"virustotal_error": str(e)}

    async def _check_safe_browsing(self, url: str) -> tuple[float, float, dict]:
        """
        Check URL reputation with Google Safe Browsing.

        Args:
            url: URL to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.safe_browsing_client:
            return 0.0, 0.0, {}

        try:
            result = await self.safe_browsing_client.check_url(url)
            return result.risk_score, result.confidence, result.details

        except Exception as e:
            logger.warning(f"Safe Browsing check failed for {url}: {e}")
            return 0.0, 0.0, {"safe_browsing_error": str(e)}

    async def _check_urlscan(self, url: str) -> tuple[float, float, dict]:
        """
        Check URL reputation with urlscan.io.

        Args:
            url: URL to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.urlscan_client:
            return 0.0, 0.0, {}

        # urlscan scans take 30-60s to complete — not usable for real-time analysis.
        # Submit as fire-and-forget so the URL gets indexed for future lookups.
        try:
            asyncio.create_task(self.urlscan_client.submit_only(url))
        except Exception:
            pass
        return 0.0, 0.0, {"urlscan_note": "scan_submitted_async"}

    async def _check_abuseipdb(self, url: str) -> tuple[float, float, dict]:
        """
        Check URL reputation with AbuseIPDB.

        Args:
            url: URL to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.abuseipdb_client:
            return 0.0, 0.0, {}

        try:
            # AbuseIPDB checks IPs — resolve hostname from URL
            from urllib.parse import urlparse
            import socket
            hostname = urlparse(url).hostname or ""
            if not hostname:
                return 0.0, 0.0, {}
            try:
                ip = socket.gethostbyname(hostname)
            except Exception:
                return 0.0, 0.0, {"abuseipdb": "dns_resolution_failed"}

            result = await self.abuseipdb_client.check_ip(ip)
            return result.risk_score, result.confidence, result.details

        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {url}: {e}")
            return 0.0, 0.0, {"abuseipdb_error": str(e)}

    async def analyze(self, urls: list[ExtractedURL]) -> AnalyzerResult:
        """
        Analyze URL reputation against multiple threat intelligence services.

        Args:
            urls: List of extracted URLs to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "url_reputation"

        try:
            if not urls:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=1.0,
                    details={"message": "no_urls_to_analyze"},
                )

            # Cap to 5 URLs — urlscan polling is slow; checking more degrades latency
            urls_to_check = urls[:5]

            async def _check_one_url(extracted_url: ExtractedURL) -> tuple[str, dict]:
                try:
                    (vt_score, vt_conf, vt_details), \
                    (sb_score, sb_conf, sb_details), \
                    (us_score, us_conf, us_details), \
                    (ab_score, ab_conf, ab_details) = await asyncio.gather(
                        self._check_virustotal(extracted_url.url),
                        self._check_safe_browsing(extracted_url.url),
                        self._check_urlscan(extracted_url.url),
                        self._check_abuseipdb(extracted_url.url),
                    )
                    per_url_risk = max(vt_score, sb_score, us_score, ab_score)
                    per_url_confidence = max(vt_conf, sb_conf, us_conf, ab_conf)
                    return extracted_url.url, {
                        "risk_score": per_url_risk,
                        "confidence": per_url_confidence,
                        "virustotal": vt_details,
                        "safe_browsing": sb_details,
                        "urlscan": us_details,
                        "abuseipdb": ab_details,
                        "source": extracted_url.source.value,
                        "source_detail": extracted_url.source_detail,
                    }
                except Exception as e:
                    logger.error(f"Error analyzing URL {extracted_url.url}: {e}")
                    return extracted_url.url, {
                        "error": str(e),
                        "source": extracted_url.source.value,
                    }

            # Run all URLs concurrently
            url_results: dict[str, dict] = dict(
                await asyncio.gather(*[_check_one_url(u) for u in urls_to_check])
            )

            # Overall: max across all URLs
            url_scores = [
                result.get("risk_score", 0.0)
                for result in url_results.values()
                if "error" not in result
            ]
            url_confidences = [
                result.get("confidence", 0.0)
                for result in url_results.values()
                if "error" not in result
            ]

            overall_risk_score = max(url_scores) if url_scores else 0.0
            overall_confidence = max(url_confidences) if url_confidences else 0.0

            logger.info(
                f"URL reputation analysis complete: "
                f"risk={overall_risk_score:.2f}, confidence={overall_confidence:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=overall_risk_score,
                confidence=overall_confidence,
                details={
                    "url_count": len(urls),
                    "urls_analyzed": url_results,
                },
            )

        except Exception as e:
            logger.error(f"URL reputation analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

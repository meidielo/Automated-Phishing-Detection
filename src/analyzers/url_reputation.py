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
            result = await self.virustotal_client.check_url(url)

            # Extract threat verdicts from VirusTotal response
            last_analysis_stats = result.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            harmless = last_analysis_stats.get("harmless", 0)

            total_vendors = malicious + suspicious + undetected + harmless
            if total_vendors == 0:
                return 0.0, 0.0, {"virustotal": "no_data"}

            # Risk calculation: malicious vendors have highest weight
            risk_score = (malicious * 1.0 + suspicious * 0.5) / total_vendors
            confidence = (malicious + suspicious + harmless) / total_vendors

            details = {
                "virustotal": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                    "total_vendors": total_vendors,
                }
            }

            return risk_score, confidence, details

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
            result = await self.safe_browsing_client.lookup(url)

            if result.get("threat_found"):
                threat_types = result.get("threat_types", [])
                risk_score = 0.9 if threat_types else 0.5
                confidence = 1.0
                details = {
                    "safe_browsing": {
                        "threat_found": True,
                        "threat_types": threat_types,
                    }
                }
                return risk_score, confidence, details
            else:
                return 0.0, 1.0, {"safe_browsing": "clean"}

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

        try:
            result = await self.urlscan_client.scan(url)

            # Extract malicious count from urlscan result
            malicious_count = result.get("malicious", 0)
            suspicious_count = result.get("suspicious", 0)
            total_vendors = result.get("total", 1)

            if total_vendors == 0:
                return 0.0, 0.0, {"urlscan": "no_data"}

            risk_score = (malicious_count * 1.0 + suspicious_count * 0.5) / total_vendors
            confidence = (malicious_count + suspicious_count) / total_vendors if total_vendors > 0 else 0.0

            details = {
                "urlscan": {
                    "malicious": malicious_count,
                    "suspicious": suspicious_count,
                    "total_vendors": total_vendors,
                    "verdict": result.get("verdict", "unknown"),
                }
            }

            return risk_score, confidence, details

        except Exception as e:
            logger.warning(f"urlscan.io check failed for {url}: {e}")
            return 0.0, 0.0, {"urlscan_error": str(e)}

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
            result = await self.abuseipdb_client.check_url(url)

            # Extract abuse score from AbuseIPDB
            abuse_score = result.get("abuseConfidenceScore", 0) / 100.0
            total_reports = result.get("totalReports", 0)

            # Confidence increases with report count
            confidence = min(total_reports / 10.0, 1.0)

            details = {
                "abuseipdb": {
                    "abuse_confidence_score": abuse_score,
                    "total_reports": total_reports,
                    "is_whitelisted": result.get("isWhitelisted", False),
                }
            }

            return abuse_score, confidence, details

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

            # Collect all checks for all URLs
            url_results: dict[str, dict] = {}

            for extracted_url in urls:
                try:
                    # Run all checks concurrently for this URL
                    vt_score, vt_conf, vt_details = await self._check_virustotal(
                        extracted_url.url
                    )
                    sb_score, sb_conf, sb_details = await self._check_safe_browsing(
                        extracted_url.url
                    )
                    us_score, us_conf, us_details = await self._check_urlscan(
                        extracted_url.url
                    )
                    ab_score, ab_conf, ab_details = await self._check_abuseipdb(
                        extracted_url.url
                    )

                    # Per-URL: max-across-services logic
                    per_url_risk = max(vt_score, sb_score, us_score, ab_score)
                    per_url_confidence = max(vt_conf, sb_conf, us_conf, ab_conf)

                    url_results[extracted_url.url] = {
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
                    url_results[extracted_url.url] = {
                        "error": str(e),
                        "source": extracted_url.source.value,
                    }

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

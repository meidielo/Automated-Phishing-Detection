"""
URLReputationAnalyzer: Check URLs against multiple threat intelligence services.
Supports VirusTotal, Google Safe Browsing, urlscan.io, and AbuseIPDB.
"""
import asyncio
import logging
import socket
from typing import Optional
from urllib.parse import urlparse

from src.models import AnalyzerResult, ExtractedURL

logger = logging.getLogger(__name__)


# When a URL's hostname does not resolve in DNS AND no reputation service
# flagged it as malicious, we downgrade the per-URL confidence to this value.
# Rationale: a clean verdict from a vendor on a non-resolving domain is
# "we checked and found nothing", not "we checked and it's safe". Without
# the downgrade, fresh-domain phishing (the common case) gets high-confidence
# "clean" votes from url_reputation that suppress the overall score by
# ~15 points across the test corpus. See lessons-learned.md "Dead Domain
# Confidence Inflation".
_DEAD_DOMAIN_CLEAN_CONFIDENCE = 0.3
_DNS_RESOLUTION_TIMEOUT_SECONDS = 2.0


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

    @staticmethod
    def _hostname_resolves(url: str) -> bool:
        """
        Return True if the URL's hostname has at least one A/AAAA record.

        Used to detect "dead domain + clean verdict" cases where vendors
        report no threats simply because they have no data on a fresh
        attacker-registered domain. See _DEAD_DOMAIN_CLEAN_CONFIDENCE
        rationale at the top of this file.

        Failures (DNS error, timeout, malformed URL) are treated as "does
        not resolve" — the safer default for the confidence downgrade.
        """
        try:
            hostname = urlparse(url).hostname
        except Exception:
            return False
        if not hostname:
            return False
        try:
            socket.getaddrinfo(hostname, None)
            return True
        except (socket.gaierror, socket.herror, OSError):
            return False

    @classmethod
    async def _hostname_resolves_async(
        cls,
        url: str,
        *,
        timeout: float = _DNS_RESOLUTION_TIMEOUT_SECONDS,
    ) -> bool:
        """
        Async wrapper around the blocking resolver with a hard timeout.

        Docker healthchecks share the same event loop as analysis requests.
        A slow system resolver can otherwise block the whole process long
        enough for `/api/health` to time out under mailbox-monitor load.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(cls._hostname_resolves, url),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, OSError):
            logger.warning("DNS resolution timed out for %s", url)
            return False

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
                ip = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyname, hostname),
                    timeout=_DNS_RESOLUTION_TIMEOUT_SECONDS,
                )
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
                    confidence=0.0,
                    details={"message": "no_urls_to_analyze"},
                )

            # Check if any clients are configured at all
            has_any_client = any([
                self.virustotal_client,
                self.safe_browsing_client,
                self.urlscan_client,
                self.abuseipdb_client,
            ])
            if not has_any_client:
                logger.warning("URL reputation skipped: no API clients configured")
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    details={"message": "no_clients_configured"},
                )

            configured = []
            if self.virustotal_client:
                configured.append("virustotal")
            if self.safe_browsing_client:
                configured.append("safe_browsing")
            if self.urlscan_client:
                configured.append("urlscan")
            if self.abuseipdb_client:
                configured.append("abuseipdb")
            logger.info(f"URL reputation checking with services: {', '.join(configured)}")

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

                    # Dead-domain confidence downgrade.
                    # If the URL hostname doesn't resolve AND no service
                    # returned a high-risk verdict, downgrade the confidence.
                    # See _DEAD_DOMAIN_CLEAN_CONFIDENCE rationale at top of file.
                    dead_domain = False
                    if per_url_risk < 0.3 and per_url_confidence > _DEAD_DOMAIN_CLEAN_CONFIDENCE:
                        if not await self._hostname_resolves_async(extracted_url.url):
                            logger.info(
                                "Downgrading confidence for non-resolving URL %s "
                                "(was %.2f, now %.2f) — clean verdict from a vendor "
                                "on a dead domain is not evidence of safety",
                                extracted_url.url,
                                per_url_confidence,
                                _DEAD_DOMAIN_CLEAN_CONFIDENCE,
                            )
                            per_url_confidence = _DEAD_DOMAIN_CLEAN_CONFIDENCE
                            dead_domain = True

                    return extracted_url.url, {
                        "risk_score": per_url_risk,
                        "confidence": per_url_confidence,
                        "virustotal": vt_details,
                        "safe_browsing": sb_details,
                        "urlscan": us_details,
                        "abuseipdb": ab_details,
                        "source": extracted_url.source.value,
                        "source_detail": extracted_url.source_detail,
                        "dead_domain": dead_domain,
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

            # Collect errors from per-URL results for visibility
            all_errors = []
            for url_key, result in url_results.items():
                if "error" in result:
                    all_errors.append(f"{url_key}: {result['error']}")
                # Also surface per-service errors
                for svc in ("virustotal", "safe_browsing", "urlscan", "abuseipdb"):
                    svc_detail = result.get(svc, {})
                    for err_key in (f"{svc}_error", "error"):
                        if err_key in svc_detail:
                            all_errors.append(f"{svc}: {svc_detail[err_key]}")

            overall_risk_score = max(url_scores) if url_scores else 0.0
            overall_confidence = max(url_confidences) if url_confidences else 0.0

            if all_errors:
                logger.warning(
                    f"URL reputation service errors: {'; '.join(all_errors[:5])}"
                )

            logger.info(
                f"URL reputation analysis complete: "
                f"risk={overall_risk_score:.2f}, confidence={overall_confidence:.2f}, "
                f"services_ok={len(url_scores)}/{len(url_results)}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=overall_risk_score,
                confidence=overall_confidence,
                details={
                    "url_count": len(urls),
                    "urls_analyzed": url_results,
                },
                errors=all_errors if all_errors else None,
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

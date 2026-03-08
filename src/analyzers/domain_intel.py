"""
DomainIntelAnalyzer: Deep domain intelligence analysis.
Performs WHOIS lookups, domain age analysis, DNS record checks, and phishing feed lookups.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlparse

from src.models import AnalyzerResult, ExtractedURL

logger = logging.getLogger(__name__)


class DomainIntelAnalyzer:
    """
    Analyze domain intelligence including registration details, age, and DNS records.

    Performs:
    - WHOIS lookups for domain registration info
    - Domain age analysis (flags domains < 30 days old)
    - Privacy-protected registration detection
    - DNS record analysis (SPF, DKIM, DMARC)
    - Phishing feed checks
    """

    def __init__(self, whois_client: Optional[object] = None):
        """
        Initialize domain intelligence analyzer with dependency injection.

        Args:
            whois_client: WHOIS lookup client
        """
        self.whois_client = whois_client

    def _extract_domain(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.

        Args:
            url: URL string

        Returns:
            Domain name or None
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                domain = url.lower()
            # Remove www. prefix if present
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception as e:
            logger.warning(f"Failed to extract domain from {url}: {e}")
            return None

    async def _check_whois(self, domain: str) -> tuple[float, float, dict]:
        """
        Perform WHOIS lookup for domain.

        Args:
            domain: Domain to lookup

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.whois_client:
            return 0.0, 0.0, {}

        try:
            whois_data = await self.whois_client.lookup(domain)

            details: dict = {
                "whois": {
                    "found": True,
                    "registrar": whois_data.get("registrar", "unknown"),
                    "created_date": str(whois_data.get("creation_date", "")),
                }
            }

            risk_score = 0.0
            confidence = 0.8

            # Check domain age
            creation_date = whois_data.get("creation_date")
            if creation_date:
                try:
                    if isinstance(creation_date, str):
                        creation_date = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))

                    age_days = (datetime.now(creation_date.tzinfo) - creation_date).days
                    details["whois"]["domain_age_days"] = age_days

                    # Newly registered domains are suspicious
                    if age_days < 30:
                        risk_score = max(risk_score, 0.7)
                        details["whois"]["newly_registered"] = True
                    elif age_days < 90:
                        risk_score = max(risk_score, 0.3)
                        details["whois"]["recently_registered"] = True

                except Exception as e:
                    logger.warning(f"Failed to parse creation date: {e}")

            # Check for privacy protection
            privacy_contact = whois_data.get("privacy_contact", False)
            if privacy_contact:
                risk_score = max(risk_score, 0.4)
                details["whois"]["privacy_protected"] = True
                confidence = 0.6

            # Check registrant details
            registrant_email = whois_data.get("registrant_email", "")
            if registrant_email and "proxy" in registrant_email.lower():
                risk_score = max(risk_score, 0.5)
                details["whois"]["proxy_registration"] = True

            return risk_score, confidence, details

        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return 0.0, 0.0, {"whois_error": str(e)}

    async def _check_dns_records(self, domain: str) -> tuple[float, float, dict]:
        """
        Check DNS records (SPF, DKIM, DMARC).

        Args:
            domain: Domain to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.whois_client:
            return 0.0, 0.0, {}

        try:
            dns_records = await self.whois_client.check_dns_records(domain)

            details: dict = {"dns_records": {}}
            risk_score = 0.0
            confidence = 0.7

            # Check SPF record
            spf_records = dns_records.get("SPF", [])
            if spf_records:
                details["dns_records"]["spf_present"] = True
                details["dns_records"]["spf_records"] = spf_records
            else:
                risk_score = max(risk_score, 0.3)
                details["dns_records"]["spf_present"] = False

            # Check DKIM record
            dkim_records = dns_records.get("DKIM", [])
            if dkim_records:
                details["dns_records"]["dkim_present"] = True
            else:
                risk_score = max(risk_score, 0.2)
                details["dns_records"]["dkim_present"] = False

            # Check DMARC policy
            dmarc_records = dns_records.get("DMARC", [])
            if dmarc_records:
                details["dns_records"]["dmarc_present"] = True
                details["dns_records"]["dmarc_policy"] = dmarc_records[0] if dmarc_records else ""
            else:
                risk_score = max(risk_score, 0.2)
                details["dns_records"]["dmarc_present"] = False

            # Check MX records
            mx_records = dns_records.get("MX", [])
            if not mx_records:
                risk_score = max(risk_score, 0.6)
                details["dns_records"]["mx_present"] = False
            else:
                details["dns_records"]["mx_present"] = True
                details["dns_records"]["mx_records"] = mx_records

            return risk_score, confidence, details

        except Exception as e:
            logger.warning(f"DNS check failed for {domain}: {e}")
            return 0.0, 0.0, {"dns_error": str(e)}

    async def _check_phishing_feeds(self, domain: str) -> tuple[float, float, dict]:
        """
        Check domain against known phishing feeds.

        Args:
            domain: Domain to check

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.whois_client:
            return 0.0, 0.0, {}

        try:
            feed_results = await self.whois_client.check_phishing_feeds(domain)

            details: dict = {"phishing_feeds": feed_results}
            risk_score = 0.0
            confidence = 0.0

            if feed_results.get("found_in_feeds"):
                risk_score = 0.95
                confidence = 1.0
                details["phishing_feeds"]["threat_level"] = "confirmed"
            elif feed_results.get("suspicious_patterns"):
                risk_score = 0.6
                confidence = 0.7
                details["phishing_feeds"]["threat_level"] = "suspicious"

            return risk_score, confidence, details

        except Exception as e:
            logger.warning(f"Phishing feed check failed for {domain}: {e}")
            return 0.0, 0.0, {"phishing_feeds_error": str(e)}

    async def analyze(self, urls: list[ExtractedURL]) -> AnalyzerResult:
        """
        Analyze domain intelligence for extracted URLs.

        Args:
            urls: List of extracted URLs to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "domain_intel"

        try:
            if not urls:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=1.0,
                    details={"message": "no_urls_to_analyze"},
                )

            domain_results: dict[str, dict] = {}
            processed_domains: set[str] = set()

            for extracted_url in urls:
                domain = self._extract_domain(extracted_url.url)
                if not domain or domain in processed_domains:
                    continue

                processed_domains.add(domain)

                try:
                    # Run all domain checks concurrently
                    whois_score, whois_conf, whois_details = await self._check_whois(domain)
                    dns_score, dns_conf, dns_details = await self._check_dns_records(domain)
                    feed_score, feed_conf, feed_details = await self._check_phishing_feeds(domain)

                    # Per-domain: max-across-checks logic
                    per_domain_risk = max(whois_score, dns_score, feed_score)
                    per_domain_confidence = max(whois_conf, dns_conf, feed_conf)

                    domain_results[domain] = {
                        "risk_score": per_domain_risk,
                        "confidence": per_domain_confidence,
                        "whois": whois_details,
                        "dns_records": dns_details,
                        "phishing_feeds": feed_details,
                    }

                except Exception as e:
                    logger.error(f"Error analyzing domain {domain}: {e}")
                    domain_results[domain] = {
                        "error": str(e),
                    }

            # Overall: max across all domains
            domain_scores = [
                result.get("risk_score", 0.0)
                for result in domain_results.values()
                if "error" not in result
            ]
            domain_confidences = [
                result.get("confidence", 0.0)
                for result in domain_results.values()
                if "error" not in result
            ]

            overall_risk_score = max(domain_scores) if domain_scores else 0.0
            overall_confidence = max(domain_confidences) if domain_confidences else 0.0

            logger.info(
                f"Domain intelligence analysis complete: "
                f"risk={overall_risk_score:.2f}, confidence={overall_confidence:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=overall_risk_score,
                confidence=overall_confidence,
                details={
                    "domain_count": len(processed_domains),
                    "domains_analyzed": domain_results,
                },
            )

        except Exception as e:
            logger.error(f"Domain intelligence analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

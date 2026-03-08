"""
AbuseIPDB v2 API client for IP reputation lookups.
Rate limit: 1000 requests/day
"""
import logging
from typing import Optional

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class AbuseIPDBClient(BaseAPIClient):
    """AbuseIPDB v2 API client."""

    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key
        """
        # Rate limit: 1000 requests per day (~0.01 per second)
        super().__init__(
            api_key=api_key,
            base_url="https://api.abuseipdb.com/api/v2",
            rate_limit=(1, 6),  # Conservative: 1 request per 6 seconds
            cache_ttl=21600,  # 6 hours default
        )

    async def verify_api_key(self) -> bool:
        """Verify AbuseIPDB API key by checking account details."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/account",
                headers=self._get_headers(),
                timeout=10,
            )
            return "data" in response
        except Exception as e:
            logger.error(f"Failed to verify AbuseIPDB API key: {e}")
            return False

    async def check_ip(
        self,
        ip: str,
        max_age_days: int = 90,
        verbose: bool = True,
    ) -> AnalyzerResult:
        """
        Check IP reputation on AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of abuse reports to consider (1-365)
            verbose: Include abuse reports in response

        Returns:
            AnalyzerResult with IP reputation
        """
        cache_key = self._get_cache_key("check_ip", ip)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": "on" if verbose else "off",
            }

            response = await self._request(
                method="GET",
                endpoint="/check",
                headers=self._get_headers(),
                params=params,
                timeout=15,
            )

            result = self._parse_check_response(response, ip)
            self._cache_set(cache_key, result, ttl=21600)  # 6 hours
            return result

        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip}: {e}")
            return AnalyzerResult(
                analyzer_name="abuseipdb",
                risk_score=0.0,
                confidence=0.0,
                details={"ip": ip},
                errors=[str(e)],
            )

    async def bulk_check_ips(self, ips: list[str]) -> dict[str, AnalyzerResult]:
        """
        Check multiple IPs (non-batched, respects rate limits).

        Args:
            ips: List of IP addresses to check

        Returns:
            Dictionary mapping IP to AnalyzerResult
        """
        results = {}
        for ip in ips:
            results[ip] = await self.check_ip(ip)
        return results

    def _get_headers(self) -> dict[str, str]:
        """Get headers for AbuseIPDB requests."""
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    @staticmethod
    def _parse_check_response(response: dict, ip: str) -> AnalyzerResult:
        """Parse AbuseIPDB check response."""
        details = {
            "ip": ip,
            "abuseipdb_url": f"https://www.abuseipdb.com/check/{ip}",
        }

        if "data" not in response:
            return AnalyzerResult(
                analyzer_name="abuseipdb",
                risk_score=0.0,
                confidence=0.0,
                details=details,
            )

        data = response["data"]

        # Main abuse score (0-100)
        abuse_score = data.get("abuseConfidenceScore", 0) / 100.0

        details.update({
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "is_whitelist": data.get("isWhitelisted", False),
            "total_reports": data.get("totalReports", 0),
        })

        # Get report categories if verbose
        if "reports" in data:
            reports = data["reports"]
            details["report_count"] = len(reports)

            # Aggregate report categories
            categories = {}
            for report in reports:
                for cat_id in report.get("categories", []):
                    category_name = AbuseIPDBClient._get_category_name(cat_id)
                    categories[category_name] = categories.get(category_name, 0) + 1

            details["report_categories"] = categories

        # Boost risk score for whitelisted IPs downward
        if data.get("isWhitelisted"):
            abuse_score = 0.0

        # Confidence based on number of reports
        total_reports = data.get("totalReports", 0)
        confidence = min(total_reports / 10.0, 1.0)  # 10+ reports = high confidence

        return AnalyzerResult(
            analyzer_name="abuseipdb",
            risk_score=min(abuse_score, 1.0),
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def _get_category_name(category_id: int) -> str:
        """Map AbuseIPDB category ID to name."""
        categories = {
            3: "Fraudulent Activity",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Proxy/VPN",
            9: "Spam",
            10: "SSH Brute-Force",
            11: "Mass Root Network Scan",
            12: "SMTP Brute-Force",
            13: "SMTP Relay",
            14: "SoftLayer Probe",
            15: "Open Proxy",
            16: "Web Application Attack",
            17: "Open DNS Resolver",
            18: "Compormised FTP",
            19: "Botnet Command/Control",
            20: "Spoofed DNS Records",
            21: "Malware Distribution",
            22: "SSH Port Forwarding",
            23: "Auto Reporting",
            24: "Dedicated Hosting Abuse",
            25: "Domain Abuse",
            26: "Hacktivism",
            27: "HTTPS/SSL Abuse",
            28: "IP Forwarding Traffic",
            29: "Malicious Web Shell Upload",
            30: "Port Scan",
            31: "Smurf Attack",
            32: "Strong CPU Bot",
            33: "Unconfirmed Bot Traffic",
            34: "Exploit Host",
            35: "Library Distribution",
            36: "Charity Fraud",
            37: "Third Party Fraud",
        }
        return categories.get(category_id, f"Category {category_id}")

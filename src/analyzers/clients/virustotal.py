"""
VirusTotal v3 API client for URL, domain, IP, and file hash lookups.
Rate limit: 4 requests/minute
"""
import logging
from typing import Optional
import hashlib

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class VirusTotalClient(BaseAPIClient):
    """VirusTotal v3 API client."""

    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
        """
        # Rate limit: 4 requests per minute
        super().__init__(
            api_key=api_key,
            base_url="https://www.virustotal.com/api/v3",
            rate_limit=(4, 60),
            cache_ttl=3600,  # 1 hour default
        )

    async def verify_api_key(self) -> bool:
        """Verify VirusTotal API key by making a test request."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/ip_addresses/1.1.1.1",
                headers={"x-apikey": self.api_key},
                timeout=10,
            )
            return "data" in response
        except Exception as e:
            logger.error(f"Failed to verify VirusTotal API key: {e}")
            return False

    async def scan_url(self, url: str, force_rescan: bool = False) -> AnalyzerResult:
        """
        Scan a URL on VirusTotal.

        Args:
            url: URL to scan
            force_rescan: If True, force a new scan even if cached

        Returns:
            AnalyzerResult with scan findings
        """
        cache_key = self._get_cache_key("scan_url", url)

        if not force_rescan:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        try:
            url_id = self._encode_url_for_vt(url)

            response = await self._request(
                method="GET",
                endpoint=f"/urls/{url_id}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )

            result = self._parse_url_response(response, url)
            self._cache_set(cache_key, result, ttl=3600)  # 1 hour
            return result

        except Exception as e:
            # 404 = URL not in VT database yet. Submit it for future lookups
            # and return "unknown" rather than treating this as an error.
            if "404" in str(e):
                try:
                    import asyncio as _asyncio
                    _asyncio.create_task(self._submit_url_for_scan(url))
                except Exception:
                    pass
                return AnalyzerResult(
                    analyzer_name="virustotal_url",
                    risk_score=0.0,
                    confidence=0.0,
                    details={"vt_status": "not_in_database", "submitted": True},
                )
            logger.error(f"VirusTotal URL scan failed for {url}: {e}")
            return AnalyzerResult(
                analyzer_name="virustotal_url",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

    async def _submit_url_for_scan(self, url: str) -> None:
        """Submit a URL to VirusTotal for scanning (fire-and-forget)."""
        try:
            session = await self._get_session()
            import aiohttp as _aiohttp
            async with session.post(
                f"{self.base_url}/urls",
                headers={"x-apikey": self.api_key, "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={url}",
                timeout=_aiohttp.ClientTimeout(total=10),
            ) as resp:
                pass  # fire-and-forget, ignore response
            logger.debug(f"Submitted URL to VirusTotal for scanning: {url[:80]}")
        except Exception as e:
            logger.debug(f"VT URL submission failed (non-critical): {e}")

    async def get_domain_report(self, domain: str) -> AnalyzerResult:
        """
        Get domain reputation from VirusTotal.

        Args:
            domain: Domain to lookup

        Returns:
            AnalyzerResult with domain reputation
        """
        cache_key = self._get_cache_key("domain", domain)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            response = await self._request(
                method="GET",
                endpoint=f"/domains/{domain}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )

            result = self._parse_domain_response(response, domain)
            self._cache_set(cache_key, result, ttl=86400)  # 24 hours
            return result

        except Exception as e:
            logger.error(f"VirusTotal domain lookup failed for {domain}: {e}")
            return AnalyzerResult(
                analyzer_name="virustotal_domain",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

    async def get_ip_report(self, ip: str) -> AnalyzerResult:
        """
        Get IP reputation from VirusTotal.

        Args:
            ip: IP address to lookup

        Returns:
            AnalyzerResult with IP reputation
        """
        cache_key = self._get_cache_key("ip", ip)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            response = await self._request(
                method="GET",
                endpoint=f"/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )

            result = self._parse_ip_response(response, ip)
            self._cache_set(cache_key, result, ttl=86400)  # 24 hours
            return result

        except Exception as e:
            logger.error(f"VirusTotal IP lookup failed for {ip}: {e}")
            return AnalyzerResult(
                analyzer_name="virustotal_ip",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

    async def check_file_hash(self, file_hash: str) -> AnalyzerResult:
        """
        Check file hash on VirusTotal.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash

        Returns:
            AnalyzerResult with file reputation
        """
        cache_key = self._get_cache_key("hash", file_hash)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            response = await self._request(
                method="GET",
                endpoint=f"/files/{file_hash}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )

            result = self._parse_hash_response(response, file_hash)
            self._cache_set(cache_key, result, ttl=86400)  # 24 hours
            return result

        except Exception as e:
            logger.error(f"VirusTotal hash check failed for {file_hash}: {e}")
            return AnalyzerResult(
                analyzer_name="virustotal_hash",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

    @staticmethod
    def _encode_url_for_vt(url: str) -> str:
        """
        Encode URL for VirusTotal v3 API.
        VT v3 uses URL ID which is base64url of SHA-256 hash.
        """
        import base64
        url_bytes = url.encode("utf-8")
        # VT v3: URL identifier is base64url of the raw URL (no hashing)
        encoded = base64.urlsafe_b64encode(url_bytes).decode().rstrip("=")
        return encoded

    @staticmethod
    def _parse_url_response(response: dict, url: str) -> AnalyzerResult:
        """Parse VirusTotal URL scan response."""
        details = {
            "url": url,
            "vt_url": f"https://virustotal.com/gui/home/search?query={url}",
        }

        if "data" not in response:
            return AnalyzerResult(
                analyzer_name="virustotal_url",
                risk_score=0.0,
                confidence=0.0,
                details=details,
            )

        data = response["data"]
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + undetected + last_analysis.get("timeout", 0)

        # Risk score: malicious vendors have highest weight
        risk_score = 0.0
        if total > 0:
            risk_score = (malicious * 1.0 + suspicious * 0.5) / total

        # Confidence based on number of vendors analyzing
        confidence = min(total / 50.0, 1.0)  # 50+ vendors = high confidence

        details.update({
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_submission_date": attributes.get("last_submission_date"),
            "total_votes_harmless": attributes.get("last_http_response_code"),
            "malicious_vendors": malicious,
            "suspicious_vendors": suspicious,
            "total_vendors": total,
        })

        return AnalyzerResult(
            analyzer_name="virustotal_url",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def _parse_domain_response(response: dict, domain: str) -> AnalyzerResult:
        """Parse VirusTotal domain lookup response."""
        details = {
            "domain": domain,
            "vt_url": f"https://virustotal.com/gui/home/search?query={domain}",
        }

        if "data" not in response:
            return AnalyzerResult(
                analyzer_name="virustotal_domain",
                risk_score=0.0,
                confidence=0.0,
                details=details,
            )

        data = response["data"]
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + undetected + last_analysis.get("timeout", 0)

        risk_score = 0.0
        if total > 0:
            risk_score = (malicious * 1.0 + suspicious * 0.5) / total

        confidence = min(total / 50.0, 1.0)

        details.update({
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories", {}),
            "malicious_vendors": malicious,
            "suspicious_vendors": suspicious,
            "total_vendors": total,
        })

        return AnalyzerResult(
            analyzer_name="virustotal_domain",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def _parse_ip_response(response: dict, ip: str) -> AnalyzerResult:
        """Parse VirusTotal IP lookup response."""
        details = {
            "ip": ip,
            "vt_url": f"https://virustotal.com/gui/home/search?query={ip}",
        }

        if "data" not in response:
            return AnalyzerResult(
                analyzer_name="virustotal_ip",
                risk_score=0.0,
                confidence=0.0,
                details=details,
            )

        data = response["data"]
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + undetected + last_analysis.get("timeout", 0)

        risk_score = 0.0
        if total > 0:
            risk_score = (malicious * 1.0 + suspicious * 0.5) / total

        confidence = min(total / 50.0, 1.0)

        details.update({
            "last_analysis_date": attributes.get("last_analysis_date"),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "malicious_vendors": malicious,
            "suspicious_vendors": suspicious,
            "total_vendors": total,
        })

        return AnalyzerResult(
            analyzer_name="virustotal_ip",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

    @staticmethod
    def _parse_hash_response(response: dict, file_hash: str) -> AnalyzerResult:
        """Parse VirusTotal file hash lookup response."""
        details = {
            "hash": file_hash,
            "vt_url": f"https://virustotal.com/gui/home/search?query={file_hash}",
        }

        if "data" not in response:
            return AnalyzerResult(
                analyzer_name="virustotal_hash",
                risk_score=0.0,
                confidence=0.0,
                details=details,
            )

        data = response["data"]
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})

        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total = malicious + suspicious + undetected + last_analysis.get("timeout", 0)

        risk_score = 0.0
        if total > 0:
            risk_score = (malicious * 1.0 + suspicious * 0.5) / total

        confidence = min(total / 50.0, 1.0)

        details.update({
            "last_analysis_date": attributes.get("last_analysis_date"),
            "names": attributes.get("names", []),
            "size": attributes.get("size"),
            "type_description": attributes.get("type_description"),
            "malicious_vendors": malicious,
            "suspicious_vendors": suspicious,
            "total_vendors": total,
        })

        return AnalyzerResult(
            analyzer_name="virustotal_hash",
            risk_score=min(risk_score, 1.0),
            confidence=confidence,
            details=details,
        )

"""
WHOIS and DNS client for domain reconnaissance.
Uses python-whois and dnspython libraries (no external API).
"""
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import whois
import dns.resolver
import dns.exception

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class WhoisClient(BaseAPIClient):
    """WHOIS and DNS lookup client."""

    def __init__(self, thread_pool_size: int = 5):
        """
        Initialize WHOIS client.

        Args:
            thread_pool_size: Number of threads for async WHOIS lookups
        """
        # WHOIS has no external API rate limits, use conservative limits
        super().__init__(
            api_key="",  # No API key needed
            base_url="",  # No base URL
            rate_limit=(10, 60),  # 10 requests per minute (conservative)
            cache_ttl=86400,  # 24 hours default
        )
        self.executor = ThreadPoolExecutor(max_workers=thread_pool_size)
        self.dns_resolver = dns.resolver.Resolver()

    async def verify_api_key(self) -> bool:
        """No API key needed for WHOIS/DNS."""
        return True

    async def lookup_domain(self, domain: str) -> AnalyzerResult:
        """
        Perform comprehensive domain lookup (WHOIS + DNS).

        Args:
            domain: Domain to lookup

        Returns:
            AnalyzerResult with domain reputation and metadata
        """
        cache_key = self._get_cache_key("domain_lookup", domain)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            # Run WHOIS in thread pool (blocking operation)
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(
                self.executor,
                self._whois_lookup,
                domain,
            )

            # Perform DNS queries (async)
            dns_data = await self._dns_lookup(domain)

            result = self._parse_domain_info(domain, whois_data, dns_data)
            self._cache_set(cache_key, result, ttl=86400)  # 24 hours
            return result

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return AnalyzerResult(
                analyzer_name="whois_dns",
                risk_score=0.0,
                confidence=0.0,
                details={"domain": domain},
                errors=[str(e)],
            )

    def _whois_lookup(self, domain: str) -> dict:
        """
        Perform WHOIS lookup (blocking, runs in executor).

        Args:
            domain: Domain to lookup

        Returns:
            Dictionary with WHOIS information
        """
        try:
            whois_obj = whois.whois(domain)
            return {
                "creation_date": whois_obj.creation_date,
                "expiration_date": whois_obj.expiration_date,
                "updated_date": whois_obj.updated_date,
                "registrar": whois_obj.registrar,
                "status": whois_obj.status,
                "name_servers": whois_obj.name_servers,
                "registrant_country": whois_obj.country,
                "org": whois_obj.org,
            }
        except Exception as e:
            logger.warning(f"WHOIS query failed for {domain}: {e}")
            return {}

    async def _dns_lookup(self, domain: str) -> dict:
        """
        Perform DNS queries (A, AAAA, MX, TXT, NS, CNAME).

        Args:
            domain: Domain to query

        Returns:
            Dictionary with DNS records
        """
        dns_data = {}

        # DNS query types to perform
        query_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        for query_type in query_types:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    self.executor,
                    self._dns_query,
                    domain,
                    query_type,
                )
                dns_data[query_type.lower()] = answers
            except Exception as e:
                logger.debug(f"DNS {query_type} query failed for {domain}: {e}")
                dns_data[query_type.lower()] = []

        return dns_data

    def _dns_query(self, domain: str, query_type: str) -> list[str]:
        """
        Perform single DNS query (blocking, runs in executor).

        Args:
            domain: Domain to query
            query_type: Query type (A, AAAA, MX, TXT, NS, CNAME)

        Returns:
            List of query results
        """
        try:
            answers = self.dns_resolver.resolve(domain, query_type)
            results = []

            if query_type == "MX":
                results = [str(rdata.exchange) for rdata in answers]
            elif query_type == "NS":
                results = [str(rdata) for rdata in answers]
            elif query_type == "TXT":
                results = [str(rdata) for rdata in answers]
            else:
                # A, AAAA, CNAME
                results = [str(rdata) for rdata in answers]

            return results
        except dns.exception.DNSException as e:
            logger.debug(f"DNS {query_type} lookup error for {domain}: {e}")
            return []

    @staticmethod
    def _parse_domain_info(
        domain: str,
        whois_data: dict,
        dns_data: dict,
    ) -> AnalyzerResult:
        """
        Parse WHOIS and DNS information to assess domain age and legitimacy.

        Args:
            domain: Domain name
            whois_data: WHOIS information
            dns_data: DNS records

        Returns:
            AnalyzerResult with domain assessment
        """
        details = {
            "domain": domain,
            "whois_available": bool(whois_data),
            "dns_records": dns_data,
        }

        risk_score = 0.0
        confidence = 0.5

        # Calculate domain age
        if whois_data:
            details.update({
                "registrar": whois_data.get("registrar"),
                "creation_date": str(whois_data.get("creation_date")),
                "expiration_date": str(whois_data.get("expiration_date")),
                "updated_date": str(whois_data.get("updated_date")),
            })

            confidence = 0.9

            # Very new domains (< 30 days) are riskier
            if whois_data.get("creation_date"):
                creation = whois_data.get("creation_date")
                if isinstance(creation, list):
                    creation = creation[0]

                if isinstance(creation, datetime):
                    age = datetime.now(creation.tzinfo) - creation
                    if age < timedelta(days=30):
                        risk_score += 0.3
                    elif age < timedelta(days=365):
                        risk_score += 0.1

            # Check expiration
            if whois_data.get("expiration_date"):
                expiration = whois_data.get("expiration_date")
                if isinstance(expiration, list):
                    expiration = expiration[0]

                if isinstance(expiration, datetime):
                    time_to_expiration = expiration - datetime.now(expiration.tzinfo)
                    if time_to_expiration < timedelta(days=30):
                        risk_score += 0.2

        else:
            # No WHOIS data - slightly suspicious
            risk_score += 0.1

        # Check DNS configuration
        has_mx = bool(dns_data.get("mx"))
        has_ns = bool(dns_data.get("ns"))
        has_a = bool(dns_data.get("a"))
        has_aaaa = bool(dns_data.get("aaaa"))

        details["has_mx_records"] = has_mx
        details["has_ns_records"] = has_ns
        details["has_a_records"] = has_a
        details["has_aaaa_records"] = has_aaaa

        # Missing standard DNS records is suspicious
        if not has_a and not has_aaaa:
            risk_score += 0.15

        if not has_ns:
            risk_score += 0.1

        # SPF, DKIM, DMARC records
        spf_records = [r for r in dns_data.get("txt", []) if "v=spf1" in r]
        dkim_domains = [r for r in dns_data.get("txt", []) if "v=DKIM1" in r]
        dmarc_records = [r for r in dns_data.get("txt", []) if "v=DMARC1" in r]

        details.update({
            "has_spf": bool(spf_records),
            "has_dkim": bool(dkim_domains),
            "has_dmarc": bool(dmarc_records),
        })

        # Missing email security records is somewhat suspicious for email domains
        if not spf_records:
            risk_score += 0.05
        if not dmarc_records:
            risk_score += 0.05

        return AnalyzerResult(
            analyzer_name="whois_dns",
            risk_score=min(risk_score, 1.0),
            confidence=min(confidence, 1.0),
            details=details,
        )

    async def get_dns_records(self, domain: str, record_type: str) -> list[str]:
        """
        Get specific DNS records for a domain.

        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, TXT, NS, CNAME)

        Returns:
            List of DNS records
        """
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                self._dns_query,
                domain,
                record_type.upper(),
            )
        except Exception as e:
            logger.error(f"DNS lookup failed for {domain} ({record_type}): {e}")
            return []

    async def close(self) -> None:
        """Close the executor."""
        self.executor.shutdown(wait=True)
        await super().close()

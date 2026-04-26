"""
Header analysis: Parse Received chains, validate authentication, detect spoofing.

Analyzes SPF, DKIM, DMARC alignment, From/Reply-To mismatches, display name spoofing,
and suspicious received chains.
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from src.models import EmailObject, HeaderAnalysisDetail
from src.utils.domains import get_root_domain

logger = logging.getLogger(__name__)

# Try to import DMARC/DKIM validation libraries
try:
    import checkdmarc
    HAS_CHECKDMARC = True
except ImportError:
    HAS_CHECKDMARC = False
    logger.warning("checkdmarc not available; DMARC validation will be limited")

try:
    import dkim
    HAS_DKIMPY = True
except ImportError:
    HAS_DKIMPY = False
    logger.warning("dkimpy not available; DKIM validation will be limited")

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not available; DNS queries will be limited")


class ReceivedChainParser:
    """Parse Received headers to extract hop information."""

    # Regex patterns for Received header parsing
    FROM_PATTERN = re.compile(r"from\s+(\S+)(?:\s+\(([^\)]+)\))?", re.IGNORECASE)
    BY_PATTERN = re.compile(r"by\s+(\S+)", re.IGNORECASE)
    WITH_PATTERN = re.compile(r"with\s+(\S+)", re.IGNORECASE)
    FOR_PATTERN = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)
    TIMESTAMP_PATTERN = re.compile(r";\s*(.*?)$", re.MULTILINE)

    @staticmethod
    def parse_received_header(header: str) -> dict:
        """
        Parse a single Received header.

        Args:
            header: Raw Received header value

        Returns:
            Dictionary with parsed components: from_host, from_ip, by_host, protocol, etc.
        """
        result = {
            "from_host": None,
            "from_ip": None,
            "by_host": None,
            "protocol": None,
            "timestamp": None,
            "raw": header,
        }

        # Extract FROM
        from_match = ReceivedChainParser.FROM_PATTERN.search(header)
        if from_match:
            # Group 1 is hostname, group 2 is IP (if in parentheses)
            result["from_host"] = from_match.group(1)
            if from_match.group(2):
                # Extract IP if in format [IP]
                ip_candidate = from_match.group(2)
                if ip_candidate.startswith("[") and ip_candidate.endswith("]"):
                    result["from_ip"] = ip_candidate[1:-1]
                else:
                    result["from_ip"] = ip_candidate

        # Extract BY
        by_match = ReceivedChainParser.BY_PATTERN.search(header)
        if by_match:
            result["by_host"] = by_match.group(1)

        # Extract WITH (protocol)
        with_match = ReceivedChainParser.WITH_PATTERN.search(header)
        if with_match:
            result["protocol"] = with_match.group(1)

        # Extract timestamp (after semicolon)
        ts_match = ReceivedChainParser.TIMESTAMP_PATTERN.search(header)
        if ts_match:
            result["timestamp"] = ts_match.group(1).strip()

        return result

    @staticmethod
    def build_chain(received_headers: list[str]) -> list[dict]:
        """
        Build a hop chain from Received headers (in reverse order).

        Args:
            received_headers: List of Received header values

        Returns:
            List of hop dictionaries
        """
        hops = []
        for i, header in enumerate(reversed(received_headers)):
            hop = ReceivedChainParser.parse_received_header(header)
            hop["hop_index"] = i
            hops.append(hop)
        return hops


class HeaderAnalyzer:
    """
    Analyze email headers for spoofing, authentication alignment, and anomalies.

    Checks:
    - SPF alignment
    - DKIM alignment
    - DMARC alignment
    - From/Reply-To mismatch
    - Display name spoofing
    - Envelope-From mismatch
    - Suspicious Received chains
    """

    def __init__(self):
        """Initialize header analyzer."""
        self.logger = logger

    def analyze(self, email: EmailObject) -> HeaderAnalysisDetail:
        """
        Perform comprehensive header analysis.

        Args:
            email: EmailObject with parsed headers

        Returns:
            HeaderAnalysisDetail with all checks
        """
        detail = HeaderAnalysisDetail()

        # Extract authentication headers
        auth_results = self._extract_auth_headers(email.raw_headers)

        # Check SPF
        detail.spf_pass = self._check_spf(auth_results, email)

        # Check DKIM
        detail.dkim_pass = self._check_dkim(auth_results, email)

        # Check DMARC
        detail.dmarc_pass = self._check_dmarc(auth_results, email)

        # Check From/Reply-To mismatch
        detail.from_reply_to_mismatch = self._check_from_reply_to_mismatch(email)

        # Check display name spoofing
        detail.display_name_spoofing = self._check_display_name_spoofing(email)

        # Check envelope From mismatch
        detail.envelope_from_mismatch = self._check_envelope_from_mismatch(email)

        # Analyze received chain
        received_chain = ReceivedChainParser.build_chain(email.received_chain)
        detail.received_chain_details = received_chain
        detail.suspicious_received_chain = self._check_suspicious_received_chain(received_chain)

        return detail

    def _extract_auth_headers(self, raw_headers: dict[str, list[str]]) -> dict:
        """
        Extract authentication-related headers.

        Args:
            raw_headers: Raw headers dictionary

        Returns:
            Dictionary with auth header info
        """
        return {
            "authentication_results": raw_headers.get("authentication-results", []),
            "spf_result": raw_headers.get("spf-result", []),
            "dkim_signature": raw_headers.get("dkim-signature", []),
            "dmarc_result": raw_headers.get("dmarc-result", []),
            "arc_seal": raw_headers.get("arc-seal", []),
            "return_path": raw_headers.get("return-path", []),
        }

    def _check_spf(self, auth_results: dict, email: EmailObject) -> Optional[bool]:
        """
        Check SPF alignment.

        Args:
            auth_results: Extracted auth headers
            email: EmailObject

        Returns:
            True if SPF passes, False if fails, None if unknown
        """
        # Check Authentication-Results header
        for result in auth_results.get("authentication_results", []):
            if "spf=pass" in result.lower():
                return True
            elif "spf=fail" in result.lower():
                return False

        # Fallback: check SPF Result header
        for result in auth_results.get("spf_result", []):
            if "pass" in result.lower():
                return True
            elif "fail" in result.lower():
                return False

        return None

    def _check_dkim(self, auth_results: dict, email: EmailObject) -> Optional[bool]:
        """
        Check DKIM alignment.

        Args:
            auth_results: Extracted auth headers
            email: EmailObject

        Returns:
            True if DKIM passes, False if fails, None if unknown
        """
        # Check DKIM-Signature presence
        if auth_results.get("dkim_signature"):
            # If DKIM-Signature exists, check Authentication-Results
            for result in auth_results.get("authentication_results", []):
                if "dkim=pass" in result.lower():
                    return True
                elif "dkim=fail" in result.lower():
                    return False

        return None

    def _check_dmarc(self, auth_results: dict, email: EmailObject) -> Optional[bool]:
        """
        Check DMARC alignment.

        Args:
            auth_results: Extracted auth headers
            email: EmailObject

        Returns:
            True if DMARC passes, False if fails, None if unknown
        """
        # Check DMARC-Result header
        for result in auth_results.get("dmarc_result", []):
            if "pass" in result.lower():
                return True
            elif "fail" in result.lower():
                return False

        # Check Authentication-Results
        for result in auth_results.get("authentication_results", []):
            if "dmarc=pass" in result.lower():
                return True
            elif "dmarc=fail" in result.lower():
                return False

        return None

    def _check_from_reply_to_mismatch(self, email: EmailObject) -> bool:
        """
        Detect From/Reply-To mismatch.

        Only flags when the root (registrable) domains differ. Subdomains
        of the same org (e.g., github.com vs noreply.github.com) are NOT
        considered mismatches because many services use different subdomains
        for transactional vs notification emails.

        Args:
            email: EmailObject

        Returns:
            True if From and Reply-To root domains differ
        """
        if not email.reply_to or not email.from_address:
            return False

        # Extract domain from addresses
        from_domain = email.from_address.split("@")[1].lower() if "@" in email.from_address else ""
        reply_domain = email.reply_to.split("@")[1].lower() if "@" in email.reply_to else ""

        if not from_domain or not reply_domain:
            return False

        # Compare root domains — subdomains of the same org are fine
        return get_root_domain(from_domain) != get_root_domain(reply_domain)

    def _check_display_name_spoofing(self, email: EmailObject) -> bool:
        """
        Detect display name spoofing (e.g., "PayPal <attacker@evil.com>").

        Args:
            email: EmailObject

        Returns:
            True if display name appears to spoof a brand
        """
        if not email.from_display_name:
            return False

        display_name = email.from_display_name.lower()
        from_address = email.from_address.lower()

        # Extract domain from email
        from_domain = from_address.split("@")[1] if "@" in from_address else ""

        # Check if display name contains a domain different from from_address
        suspicious_keywords = {
            "paypal", "amazon", "apple", "microsoft", "google", "facebook", "twitter",
            "instagram", "linkedin", "bank", "support", "noreply", "no-reply", "admin",
            "security", "verify", "confirm", "urgent", "action required",
        }

        # If display name is a known brand or service but domain doesn't match
        for keyword in suspicious_keywords:
            if keyword in display_name and keyword not in from_domain:
                return True

        return False

    def _check_envelope_from_mismatch(self, email: EmailObject) -> bool:
        """
        Check for envelope-from (Return-Path) mismatch.

        Args:
            email: EmailObject

        Returns:
            True if Return-Path differs from From domain
        """
        return_path = email.raw_headers.get("return-path", [])
        if not return_path:
            return False

        return_addr = return_path[0].strip("<>").lower() if return_path else ""
        from_addr = email.from_address.lower()

        if not return_addr or not from_addr:
            return False

        # Extract domains
        return_domain = return_addr.split("@")[1] if "@" in return_addr else ""
        from_domain = from_addr.split("@")[1] if "@" in from_addr else ""

        return return_domain != from_domain if return_domain and from_domain else False

    def _check_suspicious_received_chain(self, hop_chain: list[dict]) -> bool:
        """
        Detect anomalies in the Received chain.

        Args:
            hop_chain: List of parsed Received hops

        Returns:
            True if suspicious patterns detected
        """
        if not hop_chain:
            return False

        suspicious = False

        for i, hop in enumerate(hop_chain):
            # Check for suspicious patterns
            if hop.get("from_host") and hop.get("by_host"):
                # Check if from and by are the same (unusual)
                if hop["from_host"].lower() == hop["by_host"].lower():
                    suspicious = True

            # Check for missing hops (sender claims direct delivery)
            if i == 0 and len(hop_chain) == 1:
                # Direct delivery - check if from_ip looks suspicious
                if hop.get("from_ip") and self._is_private_ip(hop["from_ip"]):
                    suspicious = True

        return suspicious

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """
        Check if IP is private/local.

        Args:
            ip_str: IP address string

        Returns:
            True if private IP
        """
        ip_str = ip_str.strip("[]")
        private_ranges = [
            "127.",  # Loopback
            "10.",  # Private
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",  # Private
            "192.168.",  # Private
            "169.254.",  # Link-local
        ]
        return any(ip_str.startswith(prefix) for prefix in private_ranges)


def analyze_headers(email: EmailObject) -> HeaderAnalysisDetail:
    """
    Convenience function to analyze email headers.

    Args:
        email: EmailObject

    Returns:
        HeaderAnalysisDetail with analysis results
    """
    analyzer = HeaderAnalyzer()
    return analyzer.analyze(email)

"""
Blocklist/Allowlist checker for the phishing detection pipeline.

Checks email senders, domains, URLs, and IPs against local
blocklists (known phishing) and allowlists (verified legitimate).
These lists are populated by analyst feedback.
"""
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from src.models import EmailObject, ExtractedURL, Verdict

logger = logging.getLogger(__name__)


@dataclass
class ListCheckResult:
    """Result of blocklist/allowlist check."""
    is_blocklisted: bool = False
    is_allowlisted: bool = False
    blocklist_matches: list[dict] = field(default_factory=list)
    allowlist_matches: list[dict] = field(default_factory=list)
    override_verdict: Optional[Verdict] = None
    override_reason: str = ""


class BlocklistAllowlistChecker:
    """
    Checks email indicators against local blocklist/allowlist databases.

    The blocklist contains IOCs from confirmed phishing (analyst-verified
    false negatives). The allowlist contains senders/domains from
    confirmed legitimate emails (analyst-verified false positives).

    Supports checking:
    - Sender email addresses
    - Sender domains
    - URLs in email body
    - IP addresses from headers
    """

    def __init__(self, db_session_factory=None):
        """
        Args:
            db_session_factory: Async session factory for database access.
                If None, the checker runs in "no-op" mode (always returns
                empty results).
        """
        self.db_session_factory = db_session_factory

    async def check(self, email: EmailObject, extracted_urls: list[ExtractedURL]) -> ListCheckResult:
        """
        Check an email against blocklist and allowlist.

        Args:
            email: EmailObject to check
            extracted_urls: URLs extracted from the email

        Returns:
            ListCheckResult with matches and optional verdict override
        """
        result = ListCheckResult()

        if self.db_session_factory is None:
            return result

        try:
            async with self.db_session_factory() as session:
                # Check sender email
                if email.from_address:
                    await self._check_indicator(
                        session, email.from_address, "email", result
                    )

                # Check sender domain
                sender_domain = self._extract_domain_from_email(email.from_address)
                if sender_domain:
                    await self._check_indicator(
                        session, sender_domain, "domain", result
                    )

                # Check URLs
                for url_obj in extracted_urls:
                    url_domain = self._extract_domain_from_url(url_obj.url)
                    if url_domain:
                        await self._check_indicator(
                            session, url_domain, "domain", result
                        )
                    await self._check_indicator(
                        session, url_obj.url, "url", result
                    )

                # Check Reply-To domain (common in phishing)
                if email.reply_to and email.reply_to != email.from_address:
                    reply_domain = self._extract_domain_from_email(email.reply_to)
                    if reply_domain:
                        await self._check_indicator(
                            session, reply_domain, "domain", result
                        )

        except Exception as e:
            logger.warning(f"Blocklist/allowlist check failed: {e}")
            return result

        # Determine override verdict
        if result.is_blocklisted and not result.is_allowlisted:
            result.override_verdict = Verdict.CONFIRMED_PHISHING
            indicators = ", ".join(
                m["indicator"] for m in result.blocklist_matches[:3]
            )
            result.override_reason = (
                f"Blocklisted indicator(s): {indicators}"
            )
        elif result.is_allowlisted and not result.is_blocklisted:
            result.override_verdict = Verdict.CLEAN
            indicators = ", ".join(
                m["indicator"] for m in result.allowlist_matches[:3]
            )
            result.override_reason = (
                f"Allowlisted indicator(s): {indicators}"
            )

        if result.is_blocklisted or result.is_allowlisted:
            logger.info(
                f"List check for {email.email_id}: "
                f"blocklisted={result.is_blocklisted}, "
                f"allowlisted={result.is_allowlisted}, "
                f"override={result.override_verdict}"
            )

        return result

    async def _check_indicator(
        self,
        session,
        indicator: str,
        indicator_type: str,
        result: ListCheckResult,
    ):
        """Check a single indicator against both lists."""
        from sqlalchemy import select
        from src.feedback.database import LocalBlocklist, LocalAllowlist

        # Check blocklist
        stmt = select(LocalBlocklist).where(
            LocalBlocklist.indicator == indicator.lower(),
            LocalBlocklist.indicator_type == indicator_type,
        )
        rows = (await session.execute(stmt)).scalars().all()
        if rows:
            result.is_blocklisted = True
            for row in rows:
                result.blocklist_matches.append({
                    "indicator": row.indicator,
                    "type": row.indicator_type,
                    "source": getattr(row, "source", "analyst_feedback"),
                })

        # Check allowlist
        stmt = select(LocalAllowlist).where(
            LocalAllowlist.indicator == indicator.lower(),
            LocalAllowlist.indicator_type == indicator_type,
        )
        rows = (await session.execute(stmt)).scalars().all()
        if rows:
            result.is_allowlisted = True
            for row in rows:
                result.allowlist_matches.append({
                    "indicator": row.indicator,
                    "type": row.indicator_type,
                    "source": getattr(row, "source", "analyst_feedback"),
                })

    @staticmethod
    def _extract_domain_from_email(email_addr: str) -> Optional[str]:
        """Extract domain from email address."""
        if "@" in email_addr:
            return email_addr.rsplit("@", 1)[-1].lower()
        return None

    @staticmethod
    def _extract_domain_from_url(url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return (parsed.hostname or "").lower() or None
        except Exception:
            return None

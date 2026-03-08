"""
Metadata extractor: Extract sender info, timestamps, and reply chains.

Simple metadata extraction for sender information, email timestamps, and reply-to chains.
"""
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from src.models import EmailObject

logger = logging.getLogger(__name__)


@dataclass
class SenderMetadata:
    """Extracted sender information."""
    email_address: str
    display_name: str
    domain: str
    is_internal: Optional[bool] = None  # Would be set if internal domain list is provided
    has_display_name: bool = False
    display_name_matches_domain: bool = False


@dataclass
class EmailMetadata:
    """High-level email metadata."""
    email_id: str
    sender: SenderMetadata
    recipients: list[str]
    subject: str
    date: datetime
    is_reply: bool
    reply_depth: int  # How many times this email has been replied to
    has_attachments: bool
    attachment_count: int
    attachment_types: list[str]
    body_length: int
    html_body_length: int


class MetadataExtractor:
    """
    Extract metadata from emails.

    Extracts:
    - Sender information
    - Recipient lists
    - Subject line
    - Timestamps
    - Reply chain depth
    - Attachment information
    - Body statistics
    """

    # Patterns for detecting reply chains
    REPLY_PATTERNS = [
        re.compile(r"^on\s+.+?wrote:", re.IGNORECASE | re.MULTILINE),  # "On X wrote:"
        re.compile(r"^-----original message-----", re.IGNORECASE | re.MULTILINE),  # Outlook
        re.compile(r"^_+\nfrom:", re.IGNORECASE | re.MULTILINE),  # Gmail
        re.compile(r"^from:.*\nto:.*\ndate:.*\nsubject:", re.IGNORECASE | re.MULTILINE),  # Generic
    ]

    # Pattern for detecting quoted text
    QUOTE_PATTERN = re.compile(r"^[\s>]*>", re.MULTILINE)

    def __init__(self, internal_domains: Optional[list[str]] = None):
        """
        Initialize metadata extractor.

        Args:
            internal_domains: List of internal domain names for classification
        """
        self.logger = logger
        self.internal_domains = [d.lower() for d in internal_domains] if internal_domains else []

    def extract(self, email: EmailObject) -> EmailMetadata:
        """
        Extract metadata from an email.

        Args:
            email: EmailObject

        Returns:
            EmailMetadata with extracted information
        """
        # Extract sender metadata
        sender = self._extract_sender_metadata(email)

        # Extract recipient list
        recipients = email.to_addresses + email.cc_addresses

        # Detect reply chain
        is_reply, reply_depth = self._detect_reply_chain(email)

        # Attachment stats
        attachment_count = len(email.attachments)
        attachment_types = list(set(att.content_type for att in email.attachments))

        # Body lengths
        body_length = len(email.body_plain)
        html_body_length = len(email.body_html)

        return EmailMetadata(
            email_id=email.email_id,
            sender=sender,
            recipients=recipients,
            subject=email.subject,
            date=email.date,
            is_reply=is_reply,
            reply_depth=reply_depth,
            has_attachments=attachment_count > 0,
            attachment_count=attachment_count,
            attachment_types=attachment_types,
            body_length=body_length,
            html_body_length=html_body_length,
        )

    def _extract_sender_metadata(self, email: EmailObject) -> SenderMetadata:
        """
        Extract sender metadata.

        Args:
            email: EmailObject

        Returns:
            SenderMetadata
        """
        email_address = email.from_address
        display_name = email.from_display_name

        # Extract domain
        domain = ""
        if "@" in email_address:
            domain = email_address.split("@")[1].lower()

        # Check if internal
        is_internal = None
        if self.internal_domains and domain:
            is_internal = any(domain == d or domain.endswith(f".{d}") for d in self.internal_domains)

        # Check if display name matches domain
        display_name_matches_domain = False
        if display_name and domain:
            # Simple check: does domain appear in display name?
            display_name_lower = display_name.lower()
            domain_parts = domain.split(".")
            # Check if first domain part appears in display name
            if domain_parts and domain_parts[0] in display_name_lower:
                display_name_matches_domain = True

        return SenderMetadata(
            email_address=email_address,
            display_name=display_name,
            domain=domain,
            is_internal=is_internal,
            has_display_name=bool(display_name),
            display_name_matches_domain=display_name_matches_domain,
        )

    def _detect_reply_chain(self, email: EmailObject) -> tuple[bool, int]:
        """
        Detect if email is a reply and how deep the reply chain is.

        Args:
            email: EmailObject

        Returns:
            Tuple of (is_reply, reply_depth)
        """
        body_combined = email.body_plain + "\n" + email.body_html

        # Check for reply patterns
        is_reply = False
        for pattern in self.REPLY_PATTERNS:
            if pattern.search(body_combined):
                is_reply = True
                break

        # Check subject line for Re: prefixes
        reply_depth = 0
        subject = email.subject.lower()
        re_count = 0

        # Count "re:" prefixes
        i = 0
        while i < len(subject):
            if subject[i:i+3] == "re:":
                re_count += 1
                i += 3
                # Skip whitespace
                while i < len(subject) and subject[i] in (" ", "\t"):
                    i += 1
            else:
                break

        if re_count > 0:
            is_reply = True
            reply_depth = re_count

        # If we detected a reply pattern in body, increment depth
        if is_reply and reply_depth == 0:
            reply_depth = 1

        return is_reply, reply_depth

    def detect_quoted_text(self, body_plain: str) -> tuple[str, str]:
        """
        Separate original message from quoted/reply text.

        Args:
            body_plain: Plaintext body

        Returns:
            Tuple of (original_text, quoted_text)
        """
        lines = body_plain.split("\n")
        original_lines = []
        quoted_lines = []

        in_quoted = False
        for line in lines:
            # Check if line looks quoted (starts with >)
            if self.QUOTE_PATTERN.match(line):
                in_quoted = True
                quoted_lines.append(line)
            elif in_quoted and line.strip() == "":
                # Empty lines in quoted section
                quoted_lines.append(line)
            elif in_quoted and not self.QUOTE_PATTERN.match(line):
                # Might be end of quoted section, but could be continuation
                # If next few lines are quoted, this is still quoted section
                quoted_lines.append(line)
            else:
                original_lines.append(line)

        return "\n".join(original_lines), "\n".join(quoted_lines)

    def extract_email_addresses(self, text: str) -> list[str]:
        """
        Extract all email addresses from text.

        Args:
            text: Text content

        Returns:
            List of unique email addresses
        """
        email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        matches = email_pattern.findall(text)
        return list(set(matches))

    def extract_phone_numbers(self, text: str) -> list[str]:
        """
        Extract phone numbers from text.

        Args:
            text: Text content

        Returns:
            List of phone numbers
        """
        # Simple pattern for US phone numbers and international format
        patterns = [
            re.compile(r"\+?1?\s*\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})"),  # US format
            re.compile(r"\+\d{1,3}\s?\d{1,14}"),  # International format
        ]

        numbers = []
        for pattern in patterns:
            numbers.extend(pattern.findall(text))

        return numbers


def extract_metadata(email: EmailObject, internal_domains: Optional[list[str]] = None) -> EmailMetadata:
    """
    Convenience function to extract metadata.

    Args:
        email: EmailObject
        internal_domains: List of internal domain names

    Returns:
        EmailMetadata
    """
    extractor = MetadataExtractor(internal_domains)
    return extractor.extract(email)

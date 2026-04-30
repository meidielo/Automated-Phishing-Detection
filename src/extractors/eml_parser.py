"""
Email extraction layer: Parse .eml files into standardized EmailObject format.

Handles MIME structure parsing, attachment extraction, inline image detection,
and magic byte-based content type identification.
"""
import logging
import mimetypes
from datetime import datetime, timezone
from email import message_from_bytes, message_from_string
from email.message import Message, EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional, Union
from uuid import uuid4

from src.models import EmailObject, AttachmentObject

logger = logging.getLogger(__name__)

# Try to import mail-parser for advanced parsing
try:
    import mailparser
    HAS_MAILPARSER = True
except ImportError:
    HAS_MAILPARSER = False
    logger.warning("mail-parser not available; using email stdlib only")


class EMLParser:
    """
    Parses .eml files and raw email bytes into EmailObject dataclass.

    Supports:
    - Full MIME structure parsing
    - Header extraction (raw + structured)
    - Plain text and HTML body extraction
    - Inline image detection
    - Attachment extraction with magic byte detection
    - Received chain extraction
    - Archive detection (nested files)
    """

    MAGIC_BYTES = {
        b"\x50\x4b\x03\x04": "application/zip",  # ZIP / docx / xlsx / jar
        b"\x1f\x8b\x08": "application/gzip",  # gzip
        b"\x42\x5a\x68": "application/x-bzip2",  # bzip2
        b"\x37\x7a\xbc\xaf\x27\x1c": "application/x-7z-compressed",  # 7z
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "application/vnd.ms-ole",  # OLE2/Office
        b"\xff\xd8\xff": "image/jpeg",  # JPEG
        b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "image/png",  # PNG
        b"\x47\x49\x46": "image/gif",  # GIF
        b"\x25\x50\x44\x46": "application/pdf",  # PDF
        b"\x1a\x03": "application/x-rar",  # RAR
    }

    ARCHIVE_TYPES = {
        "application/zip",
        "application/gzip",
        "application/x-bzip2",
        "application/x-7z-compressed",
        "application/x-rar",
        "application/x-tar",
    }

    def __init__(self):
        """Initialize the EML parser."""
        self.logger = logger

    @staticmethod
    def detect_magic_type(content: bytes) -> str:
        """
        Detect content type from magic bytes.

        Args:
            content: Raw file content

        Returns:
            MIME type string, defaults to 'application/octet-stream'
        """
        for magic_bytes, mime_type in EMLParser.MAGIC_BYTES.items():
            if content.startswith(magic_bytes):
                return mime_type
        return "application/octet-stream"

    def parse_file(self, file_path: Union[str, Path]) -> Optional[EmailObject]:
        """
        Parse an .eml file into an EmailObject.

        Args:
            file_path: Path to .eml file

        Returns:
            EmailObject or None if parsing fails
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.logger.error(f"File not found: {file_path}")
                return None

            with open(file_path, "rb") as f:
                raw_email = f.read()

            return self.parse_bytes(raw_email)
        except Exception as e:
            self.logger.error(f"Failed to parse EML file {file_path}: {e}")
            return None

    def parse_bytes(self, raw_email: Union[bytes, str]) -> Optional[EmailObject]:
        """
        Parse raw email bytes or string into an EmailObject.

        Args:
            raw_email: Raw email as bytes or string

        Returns:
            EmailObject or None if parsing fails
        """
        try:
            if isinstance(raw_email, str):
                message = message_from_string(raw_email)
            else:
                message = message_from_bytes(raw_email)

            return self._extract_email_object(message, raw_email)
        except Exception as e:
            self.logger.error(f"Failed to parse email bytes: {e}")
            return None

    def _extract_email_object(self, message: Message, raw_email: Union[bytes, str]) -> EmailObject:
        """
        Extract EmailObject from a Message.

        Args:
            message: email.Message object
            raw_email: Original raw email (for reference)

        Returns:
            Populated EmailObject
        """
        # Extract email ID
        email_id = self._get_message_id(message)

        # Extract headers
        raw_headers = self._extract_raw_headers(message)

        # Extract basic fields
        from_address, from_display_name = self._extract_from(message)
        reply_to = self._extract_reply_to(message)
        to_addresses = self._extract_addresses(message, "To")
        cc_addresses = self._extract_addresses(message, "Cc")
        subject = message.get("Subject", "").strip()

        # Extract date
        date = self._extract_date(message)

        # Extract bodies
        body_plain, body_html = self._extract_bodies(message)

        # Extract inline images and attachments
        inline_images, attachments = self._extract_attachments(message)

        # Extract received chain
        received_chain = self._extract_received_chain(message)

        return EmailObject(
            email_id=email_id,
            raw_headers=raw_headers,
            from_address=from_address,
            from_display_name=from_display_name,
            reply_to=reply_to,
            to_addresses=to_addresses,
            cc_addresses=cc_addresses,
            subject=subject,
            body_plain=body_plain,
            body_html=body_html,
            date=date,
            attachments=attachments,
            inline_images=inline_images,
            message_id=email_id,
            received_chain=received_chain,
        )

    def _get_message_id(self, message: Message) -> str:
        """
        Extract or generate message ID.

        Args:
            message: email.Message object

        Returns:
            Message ID string
        """
        msg_id = message.get("Message-ID", "").strip()
        if msg_id:
            # Clean up Message-ID (remove angle brackets if present)
            msg_id = msg_id.strip("<>")
            return msg_id

        # Fallback: generate UUID
        return str(uuid4())

    def _extract_raw_headers(self, message: Message) -> dict[str, list[str]]:
        """
        Extract all headers as a dict mapping header name to list of values.

        Args:
            message: email.Message object

        Returns:
            Dictionary of header name -> list of values
        """
        headers: dict[str, list[str]] = {}

        for header_name, header_value in message.items():
            key = header_name.lower()
            if key not in headers:
                headers[key] = []
            headers[key].append(header_value)

        return headers

    def _extract_from(self, message: Message) -> tuple[str, str]:
        """
        Extract From address and display name.

        Args:
            message: email.Message object

        Returns:
            Tuple of (email_address, display_name)
        """
        from_header = message.get("From", "").strip()

        # Parse "Display Name <email@domain.com>" format
        if "<" in from_header and ">" in from_header:
            display_name = from_header[:from_header.index("<")].strip().strip('"')
            email_addr = from_header[from_header.index("<") + 1:from_header.rindex(">")].strip()
            return email_addr, display_name

        # Simple email format
        return from_header, ""

    def _extract_reply_to(self, message: Message) -> Optional[str]:
        """
        Extract Reply-To address.

        Args:
            message: email.Message object

        Returns:
            Reply-To address or None
        """
        reply_to = message.get("Reply-To", "").strip()
        if not reply_to:
            return None

        # Clean up if it's in <> format
        if "<" in reply_to and ">" in reply_to:
            return reply_to[reply_to.index("<") + 1:reply_to.rindex(">")].strip()

        return reply_to

    def _extract_addresses(self, message: Message, header: str) -> list[str]:
        """
        Extract email addresses from a header (To, Cc, Bcc).

        Args:
            message: email.Message object
            header: Header name (To, Cc, Bcc)

        Returns:
            List of email addresses
        """
        header_value = message.get(header, "").strip()
        if not header_value:
            return []

        addresses = []
        # Simple split by comma (doesn't handle quoted addresses perfectly but works for most cases)
        for addr in header_value.split(","):
            addr = addr.strip()
            # Extract email from "Display Name <email@domain.com>" format
            if "<" in addr and ">" in addr:
                addr = addr[addr.index("<") + 1:addr.rindex(">")].strip()
            if addr:
                addresses.append(addr)

        return addresses

    def _extract_date(self, message: Message) -> datetime:
        """
        Extract email date.

        Args:
            message: email.Message object

        Returns:
            Datetime object
        """
        try:
            date_header = message.get("Date", "")
            if date_header:
                dt = parsedate_to_datetime(date_header)
                if dt and dt.tzinfo:
                    # Convert to UTC
                    return dt.astimezone(timezone.utc)
                return dt if dt else datetime.now(timezone.utc)
        except Exception as e:
            self.logger.warning(f"Failed to parse date: {e}")

        return datetime.now(timezone.utc)

    def _extract_bodies(self, message: Message) -> tuple[str, str]:
        """
        Extract plain text and HTML bodies.

        Args:
            message: email.Message object

        Returns:
            Tuple of (body_plain, body_html)
        """
        body_plain = ""
        body_html = ""

        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()

                # Skip attachments and inline items with Content-Disposition: attachment
                if part.get("Content-Disposition", "").startswith("attachment"):
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        payload = part.get_payload()

                    if isinstance(payload, bytes):
                        charset = part.get_content_charset("utf-8")
                        text = payload.decode(charset, errors="replace")
                    else:
                        text = str(payload)

                    if content_type == "text/plain" and not body_plain:
                        body_plain = text
                    elif content_type == "text/html" and not body_html:
                        body_html = text
                except Exception as e:
                    self.logger.warning(f"Failed to extract body part {content_type}: {e}")
        else:
            # Non-multipart message
            try:
                payload = message.get_payload(decode=True)
                if payload is None:
                    payload = message.get_payload()

                if isinstance(payload, bytes):
                    charset = message.get_content_charset("utf-8")
                    text = payload.decode(charset, errors="replace")
                else:
                    text = str(payload)

                content_type = message.get_content_type()
                if content_type == "text/html":
                    body_html = text
                else:
                    body_plain = text
            except Exception as e:
                self.logger.warning(f"Failed to extract non-multipart body: {e}")

        return body_plain, body_html

    def _extract_attachments(self, message: Message) -> tuple[list[bytes], list[AttachmentObject]]:
        """
        Extract inline images and file attachments.

        Args:
            message: email.Message object

        Returns:
            Tuple of (inline_images, attachments)
        """
        inline_images: list[bytes] = []
        attachments: list[AttachmentObject] = []

        if not message.is_multipart():
            return inline_images, attachments

        for part in message.walk():
            if part == message:
                continue

            content_disposition = part.get("Content-Disposition", "").lower()
            content_id = part.get("Content-ID", "").strip()
            content_type = part.get_content_type()

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = part.get_payload()

                if isinstance(payload, str):
                    payload = payload.encode("utf-8")

                # Inline images (referenced in HTML via Content-ID)
                if content_disposition.startswith("inline") and content_id and content_type.startswith("image/"):
                    inline_images.append(payload)
                    continue

                # Attachments
                if content_disposition.startswith("attachment") or (
                    content_disposition and "filename" in content_disposition
                ):
                    filename = self._extract_filename(part)
                    if not filename:
                        filename = f"attachment_{len(attachments)}"

                    attachment = self._create_attachment_object(
                        filename=filename,
                        payload=payload,
                        content_type=content_type,
                    )
                    attachments.append(attachment)
            except Exception as e:
                self.logger.warning(f"Failed to extract attachment: {e}")

        return inline_images, attachments

    def _extract_filename(self, part: Message) -> str:
        """
        Extract filename from a message part.

        Args:
            part: Message part

        Returns:
            Filename string
        """
        filename = part.get_filename()
        if filename:
            return filename

        # Try Content-Disposition header
        content_disp = part.get("Content-Disposition", "")
        if "filename" in content_disp:
            # Simple extraction of filename="..."
            start = content_disp.find('filename="')
            if start >= 0:
                start += 10
                end = content_disp.find('"', start)
                if end >= 0:
                    return content_disp[start:end]

        return ""

    def _create_attachment_object(
        self, filename: str, payload: bytes, content_type: str
    ) -> AttachmentObject:
        """
        Create an AttachmentObject with magic byte detection and archive detection.

        Args:
            filename: Attachment filename
            payload: Raw attachment content
            content_type: MIME type from email headers

        Returns:
            Populated AttachmentObject
        """
        magic_type = self.detect_magic_type(payload)
        is_archive = magic_type in self.ARCHIVE_TYPES
        has_macros = self._detect_macros(filename, payload)

        return AttachmentObject(
            filename=filename,
            content_type=content_type,
            magic_type=magic_type,
            size_bytes=len(payload),
            content=payload,
            is_archive=is_archive,
            has_macros=has_macros,
            nested_files=[],
        )

    def _detect_macros(self, filename: str, payload: bytes) -> bool:
        """
        Detect if a file likely contains macros.

        Args:
            filename: Attachment filename
            payload: Raw content

        Returns:
            True if macros detected
        """
        # Check file extension
        name_lower = filename.lower()
        macro_extensions = {".docm", ".xlsm", ".pptm"}
        if any(name_lower.endswith(ext) for ext in macro_extensions):
            return True

        # Check for VBA streams in OLE2 files (Office 97-2003)
        # OLE2 files start with specific magic bytes
        if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            # Look for "Macros" or "VBA" streams
            if b"Macros" in payload or b"VBA" in payload:
                return True

        # Check for VBA in ZIP-based Office (docx/xlsx)
        if payload.startswith(b"\x50\x4b\x03\x04"):  # ZIP
            if b"vbaProject.bin" in payload or b"customXml" in payload:
                return True

        return False

    def _extract_received_chain(self, message: Message) -> list[str]:
        """
        Extract Received headers in order to build the email routing chain.

        Args:
            message: email.Message object

        Returns:
            List of Received header values
        """
        received = message.get_all("Received", [])
        return [r.strip() for r in received] if received else []


def parse_eml_file(file_path: Union[str, Path]) -> Optional[EmailObject]:
    """
    Convenience function to parse an EML file.

    Args:
        file_path: Path to .eml file

    Returns:
        EmailObject or None
    """
    parser = EMLParser()
    return parser.parse_file(file_path)


def parse_eml_bytes(raw_email: Union[bytes, str]) -> Optional[EmailObject]:
    """
    Convenience function to parse raw email bytes or string.

    Args:
        raw_email: Raw email bytes or string

    Returns:
        EmailObject or None
    """
    parser = EMLParser()
    return parser.parse_bytes(raw_email)

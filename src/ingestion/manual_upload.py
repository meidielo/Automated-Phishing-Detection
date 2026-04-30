"""
Manual email upload handler.

Accepts .eml and .msg files via:
- Direct file path
- Raw bytes (for API upload)
- FastAPI UploadFile objects
"""
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from src.extractors.eml_parser import EMLParser
from src.models import EmailObject

logger = logging.getLogger(__name__)

# Supported file extensions
SUPPORTED_EXTENSIONS = {".eml", ".msg"}


class ManualUploadHandler:
    """
    Handles manual email uploads from various sources.

    Supports:
    - .eml files (RFC 5322 format)
    - .msg files (Outlook MSG format, requires extract_msg)
    - Raw email bytes
    - FastAPI UploadFile objects
    """

    def __init__(self, parser: Optional[EMLParser] = None):
        self.parser = parser or EMLParser()

    def process_file(self, file_path: Union[str, Path]) -> EmailObject:
        """
        Process a single .eml or .msg file from disk.

        Args:
            file_path: Path to the email file

        Returns:
            Parsed EmailObject

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file type is unsupported
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {path}")

        ext = path.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file type: {ext}. "
                f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
            )

        logger.info(f"Processing uploaded file: {path.name} ({ext})")

        if ext == ".eml":
            return self.parser.parse_file(str(path))
        elif ext == ".msg":
            return self._parse_msg_file(path)
        else:
            raise ValueError(f"Unsupported extension: {ext}")

    def process_bytes(
        self,
        content: bytes,
        filename: str = "uploaded_email.eml",
    ) -> EmailObject:
        """
        Process raw email bytes.

        Args:
            content: Raw email content as bytes
            filename: Original filename (used for type detection)

        Returns:
            Parsed EmailObject
        """
        ext = Path(filename).suffix.lower()

        if ext == ".msg":
            return self._parse_msg_bytes(content, filename)

        # Default: treat as .eml
        if isinstance(content, bytes):
            content_str = content.decode("utf-8", errors="replace")
        else:
            content_str = content

        logger.info(f"Processing uploaded bytes: {filename} ({len(content)} bytes)")
        return self.parser.parse_bytes(content_str)

    async def process_upload_file(self, upload_file) -> EmailObject:
        """
        Process a FastAPI UploadFile object.

        Args:
            upload_file: FastAPI UploadFile instance

        Returns:
            Parsed EmailObject
        """
        content = await upload_file.read()
        filename = upload_file.filename or "uploaded_email.eml"

        logger.info(f"Processing API upload: {filename} ({len(content)} bytes)")
        return self.process_bytes(content, filename)

    def process_directory(self, dir_path: Union[str, Path]) -> list[EmailObject]:
        """
        Process all .eml/.msg files in a directory.

        Args:
            dir_path: Path to directory containing email files

        Returns:
            List of parsed EmailObject instances
        """
        path = Path(dir_path)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        emails = []
        for file_path in sorted(path.iterdir()):
            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                try:
                    email_obj = self.process_file(file_path)
                    emails.append(email_obj)
                except Exception as e:
                    logger.error(f"Failed to process {file_path.name}: {e}")

        logger.info(f"Processed {len(emails)} emails from {path}")
        return emails

    def _parse_msg_file(self, path: Path) -> EmailObject:
        """
        Parse an Outlook .msg file.

        Requires the extract_msg library. Falls back to treating
        as raw bytes if the library is not available.
        """
        try:
            import extract_msg

            msg = extract_msg.Message(str(path))
            return self._msg_to_email_object(msg)
        except ImportError:
            logger.warning(
                "extract_msg not installed; attempting raw parse of .msg file. "
                "Install with: pip install extract-msg"
            )
            with open(path, "rb") as f:
                content = f.read()
            return self.parser.parse_bytes(
                content.decode("utf-8", errors="replace")
            )

    def _parse_msg_bytes(self, content: bytes, filename: str) -> EmailObject:
        """Parse .msg from raw bytes."""
        try:
            import extract_msg

            with tempfile.NamedTemporaryFile(
                suffix=".msg", delete=False
            ) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            try:
                msg = extract_msg.Message(tmp_path)
                return self._msg_to_email_object(msg)
            finally:
                os.unlink(tmp_path)
        except ImportError:
            logger.warning("extract_msg not installed; falling back to raw parse")
            return self.parser.parse_bytes(
                content.decode("utf-8", errors="replace")
            )

    def _msg_to_email_object(self, msg) -> EmailObject:
        """Convert extract_msg Message to our EmailObject."""
        from datetime import datetime
        from src.models import AttachmentObject
        import hashlib

        # Extract basic fields
        from_addr = msg.sender or ""
        from_display = ""
        if "<" in from_addr:
            parts = from_addr.split("<")
            from_display = parts[0].strip().strip('"')
            from_addr = parts[1].rstrip(">").strip()

        to_addrs = []
        if msg.to:
            to_addrs = [a.strip() for a in msg.to.split(";")]

        cc_addrs = []
        if msg.cc:
            cc_addrs = [a.strip() for a in msg.cc.split(";")]

        # Parse date
        date = datetime.now(timezone.utc)
        if msg.date:
            try:
                date = msg.date
            except Exception:
                pass

        # Extract attachments
        attachments = []
        for att in getattr(msg, "attachments", []):
            att_content = getattr(att, "data", b"") or b""
            attachments.append(AttachmentObject(
                filename=getattr(att, "longFilename", "") or getattr(att, "shortFilename", "unknown"),
                content_type="application/octet-stream",
                magic_type="application/octet-stream",
                size_bytes=len(att_content),
                content=att_content,
                is_archive=False,
                has_macros=False,
            ))

        # Generate email ID
        email_id = hashlib.sha256(
            f"{from_addr}:{msg.subject}:{date}".encode()
        ).hexdigest()[:16]

        return EmailObject(
            email_id=email_id,
            raw_headers={},
            from_address=from_addr,
            from_display_name=from_display,
            reply_to=None,
            to_addresses=to_addrs,
            cc_addresses=cc_addrs,
            subject=msg.subject or "",
            body_plain=msg.body or "",
            body_html=getattr(msg, "htmlBody", "") or "",
            date=date,
            attachments=attachments,
            inline_images=[],
            message_id=email_id,
            received_chain=[],
        )

    def validate_file(self, file_path: Union[str, Path]) -> dict:
        """
        Validate an email file without fully parsing it.

        Returns:
            Dict with: valid (bool), file_type, size_bytes, error (if any)
        """
        path = Path(file_path)
        result = {
            "valid": False,
            "file_type": path.suffix.lower(),
            "size_bytes": 0,
            "error": None,
        }

        if not path.exists():
            result["error"] = "File not found"
            return result

        result["size_bytes"] = path.stat().st_size

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            result["error"] = f"Unsupported type: {path.suffix}"
            return result

        if result["size_bytes"] == 0:
            result["error"] = "Empty file"
            return result

        if result["size_bytes"] > 50 * 1024 * 1024:  # 50 MB
            result["error"] = "File too large (>50MB)"
            return result

        result["valid"] = True
        return result

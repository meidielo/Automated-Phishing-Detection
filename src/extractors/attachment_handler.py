"""
Attachment handler for the phishing detection pipeline.

Classifies and extracts content from email attachments using
magic bytes (not file extensions). Detects macros, archives,
embedded objects, and nested files.
"""
import io
import logging
import struct
import zipfile
from typing import Optional

from src.models import AttachmentObject

logger = logging.getLogger(__name__)

# Magic byte signatures for file type detection
MAGIC_SIGNATURES = {
    b"\x50\x4b\x03\x04": "application/zip",          # ZIP / DOCX / XLSX / PPTX
    b"\x50\x4b\x05\x06": "application/zip",          # ZIP empty archive
    b"\x50\x4b\x07\x08": "application/zip",          # ZIP spanned
    b"\xd0\xcf\x11\xe0": "application/x-ole2",       # OLE2 (DOC, XLS, PPT, MSG)
    b"\x25\x50\x44\x46": "application/pdf",          # PDF
    b"\x7f\x45\x4c\x46": "application/x-elf",        # ELF executable
    b"\x4d\x5a":         "application/x-dosexec",     # PE / EXE / DLL
    b"\x1f\x8b":         "application/gzip",          # GZIP
    b"\x42\x5a\x68":     "application/x-bzip2",      # BZIP2
    b"\xfd\x37\x7a\x58": "application/x-xz",         # XZ
    b"\x37\x7a\xbc\xaf": "application/x-7z",         # 7-Zip
    b"\x52\x61\x72\x21": "application/x-rar",        # RAR
    b"\x89\x50\x4e\x47": "image/png",                # PNG
    b"\xff\xd8\xff":     "image/jpeg",                # JPEG
    b"\x47\x49\x46\x38": "image/gif",                # GIF
    b"\x42\x4d":         "image/bmp",                 # BMP
    b"\x49\x49\x2a\x00": "image/tiff",               # TIFF (little-endian)
    b"\x4d\x4d\x00\x2a": "image/tiff",               # TIFF (big-endian)
    b"\x52\x49\x46\x46": "image/webp",               # WEBP (RIFF container)
    b"\x00\x00\x01\x00": "image/x-icon",             # ICO
}

# Dangerous file extensions that warrant higher scrutiny
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".msi", ".msp", ".mst", ".hta", ".cpl", ".reg",
    ".iso", ".img", ".vhd", ".vhdx",
    ".lnk", ".inf", ".sct", ".rgs",
}

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".iso", ".img",
}

# Macro-capable document extensions
MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".doc", ".xls", ".ppt",  # Legacy formats can contain macros
}


class AttachmentHandler:
    """
    Classifies attachments by magic bytes, detects macros and
    dangerous content, and extracts nested files from archives.
    """

    def __init__(self, max_nested_depth: int = 3, max_archive_files: int = 100):
        """
        Args:
            max_nested_depth: Max recursion depth for nested archives
            max_archive_files: Max files to extract from a single archive
        """
        self.max_nested_depth = max_nested_depth
        self.max_archive_files = max_archive_files

    def classify(self, attachment: AttachmentObject) -> AttachmentObject:
        """
        Classify an attachment by magic bytes and detect macros.

        Updates the attachment's magic_type, is_archive, and has_macros
        fields in-place and returns it.

        Args:
            attachment: AttachmentObject with content bytes

        Returns:
            Updated AttachmentObject
        """
        content = attachment.content

        # Detect magic type
        magic_type = self.detect_magic_type(content)
        if magic_type:
            attachment.magic_type = magic_type

        # Check if archive
        attachment.is_archive = self._is_archive(attachment)

        # Check for macros
        attachment.has_macros = self._has_macros(attachment)

        logger.debug(
            f"Classified attachment '{attachment.filename}': "
            f"magic={attachment.magic_type}, archive={attachment.is_archive}, "
            f"macros={attachment.has_macros}"
        )

        return attachment

    def classify_all(self, attachments: list[AttachmentObject]) -> list[AttachmentObject]:
        """Classify a list of attachments."""
        return [self.classify(att) for att in attachments]

    def detect_magic_type(self, content: bytes) -> str:
        """
        Detect file type from magic bytes.

        Args:
            content: Raw file bytes

        Returns:
            MIME type string or "application/octet-stream" if unknown
        """
        if not content or len(content) < 2:
            return "application/octet-stream"

        # Check each signature (longer signatures first for specificity)
        for sig, mime_type in sorted(
            MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])
        ):
            if content[:len(sig)] == sig:
                # Refine ZIP-based types
                if mime_type == "application/zip":
                    return self._refine_zip_type(content)
                return mime_type

        return "application/octet-stream"

    def _refine_zip_type(self, content: bytes) -> str:
        """
        Distinguish between ZIP, DOCX, XLSX, PPTX, OOXML, etc.
        by inspecting ZIP contents.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = zf.namelist()

                if "[Content_Types].xml" in names:
                    # OOXML format — determine specific type
                    if any("word/" in n for n in names):
                        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    elif any("xl/" in n for n in names):
                        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    elif any("ppt/" in n for n in names):
                        return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                    return "application/vnd.openxmlformats-officedocument"

                if "META-INF/MANIFEST.MF" in names:
                    return "application/java-archive"

                return "application/zip"
        except (zipfile.BadZipFile, Exception):
            return "application/zip"

    def _is_archive(self, attachment: AttachmentObject) -> bool:
        """Check if attachment is an archive format."""
        ext = self._get_extension(attachment.filename)
        magic = attachment.magic_type

        if ext in ARCHIVE_EXTENSIONS:
            return True

        archive_types = {
            "application/zip", "application/gzip", "application/x-bzip2",
            "application/x-xz", "application/x-7z", "application/x-rar",
        }
        return magic in archive_types

    def _has_macros(self, attachment: AttachmentObject) -> bool:
        """
        Detect if attachment contains macros.

        Checks:
        1. OLE2 compound documents with VBA streams
        2. OOXML documents with vbaProject.bin
        3. File extension indicates macro-capable format
        """
        content = attachment.content
        ext = self._get_extension(attachment.filename)

        # Extension-based check
        if ext in MACRO_EXTENSIONS:
            # For legacy formats, check OLE2 for VBA
            if attachment.magic_type == "application/x-ole2":
                return self._check_ole2_macros(content)
            # For OOXML formats (.docm, .xlsm, .pptm)
            if ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}:
                return self._check_ooxml_macros(content)
            return True  # Legacy macro format, assume yes

        # Also check ZIP-based files for vbaProject
        if attachment.magic_type and "zip" in attachment.magic_type.lower():
            return self._check_ooxml_macros(content)

        # Check OLE2 regardless of extension (could be renamed)
        if attachment.magic_type == "application/x-ole2":
            return self._check_ole2_macros(content)

        return False

    def _check_ole2_macros(self, content: bytes) -> bool:
        """Check OLE2 compound document for VBA macro streams."""
        # Look for VBA stream signatures in the raw bytes
        vba_signatures = [
            b"_VBA_PROJECT",
            b"VBA",
            b"\x00V\x00B\x00A",  # UTF-16 encoded "VBA"
            b"Macros",
            b"ThisDocument",
            b"ThisWorkbook",
        ]
        for sig in vba_signatures:
            if sig in content:
                return True
        return False

    def _check_ooxml_macros(self, content: bytes) -> bool:
        """Check OOXML (ZIP-based) document for vbaProject.bin."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for name in zf.namelist():
                    lower = name.lower()
                    if "vbaproject.bin" in lower:
                        return True
                    if "macros" in lower:
                        return True
                    if lower.endswith(".bin") and "vba" in lower:
                        return True
        except (zipfile.BadZipFile, Exception):
            pass
        return False

    def extract_nested(
        self,
        attachment: AttachmentObject,
        depth: int = 0,
    ) -> list[AttachmentObject]:
        """
        Extract nested files from archive attachments.

        Args:
            attachment: Archive attachment to extract from
            depth: Current recursion depth

        Returns:
            List of extracted AttachmentObject instances
        """
        if depth >= self.max_nested_depth:
            logger.warning(
                f"Max nesting depth ({self.max_nested_depth}) reached for "
                f"'{attachment.filename}'"
            )
            return []

        if not attachment.is_archive:
            return []

        extracted = []

        if attachment.magic_type in ("application/zip",) or \
           "openxmlformats" in (attachment.magic_type or ""):
            extracted = self._extract_from_zip(attachment, depth)
        elif attachment.magic_type == "application/gzip":
            extracted = self._extract_from_gzip(attachment, depth)
        else:
            logger.debug(
                f"No extractor for archive type {attachment.magic_type}"
            )

        attachment.nested_files = extracted
        return extracted

    def _extract_from_zip(
        self,
        attachment: AttachmentObject,
        depth: int,
    ) -> list[AttachmentObject]:
        """Extract files from a ZIP archive."""
        extracted = []

        try:
            with zipfile.ZipFile(io.BytesIO(attachment.content)) as zf:
                count = 0
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if count >= self.max_archive_files:
                        logger.warning(
                            f"Max files ({self.max_archive_files}) reached "
                            f"in '{attachment.filename}'"
                        )
                        break

                    try:
                        file_content = zf.read(info.filename)
                    except Exception as e:
                        logger.warning(
                            f"Failed to read '{info.filename}' from "
                            f"'{attachment.filename}': {e}"
                        )
                        continue

                    magic = self.detect_magic_type(file_content)
                    nested = AttachmentObject(
                        filename=info.filename,
                        content_type=magic,
                        magic_type=magic,
                        size_bytes=len(file_content),
                        content=file_content,
                        is_archive=False,
                        has_macros=False,
                    )
                    self.classify(nested)

                    # Recursively extract nested archives
                    if nested.is_archive:
                        self.extract_nested(nested, depth + 1)

                    extracted.append(nested)
                    count += 1

        except zipfile.BadZipFile:
            logger.warning(f"Bad ZIP file: '{attachment.filename}'")
        except Exception as e:
            logger.error(f"ZIP extraction error for '{attachment.filename}': {e}")

        return extracted

    def _extract_from_gzip(
        self,
        attachment: AttachmentObject,
        depth: int,
    ) -> list[AttachmentObject]:
        """Extract content from a GZIP archive."""
        import gzip

        try:
            decompressed = gzip.decompress(attachment.content)
            magic = self.detect_magic_type(decompressed)

            # Strip .gz extension for the inner filename
            inner_name = attachment.filename
            if inner_name.lower().endswith(".gz"):
                inner_name = inner_name[:-3]

            nested = AttachmentObject(
                filename=inner_name,
                content_type=magic,
                magic_type=magic,
                size_bytes=len(decompressed),
                content=decompressed,
                is_archive=False,
                has_macros=False,
            )
            self.classify(nested)

            if nested.is_archive:
                self.extract_nested(nested, depth + 1)

            return [nested]

        except Exception as e:
            logger.error(f"GZIP extraction error for '{attachment.filename}': {e}")
            return []

    def is_dangerous(self, attachment: AttachmentObject) -> bool:
        """
        Check if an attachment is potentially dangerous.

        Returns True if:
        - Has a dangerous file extension
        - Contains macros
        - Is an executable (by magic bytes)
        - Extension doesn't match magic type (possible disguise)
        """
        ext = self._get_extension(attachment.filename)

        # Dangerous extension
        if ext in DANGEROUS_EXTENSIONS:
            return True

        # Contains macros
        if attachment.has_macros:
            return True

        # Executable by magic bytes
        executable_types = {
            "application/x-dosexec",
            "application/x-elf",
        }
        if attachment.magic_type in executable_types:
            return True

        # Extension/magic mismatch (disguised file)
        if self._extension_magic_mismatch(attachment):
            return True

        return False

    def _extension_magic_mismatch(self, attachment: AttachmentObject) -> bool:
        """Detect if file extension doesn't match magic bytes (disguised file)."""
        ext = self._get_extension(attachment.filename)
        magic = attachment.magic_type

        # Define expected magic types for common extensions
        expected = {
            ".pdf": {"application/pdf"},
            ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
            ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
            ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"},
            ".doc": {"application/x-ole2"},
            ".xls": {"application/x-ole2"},
            ".ppt": {"application/x-ole2"},
            ".png": {"image/png"},
            ".jpg": {"image/jpeg"},
            ".jpeg": {"image/jpeg"},
            ".gif": {"image/gif"},
            ".zip": {"application/zip"},
        }

        if ext in expected and magic not in expected[ext]:
            logger.warning(
                f"Extension/magic mismatch: '{attachment.filename}' has "
                f"ext={ext} but magic={magic}"
            )
            return True

        return False

    def get_risk_category(self, attachment: AttachmentObject) -> str:
        """
        Categorize attachment risk level.

        Returns: "high", "medium", "low", or "benign"
        """
        if self.is_dangerous(attachment):
            return "high"

        ext = self._get_extension(attachment.filename)

        # Medium risk: documents that could contain embedded content
        medium_types = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"}
        if ext in medium_types:
            return "medium"

        # Medium risk: HTML files (could contain JS/phishing)
        if ext in {".html", ".htm", ".mhtml", ".svg"}:
            return "medium"

        # Low risk: images
        if attachment.magic_type and attachment.magic_type.startswith("image/"):
            return "low"

        # Unknown = medium
        if attachment.magic_type == "application/octet-stream":
            return "medium"

        return "benign"

    @staticmethod
    def _get_extension(filename: str) -> str:
        """Get lowercase file extension including the dot."""
        if "." in filename:
            return "." + filename.rsplit(".", 1)[-1].lower()
        return ""

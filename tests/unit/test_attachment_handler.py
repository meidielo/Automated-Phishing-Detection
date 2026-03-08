"""Tests for the attachment handler (magic bytes, macros, archives, risk)."""
import io
import struct
import zipfile
import gzip
import pytest

from src.extractors.attachment_handler import (
    AttachmentHandler,
    MAGIC_SIGNATURES,
    DANGEROUS_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    MACRO_EXTENSIONS,
)
from src.models import AttachmentObject


# ── Helpers ───────────────────────────────────────────────────────────

def _make_attachment(
    filename: str = "test.bin",
    content: bytes = b"\x00" * 10,
    content_type: str = "application/octet-stream",
    magic_type: str = "application/octet-stream",
    is_archive: bool = False,
    has_macros: bool = False,
    **kwargs,
) -> AttachmentObject:
    return AttachmentObject(
        filename=filename,
        content_type=content_type,
        magic_type=magic_type,
        size_bytes=len(content),
        content=content,
        is_archive=is_archive,
        has_macros=has_macros,
        **kwargs,
    )


def _make_zip(inner_files: dict[str, bytes]) -> bytes:
    """Create an in-memory ZIP containing the given files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in inner_files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _make_gzip(inner_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(inner_bytes)
    return buf.getvalue()


def _make_ooxml_docx() -> bytes:
    """Create a minimal DOCX (OOXML) ZIP."""
    return _make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document/>",
    })


def _make_ooxml_xlsx() -> bytes:
    return _make_zip({
        "[Content_Types].xml": b"<Types/>",
        "xl/workbook.xml": b"<workbook/>",
    })


def _make_ooxml_pptx() -> bytes:
    return _make_zip({
        "[Content_Types].xml": b"<Types/>",
        "ppt/presentation.xml": b"<presentation/>",
    })


def _make_docm_with_vba() -> bytes:
    """DOCX with a vbaProject.bin inside → macro-enabled."""
    return _make_zip({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document/>",
        "word/vbaProject.bin": b"\x00VBA_PROJECT_DATA",
    })


# ── Magic byte detection ─────────────────────────────────────────────

class TestDetectMagicType:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_empty_content(self):
        assert self.handler.detect_magic_type(b"") == "application/octet-stream"

    def test_short_content(self):
        assert self.handler.detect_magic_type(b"\x00") == "application/octet-stream"

    def test_pdf(self):
        content = b"%PDF-1.4 rest of file"
        assert self.handler.detect_magic_type(content) == "application/pdf"

    def test_png(self):
        content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "image/png"

    def test_jpeg(self):
        content = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "image/jpeg"

    def test_gif(self):
        content = b"GIF89a" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "image/gif"

    def test_pe_exe(self):
        content = b"MZ" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "application/x-dosexec"

    def test_elf(self):
        content = b"\x7fELF" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "application/x-elf"

    def test_ole2(self):
        content = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "application/x-ole2"

    def test_gzip(self):
        content = b"\x1f\x8b\x08" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "application/gzip"

    def test_rar(self):
        content = b"Rar!\x1a\x07" + b"\x00" * 100
        assert self.handler.detect_magic_type(content) == "application/x-rar"

    def test_unknown_bytes(self):
        content = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert self.handler.detect_magic_type(content) == "application/octet-stream"

    def test_zip_plain(self):
        zip_bytes = _make_zip({"hello.txt": b"world"})
        assert self.handler.detect_magic_type(zip_bytes) == "application/zip"

    def test_zip_docx(self):
        docx_bytes = _make_ooxml_docx()
        result = self.handler.detect_magic_type(docx_bytes)
        assert "wordprocessingml" in result

    def test_zip_xlsx(self):
        xlsx_bytes = _make_ooxml_xlsx()
        result = self.handler.detect_magic_type(xlsx_bytes)
        assert "spreadsheetml" in result

    def test_zip_pptx(self):
        pptx_bytes = _make_ooxml_pptx()
        result = self.handler.detect_magic_type(pptx_bytes)
        assert "presentationml" in result


# ── Classification ────────────────────────────────────────────────────

class TestClassify:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_classify_pdf(self):
        content = b"%PDF-1.4 rest"
        att = _make_attachment("report.pdf", content)
        result = self.handler.classify(att)
        assert result.magic_type == "application/pdf"
        assert result.is_archive is False
        assert result.has_macros is False

    def test_classify_zip_archive(self):
        content = _make_zip({"a.txt": b"hello"})
        att = _make_attachment("data.zip", content)
        result = self.handler.classify(att)
        assert result.magic_type == "application/zip"
        assert result.is_archive is True

    def test_classify_docm_with_macros(self):
        content = _make_docm_with_vba()
        att = _make_attachment("malicious.docm", content)
        result = self.handler.classify(att)
        assert result.has_macros is True

    def test_classify_all(self):
        atts = [
            _make_attachment("a.pdf", b"%PDF-1.4 data"),
            _make_attachment("b.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50),
        ]
        results = self.handler.classify_all(atts)
        assert len(results) == 2
        assert results[0].magic_type == "application/pdf"
        assert results[1].magic_type == "image/png"


# ── Archive detection ─────────────────────────────────────────────────

class TestIsArchive:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_zip_by_extension(self):
        att = _make_attachment("data.zip", b"\x00" * 10)
        att.magic_type = "application/octet-stream"
        assert self.handler._is_archive(att) is True

    def test_rar_by_extension(self):
        att = _make_attachment("data.rar", b"\x00" * 10)
        att.magic_type = "application/octet-stream"
        assert self.handler._is_archive(att) is True

    def test_zip_by_magic(self):
        att = _make_attachment("something", b"\x00" * 10)
        att.magic_type = "application/zip"
        assert self.handler._is_archive(att) is True

    def test_pdf_not_archive(self):
        att = _make_attachment("doc.pdf", b"\x00" * 10)
        att.magic_type = "application/pdf"
        assert self.handler._is_archive(att) is False


# ── Macro detection ───────────────────────────────────────────────────

class TestMacroDetection:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_ole2_with_vba(self):
        # OLE2 header + VBA signature somewhere in content
        content = b"\xd0\xcf\x11\xe0" + b"\x00" * 100 + b"_VBA_PROJECT" + b"\x00" * 50
        att = _make_attachment("file.doc", content)
        self.handler.classify(att)
        assert att.has_macros is True

    def test_ole2_without_vba(self):
        content = b"\xd0\xcf\x11\xe0" + b"\x00" * 200
        att = _make_attachment("file.doc", content)
        self.handler.classify(att)
        # Legacy .doc with OLE2 but no VBA signatures → macro check returns False
        assert att.has_macros is False

    def test_ooxml_with_vbaproject_bin(self):
        content = _make_docm_with_vba()
        att = _make_attachment("report.docm", content)
        self.handler.classify(att)
        assert att.has_macros is True

    def test_ooxml_without_macros(self):
        content = _make_ooxml_docx()
        att = _make_attachment("clean.docx", content)
        self.handler.classify(att)
        assert att.has_macros is False

    def test_xlsm_with_macros(self):
        content = _make_zip({
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/vbaProject.bin": b"\x00VBA",
        })
        att = _make_attachment("budget.xlsm", content)
        self.handler.classify(att)
        assert att.has_macros is True


# ── Danger / risk assessment ──────────────────────────────────────────

class TestIsDangerous:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_exe_extension(self):
        att = _make_attachment("malware.exe", b"MZ" + b"\x00" * 100)
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True

    def test_bat_extension(self):
        att = _make_attachment("script.bat", b"@echo off")
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True

    def test_ps1_extension(self):
        att = _make_attachment("exploit.ps1", b"Get-Process")
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True

    def test_exe_by_magic(self):
        # File named .txt but actually PE executable
        att = _make_attachment("innocent.txt", b"MZ" + b"\x00" * 100)
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True

    def test_macro_document(self):
        content = _make_docm_with_vba()
        att = _make_attachment("invoice.docm", content)
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True

    def test_clean_pdf_not_dangerous(self):
        att = _make_attachment("report.pdf", b"%PDF-1.4 data")
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is False

    def test_clean_png_not_dangerous(self):
        att = _make_attachment("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is False

    def test_extension_magic_mismatch(self):
        # Claims to be PDF but is actually a PE executable
        att = _make_attachment("resume.pdf", b"MZ" + b"\x00" * 100)
        self.handler.classify(att)
        assert self.handler.is_dangerous(att) is True


# ── Risk categorization ───────────────────────────────────────────────

class TestRiskCategory:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_exe_is_high(self):
        att = _make_attachment("malware.exe", b"MZ" + b"\x00" * 100)
        self.handler.classify(att)
        assert self.handler.get_risk_category(att) == "high"

    def test_pdf_is_medium(self):
        att = _make_attachment("report.pdf", b"%PDF-1.4 data")
        self.handler.classify(att)
        assert self.handler.get_risk_category(att) == "medium"

    def test_html_is_medium(self):
        att = _make_attachment("page.html", b"<html><body>hi</body></html>")
        self.handler.classify(att)
        assert self.handler.get_risk_category(att) == "medium"

    def test_png_is_low(self):
        att = _make_attachment("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        self.handler.classify(att)
        assert self.handler.get_risk_category(att) == "low"

    def test_unknown_is_medium(self):
        att = _make_attachment("mystery", b"\x01\x02\x03\x04")
        self.handler.classify(att)
        assert self.handler.get_risk_category(att) == "medium"


# ── Nested archive extraction ─────────────────────────────────────────

class TestExtractNested:
    def setup_method(self):
        self.handler = AttachmentHandler()

    def test_extract_from_zip(self):
        inner = _make_zip({
            "readme.txt": b"Hello",
            "data.csv": b"a,b,c\n1,2,3",
        })
        att = _make_attachment("archive.zip", inner)
        self.handler.classify(att)
        nested = self.handler.extract_nested(att)
        assert len(nested) == 2
        filenames = {n.filename for n in nested}
        assert "readme.txt" in filenames
        assert "data.csv" in filenames

    def test_extract_classifies_nested(self):
        """Nested files should be classified too."""
        pdf_content = b"%PDF-1.4 fake pdf"
        inner = _make_zip({"report.pdf": pdf_content})
        att = _make_attachment("docs.zip", inner)
        self.handler.classify(att)
        nested = self.handler.extract_nested(att)
        assert len(nested) == 1
        assert nested[0].magic_type == "application/pdf"

    def test_extract_from_gzip(self):
        inner_data = b"Hello compressed world"
        gz_content = _make_gzip(inner_data)
        att = _make_attachment("data.txt.gz", gz_content)
        self.handler.classify(att)
        nested = self.handler.extract_nested(att)
        assert len(nested) == 1
        assert nested[0].filename == "data.txt"
        assert nested[0].content == inner_data

    def test_max_depth_limit(self):
        handler = AttachmentHandler(max_nested_depth=1)
        inner_zip = _make_zip({"deep.txt": b"deep"})
        outer_zip = _make_zip({"inner.zip": inner_zip})
        att = _make_attachment("outer.zip", outer_zip)
        handler.classify(att)
        nested = handler.extract_nested(att, depth=0)
        # inner.zip should be extracted and classified
        assert len(nested) == 1
        assert nested[0].filename == "inner.zip"
        # But inner.zip's contents should NOT be extracted (depth limit)
        assert nested[0].nested_files == [] or nested[0].nested_files is None

    def test_max_files_limit(self):
        handler = AttachmentHandler(max_archive_files=2)
        content = _make_zip({
            "a.txt": b"a",
            "b.txt": b"b",
            "c.txt": b"c",
            "d.txt": b"d",
        })
        att = _make_attachment("many.zip", content)
        handler.classify(att)
        nested = handler.extract_nested(att)
        assert len(nested) == 2  # capped at max_archive_files

    def test_non_archive_returns_empty(self):
        att = _make_attachment("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        self.handler.classify(att)
        nested = self.handler.extract_nested(att)
        assert nested == []

    def test_bad_zip_returns_empty(self):
        att = _make_attachment("corrupt.zip", b"PK\x03\x04" + b"\xff" * 50)
        self.handler.classify(att)
        nested = self.handler.extract_nested(att)
        assert nested == []


# ── Extension helper ──────────────────────────────────────────────────

class TestGetExtension:
    def test_normal(self):
        assert AttachmentHandler._get_extension("file.pdf") == ".pdf"

    def test_uppercase(self):
        assert AttachmentHandler._get_extension("FILE.PDF") == ".pdf"

    def test_double_ext(self):
        assert AttachmentHandler._get_extension("file.tar.gz") == ".gz"

    def test_no_ext(self):
        assert AttachmentHandler._get_extension("README") == ""

    def test_hidden_file(self):
        assert AttachmentHandler._get_extension(".bashrc") == ".bashrc"


# ── Constants sanity checks ───────────────────────────────────────────

class TestConstants:
    def test_dangerous_extensions_are_lowercase(self):
        for ext in DANGEROUS_EXTENSIONS:
            assert ext.startswith(".")
            assert ext == ext.lower()

    def test_archive_extensions_are_lowercase(self):
        for ext in ARCHIVE_EXTENSIONS:
            assert ext.startswith(".")
            assert ext == ext.lower()

    def test_macro_extensions_are_lowercase(self):
        for ext in MACRO_EXTENSIONS:
            assert ext.startswith(".")
            assert ext == ext.lower()

    def test_magic_signatures_are_bytes(self):
        for sig, mime in MAGIC_SIGNATURES.items():
            assert isinstance(sig, bytes)
            assert isinstance(mime, str)
            assert len(sig) >= 2

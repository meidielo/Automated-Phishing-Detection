"""Tests for IMAP fetcher and manual upload handler."""
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime
from pathlib import Path
import tempfile
import os

from src.ingestion.imap_fetcher import IMAPFetcher
from src.ingestion.manual_upload import ManualUploadHandler
from src.config import IMAPConfig
from src.models import EmailObject


# ── IMAP Fetcher Tests ─────────────────────────────────────────────

class TestIMAPFetcherInit:
    def test_init_defaults(self):
        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        assert fetcher.config == config
        assert fetcher._connection is None
        assert fetcher._running is False

    def test_init_with_callback(self):
        config = IMAPConfig()
        cb = MagicMock()
        fetcher = IMAPFetcher(config, on_email=cb)
        assert fetcher.on_email is cb


class TestIMAPFetcherConnect:
    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_connect_success(self, mock_imap_cls):
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.select.return_value = ("OK", [b"5"])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        conn = fetcher.connect()

        mock_imap_cls.assert_called_once()
        mock_conn.login.assert_called_once_with("u", "p")
        mock_conn.select.assert_called_once_with("INBOX", readonly=False)
        assert conn == mock_conn

    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_disconnect(self, mock_imap_cls):
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        fetcher.connect()
        fetcher.disconnect()

        mock_conn.close.assert_called_once()
        mock_conn.logout.assert_called_once()
        assert fetcher._connection is None


class TestIMAPFetcherFetch:
    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_fetch_new_uids(self, mock_imap_cls):
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [])
        mock_conn.noop.return_value = ("OK", [])
        mock_conn.uid.return_value = ("OK", [b"101 102 103"])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        fetcher.connect()

        uids = fetcher.fetch_new_uids()
        assert uids == ["101", "102", "103"]

    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_fetch_new_uids_filters_processed(self, mock_imap_cls):
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [])
        mock_conn.noop.return_value = ("OK", [])
        mock_conn.uid.return_value = ("OK", [b"101 102 103"])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        fetcher.connect()
        fetcher._processed_uids = {"101", "102"}

        uids = fetcher.fetch_new_uids()
        assert uids == ["103"]

    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_fetch_email_by_uid(self, mock_imap_cls):
        raw_email = (
            b"From: test@example.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Test Email\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Hello World\r\n"
        )

        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [])
        mock_conn.noop.return_value = ("OK", [])
        mock_conn.uid.return_value = ("OK", [(b"1 (RFC822 {123}", raw_email), b")"])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        fetcher.connect()

        email_obj = fetcher.fetch_email_by_uid("1")
        assert email_obj is not None
        assert email_obj.subject == "Test Email"
        assert "1" in fetcher._processed_uids

    @patch("src.ingestion.imap_fetcher.imaplib.IMAP4_SSL")
    def test_fetch_email_failure_returns_none(self, mock_imap_cls):
        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [])
        mock_conn.select.return_value = ("OK", [])
        mock_conn.noop.return_value = ("OK", [])
        mock_conn.uid.return_value = ("NO", [None])
        mock_imap_cls.return_value = mock_conn

        config = IMAPConfig(host="imap.test.com", user="u", password="p")
        fetcher = IMAPFetcher(config)
        fetcher.connect()

        result = fetcher.fetch_email_by_uid("999")
        assert result is None

    def test_stop(self):
        config = IMAPConfig()
        fetcher = IMAPFetcher(config)
        fetcher._running = True
        fetcher.stop()
        assert fetcher._running is False


# ── Manual Upload Handler Tests ────────────────────────────────────

class TestManualUploadHandler:
    def test_process_eml_file(self):
        handler = ManualUploadHandler()
        eml_content = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Upload Test\n"
            "Date: Mon, 01 Jan 2024 12:00:00 +0000\n"
            "\n"
            "Test body\n"
        )

        with tempfile.NamedTemporaryFile(
            suffix=".eml", mode="w", delete=False
        ) as f:
            f.write(eml_content)
            tmp_path = f.name

        try:
            result = handler.process_file(tmp_path)
            assert result.subject == "Upload Test"
            assert "sender@example.com" in result.from_address
        finally:
            os.unlink(tmp_path)

    def test_process_bytes(self):
        handler = ManualUploadHandler()
        raw = (
            b"From: test@example.com\n"
            b"Subject: Bytes Test\n"
            b"\n"
            b"Body here\n"
        )
        result = handler.process_bytes(raw, "test.eml")
        assert result.subject == "Bytes Test"

    def test_unsupported_extension(self):
        handler = ManualUploadHandler()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not an email")
            tmp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported"):
                handler.process_file(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_file_not_found(self):
        handler = ManualUploadHandler()
        with pytest.raises(FileNotFoundError):
            handler.process_file("/nonexistent/email.eml")

    def test_validate_file_valid(self):
        handler = ManualUploadHandler()
        with tempfile.NamedTemporaryFile(
            suffix=".eml", mode="w", delete=False
        ) as f:
            f.write("From: test@example.com\nSubject: Test\n\nBody\n")
            tmp_path = f.name

        try:
            result = handler.validate_file(tmp_path)
            assert result["valid"] is True
            assert result["file_type"] == ".eml"
            assert result["size_bytes"] > 0
        finally:
            os.unlink(tmp_path)

    def test_validate_file_not_found(self):
        handler = ManualUploadHandler()
        result = handler.validate_file("/nonexistent.eml")
        assert result["valid"] is False
        assert result["error"] == "File not found"

    def test_validate_file_unsupported(self):
        handler = ManualUploadHandler()
        with tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False
        ) as f:
            f.write(b"fake pdf")
            tmp_path = f.name

        try:
            result = handler.validate_file(tmp_path)
            assert result["valid"] is False
            assert "Unsupported" in result["error"]
        finally:
            os.unlink(tmp_path)

    def test_process_directory(self):
        handler = ManualUploadHandler()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some .eml files
            for i in range(3):
                path = os.path.join(tmpdir, f"test_{i}.eml")
                with open(path, "w") as f:
                    f.write(
                        f"From: sender{i}@example.com\n"
                        f"Subject: Test {i}\n\n"
                        f"Body {i}\n"
                    )
            # Create a non-email file (should be skipped)
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("not an email")

            results = handler.process_directory(tmpdir)
            assert len(results) == 3

    def test_process_directory_not_a_dir(self):
        handler = ManualUploadHandler()
        with pytest.raises(NotADirectoryError):
            handler.process_directory("/nonexistent/dir")

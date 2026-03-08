"""
Unit tests for blocklist/allowlist checker.

Tests cover:
- ListCheckResult dataclass defaults
- BlocklistAllowlistChecker no-op mode (no DB)
- Domain extraction helpers
- Blocklist override → CONFIRMED_PHISHING
- Allowlist override → CLEAN
- Both blocklisted and allowlisted → no override
- Reply-To domain checking
- URL domain extraction
- Exception handling in DB access
"""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import EmailObject, ExtractedURL, URLSource, Verdict
from src.scoring.blocklist_allowlist import (
    BlocklistAllowlistChecker,
    ListCheckResult,
)


# ── helpers ──────────────────────────────────────────────────────────


def _make_email(
    email_id="test-001",
    from_address="attacker@evil.com",
    reply_to=None,
    **kwargs,
) -> EmailObject:
    """Create a minimal EmailObject for testing."""
    from datetime import datetime, timezone

    defaults = dict(
        email_id=email_id,
        subject="Test email",
        from_address=from_address,
        from_display_name="Test",
        to_addresses=["victim@example.com"],
        cc_addresses=[],
        reply_to=reply_to or "",
        body_plain="hello",
        body_html="<p>hello</p>",
        date=datetime(2026, 3, 8, tzinfo=timezone.utc),
        raw_headers={},
        attachments=[],
        inline_images=[],
        message_id="<test@example.com>",
        received_chain=[],
    )
    defaults.update(kwargs)
    return EmailObject(**defaults)


def _make_url(url: str) -> ExtractedURL:
    return ExtractedURL(url=url, source=URLSource.BODY_HTML, source_detail="test")


class _FakeRow:
    """Lightweight stand-in for a SQLAlchemy ORM row."""

    def __init__(self, indicator, indicator_type, source="analyst_feedback"):
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.source = source


def _build_session_factory(blocklist_rows=None, allowlist_rows=None):
    """
    Build a mock async session factory.

    blocklist_rows / allowlist_rows: lists of _FakeRow objects keyed
    by (indicator, indicator_type).  If None → empty for all queries.
    """
    blocklist_rows = blocklist_rows or {}
    allowlist_rows = allowlist_rows or {}

    class _FakeScalars:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _FakeSession:
        async def execute(self, stmt):
            # Inspect the compiled statement to decide what to return.
            # We detect which table by checking the string repr.
            stmt_str = str(stmt)
            result = MagicMock()
            if "local_blocklist" in stmt_str:
                result.scalars.return_value = _FakeScalars(
                    blocklist_rows.get(self._current_key, [])
                )
            else:
                result.scalars.return_value = _FakeScalars(
                    allowlist_rows.get(self._current_key, [])
                )
            return result

        _current_key = None

    # We need a smarter approach: patch _check_indicator instead.
    # Actually, let's just build a proper mock that captures the compiled SQL.
    # Simpler approach: mock _check_indicator directly for DB-dependent tests.

    @asynccontextmanager
    async def factory():
        yield _FakeSession()

    return factory


# ── ListCheckResult dataclass ────────────────────────────────────────


class TestListCheckResult:
    """Test ListCheckResult dataclass."""

    def test_defaults(self):
        r = ListCheckResult()
        assert r.is_blocklisted is False
        assert r.is_allowlisted is False
        assert r.blocklist_matches == []
        assert r.allowlist_matches == []
        assert r.override_verdict is None
        assert r.override_reason == ""

    def test_set_fields(self):
        r = ListCheckResult(
            is_blocklisted=True,
            blocklist_matches=[{"indicator": "evil.com", "type": "domain"}],
            override_verdict=Verdict.CONFIRMED_PHISHING,
            override_reason="bad domain",
        )
        assert r.is_blocklisted is True
        assert r.override_verdict == Verdict.CONFIRMED_PHISHING


# ── no-op mode (no DB) ──────────────────────────────────────────────


class TestNoOpMode:
    """When db_session_factory is None, checker returns empty result."""

    @pytest.mark.asyncio
    async def test_no_db_returns_empty(self):
        checker = BlocklistAllowlistChecker(db_session_factory=None)
        email = _make_email()
        result = await checker.check(email, [])

        assert result.is_blocklisted is False
        assert result.is_allowlisted is False
        assert result.override_verdict is None

    @pytest.mark.asyncio
    async def test_no_db_with_urls_returns_empty(self):
        checker = BlocklistAllowlistChecker(db_session_factory=None)
        email = _make_email()
        urls = [_make_url("http://evil.com")]
        result = await checker.check(email, urls)

        assert result.override_verdict is None


# ── domain extraction helpers ────────────────────────────────────────


class TestDomainExtraction:
    """Test static helper methods."""

    def test_extract_domain_from_email(self):
        assert BlocklistAllowlistChecker._extract_domain_from_email(
            "user@Example.COM"
        ) == "example.com"

    def test_extract_domain_from_email_no_at(self):
        assert BlocklistAllowlistChecker._extract_domain_from_email("nope") is None

    def test_extract_domain_from_url(self):
        assert BlocklistAllowlistChecker._extract_domain_from_url(
            "https://Evil.COM/path"
        ) == "evil.com"

    def test_extract_domain_from_url_no_scheme(self):
        # urlparse without scheme puts everything in path
        result = BlocklistAllowlistChecker._extract_domain_from_url("evil.com/path")
        # hostname will be None → returns None
        assert result is None

    def test_extract_domain_from_url_empty(self):
        assert BlocklistAllowlistChecker._extract_domain_from_url("") is None


# ── DB-backed checks (mocking _check_indicator) ─────────────────────


class TestBlocklistOverride:
    """Test blocklist detection triggers CONFIRMED_PHISHING override."""

    @pytest.mark.asyncio
    async def test_blocklisted_sender_overrides(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(from_address="attacker@evil.com")

        # Patch _check_indicator to simulate a blocklist hit on the sender
        original = checker._check_indicator

        async def fake_check(session, indicator, indicator_type, result):
            if indicator == "attacker@evil.com" and indicator_type == "email":
                result.is_blocklisted = True
                result.blocklist_matches.append(
                    {"indicator": "attacker@evil.com", "type": "email", "source": "analyst"}
                )

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            res = await checker.check(email, [])

        assert res.is_blocklisted is True
        assert res.override_verdict == Verdict.CONFIRMED_PHISHING
        assert "attacker@evil.com" in res.override_reason

    @pytest.mark.asyncio
    async def test_blocklisted_domain_overrides(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(from_address="user@phishing-domain.com")

        async def fake_check(session, indicator, indicator_type, result):
            if indicator == "phishing-domain.com" and indicator_type == "domain":
                result.is_blocklisted = True
                result.blocklist_matches.append(
                    {"indicator": "phishing-domain.com", "type": "domain", "source": "analyst"}
                )

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            res = await checker.check(email, [])

        assert res.override_verdict == Verdict.CONFIRMED_PHISHING


class TestAllowlistOverride:
    """Test allowlist detection triggers CLEAN override."""

    @pytest.mark.asyncio
    async def test_allowlisted_sender_overrides(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(from_address="ceo@trusted.com")

        async def fake_check(session, indicator, indicator_type, result):
            if indicator == "ceo@trusted.com" and indicator_type == "email":
                result.is_allowlisted = True
                result.allowlist_matches.append(
                    {"indicator": "ceo@trusted.com", "type": "email", "source": "analyst"}
                )

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            res = await checker.check(email, [])

        assert res.is_allowlisted is True
        assert res.override_verdict == Verdict.CLEAN
        assert "ceo@trusted.com" in res.override_reason


class TestBothListsNoOverride:
    """When both blocklisted AND allowlisted, no override verdict is set."""

    @pytest.mark.asyncio
    async def test_both_lists_no_override(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(from_address="ambiguous@overlap.com")

        async def fake_check(session, indicator, indicator_type, result):
            if indicator == "ambiguous@overlap.com":
                result.is_blocklisted = True
                result.blocklist_matches.append(
                    {"indicator": "ambiguous@overlap.com", "type": "email", "source": "a"}
                )
                result.is_allowlisted = True
                result.allowlist_matches.append(
                    {"indicator": "ambiguous@overlap.com", "type": "email", "source": "b"}
                )

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            res = await checker.check(email, [])

        # Both flags set → no override
        assert res.is_blocklisted is True
        assert res.is_allowlisted is True
        assert res.override_verdict is None


class TestReplyToCheck:
    """Reply-To domain is checked when it differs from sender."""

    @pytest.mark.asyncio
    async def test_reply_to_domain_checked(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(
            from_address="legit@company.com",
            reply_to="sneaky@phish.net",
        )

        checked_indicators = []

        async def fake_check(session, indicator, indicator_type, result):
            checked_indicators.append((indicator, indicator_type))

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            await checker.check(email, [])

        # Should include reply-to domain
        assert ("phish.net", "domain") in checked_indicators

    @pytest.mark.asyncio
    async def test_reply_to_same_as_sender_skipped(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(
            from_address="user@same.com",
            reply_to="user@same.com",
        )

        checked_indicators = []

        async def fake_check(session, indicator, indicator_type, result):
            checked_indicators.append((indicator, indicator_type))

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            await checker.check(email, [])

        # Reply-To domain should NOT appear separately (it's the same)
        domain_checks = [i for i in checked_indicators if i == ("same.com", "domain")]
        # Only one domain check (from the sender), not two
        assert len(domain_checks) == 1


class TestURLChecks:
    """URLs from extracted_urls are checked."""

    @pytest.mark.asyncio
    async def test_url_and_domain_checked(self):
        checker = BlocklistAllowlistChecker(db_session_factory=_build_session_factory())
        email = _make_email(from_address="x@y.com")
        urls = [_make_url("https://evil.com/steal")]

        checked = []

        async def fake_check(session, indicator, indicator_type, result):
            checked.append((indicator, indicator_type))

        with patch.object(checker, "_check_indicator", side_effect=fake_check):
            await checker.check(email, urls)

        assert ("evil.com", "domain") in checked
        assert ("https://evil.com/steal", "url") in checked


class TestExceptionHandling:
    """DB exceptions are caught gracefully."""

    @pytest.mark.asyncio
    async def test_db_exception_returns_empty(self):
        @asynccontextmanager
        async def broken_factory():
            raise RuntimeError("DB down")
            yield  # pragma: no cover

        checker = BlocklistAllowlistChecker(db_session_factory=broken_factory)
        email = _make_email()
        result = await checker.check(email, [])

        assert result.is_blocklisted is False
        assert result.override_verdict is None


class TestCheckerInit:
    """Test checker initialization."""

    def test_init_with_none(self):
        checker = BlocklistAllowlistChecker()
        assert checker.db_session_factory is None

    def test_init_with_factory(self):
        factory = MagicMock()
        checker = BlocklistAllowlistChecker(db_session_factory=factory)
        assert checker.db_session_factory is factory

"""
Regression tests for src/analyzers/url_reputation.py.

Locks the dead-domain confidence downgrade behaviour described in
lessons-learned.md "Dead Domain Confidence Inflation". Without this fix,
a vendor returning "no threats" for a non-resolving fresh attacker domain
gets credited as 0.8-confidence evidence of safety, suppressing the overall
phishing score by ~15 points across the test corpus.

The fix lives in `URLReputationAnalyzer._check_one_url` and uses the
helper `_hostname_resolves`. These tests pin both.
"""
from __future__ import annotations

import socket
from unittest.mock import AsyncMock, patch

import pytest

from src.analyzers.url_reputation import (
    URLReputationAnalyzer,
    _DEAD_DOMAIN_CLEAN_CONFIDENCE,
)
from src.models import ExtractedURL, URLSource


# ─── _hostname_resolves helper ───────────────────────────────────────────────


class TestHostnameResolves:
    def test_returns_true_for_resolving_host(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("1.2.3.4", 0))]):
            assert URLReputationAnalyzer._hostname_resolves("https://example.com/path") is True

    def test_returns_false_on_gaierror(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            assert URLReputationAnalyzer._hostname_resolves("https://nx.invalid/") is False

    def test_returns_false_on_oserror(self):
        with patch("socket.getaddrinfo", side_effect=OSError("net unreachable")):
            assert URLReputationAnalyzer._hostname_resolves("https://example.com/") is False

    def test_returns_false_for_no_hostname(self):
        # Empty / scheme-only / garbage URLs should be treated as dead
        for bad in ("", "https://", "not a url", "://example.com"):
            assert URLReputationAnalyzer._hostname_resolves(bad) is False

    @pytest.mark.asyncio
    async def test_async_wrapper_times_out_blocking_resolver(self):
        def slow_resolver(_url):
            import time
            time.sleep(0.2)
            return True

        with patch.object(URLReputationAnalyzer, "_hostname_resolves", staticmethod(slow_resolver)):
            assert await URLReputationAnalyzer._hostname_resolves_async(
                "https://slow.example/",
                timeout=0.01,
            ) is False


# ─── Dead-domain confidence downgrade ────────────────────────────────────────


def _make_extracted_url(url: str = "https://attacker.example/login") -> ExtractedURL:
    return ExtractedURL(url=url, source=URLSource.BODY_HTML, source_detail="anchor")


class TestDeadDomainConfidenceDowngrade:
    """
    The high-value regression: when no service flagged a URL AND the
    hostname is dead, confidence must drop to _DEAD_DOMAIN_CLEAN_CONFIDENCE.
    """

    def setup_method(self):
        # Stub all four reputation services as "configured but returning clean
        # with high confidence" — the worst-case scenario the fix targets.
        self.analyzer = URLReputationAnalyzer(
            virustotal_client=object(),  # truthy so has_any_client passes
            safe_browsing_client=None,
            urlscan_client=None,
            abuseipdb_client=None,
        )

    @pytest.mark.asyncio
    async def test_clean_verdict_dead_domain_downgraded(self):
        """VT returns 0 risk @ 0.8 conf, hostname doesn't resolve → conf drops to 0.3."""
        with patch.object(
            self.analyzer, "_check_virustotal",
            new=AsyncMock(return_value=(0.0, 0.8, {"vendors": "0/85"})),
        ), patch.object(
            URLReputationAnalyzer, "_hostname_resolves_async", AsyncMock(return_value=False),
        ):
            result = await self.analyzer.analyze([_make_extracted_url()])
            assert result.confidence == _DEAD_DOMAIN_CLEAN_CONFIDENCE
            url_data = list(result.details["urls_analyzed"].values())[0]
            assert url_data["dead_domain"] is True

    @pytest.mark.asyncio
    async def test_clean_verdict_live_domain_not_downgraded(self):
        """If the hostname resolves, the original confidence must be preserved."""
        with patch.object(
            self.analyzer, "_check_virustotal",
            new=AsyncMock(return_value=(0.0, 0.8, {"vendors": "0/85"})),
        ), patch.object(
            URLReputationAnalyzer, "_hostname_resolves_async", AsyncMock(return_value=True),
        ):
            result = await self.analyzer.analyze([_make_extracted_url()])
            assert result.confidence == 0.8
            url_data = list(result.details["urls_analyzed"].values())[0]
            assert url_data["dead_domain"] is False

    @pytest.mark.asyncio
    async def test_high_risk_dead_domain_not_downgraded(self):
        """If a service flagged the URL as risky, dead-domain status is irrelevant."""
        with patch.object(
            self.analyzer, "_check_virustotal",
            new=AsyncMock(return_value=(0.95, 0.9, {"vendors": "82/85"})),
        ), patch.object(
            URLReputationAnalyzer, "_hostname_resolves_async", AsyncMock(return_value=False),
        ):
            result = await self.analyzer.analyze([_make_extracted_url()])
            # High-risk verdicts are evidence regardless of DNS state
            assert result.confidence == 0.9
            assert result.risk_score == 0.95

    @pytest.mark.asyncio
    async def test_already_low_confidence_dead_domain_not_modified(self):
        """A vendor that returned 0.2 confidence shouldn't be bumped to 0.3."""
        with patch.object(
            self.analyzer, "_check_virustotal",
            new=AsyncMock(return_value=(0.0, 0.2, {})),
        ), patch.object(
            URLReputationAnalyzer, "_hostname_resolves_async", AsyncMock(return_value=False),
        ):
            result = await self.analyzer.analyze([_make_extracted_url()])
            assert result.confidence == 0.2  # not raised to 0.3

    @pytest.mark.asyncio
    async def test_dead_domain_check_skipped_when_threshold_already_met(self):
        """
        If risk_score >= 0.3 the URL is suspicious and we don't even check DNS,
        because a "low confidence + dead" downgrade would harm a real signal.
        """
        with patch.object(
            self.analyzer, "_check_virustotal",
            new=AsyncMock(return_value=(0.5, 0.8, {})),
        ), patch.object(
            URLReputationAnalyzer, "_hostname_resolves_async",
        ) as mock_resolves:
            await self.analyzer.analyze([_make_extracted_url()])
            mock_resolves.assert_not_called()


# ─── Empty-input contract ────────────────────────────────────────────────────


class TestEmptyContract:
    @pytest.mark.asyncio
    async def test_no_urls_returns_zero_confidence(self):
        analyzer = URLReputationAnalyzer(
            virustotal_client=object(),
        )
        result = await analyzer.analyze([])
        assert result.risk_score == 0.0
        assert result.confidence == 0.0
        assert "no_urls" in result.details.get("message", "")

    @pytest.mark.asyncio
    async def test_no_clients_returns_zero_confidence(self):
        analyzer = URLReputationAnalyzer()
        result = await analyzer.analyze([_make_extracted_url()])
        assert result.confidence == 0.0
        assert "no_clients" in result.details.get("message", "")

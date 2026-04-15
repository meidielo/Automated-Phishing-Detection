"""
Regression test for the cycle 12 sender_profiling cold-start fix.

Root cause the cycle 12 audit traced (four discipline gaps stacked):
cycle 4's dead-domain-confidence lesson applied to url_reputation only,
compounded by doc/config drift, compounded by no end-to-end eval until
cycle 10, compounded by cycle 10 framing absorbing the first bad
baseline as "data, not goalposts".

The concrete bug: sender_profiling returned risk_score=0.45,
confidence=0.5 on cold-start senders (email_count < 3). In weighted
scoring this acted as a "moderate risk at moderate confidence" signal
that systematically diluted stronger signals from header_analysis and
brand_impersonation on phishing samples. In the cycle 10 eval baseline,
every phishing sample had sender_profiling = 0.45/0.5 regardless of
sender — literally identical output on 22 different senders — and the
weighted overall score on those samples landed at 0.19–0.42, below the
LIKELY_PHISHING threshold, even when brand_impersonation was producing
0.75–0.85 at high confidence.

The fix: when email_count < 3, return a zero-impact result
(risk_score=0.0, confidence=0.0). This skips the analyzer from the
weighted score (decision_engine.py:227 skips zero-confidence) AND
unblocks _is_clean_email (decision_engine.py:437 checks risk_score > 0.2).

This test locks the cold-start behavior. Name encodes the bug:
test_sender_profiling_cold_start_skips_from_scoring.
"""
from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from src.analyzers.sender_profiling import SenderProfileAnalyzer
from src.models import EmailObject


def _make_email(from_address: str = "attacker@evil.example") -> EmailObject:
    return EmailObject(
        email_id="cold-start-test",
        raw_headers={},
        from_address=from_address,
        from_display_name="",
        reply_to=None,
        to_addresses=["target@company.example"],
        cc_addresses=[],
        subject="Test",
        body_plain="Body text",
        body_html="",
        date=datetime.utcnow(),
        attachments=[],
        inline_images=[],
        message_id="<msg@test>",
        received_chain=[],
    )


class TestSenderProfilingColdStart:
    """
    The smoking-gun regression test. Constructs a fresh SenderProfileAnalyzer
    with a temporary empty database, runs it against an email from a
    never-seen sender, and asserts the result is zero-impact on scoring.
    """

    @pytest.mark.asyncio
    async def test_sender_profiling_cold_start_skips_from_scoring(self, tmp_path):
        # Fresh DB, no prior history for any sender
        db_path = str(tmp_path / "sender_profiles.db")
        analyzer = SenderProfileAnalyzer(db_path=db_path)

        email = _make_email("first-time-sender@example.com")
        result = await analyzer.analyze(email)

        # This is the contract the weighted-score path depends on:
        # confidence=0.0 means decision_engine.py:227 skips the analyzer
        # from the weighted sum entirely, so it cannot dilute real signals.
        assert result.confidence == 0.0, (
            "sender_profiling must return confidence=0.0 on cold-start "
            "senders or it will dilute real signals from other analyzers. "
            "See cycle 12 HISTORY entry for the root-cause trace."
        )
        # This is the contract the _is_clean_email override depends on:
        # risk_score=0.0 on cold start means the CLEAN path is not blocked
        # by a spurious absence-of-data signal.
        assert result.risk_score == 0.0, (
            "sender_profiling must return risk_score=0.0 on cold-start "
            "senders or _is_clean_email will block CLEAN verdicts on "
            "every cold-start deployment. See decision_engine.py:437."
        )
        # The result still carries the cold_start marker in details for
        # debugging, so operators can see WHY the analyzer was skipped.
        assert result.details.get("message") == "cold_start"
        assert result.details.get("email_count") == 0

    @pytest.mark.asyncio
    async def test_three_prior_observations_unlocks_real_scoring(self, tmp_path):
        """Once a sender has 3+ prior observations, the analyzer produces
        real output (the cold-start guard no longer fires)."""
        db_path = str(tmp_path / "sender_profiles.db")
        analyzer = SenderProfileAnalyzer(db_path=db_path)

        sender = "regular-sender@example.com"
        # Three prior observations to cross the cold-start threshold.
        # analyze() calls _update_sender_history internally even on the
        # cold-start early-return path, so three back-to-back analyses
        # populate the baseline.
        for _ in range(3):
            await analyzer.analyze(_make_email(sender))

        # The fourth analyze() should see email_count >= 3 and produce
        # a real result with non-zero confidence.
        result = await analyzer.analyze(_make_email(sender))

        assert result.confidence > 0.0, (
            "after 3 prior observations, sender_profiling should produce "
            "a real baseline-derived signal with non-zero confidence"
        )
        assert result.details.get("message") != "cold_start"

    @pytest.mark.asyncio
    async def test_cold_start_does_not_block_clean_override(self, tmp_path):
        """
        Semantic test: on cold start the result must not have
        risk_score > 0.2, because decision_engine._is_clean_email returns
        False on any sender_profiling.risk_score > 0.2. A spurious
        cold-start 0.3 (the pre-cycle-12 value) would dead-block the
        CLEAN override for every cold-start deployment — which is the
        second-order bug the cycle 7 NEW-1 fix was protecting against
        on paper, but the scenario wasn't reachable in practice until
        cycle 12 fixed this analyzer.
        """
        db_path = str(tmp_path / "sender_profiles.db")
        analyzer = SenderProfileAnalyzer(db_path=db_path)

        result = await analyzer.analyze(_make_email())

        assert result.risk_score <= 0.2, (
            "cold-start sender_profiling must have risk_score <= 0.2 "
            "or it will dead-block _is_clean_email on every fresh "
            "deployment. See cycle 7 NEW-1 and cycle 12 audit for history."
        )

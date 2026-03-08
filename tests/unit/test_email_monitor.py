"""
Unit tests for the email monitoring service.

Tests cover:
- EmailMonitor lifecycle (start, poll, stop)
- AlertDispatcher (log, webhook, callback)
- ResultStore (JSONL writing)
- Processing logic (analyze → store → alert)
- Graceful error handling
- Stats tracking
"""
import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from src.automation.email_monitor import (
    AlertDispatcher,
    EmailMonitor,
    ResultStore,
    ALERT_VERDICTS,
)
from src.config import PipelineConfig, IMAPConfig
from src.models import EmailObject, PipelineResult, Verdict


# ── helpers ──────────────────────────────────────────────────────────


def _make_email(
    email_id="monitor-001",
    from_address="sender@test.com",
    subject="Test Subject",
) -> EmailObject:
    return EmailObject(
        email_id=email_id,
        subject=subject,
        from_address=from_address,
        from_display_name="Sender",
        to_addresses=["recipient@example.com"],
        cc_addresses=[],
        reply_to="",
        body_plain="test body",
        body_html="<p>test</p>",
        date=datetime(2026, 3, 8, tzinfo=timezone.utc),
        raw_headers={},
        attachments=[],
        inline_images=[],
        message_id="<test@example.com>",
        received_chain=[],
    )


def _make_result(
    email_id="monitor-001",
    verdict=Verdict.CLEAN,
    score=0.1,
) -> PipelineResult:
    return PipelineResult(
        email_id=email_id,
        verdict=verdict,
        overall_score=score,
        overall_confidence=0.9,
        analyzer_results={},
        extracted_urls=[],
        iocs={},
        reasoning="test reasoning",
        timestamp=datetime(2026, 3, 8, tzinfo=timezone.utc),
    )


# ── AlertDispatcher ─────────────────────────────────────────────────


class TestAlertDispatcher:

    @pytest.mark.asyncio
    async def test_dispatch_logs_warning(self, caplog):
        dispatcher = AlertDispatcher()
        email = _make_email()
        result = _make_result(verdict=Verdict.CONFIRMED_PHISHING, score=0.95)

        import logging
        with caplog.at_level(logging.WARNING):
            await dispatcher.dispatch(email, result)

        assert "PHISHING ALERT" in caplog.text

    @pytest.mark.asyncio
    async def test_dispatch_writes_alert_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "alerts.jsonl")
            dispatcher = AlertDispatcher()
            dispatcher.set_alert_log(log_path)

            email = _make_email()
            result = _make_result(verdict=Verdict.LIKELY_PHISHING, score=0.75)

            await dispatcher.dispatch(email, result)

            lines = Path(log_path).read_text().strip().split("\n")
            assert len(lines) == 1
            payload = json.loads(lines[0])
            assert payload["verdict"] == "LIKELY_PHISHING"
            assert payload["from"] == "sender@test.com"

    @pytest.mark.asyncio
    async def test_dispatch_fires_sync_callback(self):
        dispatcher = AlertDispatcher()
        received = []
        dispatcher.register_callback(lambda p: received.append(p))

        email = _make_email()
        result = _make_result(verdict=Verdict.CONFIRMED_PHISHING)

        await dispatcher.dispatch(email, result)

        assert len(received) == 1
        assert received[0]["verdict"] == "CONFIRMED_PHISHING"

    @pytest.mark.asyncio
    async def test_dispatch_fires_async_callback(self):
        dispatcher = AlertDispatcher()
        received = []

        async def async_cb(payload):
            received.append(payload)

        dispatcher.register_callback(async_cb)

        email = _make_email()
        result = _make_result(verdict=Verdict.CONFIRMED_PHISHING)

        await dispatcher.dispatch(email, result)

        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_callback_error_doesnt_crash(self):
        dispatcher = AlertDispatcher()
        dispatcher.register_callback(lambda p: 1 / 0)  # ZeroDivisionError

        email = _make_email()
        result = _make_result(verdict=Verdict.CONFIRMED_PHISHING)

        # Should not raise
        await dispatcher.dispatch(email, result)


# ── ResultStore ──────────────────────────────────────────────────────


class TestResultStore:

    @pytest.mark.asyncio
    async def test_store_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = os.path.join(tmp, "results.jsonl")
            store = ResultStore(
                db_path="nonexistent.db",
                jsonl_path=jsonl_path,
            )

            email = _make_email()
            result = _make_result()

            await store.store(email, result)

            lines = Path(jsonl_path).read_text().strip().split("\n")
            assert len(lines) == 1
            record = json.loads(lines[0])
            assert record["email_id"] == "monitor-001"
            assert record["verdict"] == "CLEAN"

    @pytest.mark.asyncio
    async def test_store_appends_multiple(self):
        with tempfile.TemporaryDirectory() as tmp:
            jsonl_path = os.path.join(tmp, "results.jsonl")
            store = ResultStore(db_path="nonexistent.db", jsonl_path=jsonl_path)

            for i in range(3):
                email = _make_email(email_id=f"email-{i}")
                result = _make_result(email_id=f"email-{i}")
                await store.store(email, result)

            lines = Path(jsonl_path).read_text().strip().split("\n")
            assert len(lines) == 3


# ── EmailMonitor ─────────────────────────────────────────────────────


class TestEmailMonitor:

    def _make_monitor(self):
        pipeline = MagicMock()
        pipeline.analyze = AsyncMock(return_value=_make_result())

        fetcher = MagicMock()
        fetcher.config = IMAPConfig(
            host="imap.test.com",
            user="test@test.com",
            password="secret",
        )
        fetcher.fetch_all_new = MagicMock(return_value=[])
        fetcher.disconnect = MagicMock()
        fetcher.get_uid_for_email = MagicMock(return_value="42")
        fetcher.ensure_folder_exists = MagicMock(return_value=True)
        fetcher.move_to_folder = MagicMock(return_value=True)

        alerts = MagicMock(spec=AlertDispatcher)
        alerts.dispatch = AsyncMock()

        store = MagicMock(spec=ResultStore)
        store.store = AsyncMock()

        monitor = EmailMonitor(
            pipeline=pipeline,
            fetcher=fetcher,
            alert_dispatcher=alerts,
            result_store=store,
            poll_interval=0,  # no delay in tests
        )
        return monitor, pipeline, fetcher, alerts, store

    @pytest.mark.asyncio
    async def test_run_stops_after_max_iterations(self):
        monitor, _, fetcher, _, _ = self._make_monitor()

        await monitor.run(max_iterations=3)

        assert fetcher.fetch_all_new.call_count == 3
        assert fetcher.disconnect.called

    @pytest.mark.asyncio
    async def test_processes_fetched_emails(self):
        monitor, pipeline, fetcher, _, store = self._make_monitor()
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])

        await monitor.run(max_iterations=1)

        pipeline.analyze.assert_called_once_with(email)
        store.store.assert_called_once()

    @pytest.mark.asyncio
    async def test_alerts_on_phishing_verdict(self):
        monitor, pipeline, fetcher, alerts, _ = self._make_monitor()
        email = _make_email()
        phishing_result = _make_result(
            verdict=Verdict.CONFIRMED_PHISHING, score=0.95
        )
        pipeline.analyze = AsyncMock(return_value=phishing_result)
        fetcher.fetch_all_new = MagicMock(return_value=[email])

        await monitor.run(max_iterations=1)

        alerts.dispatch.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_alert_on_clean_verdict(self):
        monitor, pipeline, fetcher, alerts, _ = self._make_monitor()
        email = _make_email()
        clean_result = _make_result(verdict=Verdict.CLEAN, score=0.1)
        pipeline.analyze = AsyncMock(return_value=clean_result)
        fetcher.fetch_all_new = MagicMock(return_value=[email])

        await monitor.run(max_iterations=1)

        alerts.dispatch.assert_not_called()

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])

        phishing_result = _make_result(verdict=Verdict.LIKELY_PHISHING)
        pipeline.analyze = AsyncMock(return_value=phishing_result)

        await monitor.run(max_iterations=2)

        assert monitor.stats["emails_processed"] == 2
        assert monitor.stats["phishing_detected"] == 2
        assert monitor.stats["quarantined"] == 2
        assert monitor.stats["errors"] == 0

    @pytest.mark.asyncio
    async def test_error_in_analyze_increments_error_count(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(side_effect=RuntimeError("boom"))

        await monitor.run(max_iterations=1)

        assert monitor.stats["errors"] == 1
        assert monitor.stats["emails_processed"] == 0

    @pytest.mark.asyncio
    async def test_imap_fetch_error_handled(self):
        monitor, _, fetcher, _, _ = self._make_monitor()
        fetcher.fetch_all_new = MagicMock(side_effect=ConnectionError("lost"))
        fetcher._connection = None

        await monitor.run(max_iterations=2)

        assert monitor.stats["errors"] == 2

    @pytest.mark.asyncio
    async def test_stop_method(self):
        monitor, _, fetcher, _, _ = self._make_monitor()
        call_count_at_stop = None

        # Stop after first poll cycle
        original_fetch = fetcher.fetch_all_new

        def fetch_and_stop():
            result = original_fetch()
            monitor.stop()
            return result

        fetcher.fetch_all_new = MagicMock(side_effect=fetch_and_stop)

        await monitor.run(max_iterations=100)

        # Should have stopped after 1 cycle despite max_iterations=100
        assert fetcher.fetch_all_new.call_count == 1

    @pytest.mark.asyncio
    async def test_from_config(self):
        config = PipelineConfig(
            imap=IMAPConfig(
                host="imap.test.com",
                user="user@test.com",
                password="pass",
                poll_interval_seconds=30,
                quarantine_folder="Junk",
            ),
        )
        monitor = EmailMonitor.from_config(config)
        assert monitor.poll_interval == 30
        assert monitor.fetcher.config.host == "imap.test.com"
        assert monitor.quarantine_folder == "Junk"

    @pytest.mark.asyncio
    async def test_quarantine_called_on_phishing(self):
        monitor, pipeline, fetcher, alerts, _ = self._make_monitor()
        monitor.quarantine_folder = "Quarantine"
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(
            return_value=_make_result(verdict=Verdict.CONFIRMED_PHISHING)
        )

        await monitor.run(max_iterations=1)

        fetcher.get_uid_for_email.assert_called_once_with(email.email_id)
        fetcher.ensure_folder_exists.assert_called_once_with("Quarantine")
        fetcher.move_to_folder.assert_called_once_with("42", "Quarantine")
        assert monitor.stats["quarantined"] == 1

    @pytest.mark.asyncio
    async def test_quarantine_not_called_on_clean(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(
            return_value=_make_result(verdict=Verdict.CLEAN)
        )

        await monitor.run(max_iterations=1)

        fetcher.move_to_folder.assert_not_called()
        assert monitor.stats["quarantined"] == 0

    @pytest.mark.asyncio
    async def test_quarantine_stat_not_incremented_when_move_fails(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        fetcher.move_to_folder = MagicMock(return_value=False)
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(
            return_value=_make_result(verdict=Verdict.CONFIRMED_PHISHING)
        )

        await monitor.run(max_iterations=1)

        assert monitor.stats["quarantined"] == 0

    @pytest.mark.asyncio
    async def test_recent_results_populated(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        email = _make_email(email_id="e1", subject="Hello", from_address="a@b.com")
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(
            return_value=_make_result(email_id="e1", verdict=Verdict.CLEAN)
        )

        await monitor.run(max_iterations=1)

        assert len(monitor._recent_results) == 1
        rec = monitor._recent_results[0]
        assert rec["email_id"] == "e1"
        assert rec["verdict"] == "CLEAN"
        assert rec["subject"] == "Hello"
        assert rec["quarantined"] is False

    @pytest.mark.asyncio
    async def test_recent_results_capped_at_max(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        monitor._MAX_RECENT = 5

        emails = [_make_email(email_id=f"e{i}") for i in range(8)]
        fetcher.fetch_all_new = MagicMock(return_value=emails)

        await monitor.run(max_iterations=1)

        assert len(monitor._recent_results) == 5

    @pytest.mark.asyncio
    async def test_recent_results_quarantined_flag_set(self):
        monitor, pipeline, fetcher, _, _ = self._make_monitor()
        email = _make_email()
        fetcher.fetch_all_new = MagicMock(return_value=[email])
        pipeline.analyze = AsyncMock(
            return_value=_make_result(verdict=Verdict.CONFIRMED_PHISHING)
        )

        await monitor.run(max_iterations=1)

        assert monitor._recent_results[0]["quarantined"] is True


class TestAlertVerdicts:
    """Verify which verdicts trigger alerts."""

    def test_confirmed_phishing_triggers_alert(self):
        assert Verdict.CONFIRMED_PHISHING in ALERT_VERDICTS

    def test_likely_phishing_triggers_alert(self):
        assert Verdict.LIKELY_PHISHING in ALERT_VERDICTS

    def test_suspicious_no_alert(self):
        assert Verdict.SUSPICIOUS not in ALERT_VERDICTS

    def test_clean_no_alert(self):
        assert Verdict.CLEAN not in ALERT_VERDICTS

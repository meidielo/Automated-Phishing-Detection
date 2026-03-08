"""
Continuous email monitoring service.

Polls an IMAP mailbox, runs every incoming email through the phishing
detection pipeline, stores results in the feedback database, and
optionally fires alerts on high-severity verdicts.

Usage:
    # As a standalone service:
    python -m src.automation.email_monitor

    # Or via main.py:
    python main.py monitor

    # Or from code:
    monitor = EmailMonitor.from_config(config)
    await monitor.run()
"""
import asyncio
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from src.config import PipelineConfig
from src.ingestion.imap_fetcher import IMAPFetcher
from src.models import EmailObject, PipelineResult, Verdict
from src.orchestrator.pipeline import PhishingPipeline

logger = logging.getLogger(__name__)

# Verdicts that should trigger an alert
ALERT_VERDICTS = {Verdict.CONFIRMED_PHISHING, Verdict.LIKELY_PHISHING}


class AlertDispatcher:
    """
    Dispatches alerts when a phishing email is detected.

    Supports multiple alert channels:
    - Log file (always on)
    - Webhook (POST JSON to a URL)
    - Custom callback

    Extend this class or register callbacks for Slack, PagerDuty,
    email-to-SOC, SIEM ingestion, etc.
    """

    def __init__(self):
        self._callbacks: list[Callable] = []
        self._webhook_url: Optional[str] = None
        self._alert_log_path: Optional[Path] = None

    def set_webhook(self, url: str):
        """Set a webhook URL to POST alert payloads to."""
        self._webhook_url = url

    def set_alert_log(self, path: str):
        """Set a file path to append alert JSON lines to."""
        self._alert_log_path = Path(path)
        self._alert_log_path.parent.mkdir(parents=True, exist_ok=True)

    def register_callback(self, fn: Callable):
        """Register a custom async or sync callback for alerts."""
        self._callbacks.append(fn)

    async def dispatch(self, email: EmailObject, result: PipelineResult):
        """
        Fire alert for a detected phishing email.

        Args:
            email: The analyzed EmailObject
            result: The pipeline analysis result
        """
        alert_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_id": result.email_id,
            "verdict": result.verdict.value,
            "score": result.overall_score,
            "confidence": result.overall_confidence,
            "from": email.from_address,
            "subject": email.subject,
            "to": email.to_addresses,
            "reasoning": result.reasoning if isinstance(result.reasoning, str) else str(result.reasoning),
            "extracted_urls": result.extracted_urls[:10] if result.extracted_urls else [],
        }

        # Always log
        logger.warning(
            f"PHISHING ALERT: verdict={result.verdict.value} "
            f"score={result.overall_score:.3f} "
            f"from={email.from_address} "
            f"subject='{email.subject}'"
        )

        # Append to alert log file
        if self._alert_log_path:
            try:
                with open(self._alert_log_path, "a") as f:
                    f.write(json.dumps(alert_payload) + "\n")
            except Exception as e:
                logger.error(f"Failed to write alert log: {e}")

        # POST to webhook
        if self._webhook_url:
            await self._post_webhook(alert_payload)

        # Fire custom callbacks
        for cb in self._callbacks:
            try:
                ret = cb(alert_payload)
                if asyncio.iscoroutine(ret):
                    await ret
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    async def _post_webhook(self, payload: dict):
        """POST alert payload to configured webhook URL."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status >= 300:
                        logger.error(
                            f"Webhook returned {resp.status}: {await resp.text()}"
                        )
                    else:
                        logger.info(f"Alert webhook delivered: {resp.status}")
        except ImportError:
            logger.warning("aiohttp not installed — webhook alerts disabled")
        except Exception as e:
            logger.error(f"Webhook delivery failed: {e}")


class ResultStore:
    """
    Persists analysis results to the feedback database and/or JSON lines file.

    When the full feedback DB is available, results go into the
    pipeline_results table. As a fallback, results are appended to a
    JSONL file so nothing is lost.
    """

    def __init__(self, db_path: str = "data/feedback.db", jsonl_path: str = "data/results.jsonl"):
        self._db_path = db_path
        self._jsonl_path = Path(jsonl_path)
        self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    async def store(self, email: EmailObject, result: PipelineResult):
        """Store an analysis result."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_id": result.email_id,
            "verdict": result.verdict.value,
            "score": result.overall_score,
            "confidence": result.overall_confidence,
            "from": email.from_address,
            "subject": email.subject,
            "reasoning": result.reasoning if isinstance(result.reasoning, str) else str(result.reasoning),
        }

        # Always write to JSONL (append-only, crash-safe)
        try:
            with open(self._jsonl_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Failed to write result JSONL: {e}")

        # Try to write to the feedback database
        try:
            await self._store_to_db(result)
        except Exception as e:
            logger.debug(f"DB store skipped (fallback to JSONL): {e}")

    async def _store_to_db(self, result: PipelineResult):
        """Insert result into the pipeline_results table."""
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from src.feedback.database import PipelineResultRecord

        engine = create_async_engine(
            f"sqlite+aiosqlite:///{self._db_path}", echo=False
        )
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with async_session() as session:
            row = PipelineResultRecord(
                email_id=result.email_id,
                verdict=result.verdict.value,
                overall_score=result.overall_score,
                overall_confidence=result.overall_confidence,
                result_json=json.dumps({
                    "reasoning": result.reasoning,
                    "extracted_urls": result.extracted_urls[:20] if result.extracted_urls else [],
                }),
                analyzed_at=result.timestamp or datetime.now(timezone.utc),
            )
            session.add(row)
            await session.commit()

        await engine.dispose()


class EmailMonitor:
    """
    Continuous email monitoring service.

    Lifecycle:
    1. Connect to IMAP mailbox
    2. Poll for new (UNSEEN) emails every N seconds
    3. Parse each email → run through PhishingPipeline
    4. Store result → fire alert if verdict is phishing
    5. Repeat until stopped (SIGINT/SIGTERM)

    Graceful shutdown: catches SIGINT/SIGTERM, finishes current batch,
    then exits cleanly.
    """

    def __init__(
        self,
        pipeline: PhishingPipeline,
        fetcher: IMAPFetcher,
        alert_dispatcher: Optional[AlertDispatcher] = None,
        result_store: Optional[ResultStore] = None,
        poll_interval: int = 60,
    ):
        self.pipeline = pipeline
        self.fetcher = fetcher
        self.alerts = alert_dispatcher or AlertDispatcher()
        self.store = result_store or ResultStore()
        self.poll_interval = poll_interval
        self.quarantine_folder = "Quarantine"
        self._running = False
        self._stats = {
            "started_at": None,
            "emails_processed": 0,
            "phishing_detected": 0,
            "quarantined": 0,
            "errors": 0,
            "last_poll": None,
        }
        self._recent_results: list[dict] = []  # last 200 results for the UI
        self._MAX_RECENT = 200

    @classmethod
    def from_config(cls, config: PipelineConfig) -> "EmailMonitor":
        """
        Create an EmailMonitor from PipelineConfig.

        Args:
            config: Fully loaded PipelineConfig

        Returns:
            Configured EmailMonitor ready to run
        """
        pipeline = PhishingPipeline(config)
        fetcher = IMAPFetcher(config.imap)

        alert_dispatcher = AlertDispatcher()
        alert_dispatcher.set_alert_log("data/alerts.jsonl")

        # If ALERT_WEBHOOK_URL is set, enable webhook
        import os
        webhook_url = os.getenv("ALERT_WEBHOOK_URL")
        if webhook_url:
            alert_dispatcher.set_webhook(webhook_url)

        result_store = ResultStore(
            db_path=config.feedback_db_path,
            jsonl_path="data/results.jsonl",
        )

        monitor = cls(
            pipeline=pipeline,
            fetcher=fetcher,
            alert_dispatcher=alert_dispatcher,
            result_store=result_store,
            poll_interval=config.imap.poll_interval_seconds,
        )
        monitor.quarantine_folder = config.imap.quarantine_folder
        return monitor

    async def run(self, max_iterations: Optional[int] = None):
        """
        Start the monitoring loop.

        Args:
            max_iterations: Stop after N poll cycles (None = run forever).
                           Useful for testing.
        """
        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()
        iteration = 0

        # Register signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        logger.info(
            f"Email monitor started: "
            f"server={self.fetcher.config.host}, "
            f"folder={self.fetcher.config.folder}, "
            f"interval={self.poll_interval}s"
        )

        while self._running:
            if max_iterations is not None and iteration >= max_iterations:
                logger.info(f"Reached max iterations ({max_iterations}), stopping")
                break

            try:
                await self._poll_and_analyze()
                self._stats["last_poll"] = datetime.now(timezone.utc).isoformat()

            except Exception as e:
                logger.error(f"Poll cycle error: {e}", exc_info=True)
                self._stats["errors"] += 1

            iteration += 1

            if self._running:
                await asyncio.sleep(self.poll_interval)

        # Clean shutdown
        self.fetcher.disconnect()
        logger.info(
            f"Email monitor stopped. Stats: "
            f"processed={self._stats['emails_processed']}, "
            f"phishing={self._stats['phishing_detected']}, "
            f"errors={self._stats['errors']}"
        )

    async def _poll_and_analyze(self):
        """Single poll cycle: fetch new emails, analyze each one."""
        try:
            emails = self.fetcher.fetch_all_new()
        except Exception as e:
            logger.error(f"IMAP fetch failed: {e}")
            self.fetcher._connection = None  # force reconnect next cycle
            raise

        if emails:
            logger.info(f"Processing {len(emails)} new email(s)")

        for email_obj in emails:
            await self._process_single(email_obj)

    async def _process_single(self, email_obj: EmailObject):
        """Analyze a single email and handle the result."""
        quarantined = False
        try:
            logger.info(
                f"Analyzing email: id={email_obj.email_id}, "
                f"from={email_obj.from_address}, "
                f"subject='{email_obj.subject}'"
            )

            result = await self.pipeline.analyze(email_obj)
            self._stats["emails_processed"] += 1

            logger.info(
                f"Result: id={result.email_id}, "
                f"verdict={result.verdict.value}, "
                f"score={result.overall_score:.3f}"
            )

            # Store result
            await self.store.store(email_obj, result)

            # Alert + quarantine if phishing
            if result.verdict in ALERT_VERDICTS:
                self._stats["phishing_detected"] += 1
                await self.alerts.dispatch(email_obj, result)

                # Move to quarantine folder
                uid = self.fetcher.get_uid_for_email(email_obj.email_id)
                if uid:
                    self.fetcher.ensure_folder_exists(self.quarantine_folder)
                    ok = self.fetcher.move_to_folder(uid, self.quarantine_folder)
                    if ok:
                        quarantined = True
                        self._stats["quarantined"] += 1
                        logger.info(
                            f"Quarantined email {email_obj.email_id} "
                            f"(UID {uid}) → '{self.quarantine_folder}'"
                        )
                    else:
                        logger.warning(f"Failed to quarantine email {email_obj.email_id}")

        except Exception as e:
            logger.error(
                f"Failed to analyze email {email_obj.email_id}: {e}",
                exc_info=True,
            )
            self._stats["errors"] += 1

        # Track in recent results for UI
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_id": email_obj.email_id,
            "from": email_obj.from_address,
            "subject": email_obj.subject,
            "verdict": getattr(result, "verdict", Verdict.SUSPICIOUS).value if "result" in dir() else "ERROR",
            "score": getattr(result, "overall_score", 0.0) if "result" in dir() else 0.0,
            "quarantined": quarantined,
        }
        self._recent_results.append(record)
        if len(self._recent_results) > self._MAX_RECENT:
            self._recent_results.pop(0)

    def stop(self):
        """Signal the monitor to stop after the current cycle."""
        logger.info("Shutdown signal received, stopping after current cycle...")
        self._running = False

    @property
    def stats(self) -> dict:
        """Return current monitoring statistics."""
        return dict(self._stats)


# ── Standalone entry point ───────────────────────────────────────────

async def _main():
    """Run the email monitor as a standalone service."""
    from dotenv import load_dotenv
    load_dotenv()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    config = PipelineConfig.from_env()

    if not config.imap.user or not config.imap.password:
        logger.error(
            "IMAP credentials not configured. Set IMAP_HOST, IMAP_USER, "
            "IMAP_PASSWORD environment variables."
        )
        sys.exit(1)

    monitor = EmailMonitor.from_config(config)
    await monitor.run()


if __name__ == "__main__":
    asyncio.run(_main())

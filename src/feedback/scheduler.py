"""
Background scheduler for automatic retraining.

Provides:
- Periodic check for retrain necessity (every 24 hours)
- Manual trigger support
- Event logging
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.config import PipelineConfig
from src.feedback.database import DatabaseManager
from src.feedback.retrainer import RetrainOrchestrator

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class RetrainScheduler:
    """
    Background scheduler for automatic model retraining.

    Runs retrain checks at regular intervals and manually via API trigger.
    """

    def __init__(
        self,
        config: PipelineConfig,
        db_manager: DatabaseManager,
        check_interval_hours: int = 24,
    ):
        """
        Initialize retraining scheduler.

        Args:
            config: Pipeline configuration
            db_manager: Database manager instance
            check_interval_hours: Hours between automatic retrain checks (default: 24)
        """
        self.config = config
        self.db_manager = db_manager
        self.check_interval = timedelta(hours=check_interval_hours)
        self.orchestrator = RetrainOrchestrator(config, db_manager)
        self.running = False
        self.last_check: Optional[datetime] = None
        self.scheduler_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """
        Start background scheduler.

        Creates an async task that runs indefinitely.

        Raises:
            RuntimeError: If already running
        """
        if self.running:
            raise RuntimeError("Scheduler already running")

        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info(
            f"Retraining scheduler started (check interval: {self.check_interval})"
        )

    async def stop(self) -> None:
        """
        Stop background scheduler gracefully.

        Cancels the scheduler task and waits for it to finish.
        """
        if not self.running:
            logger.warning("Scheduler not running")
            return

        self.running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass

        logger.info("Retraining scheduler stopped")

    async def _scheduler_loop(self) -> None:
        """
        Main scheduler loop. Runs until stopped.

        Periodically checks if retraining is needed and executes it.

        Does not raise exceptions; logs errors instead.
        """
        while self.running:
            try:
                await self._check_and_retrain()
                self.last_check = _utc_now()
                await asyncio.sleep(self.check_interval.total_seconds())

            except asyncio.CancelledError:
                logger.info("Scheduler loop cancelled")
                break

            except Exception as e:
                logger.error(
                    f"Error in scheduler loop: {e}",
                    exc_info=True,
                )
                # Continue despite errors
                await asyncio.sleep(300)  # Wait 5 min before retry

    async def _check_and_retrain(self) -> None:
        """
        Check if retraining should occur and execute if needed.

        Raises:
            Any exceptions from database or retraining operations.
        """
        try:
            async with self.db_manager.async_session_maker() as session:
                # Check if retraining is needed
                should_retrain, reason = await self.orchestrator.should_retrain(
                    session
                )

                if should_retrain:
                    logger.info(f"Triggering scheduled retrain: {reason}")
                    result = await self.orchestrator.run_full_retrain(
                        session, triggered_by="scheduled"
                    )

                    if result["status"] == "completed":
                        logger.info(
                            f"Scheduled retrain completed: {result['run_id']}, "
                            f"feedback_count={result['feedback_count']}"
                        )
                    else:
                        logger.error(
                            f"Scheduled retrain failed: {result.get('error')}"
                        )
                else:
                    logger.debug(f"No retrain needed: {reason}")

        except Exception as e:
            logger.error(f"Error in check_and_retrain: {e}", exc_info=True)
            raise

    async def trigger_retrain(self, triggered_by: str) -> dict:
        """
        Manually trigger a retraining run.

        Can be called from API endpoint.

        Args:
            triggered_by: Username or identifier of who triggered the retrain

        Returns:
            Result dict from retraining orchestrator
        """
        try:
            logger.info(f"Manual retrain triggered by {triggered_by}")

            async with self.db_manager.async_session_maker() as session:
                result = await self.orchestrator.run_full_retrain(
                    session, triggered_by=triggered_by
                )
                return result

        except Exception as e:
            logger.error(f"Manual retrain failed: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e),
            }

    async def get_retrain_history(
        self, limit: int = 10
    ) -> list[dict]:
        """
        Get history of recent retraining runs.

        Args:
            limit: Maximum number of runs to return

        Returns:
            List of retrain run dicts
        """
        try:
            from sqlalchemy import select

            from src.feedback.database import RetrainRun

            async with self.db_manager.async_session_maker() as session:
                stmt = (
                    select(RetrainRun)
                    .order_by(RetrainRun.started_at.desc())
                    .limit(limit)
                )
                result = await session.execute(stmt)
                runs = result.scalars().all()

                return [
                    {
                        "run_id": run.run_id,
                        "triggered_by": run.triggered_by,
                        "status": run.status,
                        "feedback_records_used": run.feedback_records_used,
                        "model_improvement": run.model_improvement,
                        "started_at": run.started_at.isoformat(),
                        "completed_at": (
                            run.completed_at.isoformat()
                            if run.completed_at
                            else None
                        ),
                        "error_message": run.error_message,
                    }
                    for run in runs
                ]

        except Exception as e:
            logger.error(f"Error fetching retrain history: {e}", exc_info=True)
            return []

    async def get_last_check_time(self) -> Optional[str]:
        """
        Get timestamp of last retrain check.

        Returns:
            ISO format timestamp or None if no checks performed yet
        """
        if self.last_check:
            return self.last_check.isoformat()
        return None

    @property
    def is_running(self) -> bool:
        """Check if scheduler is currently running."""
        return self.running and self.scheduler_task is not None

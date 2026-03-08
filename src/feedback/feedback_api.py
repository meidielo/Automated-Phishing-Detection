"""
FastAPI application for the feedback loop and retraining system.

Provides REST endpoints for:
- Submitting analyst feedback and corrections
- Viewing feedback statistics and performance metrics
- Exporting feedback records
- Triggering and monitoring retraining
- Health checks
- Gap analysis (identifying weak analyzer areas)
"""
import csv
import io
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import PipelineConfig
from src.feedback.database import (
    DatabaseManager,
    FeedbackRecord,
    LocalAllowlist,
    LocalBlocklist,
    PipelineResult,
)
from src.feedback.retrainer import RetrainOrchestrator
from src.feedback.scheduler import RetrainScheduler
from src.models import Verdict

logger = logging.getLogger(__name__)


# Pydantic models for request/response validation


class FeedbackSubmissionRequest(BaseModel):
    """Analyst feedback on a pipeline verdict."""

    email_id: str = Field(..., description="Email ID that was analyzed")
    original_verdict: str = Field(
        ..., description="Original pipeline verdict (CLEAN, SUSPICIOUS, etc.)"
    )
    correct_label: str = Field(
        ..., description="Correct label according to analyst"
    )
    analyst_notes: Optional[str] = Field(
        None, description="Why analyst disagreed with pipeline"
    )
    feature_vector: dict = Field(
        default_factory=dict,
        description="Feature vector from original analysis (for retraining)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "email_id": "msg_abc123",
                "original_verdict": "SUSPICIOUS",
                "correct_label": "CONFIRMED_PHISHING",
                "analyst_notes": "Email contains BEC indicators missed by NLP",
                "feature_vector": {
                    "header_risk_score": 0.3,
                    "url_reputation_score": 0.8,
                },
            }
        }


class FeedbackResponse(BaseModel):
    """Response when feedback is accepted."""

    id: int
    email_id: str
    original_verdict: str
    correct_label: str
    submitted_at: datetime
    actions_taken: list[str]

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    """Performance statistics from feedback data."""

    total_feedback_records: int
    total_unique_emails: int
    false_positives: int
    false_negatives: int
    correct_verdicts: int
    precision: float
    recall: float
    f1_score: float
    last_updated: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "total_feedback_records": 156,
                "total_unique_emails": 142,
                "false_positives": 24,
                "false_negatives": 8,
                "correct_verdicts": 124,
                "precision": 0.84,
                "recall": 0.94,
                "f1_score": 0.89,
                "last_updated": "2026-03-08T15:30:00Z",
            }
        }


class RetrainResponse(BaseModel):
    """Response from retrain trigger."""

    run_id: str
    status: str
    feedback_count: int
    weights_updated: bool
    new_weights: Optional[dict[str, float]] = None
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "run_id": "retrain_abc12345_1234567890",
                "status": "completed",
                "feedback_count": 87,
                "weights_updated": True,
                "new_weights": {
                    "header_analysis": 0.12,
                    "url_reputation": 0.16,
                },
                "message": "Retraining completed successfully",
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    timestamp: datetime
    database_connected: bool
    scheduler_running: bool

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2026-03-08T15:30:00Z",
                "database_connected": True,
                "scheduler_running": True,
            }
        }


class GapAnalysisResponse(BaseModel):
    """Gap analysis showing weak analyzer areas."""

    analyzer: str
    false_negatives: int
    false_positives: int
    total_errors: int
    fn_percentage: float
    fp_percentage: float
    high_confidence_errors: int

    class Config:
        json_schema_extra = {
            "example": {
                "analyzer": "url_reputation",
                "false_negatives": 12,
                "false_positives": 3,
                "total_errors": 15,
                "fn_percentage": 80.0,
                "fp_percentage": 20.0,
                "high_confidence_errors": 8,
            }
        }


def create_app(
    config: PipelineConfig,
    db_manager: DatabaseManager,
    scheduler: Optional[RetrainScheduler] = None,
) -> FastAPI:
    """
    Create and configure FastAPI application.

    Args:
        config: Pipeline configuration
        db_manager: Database manager instance
        scheduler: Optional RetrainScheduler instance

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Phishing Detection Feedback API",
        description="Feedback loop and retraining endpoints",
        version="1.0.0",
    )

    # Store references for use in endpoints
    app.state.config = config
    app.state.db_manager = db_manager
    app.state.scheduler = scheduler
    app.state.orchestrator = RetrainOrchestrator(config, db_manager)

    # Dependency for bearer token auth
    async def verify_bearer_token(
        authorization: Optional[str] = Header(None),
    ) -> str:
        """
        Verify Bearer token from Authorization header.

        Args:
            authorization: Authorization header value

        Returns:
            Token string

        Raises:
            HTTPException: If token missing or invalid
        """
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
            )

        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format",
            )

        token = parts[1]

        # Check token against config
        if not config.analyst_api_token or token != config.analyst_api_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

        return token

    async def get_db_session() -> AsyncSession:
        """Dependency for getting database session."""
        async with db_manager.async_session_maker() as session:
            yield session

    # Rate limiting (simple in-memory counter per endpoint)
    from collections import defaultdict
    from datetime import datetime, timedelta

    rate_limits = defaultdict(list)
    MAX_REQUESTS_PER_MINUTE = 60

    def check_rate_limit(client_id: str) -> None:
        """
        Check rate limit for client.

        Args:
            client_id: Client identifier (IP, token, etc)

        Raises:
            HTTPException: If rate limit exceeded
        """
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)

        # Clean old entries
        rate_limits[client_id] = [
            ts for ts in rate_limits[client_id] if ts > minute_ago
        ]

        if len(rate_limits[client_id]) >= MAX_REQUESTS_PER_MINUTE:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded (60 requests/minute)",
            )

        rate_limits[client_id].append(now)

    # Endpoints

    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        """
        Health check endpoint.

        Returns:
            Health status and component status
        """
        try:
            # Try to get a session to verify database
            async with db_manager.async_session_maker() as session:
                await session.execute(select(1))
                db_connected = True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_connected = False

        scheduler_running = (
            app.state.scheduler.is_running
            if app.state.scheduler
            else False
        )

        status_str = (
            "healthy"
            if db_connected and scheduler_running
            else "degraded"
        )

        return HealthResponse(
            status=status_str,
            timestamp=datetime.utcnow(),
            database_connected=db_connected,
            scheduler_running=scheduler_running,
        )

    @app.post(
        "/api/v1/feedback",
        response_model=FeedbackResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def submit_feedback(
        feedback: FeedbackSubmissionRequest,
        token: str = Depends(verify_bearer_token),
        session: AsyncSession = Depends(get_db_session),
    ) -> FeedbackResponse:
        """
        Submit analyst correction for a pipeline verdict.

        When feedback is received:
        - False negative (missed phishing): Add IOCs to local blocklist
        - False positive (legitimate flagged): Add sender/domain to allowlist

        Args:
            feedback: Feedback submission
            token: Bearer token (verified by dependency)
            session: Database session

        Returns:
            Created feedback record with actions taken

        Raises:
            HTTPException: If validation fails
        """
        check_rate_limit(token)

        try:
            # Validate verdicts
            valid_verdicts = {v.value for v in Verdict}
            if feedback.original_verdict not in valid_verdicts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid original_verdict: {feedback.original_verdict}",
                )
            if feedback.correct_label not in valid_verdicts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid correct_label: {feedback.correct_label}",
                )

            # Create feedback record
            db_record = FeedbackRecord(
                email_id=feedback.email_id,
                original_verdict=feedback.original_verdict,
                correct_label=feedback.correct_label,
                analyst_notes=feedback.analyst_notes,
                feature_vector=json.dumps(feedback.feature_vector),
                submitted_at=datetime.utcnow(),
            )
            session.add(db_record)
            await session.flush()

            actions_taken = []

            # Determine error type and take actions
            original_severity = _verdict_to_severity(feedback.original_verdict)
            correct_severity = _verdict_to_severity(feedback.correct_label)

            if original_severity > correct_severity:
                # False positive: add to allowlist
                actions_taken.append("added_to_allowlist")

                # Extract sender domain if available
                if "@" in feedback.email_id:
                    domain = feedback.email_id.split("@")[1]
                    allowlist_entry = LocalAllowlist(
                        indicator=domain,
                        indicator_type="domain",
                        added_by="analyst",
                        added_at=datetime.utcnow(),
                        reason=feedback.analyst_notes,
                    )
                    session.add(allowlist_entry)

            elif original_severity < correct_severity:
                # False negative: add to blocklist
                actions_taken.append("added_to_blocklist")

                # Add sender domain to blocklist
                if "@" in feedback.email_id:
                    domain = feedback.email_id.split("@")[1]
                    blocklist_entry = LocalBlocklist(
                        indicator=domain,
                        indicator_type="domain",
                        added_by="analyst",
                        added_at=datetime.utcnow(),
                        reason=feedback.analyst_notes,
                    )
                    session.add(blocklist_entry)

            await session.commit()

            logger.info(
                f"Feedback submitted for {feedback.email_id}: "
                f"{feedback.original_verdict} -> {feedback.correct_label}, "
                f"actions: {actions_taken}"
            )

            return FeedbackResponse(
                id=db_record.id,
                email_id=db_record.email_id,
                original_verdict=db_record.original_verdict,
                correct_label=db_record.correct_label,
                submitted_at=db_record.submitted_at,
                actions_taken=actions_taken,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error submitting feedback: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to submit feedback",
            )

    @app.get("/api/v1/feedback/stats", response_model=StatsResponse)
    async def get_feedback_stats(
        token: str = Depends(verify_bearer_token),
        session: AsyncSession = Depends(get_db_session),
    ) -> StatsResponse:
        """
        Get performance statistics from feedback data.

        Calculates precision, recall, and F1 score.

        Args:
            token: Bearer token
            session: Database session

        Returns:
            Statistics response
        """
        check_rate_limit(token)

        try:
            # Count feedback records
            total_stmt = select(func.count(FeedbackRecord.id))
            total_result = await session.execute(total_stmt)
            total_count = total_result.scalar() or 0

            # Count unique emails
            unique_stmt = select(
                func.count(func.distinct(FeedbackRecord.email_id))
            )
            unique_result = await session.execute(unique_stmt)
            unique_count = unique_result.scalar() or 0

            # Get all feedback
            all_stmt = select(FeedbackRecord)
            all_result = await session.execute(all_stmt)
            all_records = all_result.scalars().all()

            false_positives = 0
            false_negatives = 0
            correct_verdicts = 0

            for record in all_records:
                original_severity = _verdict_to_severity(
                    record.original_verdict
                )
                correct_severity = _verdict_to_severity(record.correct_label)

                if original_severity == correct_severity:
                    correct_verdicts += 1
                elif original_severity > correct_severity:
                    false_positives += 1
                else:
                    false_negatives += 1

            # Calculate metrics
            total_errors = false_positives + false_negatives
            if total_errors == 0:
                precision = recall = f1 = 1.0
            else:
                # Assume pipeline made predictions
                # TP = correct verdicts, FP = false positives, FN = false negatives
                tp = correct_verdicts
                fp = false_positives
                fn = false_negatives

                precision = (
                    tp / (tp + fp) if (tp + fp) > 0 else 0.0
                )
                recall = (
                    tp / (tp + fn) if (tp + fn) > 0 else 0.0
                )
                f1 = (
                    2 * (precision * recall) / (precision + recall)
                    if (precision + recall) > 0
                    else 0.0
                )

            return StatsResponse(
                total_feedback_records=total_count,
                total_unique_emails=unique_count,
                false_positives=false_positives,
                false_negatives=false_negatives,
                correct_verdicts=correct_verdicts,
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1_score=round(f1, 4),
                last_updated=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Error calculating stats: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to calculate statistics",
            )

    @app.get("/api/v1/feedback/export")
    async def export_feedback(
        format: str = Query("csv", regex="^(csv|jsonl)$"),
        token: str = Depends(verify_bearer_token),
        session: AsyncSession = Depends(get_db_session),
    ):
        """
        Export feedback records in CSV or JSONL format.

        Args:
            format: Export format (csv or jsonl)
            token: Bearer token
            session: Database session

        Returns:
            Streamed file response
        """
        check_rate_limit(token)

        try:
            stmt = select(FeedbackRecord).order_by(
                desc(FeedbackRecord.submitted_at)
            )
            result = await session.execute(stmt)
            records = result.scalars().all()

            if format == "csv":
                return _export_csv(records)
            else:  # jsonl
                return _export_jsonl(records)

        except Exception as e:
            logger.error(f"Error exporting feedback: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to export feedback",
            )

    @app.post("/api/v1/retrain", response_model=RetrainResponse)
    async def trigger_retrain(
        token: str = Depends(verify_bearer_token),
        session: AsyncSession = Depends(get_db_session),
    ) -> RetrainResponse:
        """
        Manually trigger retraining.

        Args:
            token: Bearer token (used as triggered_by identifier)
            session: Database session

        Returns:
            Retrain result
        """
        check_rate_limit(token)

        try:
            orchestrator = app.state.orchestrator
            result = await orchestrator.run_full_retrain(
                session, triggered_by="manual_api"
            )

            if result["status"] == "completed":
                return RetrainResponse(
                    run_id=result["run_id"],
                    status="completed",
                    feedback_count=result["feedback_count"],
                    weights_updated=result["weights_updated"],
                    new_weights=result.get("new_weights"),
                    message="Retraining completed successfully",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Retraining failed: {result.get('error')}",
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error triggering retrain: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to trigger retraining",
            )

    @app.get("/api/v1/retrain/history")
    async def get_retrain_history(
        limit: int = Query(10, ge=1, le=100),
        token: str = Depends(verify_bearer_token),
    ) -> list[dict]:
        """
        Get history of retraining runs.

        Args:
            limit: Maximum number of runs to return
            token: Bearer token

        Returns:
            List of retrain run records
        """
        check_rate_limit(token)

        if app.state.scheduler:
            return await app.state.scheduler.get_retrain_history(limit)
        return []

    @app.get("/api/v1/retrain/gap-analysis")
    async def get_gap_analysis(
        token: str = Depends(verify_bearer_token),
        session: AsyncSession = Depends(get_db_session),
    ) -> list[GapAnalysisResponse]:
        """
        Identify systematic weaknesses per analyzer.

        Returns:
            Sorted list of analyzer gaps (highest impact first)
        """
        check_rate_limit(token)

        try:
            orchestrator = app.state.orchestrator
            gaps = await orchestrator.get_gap_analysis(session)

            response = [
                GapAnalysisResponse(
                    analyzer=name,
                    false_negatives=stats["false_negatives"],
                    false_positives=stats["false_positives"],
                    total_errors=stats["total_errors"],
                    fn_percentage=stats.get("fn_percentage", 0.0),
                    fp_percentage=stats.get("fp_percentage", 0.0),
                    high_confidence_errors=stats.get(
                        "high_confidence_errors", 0
                    ),
                )
                for name, stats in gaps.items()
            ]

            # Sort by total errors (descending)
            response.sort(key=lambda x: x.total_errors, reverse=True)
            return response

        except Exception as e:
            logger.error(f"Error in gap analysis: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to perform gap analysis",
            )

    return app


def _verdict_to_severity(verdict: str) -> int:
    """
    Convert verdict string to numeric severity.

    Args:
        verdict: Verdict value as string

    Returns:
        Severity 0-3
    """
    severity_map = {
        Verdict.CLEAN.value: 0,
        Verdict.SUSPICIOUS.value: 1,
        Verdict.LIKELY_PHISHING.value: 2,
        Verdict.CONFIRMED_PHISHING.value: 3,
    }
    return severity_map.get(verdict, 1)


def _export_csv(records: list) -> StreamingResponse:
    """
    Export records as CSV.

    Args:
        records: List of FeedbackRecord objects

    Returns:
        StreamingResponse with CSV data
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "email_id",
            "original_verdict",
            "correct_label",
            "analyst_notes",
            "submitted_at",
        ]
    )

    # Rows
    for record in records:
        writer.writerow(
            [
                record.email_id,
                record.original_verdict,
                record.correct_label,
                record.analyst_notes or "",
                record.submitted_at.isoformat(),
            ]
        )

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=feedback_records.csv"
        },
    )


def _export_jsonl(records: list) -> StreamingResponse:
    """
    Export records as JSONL.

    Args:
        records: List of FeedbackRecord objects

    Returns:
        StreamingResponse with JSONL data
    """
    def generate():
        for record in records:
            obj = {
                "email_id": record.email_id,
                "original_verdict": record.original_verdict,
                "correct_label": record.correct_label,
                "analyst_notes": record.analyst_notes,
                "submitted_at": record.submitted_at.isoformat(),
            }
            yield json.dumps(obj) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": "attachment; filename=feedback_records.jsonl"
        },
    )

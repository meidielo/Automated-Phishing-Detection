"""
SQLAlchemy async database setup for feedback loop persistence.

This module provides:
- Async session factory
- Table schemas for feedback, pipeline results, and block/allowlists
- Migration support via Alembic
"""
import logging
from typing import AsyncGenerator

from sqlalchemy import Column, DateTime, Index, Integer, String, Text, create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

logger = logging.getLogger(__name__)

Base = declarative_base()


class FeedbackRecord(Base):
    """
    Stores analyst corrections and feedback on pipeline verdicts.

    Attributes:
        id: Primary key
        email_id: Reference to analyzed email
        original_verdict: Pipeline's original classification
        correct_label: Analyst's correction
        analyst_notes: Why analyst disagreed
        feature_vector: JSON dict of features used in original prediction
        submitted_at: Timestamp of feedback submission
    """

    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String(255), nullable=False, index=True)
    original_verdict = Column(String(50), nullable=False)
    correct_label = Column(String(50), nullable=False)
    analyst_notes = Column(Text, nullable=True)
    feature_vector = Column(Text, nullable=True)  # JSON serialized
    submitted_at = Column(DateTime, nullable=False, index=True)

    __table_args__ = (
        Index("idx_feedback_email_verdict", "email_id", "original_verdict"),
        Index("idx_feedback_submitted", "submitted_at"),
    )


class PipelineResult(Base):
    """
    Snapshot of pipeline analysis results for later comparison.

    Attributes:
        id: Primary key
        email_id: Reference to analyzed email
        result_json: Full PipelineResult serialized as JSON
        analyzed_at: When analysis was performed
    """

    __tablename__ = "pipeline_results"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String(255), nullable=False, unique=True, index=True)
    result_json = Column(Text, nullable=False)  # JSON serialized PipelineResult
    analyzed_at = Column(DateTime, nullable=False, index=True)

    __table_args__ = (Index("idx_pipeline_analyzed", "analyzed_at"),)


class LocalBlocklist(Base):
    """
    Local blocklist built from false negatives (missed phishing).

    When analysts correct a false negative, we add indicators to this list.

    Attributes:
        id: Primary key
        indicator: Email, domain, URL, IP, hash, etc.
        indicator_type: Type of indicator (email, domain, url, ip, hash)
        added_by: Analyst username or "system"
        added_at: When indicator was added
        reason: Optional justification
    """

    __tablename__ = "local_blocklist"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)
    added_by = Column(String(100), nullable=False)
    added_at = Column(DateTime, nullable=False, index=True)
    reason = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_blocklist_indicator", "indicator", "indicator_type"),
        Index("idx_blocklist_added", "added_at"),
    )


class LocalAllowlist(Base):
    """
    Local allowlist built from false positives (incorrectly flagged legitimate emails).

    When analysts correct a false positive, we add indicators to this list.

    Attributes:
        id: Primary key
        indicator: Email, domain, URL, IP, hash, etc.
        indicator_type: Type of indicator
        added_by: Analyst username or "system"
        added_at: When indicator was added
        reason: Optional justification
    """

    __tablename__ = "local_allowlist"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)
    added_by = Column(String(100), nullable=False)
    added_at = Column(DateTime, nullable=False, index=True)
    reason = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_allowlist_indicator", "indicator", "indicator_type"),
        Index("idx_allowlist_added", "added_at"),
    )


class RetrainRun(Base):
    """
    Log of retraining events for audit and performance tracking.

    Attributes:
        id: Primary key
        run_id: Unique identifier for this retraining run
        triggered_by: "scheduled" or analyst username
        feedback_records_used: Count of feedback records in training set
        model_improvement: % change in F1 score (can be negative)
        started_at: When retraining began
        completed_at: When retraining finished
        status: "pending", "in_progress", "completed", "failed"
        error_message: If status is "failed"
    """

    __tablename__ = "retrain_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(100), nullable=False, unique=True, index=True)
    triggered_by = Column(String(100), nullable=False)
    feedback_records_used = Column(Integer, default=0)
    model_improvement = Column(String(50), nullable=True)  # e.g., "+2.3%"
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False, index=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (Index("idx_retrain_status", "status"),)


class DatabaseManager:
    """
    High-level async database manager for feedback loop.

    Provides:
    - Async engine and session factory
    - Table creation
    - Session context managers
    """

    def __init__(self, database_url: str, echo: bool = False) -> None:
        """
        Initialize async database manager.

        Args:
            database_url: SQLAlchemy async database URL (e.g., sqlite+aiosqlite:///)
            echo: Whether to log SQL statements
        """
        self.database_url = database_url
        self.echo = echo
        self.engine = None
        self.async_session_maker = None

    async def initialize(self) -> None:
        """
        Create engine and session factory. Must be called before use.

        Raises:
            RuntimeError: If already initialized
        """
        if self.engine is not None:
            raise RuntimeError("DatabaseManager already initialized")

        self.engine = create_async_engine(
            self.database_url,
            echo=self.echo,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self.async_session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info(f"Database initialized: {self.database_url}")

    async def create_tables(self) -> None:
        """
        Create all tables if they don't exist.

        Raises:
            RuntimeError: If not initialized
        """
        if self.engine is None:
            raise RuntimeError("DatabaseManager not initialized")

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created or verified")

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Async context manager for database sessions.

        Usage:
            async with db_manager.get_session() as session:
                result = await session.execute(query)

        Yields:
            AsyncSession: Database session

        Raises:
            RuntimeError: If not initialized
        """
        if self.async_session_maker is None:
            raise RuntimeError("DatabaseManager not initialized")

        async with self.async_session_maker() as session:
            yield session

    async def close(self) -> None:
        """Close database engine and cleanup."""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database engine closed")


def create_sqlite_url(db_path: str) -> str:
    """
    Create async SQLite connection URL.

    Args:
        db_path: Path to SQLite database file

    Returns:
        Async SQLite URL string for SQLAlchemy
    """
    # Ensure parent directory exists
    import os

    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    return f"sqlite+aiosqlite:///{db_path}"

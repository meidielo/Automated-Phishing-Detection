"""
Feedback loop and retraining system for the phishing detection pipeline.

Modules:
- database: SQLAlchemy async database setup
- retrainer: Weight retraining and gap analysis
- scheduler: Background retraining scheduler
- feedback_api: FastAPI REST endpoints

Main components to import:
- DatabaseManager: Database initialization and session management
- RetrainOrchestrator: Retraining execution orchestration
- RetrainScheduler: Background automatic retraining
- create_app: FastAPI application factory
"""

from src.feedback.database import (
    DatabaseManager,
    FeedbackRecord,
    LocalAllowlist,
    LocalBlocklist,
    PipelineResult,
    RetrainRun,
    create_sqlite_url,
)
from src.feedback.feedback_api import (
    FeedbackResponse,
    FeedbackSubmissionRequest,
    HealthResponse,
    StatsResponse,
    create_app,
)
from src.feedback.retrainer import (
    IntentClassifierRetrainer,
    RetrainOrchestrator,
    WeightRetainer,
)
from src.feedback.scheduler import RetrainScheduler

__all__ = [
    # Database
    "DatabaseManager",
    "FeedbackRecord",
    "LocalAllowlist",
    "LocalBlocklist",
    "PipelineResult",
    "RetrainRun",
    "create_sqlite_url",
    # Retraining
    "RetrainOrchestrator",
    "WeightRetainer",
    "IntentClassifierRetrainer",
    # Scheduler
    "RetrainScheduler",
    # API
    "create_app",
    "FeedbackSubmissionRequest",
    "FeedbackResponse",
    "StatsResponse",
    "HealthResponse",
]

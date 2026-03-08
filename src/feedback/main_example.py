"""
Example main application demonstrating the complete feedback loop system.

This shows how to:
1. Initialize the database
2. Start the retraining scheduler
3. Create and run the FastAPI server
4. Handle graceful shutdown
"""
import asyncio
import logging
import os
import signal
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.config import PipelineConfig
from src.feedback import (
    DatabaseManager,
    RetrainScheduler,
    create_app,
    create_sqlite_url,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Global references for shutdown handling
_scheduler: RetrainScheduler = None
_db_manager: DatabaseManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager for startup/shutdown.

    Initializes database and scheduler on startup,
    gracefully shuts down on application exit.
    """
    global _scheduler, _db_manager

    # Startup
    logger.info("Starting phishing detection feedback API...")

    try:
        # Load configuration from environment
        config = PipelineConfig.from_env()

        # Validate required config
        if not config.analyst_api_token:
            raise ValueError(
                "ANALYST_API_TOKEN environment variable not set"
            )

        logger.info(f"Using database: {config.feedback_db_path}")

        # Initialize database
        db_url = create_sqlite_url(config.feedback_db_path)
        _db_manager = DatabaseManager(db_url, echo=False)

        await _db_manager.initialize()
        await _db_manager.create_tables()
        logger.info("Database initialized and tables created")

        # Initialize and start scheduler
        _scheduler = RetrainScheduler(
            config,
            _db_manager,
            check_interval_hours=24,
        )
        await _scheduler.start()
        logger.info("Retraining scheduler started")

        # Create FastAPI app
        app.state.feedback_app = create_app(config, _db_manager, _scheduler)
        logger.info("Feedback API app created")

        logger.info("Startup complete. API is ready.")

    except Exception as e:
        logger.error(f"Failed to start application: {e}", exc_info=True)
        raise

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down...")

    try:
        if _scheduler:
            await _scheduler.stop()
            logger.info("Scheduler stopped")

        if _db_manager:
            await _db_manager.close()
            logger.info("Database closed")

        logger.info("Shutdown complete")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)


def create_main_app() -> FastAPI:
    """
    Create the main FastAPI application with lifespan management.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Phishing Detection Feedback API",
        description=(
            "Feedback loop and retraining system for "
            "automated phishing detection"
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    # Mount feedback endpoints
    @app.on_event("startup")
    async def startup():
        """Mount feedback sub-app after main app starts."""
        # This will be populated during lifespan startup
        pass

    # Root endpoint
    @app.get("/", tags=["System"])
    async def root():
        """Root endpoint with API information."""
        return {
            "name": "Phishing Detection Feedback API",
            "version": "1.0.0",
            "endpoints": {
                "health": "/api/v1/health",
                "feedback": {
                    "submit": "POST /api/v1/feedback",
                    "stats": "GET /api/v1/feedback/stats",
                    "export": "GET /api/v1/feedback/export",
                },
                "retrain": {
                    "trigger": "POST /api/v1/retrain",
                    "history": "GET /api/v1/retrain/history",
                    "gap_analysis": "GET /api/v1/retrain/gap-analysis",
                },
            },
            "docs": "/docs",
            "openapi_schema": "/openapi.json",
        }

    # Include feedback sub-app endpoints
    # (in lifespan, the feedback app is created with all endpoints)
    # For simplicity, we'll add them directly here by including the feedback app

    @app.get("/api/v1/health", tags=["System"])
    async def health():
        """Health check - delegates to feedback app."""
        from src.feedback import DatabaseManager

        try:
            if _db_manager:
                async with _db_manager.async_session_maker() as session:
                    await session.execute("SELECT 1")
                db_ok = True
            else:
                db_ok = False

            scheduler_ok = _scheduler.is_running if _scheduler else False

            return {
                "status": "healthy" if db_ok and scheduler_ok else "degraded",
                "database": "ok" if db_ok else "error",
                "scheduler": "running" if scheduler_ok else "stopped",
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }

    return app


# Create application instance
app = create_main_app()


if __name__ == "__main__":
    """
    Run the application with uvicorn.

    Usage:
        python -m src.feedback.main_example

    Environment variables:
        ANALYST_API_TOKEN: Bearer token for API authentication (required)
        FEEDBACK_DB_PATH: Path to SQLite database (default: data/feedback.db)
        LOG_LEVEL: Logging level (default: INFO)
        DASHBOARD_PORT: Port to run on (default: 8000)
    """
    import uvicorn

    # Get port from config or use default
    port = int(os.getenv("DASHBOARD_PORT", "8000"))
    host = os.getenv("FEEDBACK_API_HOST", "0.0.0.0")

    logger.info(f"Starting server on {host}:{port}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )

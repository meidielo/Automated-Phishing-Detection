"""
FastAPI dashboard for phishing detection system.
Provides web interface for analysis review, statistics, and result details.
"""
import logging
from datetime import datetime, timedelta
from html import escape
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from src.models import PipelineResult, Verdict


logger = logging.getLogger(__name__)

DASHBOARD_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: blob:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "frame-src 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class PhishingDashboard:
    """Dashboard service providing web routes and statistics."""

    def __init__(self, template_dir: Optional[str] = None, storage_backend=None):
        """
        Initialize dashboard.

        Args:
            template_dir: Directory containing Jinja2 templates.
            storage_backend: Backend for storing/retrieving analysis results.
        """
        if template_dir is None:
            template_dir = "./templates"

        try:
            self.env = Environment(loader=FileSystemLoader(template_dir))
        except Exception as e:
            logger.warning(f"Could not load templates from {template_dir}: {e}")
            self.env = None

        self.storage = storage_backend
        self.router = APIRouter(prefix="/dashboard", tags=["dashboard"])
        self._register_routes()

    def _register_routes(self):
        """Register all dashboard routes."""
        self.router.get("")(self.get_dashboard)
        self.router.get("/")(self.get_dashboard)
        self.router.get("/stats")(self.get_stats)
        self.router.get("/email/{email_id}")(self.get_email_detail)
        self.router.get("/api/pending")(self.api_pending_reviews)
        self.router.get("/api/stats")(self.api_stats)

    async def get_dashboard(self) -> HTMLResponse:
        """
        GET /dashboard
        Main dashboard page.  All data loads client-side via fetch(),
        so there is nothing to template-render server-side.  We serve
        the file directly (same pattern as every other page) so Jinja2
        cannot misinterpret JS template-literals or CSS as Jinja tags.
        SharedHTMLMiddleware injects _shared.html (auth + theme) on the
        way out.
        """
        from pathlib import Path
        dashboard_path = Path(self.env.loader.searchpath[0]) / "dashboard.html" if self.env else None
        if dashboard_path and dashboard_path.exists():
            return HTMLResponse(
                content=dashboard_path.read_text(encoding="utf-8"),
                headers={"Content-Security-Policy": DASHBOARD_CSP},
            )
        return HTMLResponse(
            content=self._generate_fallback_dashboard(),
            headers={"Content-Security-Policy": DASHBOARD_CSP},
        )

    async def get_stats(self) -> HTMLResponse:
        """
        GET /dashboard/stats
        Dashboard page showing verdict distribution and statistics.

        Returns:
            HTMLResponse with statistics visualization.
        """
        # Fetch statistics from storage
        stats = {
            "total_emails": 0,
            "verdict_distribution": {
                "CLEAN": 0,
                "SUSPICIOUS": 0,
                "LIKELY_PHISHING": 0,
                "CONFIRMED_PHISHING": 0,
            },
            "average_score": 0.0,
            "emails_last_24h": 0,
        }

        if self.storage:
            try:
                stats = await self.storage.get_statistics()
            except Exception as e:
                logger.error(f"Error fetching statistics: {e}")

        return HTMLResponse(
            content=self._generate_stats_page(stats),
            headers={"Content-Security-Policy": DASHBOARD_CSP},
        )

    async def get_email_detail(self, email_id: str) -> str:
        """
        GET /dashboard/email/{email_id}
        Detailed analysis view for a specific email.

        Args:
            email_id: Email ID to display details for.

        Returns:
            HTML string with detailed analysis.
        """
        if not self.storage:
            raise HTTPException(status_code=503, detail="Storage backend not configured")

        try:
            result = await self.storage.get_result(email_id)
        except Exception as e:
            logger.error(f"Error fetching result for {email_id}: {e}")
            raise HTTPException(status_code=404, detail="Analysis result not found")

        if result is None:
            raise HTTPException(status_code=404, detail="Analysis result not found")

        # Generate HTML from result
        return HTMLResponse(
            content=self._generate_email_detail_page(result),
            headers={"Content-Security-Policy": DASHBOARD_CSP},
        )

    async def api_pending_reviews(self, limit: int = Query(50, ge=1, le=1000)) -> dict:
        """
        GET /dashboard/api/pending
        API endpoint returning pending reviews as JSON.

        Args:
            limit: Maximum number of pending items to return.

        Returns:
            JSON with pending review queue.
        """
        if not self.storage:
            return {"pending": [], "count": 0}

        try:
            pending = await self.storage.get_pending_reviews(limit=limit)
            return {
                "pending": [
                    {
                        "email_id": p.email_id,
                        "verdict": p.verdict.value,
                        "score": p.overall_score,
                        "timestamp": p.timestamp.isoformat(),
                    }
                    for p in pending
                ],
                "count": len(pending),
            }
        except Exception as e:
            logger.error(f"Error fetching pending reviews: {e}")
            return {"pending": [], "count": 0, "error": str(e)}

    async def api_stats(self) -> dict:
        """
        GET /dashboard/api/stats
        API endpoint returning statistics as JSON.

        Returns:
            JSON with verdict distribution and metrics.
        """
        if not self.storage:
            return {
                "total_emails": 0,
                "verdict_distribution": {},
                "average_score": 0.0,
            }

        try:
            stats = await self.storage.get_statistics()
            return stats
        except Exception as e:
            logger.error(f"Error fetching statistics: {e}")
            return {
                "error": str(e),
                "total_emails": 0,
                "verdict_distribution": {},
            }

    def _generate_fallback_dashboard(self) -> str:
        """Generate simple fallback dashboard HTML."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Detection Dashboard</title>
            <link rel="stylesheet" href="/static/dashboard-report.css">
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Phishing Detection Dashboard</h1>
                    <p>Real-time email analysis and threat intelligence</p>
                </div>

                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-label">Clean</div>
                        <div class="stat-number verdict-clean">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Suspicious</div>
                        <div class="stat-number verdict-suspicious">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Likely Phishing</div>
                        <div class="stat-number verdict-likely-phishing">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Confirmed Phishing</div>
                        <div class="stat-number verdict-confirmed-phishing">0</div>
                    </div>
                </div>

                <div class="pending-queue">
                    <h2>Pending Review Queue</h2>
                    <div class="no-data">
                        <p>No pending reviews at this time.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

    def _generate_stats_page(self, stats: dict) -> str:
        """Generate statistics page HTML."""
        verdict_dist = stats.get("verdict_distribution", {})

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Analysis Statistics</title>
            <link rel="stylesheet" href="/static/dashboard-report.css">
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Analysis Statistics</h1>
                    <p>Verdict distribution over time</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-box">
                        <h3>Total Emails Analyzed</h3>
                        <div class="metric-number">{stats.get('total_emails', 0)}</div>
                    </div>

                    <div class="stat-box">
                        <h3>Average Phishing Score</h3>
                        <div class="metric-number">{stats.get('average_score', 0):.3f}</div>
                    </div>

                    <div class="stat-box">
                        <h3>Verdict Distribution</h3>
                        {self._generate_verdict_bars(verdict_dist)}
                    </div>

                    <div class="stat-box">
                        <h3>Emails (Last 24h)</h3>
                        <div class="metric-number">{stats.get('emails_last_24h', 0)}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_email_detail_page(self, result: PipelineResult) -> str:
        """Generate detailed email analysis page HTML."""
        safe_email_id = escape(result.email_id)
        safe_reasoning = escape(result.reasoning)
        verdict_class = self._verdict_class(result.verdict)
        score_value = self._percent(result.overall_score)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Analysis - {safe_email_id}</title>
            <link rel="stylesheet" href="/static/dashboard-report.css">
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Email Analysis Details</h1>
                    <p>Email ID: <strong>{safe_email_id}</strong></p>
                    <div class="verdict-badge {verdict_class}">
                        {escape(result.verdict.value)}
                    </div>
                </div>

                <div class="section">
                    <h2>Score Breakdown</h2>
                    <p><strong>Overall Score:</strong> {result.overall_score:.3f}</p>
                    <progress class="report-progress score-progress" max="100" value="{score_value}"></progress>
                    <p><strong>Confidence:</strong> {result.overall_confidence:.3f}</p>
                </div>

                <div class="section">
                    <h2>Analyzer Results</h2>
                    {self._generate_analyzer_results_html(result)}
                </div>

                <div class="section">
                    <h2>Reasoning</h2>
                    <p>{safe_reasoning}</p>
                </div>

                <div class="section">
                    <h2>Analysis Metadata</h2>
                    <p><strong>Timestamp:</strong> {result.timestamp.isoformat()}</p>
                    <p><strong>Number of URLs:</strong> {len(result.extracted_urls)}</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html

    @staticmethod
    def _percent(value: float) -> int:
        """Return a clamped integer percentage for HTML progress elements."""
        return max(0, min(100, int(round(value * 100))))

    @staticmethod
    def _verdict_class(verdict: Verdict | str) -> str:
        """Map verdict names to CSS classes without emitting inline styles."""
        value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
        classes = {
            "CLEAN": "verdict-clean",
            "SUSPICIOUS": "verdict-suspicious",
            "LIKELY_PHISHING": "verdict-likely-phishing",
            "CONFIRMED_PHISHING": "verdict-confirmed-phishing",
        }
        return classes.get(value, "verdict-unknown")

    @staticmethod
    def _generate_verdict_bars(verdict_dist: dict) -> str:
        """Generate HTML for verdict distribution bars."""
        total = sum(verdict_dist.values()) or 1
        html = ""

        for verdict, count in verdict_dist.items():
            percentage = max(0, min(100, int(round((count / total) * 100))))
            verdict_class = PhishingDashboard._verdict_class(str(verdict))
            safe_verdict = escape(str(verdict))
            html += f"""
            <div class="bar-row">
                <div>{safe_verdict}: {count}</div>
                <progress class="report-progress {verdict_class}" max="100" value="{percentage}"></progress>
            </div>
            """

        return html

    @staticmethod
    def _generate_analyzer_results_html(result: PipelineResult) -> str:
        """Generate HTML for analyzer results breakdown."""
        html = ""
        for analyzer_name, analyzer_result in result.analyzer_results.items():
            bar_width = PhishingDashboard._percent(analyzer_result.risk_score)
            safe_analyzer_name = escape(analyzer_name)
            html += f"""
            <div class="analyzer-result">
                <strong>{safe_analyzer_name}</strong><br>
                Score: {analyzer_result.risk_score:.3f} | Confidence: {analyzer_result.confidence:.3f}
                <progress class="report-progress score-progress" max="100" value="{bar_width}"></progress>
            </div>
            """

        return html

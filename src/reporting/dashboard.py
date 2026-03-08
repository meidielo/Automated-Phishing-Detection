"""
FastAPI dashboard for phishing detection system.
Provides web interface for analysis review, statistics, and result details.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from src.models import PipelineResult, Verdict


logger = logging.getLogger(__name__)


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
        self.router.get("/")(self.get_dashboard)
        self.router.get("/stats")(self.get_stats)
        self.router.get("/email/{email_id}")(self.get_email_detail)
        self.router.get("/api/pending")(self.api_pending_reviews)
        self.router.get("/api/stats")(self.api_stats)

    async def get_dashboard(self) -> str:
        """
        GET /dashboard
        Main dashboard page showing pending review queue.

        Returns:
            HTML string for dashboard main page.
        """
        try:
            template = self.env.get_template("dashboard.html") if self.env else None
        except TemplateNotFound:
            template = None

        if template is None:
            return self._generate_fallback_dashboard()

        # Fetch pending reviews from storage
        pending = []
        if self.storage:
            try:
                pending = await self.storage.get_pending_reviews(limit=50)
            except Exception as e:
                logger.error(f"Error fetching pending reviews: {e}")

        context = {
            "page_title": "Phishing Detection Dashboard",
            "pending_count": len(pending),
            "pending_reviews": pending,
            "current_time": datetime.utcnow().isoformat(),
        }

        return template.render(context)

    async def get_stats(self) -> str:
        """
        GET /dashboard/stats
        Dashboard page showing verdict distribution and statistics.

        Returns:
            HTML string with statistics visualization.
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

        # Generate HTML
        return self._generate_stats_page(stats)

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
        return self._generate_email_detail_page(result)

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
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
                .stat-card { background-color: white; padding: 20px; border-radius: 5px; text-align: center; }
                .stat-number { font-size: 32px; font-weight: bold; margin: 10px 0; }
                .stat-label { color: #666; }
                .pending-queue { background-color: white; padding: 20px; border-radius: 5px; }
                .no-data { color: #999; text-align: center; padding: 40px; }
            </style>
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
                        <div class="stat-number" style="color: #28a745;">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Suspicious</div>
                        <div class="stat-number" style="color: #ffc107;">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Likely Phishing</div>
                        <div class="stat-number" style="color: #fd7e14;">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Confirmed Phishing</div>
                        <div class="stat-number" style="color: #dc3545;">0</div>
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
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 20px 0; }}
                .stat-box {{ background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stat-box h3 {{ margin: 0 0 10px 0; color: #2c3e50; }}
                .bar {{ background-color: #e9ecef; height: 30px; border-radius: 3px; margin: 10px 0; overflow: hidden; }}
                .bar-fill {{ height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }}
            </style>
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
                        <div style="font-size: 28px; font-weight: bold;">{stats.get('total_emails', 0)}</div>
                    </div>

                    <div class="stat-box">
                        <h3>Average Phishing Score</h3>
                        <div style="font-size: 28px; font-weight: bold;">{stats.get('average_score', 0):.3f}</div>
                    </div>

                    <div class="stat-box">
                        <h3>Verdict Distribution</h3>
                        {self._generate_verdict_bars(verdict_dist)}
                    </div>

                    <div class="stat-box">
                        <h3>Emails (Last 24h)</h3>
                        <div style="font-size: 28px; font-weight: bold;">{stats.get('emails_last_24h', 0)}</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_email_detail_page(self, result: PipelineResult) -> str:
        """Generate detailed email analysis page HTML."""
        verdict_colors = {
            Verdict.CLEAN: "#28a745",
            Verdict.SUSPICIOUS: "#ffc107",
            Verdict.LIKELY_PHISHING: "#fd7e14",
            Verdict.CONFIRMED_PHISHING: "#dc3545",
        }

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Analysis - {result.email_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .verdict {{ font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 3px; display: inline-block; }}
                .section {{ background-color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .analyzer-result {{ padding: 10px; margin: 10px 0; background-color: #f8f9fa; border-left: 4px solid #0d6efd; }}
                .score-bar {{ background-color: #e9ecef; height: 20px; border-radius: 3px; overflow: hidden; }}
                .score-fill {{ height: 100%; background-color: #0d6efd; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Email Analysis Details</h1>
                    <p>Email ID: <strong>{result.email_id}</strong></p>
                    <div class="verdict" style="background-color: {verdict_colors.get(result.verdict, '#999')};">
                        {result.verdict.value}
                    </div>
                </div>

                <div class="section">
                    <h2>Score Breakdown</h2>
                    <p><strong>Overall Score:</strong> {result.overall_score:.3f}</p>
                    <div class="score-bar">
                        <div class="score-fill" style="width: {result.overall_score * 100}%"></div>
                    </div>
                    <p><strong>Confidence:</strong> {result.overall_confidence:.3f}</p>
                </div>

                <div class="section">
                    <h2>Analyzer Results</h2>
                    {self._generate_analyzer_results_html(result)}
                </div>

                <div class="section">
                    <h2>Reasoning</h2>
                    <p>{result.reasoning}</p>
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
    def _generate_verdict_bars(verdict_dist: dict) -> str:
        """Generate HTML for verdict distribution bars."""
        colors = {
            "CLEAN": "#28a745",
            "SUSPICIOUS": "#ffc107",
            "LIKELY_PHISHING": "#fd7e14",
            "CONFIRMED_PHISHING": "#dc3545",
        }

        total = sum(verdict_dist.values()) or 1
        html = ""

        for verdict, count in verdict_dist.items():
            percentage = (count / total) * 100
            color = colors.get(verdict, "#999")
            html += f"""
            <div style="margin: 10px 0;">
                <div>{verdict}: {count}</div>
                <div class="bar">
                    <div class="bar-fill" style="width: {percentage}%; background-color: {color};"></div>
                </div>
            </div>
            """

        return html

    @staticmethod
    def _generate_analyzer_results_html(result: PipelineResult) -> str:
        """Generate HTML for analyzer results breakdown."""
        html = ""
        for analyzer_name, analyzer_result in result.analyzer_results.items():
            bar_width = int(analyzer_result.risk_score * 100)
            html += f"""
            <div class="analyzer-result">
                <strong>{analyzer_name}</strong><br>
                Score: {analyzer_result.risk_score:.3f} | Confidence: {analyzer_result.confidence:.3f}
                <div class="score-bar" style="margin-top: 5px;">
                    <div class="score-fill" style="width: {bar_width}%"></div>
                </div>
            </div>
            """

        return html

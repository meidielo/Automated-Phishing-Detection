#!/usr/bin/env python3
"""
Main entry point for phishing detection system.

Supports two modes:
1. CLI: python main.py --analyze <email.eml>
2. Server: python main.py --serve (starts FastAPI dashboard and API)
"""
import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse
from uvicorn import run

from src.config import PipelineConfig
from src.models import EmailObject
from src.orchestrator.pipeline import PhishingPipeline
from src.reporting.report_generator import ReportGenerator
from src.reporting.ioc_exporter import IOCExporter
from src.reporting.dashboard import PhishingDashboard


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class PhishingDetectionApp:
    """Main application orchestrator."""

    def __init__(self):
        """Initialize application."""
        self.config = PipelineConfig.from_env()
        self.pipeline = PhishingPipeline.from_config(self.config)
        self.report_gen = ReportGenerator(template_dir="./templates")
        self.ioc_exporter = IOCExporter()
        self.dashboard = PhishingDashboard(template_dir="./templates")

    async def analyze_email_file(self, email_path: str, output_format: str = "json"):
        """
        Analyze email from EML file.

        Args:
            email_path: Path to .eml file.
            output_format: Output format (json, html, stix, all).

        Returns:
            Analysis result in specified format.
        """
        email_path = Path(email_path)
        if not email_path.exists():
            logger.error(f"Email file not found: {email_path}")
            return None

        try:
            # Parse email
            from src.extractors.eml_parser import EMLParser
            parser = EMLParser()
            email = await parser.parse_file(str(email_path))

            # Analyze
            logger.info(f"Analyzing email from {email_path}")
            result = await self.pipeline.analyze(email)

            # Generate outputs
            outputs = {}

            if output_format in ["json", "all"]:
                outputs["json"] = self.report_gen.generate_json(result)
                logger.info("Generated JSON report")

            if output_format in ["html", "all"]:
                try:
                    outputs["html"] = self.report_gen.generate_human_readable(result)
                    logger.info("Generated HTML report")
                except Exception as e:
                    logger.warning(f"Could not generate HTML report: {e}")

            if output_format in ["stix", "all"]:
                outputs["stix"] = self.ioc_exporter.export_stix(result)
                logger.info("Generated STIX 2.1 bundle")

            # Display results
            if output_format == "json":
                import json
                print(json.dumps(outputs["json"], indent=2))
            elif output_format == "html":
                print(outputs.get("html", "No HTML output available"))
            elif output_format == "stix":
                print(outputs.get("stix", "No STIX output available"))
            elif output_format == "all":
                # Save all outputs to files
                email_id = email.email_id
                json_path = f"{email_id}_report.json"
                html_path = f"{email_id}_report.html"
                stix_path = f"{email_id}_iocs.json"

                import json
                if "json" in outputs:
                    with open(json_path, "w") as f:
                        json.dump(outputs["json"], f, indent=2)
                    logger.info(f"Wrote JSON report to {json_path}")

                if "html" in outputs:
                    with open(html_path, "w") as f:
                        f.write(outputs["html"])
                    logger.info(f"Wrote HTML report to {html_path}")

                if "stix" in outputs:
                    with open(stix_path, "w") as f:
                        f.write(outputs["stix"])
                    logger.info(f"Wrote STIX bundle to {stix_path}")

                print(f"Analysis complete. Reports saved to:")
                if "json" in outputs:
                    print(f"  - {json_path}")
                if "html" in outputs:
                    print(f"  - {html_path}")
                if "stix" in outputs:
                    print(f"  - {stix_path}")

        except Exception as e:
            logger.error(f"Error analyzing email: {e}", exc_info=True)
            return None

    def create_fastapi_app(self) -> FastAPI:
        """
        Create FastAPI application.

        Returns:
            FastAPI app with analysis and dashboard routes.
        """
        app = FastAPI(
            title="Phishing Detection System",
            description="Automated phishing detection and analysis API",
            version="1.0.0",
        )

        @app.get("/", response_class=HTMLResponse)
        async def index():
            """Serve the main upload/analyze page."""
            index_path = Path("./templates/index.html")
            return HTMLResponse(content=index_path.read_text(encoding="utf-8"))

        @app.post("/api/analyze/upload")
        async def analyze_upload(file: UploadFile = File(...)):
            """
            Analyze an uploaded .eml file.

            Returns:
                Analysis result with verdict, scores, and IOCs.
            """
            try:
                raw = await file.read()
                if not raw:
                    raise HTTPException(status_code=400, detail="Empty file uploaded")

                from src.extractors.eml_parser import EMLParser
                parser = EMLParser()
                email = parser.parse_bytes(raw)
                if email is None:
                    raise HTTPException(status_code=422, detail="Could not parse email file")

                logger.info(f"Analyzing uploaded email: {email.email_id}")
                result = await self.pipeline.analyze(email)

                # Serialize to JSON-friendly dict
                def _safe(v):
                    if hasattr(v, 'value'):
                        return v.value
                    if hasattr(v, 'isoformat'):
                        return v.isoformat()
                    return v

                analyzer_results = {}
                for name, ar in (result.analyzer_results or {}).items():
                    analyzer_results[name] = {
                        "risk_score": ar.risk_score,
                        "confidence": ar.confidence,
                        "details": str(ar.details) if ar.details else None,
                    }

                iocs = result.iocs or {}
                headers_raw = iocs.get("headers", {})
                headers_out = {}
                if hasattr(headers_raw, '__dict__'):
                    headers_out = {k: _safe(v) for k, v in vars(headers_raw).items()}
                elif isinstance(headers_raw, dict):
                    headers_out = {k: _safe(v) for k, v in headers_raw.items()}

                return {
                    "email_id": result.email_id,
                    "verdict": result.verdict.value,
                    "overall_score": result.overall_score,
                    "overall_confidence": result.overall_confidence,
                    "timestamp": result.timestamp.isoformat(),
                    "analyzer_results": analyzer_results,
                    "extracted_urls": result.extracted_urls or [],
                    "reasoning": result.reasoning if isinstance(result.reasoning, list) else [str(result.reasoning)],
                    "iocs": {"headers": headers_out},
                }

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Upload analysis failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "version": "1.0.0",
                "pipeline": "ready",
            }

        @app.get("/api/config")
        async def get_config():
            """Get pipeline configuration (sanitized)."""
            return {
                "max_concurrent_analyzers": self.config.max_concurrent_analyzers,
                "pipeline_timeout": self.config.pipeline_timeout,
                "url_detonation_timeout": self.config.url_detonation_timeout,
            }

        # Include dashboard routes
        app.include_router(self.dashboard.router)

        return app

    def run_server(self, host: str = "0.0.0.0", port: int = None):
        """
        Start FastAPI server with dashboard.

        Args:
            host: Host to bind to.
            port: Port to bind to (defaults to config.dashboard_port).
        """
        if port is None:
            port = self.config.dashboard_port

        app = self.create_fastapi_app()

        logger.info(f"Starting server on {host}:{port}")
        logger.info(f"Dashboard available at http://{host}:{port}/dashboard")
        logger.info(f"API available at http://{host}:{port}/api")

        run(
            app,
            host=host,
            port=port,
            log_level=self.config.log_level.lower(),
        )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Automated phishing detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze email from file
  python main.py --analyze email.eml

  # Analyze and generate all reports
  python main.py --analyze email.eml --format all

  # Start server with dashboard
  python main.py --serve

  # Start server on custom port
  python main.py --serve --port 9000

  # Monitor inbox continuously
  python main.py monitor

  # Monitor with custom poll interval
  python main.py monitor --interval 30
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Analyze subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Analyze email file")
    analyze_parser.add_argument(
        "email_file",
        help="Path to email file (.eml)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "html", "stix", "all"],
        default="json",
        help="Output format (default: json)",
    )

    # Serve subcommand
    serve_parser = subparsers.add_parser("serve", help="Start API server")
    serve_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        help="Port to bind to (default from config)",
    )

    # Monitor subcommand
    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Continuously monitor inbox for phishing emails",
    )
    monitor_parser.add_argument(
        "--interval",
        type=int,
        help="Poll interval in seconds (default from config, usually 60)",
    )

    # Legacy: support old --analyze and --serve flags
    parser.add_argument(
        "--analyze",
        metavar="EMAIL_FILE",
        help="Path to email file to analyze (legacy flag)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start server mode (legacy flag)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port for server mode",
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "stix", "all"],
        default="json",
        help="Output format for analysis",
    )

    args = parser.parse_args()

    # Initialize app
    app = PhishingDetectionApp()

    # Handle legacy flags
    if args.analyze:
        asyncio.run(app.analyze_email_file(args.analyze, args.format))
    elif args.serve:
        app.run_server(port=args.port)
    # Handle new subcommands
    elif args.command == "analyze":
        asyncio.run(app.analyze_email_file(args.email_file, args.format))
    elif args.command == "serve":
        app.run_server(host=args.host, port=args.port)
    elif args.command == "monitor":
        from src.automation.email_monitor import EmailMonitor
        config = PipelineConfig.from_env()
        monitor = EmailMonitor.from_config(config)
        if args.interval:
            monitor.poll_interval = args.interval
        asyncio.run(monitor.run())
    else:
        # No command specified
        if len(sys.argv) == 1:
            parser.print_help()
        else:
            logger.error("Invalid command")
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Main entry point for phishing detection system.

Supports two modes:
1. CLI: python main.py --analyze <email.eml>
2. Server: python main.py --serve (starts FastAPI dashboard and API)
"""
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(override=True)  # override=True so .env values win over empty system env vars

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from uvicorn import run

from src.config import PipelineConfig
from src.models import EmailObject
from src.orchestrator.pipeline import PhishingPipeline
from src.reporting.report_generator import ReportGenerator
from src.reporting.ioc_exporter import IOCExporter
from src.reporting.sigma_exporter import SigmaExporter
from src.reporting.dashboard import PhishingDashboard
from src.security.web_security import (
    SSRFBlockedError,
    TokenVerifier,
    add_security_headers_middleware,
    default_ssrf_guard,
)


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
        self.sigma_exporter = SigmaExporter()
        self.dashboard = PhishingDashboard(template_dir="./templates")
        self.token_verifier = TokenVerifier(
            getattr(self.config, "analyst_api_token", None)
        )
        self._monitor = None  # set when IMAP monitor starts
        self._upload_results: list[dict] = []  # results from manual uploads (shown on monitor)

    async def analyze_email_file(self, email_path: str, output_format: str = "json"):
        """
        Analyze email from EML file.

        Args:
            email_path: Path to .eml file.
            output_format: Output format (json, html, stix, sigma, all).

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

            if output_format in ["sigma", "all"]:
                sigma_rule = self.sigma_exporter.export_campaign_rule(result)
                if sigma_rule:
                    outputs["sigma"] = sigma_rule
                    logger.info("Generated Sigma detection rule")
                else:
                    logger.info("No Sigma rule emitted (CLEAN verdict or no observables)")

            # Display results
            if output_format == "json":
                import json
                print(json.dumps(outputs["json"], indent=2))
            elif output_format == "html":
                print(outputs.get("html", "No HTML output available"))
            elif output_format == "stix":
                print(outputs.get("stix", "No STIX output available"))
            elif output_format == "sigma":
                print(outputs.get("sigma", "No Sigma rule emitted (CLEAN verdict or no observables)"))
            elif output_format == "all":
                # Save all outputs to files
                email_id = email.email_id
                json_path = f"{email_id}_report.json"
                html_path = f"{email_id}_report.html"
                stix_path = f"{email_id}_iocs.json"
                sigma_path = f"{email_id}_rule.yml"

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

                if "sigma" in outputs:
                    with open(sigma_path, "w") as f:
                        f.write(outputs["sigma"])
                    logger.info(f"Wrote Sigma rule to {sigma_path}")

                print(f"Analysis complete. Reports saved to:")
                if "json" in outputs:
                    print(f"  - {json_path}")
                if "html" in outputs:
                    print(f"  - {html_path}")
                if "stix" in outputs:
                    print(f"  - {stix_path}")
                if "sigma" in outputs:
                    print(f"  - {sigma_path}")

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

        # Attach security headers (CSP, X-Frame-Options, HSTS, etc.)
        # to every response. See src/security/web_security.py.
        add_security_headers_middleware(app)

        # Capture token verifier locally so route closures can reference it
        # without re-reading self.token_verifier on every request.
        require_token = self.token_verifier

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

                # Build analyzer_results with proper dict details (not str())
                analyzer_results = {}
                for name, ar in (result.analyzer_results or {}).items():
                    details = ar.details or {}
                    safe_details = {}
                    for k, v in details.items():
                        if k == "screenshots":
                            safe_details[k] = {url: "(base64 image)" for url in (v or {})}
                        elif isinstance(v, bytes):
                            safe_details[k] = "(binary data)"
                        else:
                            safe_details[k] = v
                    analyzer_results[name] = {
                        "risk_score": ar.risk_score,
                        "confidence": ar.confidence,
                        "details": safe_details,
                        "errors": ar.errors if ar.errors else None,
                    }

                extracted_urls_list = [
                    {"url": u.url, "source": u.source.value, "source_detail": u.source_detail}
                    if hasattr(u, 'source') else {"url": u.url if hasattr(u, 'url') else str(u), "source": "unknown", "source_detail": ""}
                    for u in (result.extracted_urls or [])
                ]

                reasoning_text = result.reasoning if isinstance(result.reasoning, str) else str(result.reasoning)

                iocs = result.iocs or {}
                headers_raw = iocs.get("headers", {})
                headers_out = {}
                if hasattr(headers_raw, '__dict__'):
                    headers_out = {k: _safe(v) for k, v in vars(headers_raw).items()}
                elif isinstance(headers_raw, dict):
                    headers_out = {k: _safe(v) for k, v in headers_raw.items()}

                # Add email metadata the frontend expects
                headers_out["from_address"] = email.from_address or ""
                headers_out["from_display_name"] = email.from_display_name or ""
                headers_out["subject"] = email.subject or ""
                headers_out["reply_to"] = email.reply_to or ""
                headers_out["to_addresses"] = email.to_addresses or []

                # Convert boolean auth fields to string format frontend expects
                def _auth_str(val):
                    if val is True:
                        return "pass"
                    elif val is False:
                        return "fail"
                    return "unknown"
                headers_out["spf_result"] = _auth_str(headers_out.get("spf_pass"))
                headers_out["dkim_result"] = _auth_str(headers_out.get("dkim_pass"))
                headers_out["dmarc_result"] = _auth_str(headers_out.get("dmarc_pass"))
                # Alias keys the frontend expects
                headers_out["reply_to_mismatch"] = headers_out.get("from_reply_to_mismatch", False)

                from datetime import datetime, timezone
                timestamp = datetime.now(timezone.utc).isoformat()

                # Build monitor-compatible record
                monitor_record = {
                    "timestamp": timestamp,
                    "email_id": result.email_id,
                    "account": "upload",
                    "provider": "manual",
                    "from": email.from_address or "unknown",
                    "display_name": email.from_display_name or "",
                    "reply_to": email.reply_to or "",
                    "to": email.to_addresses or [],
                    "subject": email.subject or "",
                    "verdict": result.verdict.value,
                    "score": result.overall_score,
                    "confidence": result.overall_confidence,
                    "quarantined": False,
                    "analyzer_results": analyzer_results,
                    "extracted_urls": extracted_urls_list,
                    "reasoning": reasoning_text,
                    "body_preview": (email.body_plain or "")[:2000],
                    "body_html": (email.body_html or "")[:5000],
                }

                # Store in upload results for monitor page
                self._upload_results.append(monitor_record)
                if len(self._upload_results) > 200:
                    self._upload_results.pop(0)

                # Also write to results.jsonl for the Full Log tab
                try:
                    import json as _json
                    log_path = Path("data/results.jsonl")
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(log_path, "a", encoding="utf-8") as f:
                        f.write(_json.dumps(monitor_record, default=str) + "\n")
                except Exception as _log_err:
                    logger.warning(f"Failed to write result to log: {_log_err}")

                return {
                    "email_id": result.email_id,
                    "verdict": result.verdict.value,
                    "overall_score": result.overall_score,
                    "overall_confidence": result.overall_confidence,
                    "timestamp": timestamp,
                    "analyzer_results": analyzer_results,
                    "extracted_urls": extracted_urls_list,
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

        @app.get("/api/system-status", dependencies=[Depends(require_token)])
        async def system_status():
            """Return which API keys are configured and system info (no key values)."""
            a = self.config.api
            return {
                "api_keys": {
                    "virustotal":          bool(a.virustotal_key),
                    "urlscan":             bool(a.urlscan_key),
                    "abuseipdb":           bool(a.abuseipdb_key),
                    "google_safebrowsing": bool(a.google_safebrowsing_key),
                    "hybrid_analysis":     bool(a.hybrid_analysis_key),
                    "anyrun":              bool(a.anyrun_key),
                    "joesandbox":          bool(a.joesandbox_key),
                    "anthropic":           bool(a.anthropic_key),
                    "openai":              bool(a.openai_key),
                },
                "llm_provider":     a.llm_provider,
                "sandbox_provider": a.sandbox_provider,
                "imap": {
                    "configured":         bool(self.config.imap.user and self.config.imap.password),
                    "host":               self.config.imap.host if self.config.imap.user else None,
                    "folder":             self.config.imap.folder,
                    "quarantine_folder":  self.config.imap.quarantine_folder,
                    "poll_interval":      self.config.imap.poll_interval_seconds,
                },
            }

        @app.get("/api/diagnose", dependencies=[Depends(require_token)])
        async def diagnose_apis():
            """
            Live diagnostic: test each external API with a real HTTP request.
            Returns pass/fail status for each service.
            """
            import aiohttp as _aiohttp
            import base64 as _b64

            results = {}
            a = self.config.api

            async def _test_service(name, coro):
                try:
                    results[name] = await asyncio.wait_for(coro, timeout=15)
                except asyncio.TimeoutError:
                    results[name] = {"status": "fail", "error": "timeout (15s)"}
                except Exception as e:
                    results[name] = {"status": "fail", "error": str(e)}

            async def _check_vt():
                if not a.virustotal_key:
                    return {"status": "skip", "reason": "no API key"}
                async with _aiohttp.ClientSession() as s:
                    url_id = _b64.urlsafe_b64encode(b"https://www.google.com").decode().rstrip("=")
                    async with s.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={"x-apikey": a.virustotal_key},
                        timeout=_aiohttp.ClientTimeout(total=12),
                    ) as r:
                        if r.status == 200:
                            return {"status": "pass", "http": 200}
                        elif r.status == 404:
                            return {"status": "pass", "http": 404, "note": "key valid, URL not in DB"}
                        elif r.status == 401:
                            return {"status": "fail", "http": 401, "error": "invalid API key"}
                        elif r.status == 429:
                            return {"status": "warn", "http": 429, "error": "rate limited"}
                        else:
                            return {"status": "fail", "http": r.status}

            async def _check_sb():
                if not a.google_safebrowsing_key:
                    return {"status": "skip", "reason": "no API key"}
                async with _aiohttp.ClientSession() as s:
                    async with s.post(
                        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={a.google_safebrowsing_key}",
                        json={
                            "client": {"clientId": "diag", "clientVersion": "1.0"},
                            "threatInfo": {
                                "threatTypes": ["SOCIAL_ENGINEERING"],
                                "platformTypes": ["ANY_PLATFORM"],
                                "threatEntryTypes": ["URL"],
                                "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/s/phishing.html"}],
                            },
                        },
                        timeout=_aiohttp.ClientTimeout(total=12),
                    ) as r:
                        if r.status == 200:
                            data = await r.json()
                            matches = len(data.get("matches", []))
                            return {"status": "pass", "http": 200, "threats_found": matches}
                        elif r.status == 403:
                            return {"status": "fail", "http": 403, "error": "API key invalid or Safe Browsing API not enabled in Google Cloud Console"}
                        else:
                            return {"status": "fail", "http": r.status}

            async def _check_abuseipdb():
                if not a.abuseipdb_key:
                    return {"status": "skip", "reason": "no API key"}
                async with _aiohttp.ClientSession() as s:
                    async with s.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                        headers={"Key": a.abuseipdb_key, "Accept": "application/json"},
                        timeout=_aiohttp.ClientTimeout(total=12),
                    ) as r:
                        if r.status == 200:
                            data = await r.json()
                            score = data.get("data", {}).get("abuseConfidenceScore", "?")
                            return {"status": "pass", "http": 200, "test_ip_score": score}
                        elif r.status == 401:
                            return {"status": "fail", "http": 401, "error": "invalid API key"}
                        elif r.status == 429:
                            return {"status": "warn", "http": 429, "error": "rate limited"}
                        else:
                            return {"status": "fail", "http": r.status}

            async def _check_urlscan():
                if not a.urlscan_key:
                    return {"status": "skip", "reason": "no API key"}
                async with _aiohttp.ClientSession() as s:
                    async with s.get(
                        "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
                        headers={"API-Key": a.urlscan_key},
                        timeout=_aiohttp.ClientTimeout(total=12),
                    ) as r:
                        if r.status == 200:
                            return {"status": "pass", "http": 200, "note": "fire-and-forget by design, always confidence=0"}
                        elif r.status == 401:
                            return {"status": "fail", "http": 401, "error": "invalid API key"}
                        else:
                            return {"status": "fail", "http": r.status}

            async def _check_anthropic():
                if not a.anthropic_key:
                    return {"status": "skip", "reason": "no API key"}
                async with _aiohttp.ClientSession() as s:
                    async with s.post(
                        "https://api.anthropic.com/v1/messages",
                        json={"model": "claude-haiku-4-5-20251001", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]},
                        headers={"x-api-key": a.anthropic_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                        timeout=_aiohttp.ClientTimeout(total=12),
                    ) as r:
                        if r.status == 200:
                            return {"status": "pass", "http": 200}
                        elif r.status == 401:
                            return {"status": "fail", "http": 401, "error": "invalid API key"}
                        else:
                            return {"status": "fail", "http": r.status}

            await asyncio.gather(
                _test_service("virustotal", _check_vt()),
                _test_service("google_safebrowsing", _check_sb()),
                _test_service("abuseipdb", _check_abuseipdb()),
                _test_service("urlscan", _check_urlscan()),
                _test_service("anthropic_llm", _check_anthropic()),
            )

            # Summary
            passing = sum(1 for v in results.values() if v.get("status") == "pass")
            total = len(results)
            return {
                "summary": f"{passing}/{total} services operational",
                "services": results,
                "notes": {
                    "url_detonation": "not implemented (no browser sandbox)",
                    "urlscan": "works but fire-and-forget design means confidence=0 always",
                },
            }

        @app.get("/status", response_class=HTMLResponse)
        async def status_page():
            """Serve the API/system status page."""
            status_path = Path("./templates/status.html")
            return HTMLResponse(content=status_path.read_text(encoding="utf-8"))

        @app.get("/api/config")
        async def get_config():
            """Get pipeline configuration (sanitized)."""
            return {
                "max_concurrent_analyzers": self.config.max_concurrent_analyzers,
                "pipeline_timeout": self.config.pipeline_timeout,
                "url_detonation_timeout": self.config.url_detonation_timeout,
            }

        @app.get("/monitor", response_class=HTMLResponse)
        async def monitor_page():
            """Serve the automation monitor/review page."""
            monitor_path = Path("./templates/monitor.html")
            return HTMLResponse(content=monitor_path.read_text(encoding="utf-8"))

        @app.get("/api/monitor/stats")
        async def monitor_stats():
            """Return current monitor stats and recent results."""
            # Merge IMAP monitor results + manual upload results
            monitor_recent = []
            monitor_stats_dict = {}
            is_running = False

            if self._monitor is not None:
                monitor_recent = list(self._monitor._recent_results[-50:])
                monitor_stats_dict = self._monitor.stats
                is_running = self._monitor._running

            # Merge upload results with monitor results
            all_recent = monitor_recent + list(self._upload_results[-50:])
            # Sort by timestamp descending
            all_recent.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
            all_recent = all_recent[:50]

            return {
                "running": is_running,
                "stats": monitor_stats_dict,
                "recent": all_recent,
                "imap_configured": self._monitor is not None or bool(self.config.imap.user),
                "quarantine_folder": getattr(self._monitor, "quarantine_folder", None) if self._monitor else None,
            }

        @app.get("/api/monitor/log")
        async def monitor_log(limit: int = 100):
            """Return recent results from the JSONL log file."""
            log_path = Path("data/results.jsonl")
            if not log_path.exists():
                return {"entries": []}
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            import json as _json
            entries = []
            for line in reversed(lines[-limit:]):
                try:
                    entries.append(_json.loads(line))
                except Exception:
                    pass
            return {"entries": entries}

        @app.get("/api/monitor/email/{email_id}", dependencies=[Depends(require_token)])
        async def monitor_email_detail(email_id: str):
            """Return full details for a specific analyzed email."""
            # Search IMAP monitor results
            if self._monitor is not None:
                for record in reversed(self._monitor._recent_results):
                    if record.get("email_id") == email_id:
                        return record

            # Search upload results
            for record in reversed(self._upload_results):
                if record.get("email_id") == email_id:
                    return record

            raise HTTPException(status_code=404, detail="Email not found in recent results")

        @app.post("/api/detonate-url", dependencies=[Depends(require_token)])
        async def detonate_url_endpoint(request: Request):
            """
            On-demand URL detonation: visit a URL in headless browser
            and return screenshot + analysis.

            SSRF-guarded: the URL is DNS-resolved and rejected if it points
            at any private/loopback/link-local/CGNAT/cloud-metadata range.
            See src/security/web_security.py::SSRFGuard for the deny list.
            """
            payload = await request.json()
            url = payload.get("url", "").strip()
            if not url:
                raise HTTPException(status_code=400, detail="url is required")

            # Default to https:// if no scheme was provided
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            # SSRF check: refuse private/loopback/metadata IPs before doing
            # ANY work. The check resolves DNS so we catch hostname tricks.
            try:
                default_ssrf_guard.assert_safe(url)
            except SSRFBlockedError as e:
                logger.warning(f"SSRF blocked for url={url!r}: {e}")
                raise HTTPException(status_code=400, detail=f"URL rejected: {e}")

            try:
                from src.analyzers.url_detonation import detonate_single_url
                result = await asyncio.wait_for(
                    detonate_single_url(url),
                    timeout=30,
                )
                return result
            except ImportError:
                raise HTTPException(
                    status_code=501,
                    detail="URL detonation requires Playwright. Install with: pip install playwright && python -m playwright install chromium"
                )
            except asyncio.TimeoutError:
                raise HTTPException(status_code=504, detail="URL detonation timed out (30s)")
            except Exception as e:
                logger.error(f"URL detonation failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/monitor/alerts")
        async def monitor_alerts(limit: int = 50):
            """Return recent alerts from the alert log file."""
            alert_path = Path("data/alerts.jsonl")
            if not alert_path.exists():
                return {"alerts": []}
            lines = alert_path.read_text(encoding="utf-8").strip().splitlines()
            import json as _json
            alerts = []
            for line in reversed(lines[-limit:]):
                try:
                    alerts.append(_json.loads(line))
                except Exception:
                    pass
            return {"alerts": alerts}

        # ── Account management routes ─────────────────────────────
        @app.get("/accounts", response_class=HTMLResponse)
        async def accounts_page():
            """Serve the account management page."""
            accounts_path = Path("./templates/accounts.html")
            return HTMLResponse(content=accounts_path.read_text(encoding="utf-8"))

        @app.get("/api/accounts", dependencies=[Depends(require_token)])
        async def api_list_accounts():
            """List all configured email accounts (passwords masked)."""
            from src.automation.multi_account_monitor import list_accounts
            accounts = list_accounts()
            return {"accounts": accounts}

        @app.post("/api/accounts/add", dependencies=[Depends(require_token)])
        async def api_add_account(request: Request):
            """
            Add a new email account.

            Expects JSON body with:
            - type: "gmail" | "outlook" | "imap"
            - For gmail: credentials (JSON object from Google Cloud Console)
            - For outlook: client_id
            - For imap: host, port, user, password
            """
            import json as _json
            from src.automation.multi_account_monitor import add_account_to_file

            payload = await request.json()
            acct_type = payload.get("type", "").lower()

            if acct_type == "gmail":
                credentials = payload.get("credentials")
                if not credentials:
                    raise HTTPException(status_code=400, detail="Gmail credentials JSON required")

                # Save credentials to a temp file for the OAuth flow
                creds_path = f"data/gmail_creds_{len(list_accounts_helper())}.json"
                Path(creds_path).parent.mkdir(parents=True, exist_ok=True)
                with open(creds_path, "w") as f:
                    if isinstance(credentials, str):
                        f.write(credentials)
                    else:
                        _json.dump(credentials, f)

                token_path = f"data/gmail_token_{len(list_accounts_helper())}.json"

                add_account_to_file({
                    "type": "gmail",
                    "email": payload.get("email", ""),
                    "credentials_path": creds_path,
                    "token_path": token_path,
                })
                return {
                    "status": "added",
                    "type": "gmail",
                    "note": "OAuth authentication needed. Run 'python main.py add-account gmail' to complete auth flow, or authenticate via the Gmail provider on first monitor start.",
                }

            elif acct_type == "outlook":
                client_id = payload.get("client_id", "").strip()
                if not client_id:
                    raise HTTPException(status_code=400, detail="Outlook client_id required")

                token_path = f"data/outlook_token_{len(list_accounts_helper())}.json"

                add_account_to_file({
                    "type": "outlook",
                    "email": payload.get("email", ""),
                    "client_id": client_id,
                    "token_path": token_path,
                })
                return {
                    "status": "added",
                    "type": "outlook",
                    "note": "Device code authentication needed on first monitor start.",
                }

            elif acct_type == "imap":
                host = payload.get("host", "").strip()
                user = payload.get("user", "").strip()
                password = payload.get("password", "")
                port = int(payload.get("port", 993))

                if not all([host, user, password]):
                    raise HTTPException(status_code=400, detail="IMAP requires host, user, and password")

                add_account_to_file({
                    "type": "imap",
                    "host": host,
                    "port": port,
                    "user": user,
                    "password": password,
                    "folder": payload.get("folder", "INBOX"),
                })
                return {"status": "added", "type": "imap", "email": user}

            else:
                raise HTTPException(status_code=400, detail=f"Unknown account type: {acct_type}")

        @app.post("/api/accounts/remove", dependencies=[Depends(require_token)])
        async def api_remove_account(request: Request):
            """Remove an account by email or type."""
            from src.automation.multi_account_monitor import remove_account_from_file
            payload = await request.json()
            email_or_type = payload.get("email") or payload.get("identifier", "")
            if not email_or_type:
                raise HTTPException(status_code=400, detail="email or identifier required")
            remove_account_from_file(email_or_type)
            return {"status": "removed", "identifier": email_or_type}

        def list_accounts_helper():
            from src.automation.multi_account_monitor import list_accounts
            return list_accounts()

        # ── Feedback / Learning endpoints ────────────────────────────
        _feedback_db = None

        async def _get_feedback_db():
            nonlocal _feedback_db
            if _feedback_db is None:
                from src.feedback.database import DatabaseManager, create_sqlite_url
                db_path = getattr(self.config, "feedback_db_path", "data/feedback.db")
                _feedback_db = DatabaseManager(create_sqlite_url(db_path), echo=False)
                await _feedback_db.initialize()
                await _feedback_db.create_tables()
            return _feedback_db

        @app.post("/api/feedback", dependencies=[Depends(require_token)])
        async def submit_feedback(request: Request):
            """
            Submit analyst feedback on an analysis result.
            Enables the system to learn from corrections.
            """
            import traceback as _tb
            try:
                payload = await request.json()
                email_id = payload.get("email_id", "").strip()
                original_verdict = payload.get("original_verdict", "").strip()
                correct_label = payload.get("correct_label", "").strip()
                analyst_notes = payload.get("notes", "").strip()
                feature_vector = payload.get("feature_vector", {})

                if not email_id or not correct_label:
                    raise HTTPException(status_code=400, detail="email_id and correct_label required")

                valid_labels = ["CLEAN", "SUSPICIOUS", "LIKELY_PHISHING", "CONFIRMED_PHISHING"]
                if correct_label not in valid_labels:
                    raise HTTPException(status_code=400, detail=f"correct_label must be one of: {valid_labels}")

                db = await _get_feedback_db()

                from src.feedback.database import FeedbackRecord, LocalBlocklist, LocalAllowlist
                from sqlalchemy import select
                from datetime import datetime, timezone

                actions_taken = []

                async with db.async_session_maker() as session:
                    record = FeedbackRecord(
                        email_id=email_id,
                        original_verdict=original_verdict or "UNKNOWN",
                        correct_label=correct_label,
                        analyst_notes=analyst_notes,
                        feature_vector=json.dumps(feature_vector) if feature_vector else "{}",
                        submitted_at=datetime.now(timezone.utc),
                    )
                    session.add(record)
                    actions_taken.append("feedback_recorded")

                    # Auto-blocklist: if analyst says it's phishing but system said clean
                    severity = {"CLEAN": 0, "SUSPICIOUS": 1, "LIKELY_PHISHING": 2, "CONFIRMED_PHISHING": 3}
                    orig_sev = severity.get(original_verdict, 0)
                    corr_sev = severity.get(correct_label, 0)

                    if corr_sev > orig_sev and corr_sev >= 2:
                        # False negative — find sender in upload results or monitor results
                        sender = ""
                        for rec in reversed(self._upload_results):
                            if rec.get("email_id") == email_id:
                                sender = rec.get("from", "")
                                break
                        if sender and not sender.endswith(("@gmail.com", "@outlook.com", "@yahoo.com")):
                            existing = await session.execute(
                                select(LocalBlocklist).where(LocalBlocklist.indicator == sender)
                            )
                            if not existing.scalar_one_or_none():
                                session.add(LocalBlocklist(
                                    indicator=sender,
                                    indicator_type="email",
                                    added_by="analyst_feedback",
                                    added_at=datetime.now(timezone.utc),
                                    reason=f"False negative: was {original_verdict}, should be {correct_label}",
                                ))
                                actions_taken.append(f"blocklisted_sender:{sender}")

                    elif corr_sev < orig_sev and orig_sev >= 2:
                        # False positive — find sender
                        sender = ""
                        for rec in reversed(self._upload_results):
                            if rec.get("email_id") == email_id:
                                sender = rec.get("from", "")
                                break
                        if sender:
                            existing = await session.execute(
                                select(LocalAllowlist).where(LocalAllowlist.indicator == sender)
                            )
                            if not existing.scalar_one_or_none():
                                session.add(LocalAllowlist(
                                    indicator=sender,
                                    indicator_type="email",
                                    added_by="analyst_feedback",
                                    added_at=datetime.now(timezone.utc),
                                    reason=f"False positive: was {original_verdict}, should be {correct_label}",
                                ))
                                actions_taken.append(f"allowlisted_sender:{sender}")

                    await session.commit()

                return {
                    "status": "ok",
                    "email_id": email_id,
                    "original_verdict": original_verdict,
                    "correct_label": correct_label,
                    "actions_taken": actions_taken,
                }
            except HTTPException:
                raise
            except Exception as exc:
                logger.error("Feedback endpoint error: %s\n%s", exc, _tb.format_exc())
                return JSONResponse(
                    status_code=500,
                    content={"error": str(exc), "detail": _tb.format_exc().split("\n")[-3:]},
                )

        @app.get("/api/feedback/stats", dependencies=[Depends(require_token)])
        async def feedback_stats():
            """Return feedback statistics and model accuracy metrics."""
            db = await _get_feedback_db()
            from src.feedback.database import FeedbackRecord
            from sqlalchemy import select, func

            async with db.async_session_maker() as session:
                total = await session.execute(select(func.count(FeedbackRecord.id)))
                total_count = total.scalar() or 0

                if total_count == 0:
                    return {
                        "total_feedback": 0,
                        "accuracy": None,
                        "false_positives": 0,
                        "false_negatives": 0,
                        "corrections": [],
                    }

                # Count agreements vs disagreements
                all_records = await session.execute(select(FeedbackRecord).order_by(FeedbackRecord.submitted_at.desc()).limit(200))
                records = all_records.scalars().all()

                agree = 0
                false_pos = 0
                false_neg = 0
                corrections = []

                severity = {"CLEAN": 0, "SUSPICIOUS": 1, "LIKELY_PHISHING": 2, "CONFIRMED_PHISHING": 3}

                for r in records:
                    if r.original_verdict == r.correct_label:
                        agree += 1
                    else:
                        orig_sev = severity.get(r.original_verdict, 0)
                        corr_sev = severity.get(r.correct_label, 0)
                        if corr_sev > orig_sev:
                            false_neg += 1
                        else:
                            false_pos += 1
                        corrections.append({
                            "email_id": r.email_id,
                            "original": r.original_verdict,
                            "correct": r.correct_label,
                            "notes": r.analyst_notes,
                            "time": r.submitted_at.isoformat() if r.submitted_at else None,
                        })

                return {
                    "total_feedback": total_count,
                    "accuracy": round(agree / len(records) * 100, 1) if records else None,
                    "agreements": agree,
                    "false_positives": false_pos,
                    "false_negatives": false_neg,
                    "recent_corrections": corrections[:20],
                }

        @app.post("/api/feedback/retrain", dependencies=[Depends(require_token)])
        async def trigger_retrain():
            """Manually trigger model weight retraining from feedback data."""
            db = await _get_feedback_db()
            from src.feedback.retrainer import RetrainOrchestrator

            orchestrator = RetrainOrchestrator(self.config)
            async with db.async_session_maker() as session:
                result = await orchestrator.run_full_retrain(session)

            return {
                "status": result.get("status", "completed"),
                "feedback_used": result.get("feedback_records_used", 0),
                "new_weights": result.get("new_weights"),
                "improvement": result.get("model_improvement"),
            }

        # Include dashboard routes
        app.include_router(self.dashboard.router)

        return app

    def run_server(self, host: str = "127.0.0.1", port: int = None):
        """
        Start FastAPI server with dashboard.

        Args:
            host: Host to bind to. Defaults to 127.0.0.1 (loopback only).
                Binding to a non-loopback address is allowed but requires
                that ANALYST_API_TOKEN is set, otherwise the server refuses
                to start. See SECURITY.md hardening guidance.
            port: Port to bind to (defaults to config.dashboard_port).
        """
        if port is None:
            port = self.config.dashboard_port

        # Refuse to expose an unauthenticated API to a non-loopback address.
        # This is the perimeter check that closes THREAT_MODEL.md R1.
        is_loopback = host in ("127.0.0.1", "::1", "localhost")
        if not is_loopback and not self.token_verifier.enabled:
            logger.error(
                "REFUSING TO START: host=%s is non-loopback but ANALYST_API_TOKEN "
                "is not set. Either bind to 127.0.0.1 (the default) or set "
                "ANALYST_API_TOKEN before exposing the dashboard.",
                host,
            )
            sys.exit(2)

        if not is_loopback:
            logger.warning(
                "Binding to %s — this exposes the dashboard beyond loopback. "
                "Auth is enabled; ensure ANALYST_API_TOKEN is high-entropy.",
                host,
            )
        if not self.token_verifier.enabled:
            logger.warning(
                "ANALYST_API_TOKEN is not set — API authentication is DISABLED. "
                "Server will only accept loopback connections. Set "
                "ANALYST_API_TOKEN to enable auth and allow remote access.",
            )

        app = self.create_fastapi_app()

        # Start monitor in background — uses MultiAccountMonitor if accounts.json
        # exists, falls back to legacy IMAP monitor if IMAP env vars are set
        from src.automation.multi_account_monitor import MultiAccountMonitor, load_providers_from_file

        @app.on_event("startup")
        async def start_monitor():
            try:
                monitor = MultiAccountMonitor.from_config(self.config)
                if monitor.providers:
                    self._monitor = monitor
                    asyncio.create_task(monitor.run())
                    accounts = [p.account_id for p in monitor.providers]
                    logger.info(
                        f"Multi-account monitor started: {len(accounts)} account(s) "
                        f"[{', '.join(accounts)}]"
                    )
                elif self.config.imap.user and self.config.imap.password:
                    from src.automation.email_monitor import EmailMonitor
                    self._monitor = EmailMonitor.from_config(self.config)
                    asyncio.create_task(self._monitor.run())
                    logger.info(
                        f"IMAP monitor started: {self.config.imap.user}@"
                        f"{self.config.imap.host} → quarantine='{self.config.imap.quarantine_folder}'"
                    )
                else:
                    logger.info(
                        "No email accounts configured — monitor inactive. "
                        "Add accounts at /accounts or set IMAP env vars."
                    )
            except Exception as e:
                logger.error(f"Failed to start monitor: {e}", exc_info=True)

        @app.on_event("shutdown")
        async def stop_monitor():
            if self._monitor:
                self._monitor.stop()

        logger.info(f"Starting server on {host}:{port}")
        logger.info(f"Dashboard: http://{host}:{port}/dashboard")
        logger.info(f"Monitor:   http://{host}:{port}/monitor")
        logger.info(f"API:       http://{host}:{port}/api")

        run(
            app,
            host=host,
            port=port,
            log_level=self.config.log_level.lower(),
        )


def _cmd_add_account(args):
    """Interactive guided flow to add an email account."""
    import json
    from src.automation.multi_account_monitor import add_account_to_file

    acct_type = args.type

    print(f"\n{'='*50}")
    print(f"  Add {acct_type.upper()} Account")
    print(f"{'='*50}\n")

    if acct_type == "gmail":
        print("Step 1: Go to https://console.cloud.google.com")
        print("Step 2: Enable the Gmail API")
        print("Step 3: Create OAuth 2.0 Client ID (Desktop app)")
        print("Step 4: Download the credentials JSON file")
        print()

        creds_path = input("Path to credentials.json [credentials.json]: ").strip() or "credentials.json"
        if not Path(creds_path).exists():
            print(f"\n  Error: {creds_path} not found.")
            print("  Download it from Google Cloud Console first.\n")
            sys.exit(1)

        token_path = f"data/gmail_token_{len(_list_accounts())}.json"

        # Authenticate immediately
        from src.ingestion.gmail_provider import GmailProvider
        provider = GmailProvider(credentials_path=creds_path, token_path=token_path)
        print("\nOpening browser for Google sign-in...")
        if not provider.authenticate():
            print("\n  Authentication failed. Please try again.\n")
            sys.exit(1)

        add_account_to_file({
            "type": "gmail",
            "email": provider.account_id,
            "credentials_path": creds_path,
            "token_path": token_path,
        })
        print(f"\n  Added: {provider.account_id} (Gmail)")
        print(f"  Token saved to: {token_path}\n")

    elif acct_type == "outlook":
        print("Step 1: Go to https://portal.azure.com → App Registrations")
        print("Step 2: Register new app (redirect: http://localhost)")
        print("Step 3: Add API permissions: Mail.Read, Mail.ReadWrite")
        print("Step 4: Copy the Application (client) ID")
        print()

        client_id = args.client_id or input("Application (client) ID: ").strip()
        if not client_id:
            print("\n  Error: Client ID required.\n")
            sys.exit(1)

        token_path = f"data/outlook_token_{len(_list_accounts())}.json"

        from src.ingestion.outlook_provider import OutlookProvider
        provider = OutlookProvider(client_id=client_id, token_path=token_path)
        print("\nFollow the device code flow to sign in...")
        if not provider.authenticate():
            print("\n  Authentication failed. Please try again.\n")
            sys.exit(1)

        add_account_to_file({
            "type": "outlook",
            "email": provider.account_id,
            "client_id": client_id,
            "token_path": token_path,
        })
        print(f"\n  Added: {provider.account_id} (Outlook)")

    elif acct_type == "imap":
        print("Works with: Yahoo, ProtonMail, Zoho, FastMail, or any IMAP server")
        print()

        host = args.host or input("IMAP server (e.g., imap.yahoo.com): ").strip()
        port = args.port or int(input("Port [993]: ").strip() or "993")
        user = args.user or input("Email address: ").strip()

        import getpass
        password = getpass.getpass("Password/app-password: ")

        if not all([host, user, password]):
            print("\n  Error: All fields required.\n")
            sys.exit(1)

        add_account_to_file({
            "type": "imap",
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "folder": "INBOX",
        })
        print(f"\n  Added: {user}@{host} (IMAP)")

    else:
        print(f"Unknown account type: {acct_type}")
        print("Supported: gmail, outlook, imap")
        sys.exit(1)

    print(f"\nRun 'python main.py monitor' to start monitoring.\n")


def _cmd_accounts(args):
    """List or remove configured accounts."""
    from src.automation.multi_account_monitor import list_accounts, remove_account_from_file

    if args.action == "list":
        accounts = list_accounts()
        if not accounts:
            print("\nNo accounts configured.")
            print("Add one with: python main.py add-account gmail|outlook|imap\n")
            return
        print(f"\nConfigured accounts ({len(accounts)}):\n")
        for i, a in enumerate(accounts, 1):
            email = a.get("email") or a.get("user") or "unknown"
            print(f"  {i}. [{a['type'].upper():8s}]  {email}")
        print()

    elif args.action == "remove":
        if not args.email:
            print("Usage: python main.py accounts remove <email-or-type>")
            sys.exit(1)
        remove_account_from_file(args.email)
        print(f"Removed account matching: {args.email}")


def _list_accounts():
    """Helper to list accounts for internal use."""
    from src.automation.multi_account_monitor import list_accounts
    return list_accounts()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Automated phishing detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick Start:
  1. Add an email account:
     python main.py add-account gmail
     python main.py add-account outlook --client-id YOUR_ID
     python main.py add-account imap --host imap.yahoo.com --user you@yahoo.com

  2. Start monitoring:
     python main.py monitor

  3. Or analyze a single email file:
     python main.py analyze suspicious.eml

  4. Or start the web dashboard:
     python main.py serve
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ── add-account ──────────────────────────────────────────────
    add_acct = subparsers.add_parser(
        "add-account",
        help="Connect an email account (Gmail, Outlook, or IMAP)",
    )
    add_acct.add_argument(
        "type",
        choices=["gmail", "outlook", "imap"],
        help="Email provider type",
    )
    add_acct.add_argument("--host", help="IMAP server hostname")
    add_acct.add_argument("--port", type=int, help="IMAP port (default: 993)")
    add_acct.add_argument("--user", help="Email address / username")
    # NOTE: --password deliberately omitted — passwords on CLI are visible
    # in process listings (ps aux). Always use interactive getpass prompt.
    add_acct.add_argument("--client-id", help="Azure/Outlook Application Client ID")

    # ── accounts ─────────────────────────────────────────────────
    accts = subparsers.add_parser(
        "accounts",
        help="List or remove configured email accounts",
    )
    accts.add_argument(
        "action",
        choices=["list", "remove"],
        help="list = show all accounts, remove = delete an account",
    )
    accts.add_argument("email", nargs="?", help="Email to remove (for 'remove' action)")

    # ── monitor ──────────────────────────────────────────────────
    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Monitor all connected accounts for phishing emails",
    )
    monitor_parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Poll interval in seconds (default: 30)",
    )
    monitor_parser.add_argument(
        "--accounts",
        help="Comma-separated list of specific accounts to monitor",
    )

    # ── analyze ──────────────────────────────────────────────────
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a single .eml email file",
    )
    analyze_parser.add_argument("email_file", help="Path to .eml file")
    analyze_parser.add_argument(
        "--format",
        choices=["json", "html", "stix", "sigma", "all"],
        default="json",
        help="Output format (default: json). 'sigma' emits a Sigma detection rule scoped to this email's IOCs; 'all' writes JSON, HTML, STIX, and Sigma side by side.",
    )

    # ── serve ────────────────────────────────────────────────────
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start web dashboard and API server",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1 loopback). Setting a "
             "non-loopback host requires ANALYST_API_TOKEN to be set.",
    )
    serve_parser.add_argument("--port", type=int)

    # ── Legacy flags ─────────────────────────────────────────────
    parser.add_argument("--analyze", metavar="EMAIL_FILE", help=argparse.SUPPRESS)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--format", choices=["json", "html", "stix", "sigma", "all"],
                        default="json", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # ── Route to handler ─────────────────────────────────────────

    # Legacy flags
    if args.analyze:
        app = PhishingDetectionApp()
        asyncio.run(app.analyze_email_file(args.analyze, args.format))
        return
    if args.serve:
        app = PhishingDetectionApp()
        app.run_server(port=args.port)
        return

    # Subcommands
    if args.command == "add-account":
        _cmd_add_account(args)

    elif args.command == "accounts":
        _cmd_accounts(args)

    elif args.command == "monitor":
        from src.automation.multi_account_monitor import MultiAccountMonitor
        config = PipelineConfig.from_env()
        monitor = MultiAccountMonitor.from_config(config)

        if args.interval:
            monitor.poll_interval = args.interval

        if not monitor.providers:
            print("\nNo email accounts configured yet.\n")
            print("Add one first:")
            print("  python main.py add-account gmail")
            print("  python main.py add-account outlook --client-id YOUR_ID")
            print("  python main.py add-account imap --host HOST --user USER\n")
            sys.exit(1)

        accounts = [p.account_id for p in monitor.providers]
        print(f"\nMonitoring {len(accounts)} account(s): {', '.join(accounts)}")
        print(f"Poll interval: {monitor.poll_interval}s")
        print(f"Quarantine: '{monitor.quarantine_destination}'")
        print("Press Ctrl+C to stop.\n")

        asyncio.run(monitor.run())

    elif args.command == "analyze":
        app = PhishingDetectionApp()
        asyncio.run(app.analyze_email_file(args.email_file, args.format))

    elif args.command == "serve":
        app = PhishingDetectionApp()
        app.run_server(host=args.host, port=args.port)

    else:
        if len(sys.argv) == 1:
            parser.print_help()
        else:
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()

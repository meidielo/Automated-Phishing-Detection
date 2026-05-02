#!/usr/bin/env python3
"""
Main entry point for phishing detection system.

Supports two modes:
1. CLI: python main.py --analyze <email.eml>
2. Server: python main.py --serve (starts FastAPI dashboard and API)
"""
import argparse
import asyncio
import html
import json
import logging
import os
import re
import sys
from collections import deque
from pathlib import Path
from time import monotonic

from dotenv import load_dotenv
load_dotenv(override=True)  # override=True so .env values win over empty system env vars

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from uvicorn import run

from src.billing.plans import plan_payload
from src.billing.stripe_client import (
    StripeAPIError,
    StripeBillingClient,
    StripeConfigError,
    StripeWebhookError,
    missing_checkout_env,
    plan_slug_for_price_id,
    price_id_for_plan,
    stripe_config_from_env,
    verify_stripe_webhook,
)
from src.config import PipelineConfig
from src.models import EmailObject
from src.orchestrator.pipeline import PhishingPipeline
from src.reporting.report_generator import ReportGenerator
from src.reporting.ioc_exporter import IOCExporter
from src.reporting.sigma_exporter import SigmaExporter
from src.reporting.dashboard import PhishingDashboard
from src.security.web_security import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    SSRFBlockedError,
    TokenVerifier,
    add_security_headers_middleware,
    default_ssrf_guard,
)
from src.security.html_sanitizer import sanitize_email_html
from src.feedback.email_lookup import EmailLookupIndex
from src.saas import (
    USER_CSRF_COOKIE_NAME,
    USER_SESSION_COOKIE_NAME,
    DuplicateEmailError,
    InvalidCredentialsError,
    PasswordResetTokenError,
    SaaSSessionManager,
    SaaSStore,
)
from src.saas.auth import USER_SESSION_MAX_AGE_SECONDS, verify_user_csrf
from src.saas.email_delivery import (
    EmailDeliveryError,
    PasswordResetEmail,
    SMTPPasswordResetMailer,
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

_STATIC_URL_RE = re.compile(
    r"(?P<attr>\b(?:href|src)=)(?P<quote>[\"'])(?P<url>/static/[^\"'?>\s]+)"
    r"(?:\?v=[^\"']*)?(?P=quote)"
)


def _asset_version_from_static_dir(static_dir: Path) -> str:
    """Return a stable cache-busting version for static asset URLs."""
    configured = (
        os.getenv("STATIC_ASSET_VERSION")
        or os.getenv("APP_BUILD_SHA")
        or os.getenv("GIT_COMMIT")
    )
    if configured:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "", configured)[:64]
        if safe:
            return safe

    newest = 0
    if static_dir.exists():
        for path in static_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                newest = max(newest, path.stat().st_mtime_ns)
            except OSError:
                continue
    return str(newest or 0)


def _tail_jsonl_records(log_path: Path, limit: int) -> list[dict]:
    """Return the newest JSONL records without reading the whole file."""
    if limit <= 0 or not log_path.exists():
        return []

    try:
        with log_path.open("r", encoding="utf-8") as fh:
            lines = deque(fh, maxlen=limit)
    except OSError as e:
        logger.warning("Failed to read monitor log %s: %s", log_path, e)
        return []

    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # Ignore partial/corrupt lines so one bad append doesn't break the UI.
            continue
    return entries


def _compact_monitor_record(record: dict) -> dict:
    """Keep only fields needed by dashboard/list views."""
    score = record.get("overall_score", record.get("score"))
    confidence = record.get("overall_confidence", record.get("confidence"))
    analyzer_results = record.get("analyzer_results")
    compact = {
        "email_id": record.get("email_id"),
        "from": record.get("from"),
        "subject": record.get("subject"),
        "verdict": record.get("verdict"),
        "score": score,
        "overall_score": score,
        "overall_confidence": confidence,
        "timestamp": record.get("timestamp", record.get("ts")),
        "quarantined": record.get("quarantined", False),
        "analyzer_count": len(analyzer_results) if isinstance(analyzer_results, dict) else 0,
    }
    if record.get("payment_protection") is not None:
        compact["payment_protection"] = record.get("payment_protection")
    return compact


def _safe_api_value(value):
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _serialize_analyzer_results(result) -> dict:
    analyzer_results = {}
    for name, ar in (result.analyzer_results or {}).items():
        details = ar.details or {}
        safe_details = {}
        for key, value in details.items():
            if key == "screenshots":
                safe_details[key] = {url: "(base64 image)" for url in (value or {})}
            elif isinstance(value, bytes):
                safe_details[key] = "(binary data)"
            else:
                safe_details[key] = value
        analyzer_results[name] = {
            "risk_score": ar.risk_score,
            "confidence": ar.confidence,
            "details": safe_details,
            "errors": ar.errors if ar.errors else None,
        }
    return analyzer_results


def _payment_protection_from_analyzers(analyzer_results: dict) -> dict | None:
    if "payment_fraud" not in analyzer_results:
        return None
    return analyzer_results["payment_fraud"].get("details")


def _extracted_urls_payload(result) -> list[dict]:
    return [
        {"url": u.url, "source": u.source.value, "source_detail": u.source_detail}
        if hasattr(u, "source")
        else {
            "url": u.url if hasattr(u, "url") else str(u),
            "source": "unknown",
            "source_detail": "",
        }
        for u in (result.extracted_urls or [])
    ]


def _headers_payload(email: EmailObject, result) -> dict:
    iocs = result.iocs or {}
    headers_raw = iocs.get("headers", {})
    if hasattr(headers_raw, "__dict__"):
        headers_out = {key: _safe_api_value(value) for key, value in vars(headers_raw).items()}
    elif isinstance(headers_raw, dict):
        headers_out = {key: _safe_api_value(value) for key, value in headers_raw.items()}
    else:
        headers_out = {}

    headers_out["from_address"] = email.from_address or ""
    headers_out["from_display_name"] = email.from_display_name or ""
    headers_out["subject"] = email.subject or ""
    headers_out["reply_to"] = email.reply_to or ""
    headers_out["to_addresses"] = email.to_addresses or []

    def _auth_str(val):
        if val is True:
            return "pass"
        if val is False:
            return "fail"
        return "unknown"

    headers_out["spf_result"] = _auth_str(headers_out.get("spf_pass"))
    headers_out["dkim_result"] = _auth_str(headers_out.get("dkim_pass"))
    headers_out["dmarc_result"] = _auth_str(headers_out.get("dmarc_pass"))
    headers_out["reply_to_mismatch"] = headers_out.get("from_reply_to_mismatch", False)
    return headers_out


def _api_payload_from_pipeline(email: EmailObject, result, timestamp: str) -> dict:
    analyzer_results = _serialize_analyzer_results(result)
    return {
        "email_id": result.email_id,
        "verdict": result.verdict.value,
        "overall_score": result.overall_score,
        "overall_confidence": result.overall_confidence,
        "timestamp": timestamp,
        "analyzer_results": analyzer_results,
        "payment_protection": _payment_protection_from_analyzers(analyzer_results),
        "extracted_urls": _extracted_urls_payload(result),
        "reasoning": result.reasoning if isinstance(result.reasoning, list) else [str(result.reasoning)],
        "iocs": {"headers": _headers_payload(email, result)},
    }


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
        session_secret = (
            getattr(self.config, "saas_session_secret", "")
            or getattr(self.config, "analyst_api_token", "")
        )
        self.saas_session_manager = SaaSSessionManager(session_secret)
        self._saas_store = None
        self._monitor = None  # set when IMAP monitor starts
        # Display-only: in-memory list of recent uploads for the monitor
        # page render. Capped at 200; NOT used for any lookup that needs
        # to survive restart. See ADR 0002 §"Why this split".
        self._upload_results: list[dict] = []
        # Persistent lookup index over data/results.jsonl. Used by the
        # feedback endpoint and /api/monitor/email/{id} to resolve
        # email_id -> record across restarts. See ADR 0002.
        self.email_index = EmailLookupIndex(jsonl_path="data/results.jsonl")

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
            try:
                result = await self.pipeline.analyze(email)
            finally:
                # Single-shot CLI run: release the pipeline's aiohttp sessions
                # so we don't leak them on process exit. The serve path keeps
                # the pipeline alive across requests and closes it on shutdown.
                await self.pipeline.close()

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

        static_dir = Path("./static")
        static_asset_version = _asset_version_from_static_dir(static_dir)
        build_sha = os.getenv("APP_BUILD_SHA") or os.getenv("GIT_COMMIT") or "unknown"
        if static_dir.exists():
            app.mount("/static", StaticFiles(directory=static_dir), name="static")
        else:
            logger.warning("Static asset directory not found; dashboard vendor assets unavailable")

        # Capture token verifier locally so route closures can reference it
        # without re-reading self.token_verifier on every request.
        require_token = self.token_verifier

        def _has_valid_html_session(request: Request) -> bool:
            if not self.token_verifier.enabled:
                return True
            return self.token_verifier.verify_session_cookie(
                request.cookies.get(SESSION_COOKIE_NAME)
            )

        def _login_redirect(request: Request) -> RedirectResponse:
            from urllib.parse import quote

            target = request.url.path
            if request.url.query:
                target += "?" + request.url.query
            return RedirectResponse(
                url=f"/login?next={quote(target, safe='/?:=&')}",
                status_code=303,
            )

        from starlette.middleware.base import BaseHTTPMiddleware

        class HTMLAuthRedirectMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                path = request.url.path
                html_path = (
                    path in {"/analyze", "/status", "/monitor", "/accounts"}
                    or path == "/dashboard"
                    or path.startswith("/dashboard/")
                )
                if (
                    request.method.upper() == "GET"
                    and html_path
                    and not path.startswith("/dashboard/api/")
                    and not _has_valid_html_session(request)
                ):
                    return _login_redirect(request)
                return await call_next(request)

        app.add_middleware(HTMLAuthRedirectMiddleware)

        # ── Shared HTML fragment (auth, theme, scrollbar) ─────────
        # Loaded once at startup, token placeholder replaced per-request.
        _shared_html_raw = Path("./templates/_shared.html").read_text(encoding="utf-8")

        def _version_static_urls(html_text: str) -> str:
            """Append the build/static version to HTML static asset references."""
            if not static_asset_version:
                return html_text

            def _replace(match: re.Match) -> str:
                attr = match.group("attr")
                quote = match.group("quote")
                url = match.group("url")
                return f"{attr}{quote}{url}?v={static_asset_version}{quote}"

            return _STATIC_URL_RE.sub(_replace, html_text)

        def _inject_shared(html: str) -> str:
            """Inject shared CSS/JS (auth, theme) before </head> in any page."""
            return _version_static_urls(
                html.replace("</head>", _shared_html_raw + "\n</head>", 1)
            )

        def _demo_enabled() -> bool:
            return bool(getattr(self.config, "public_demo_mode", False))

        def _login_success_redirect(next_path: str) -> RedirectResponse:
            if not next_path.startswith("/") or next_path.startswith("//"):
                next_path = "/dashboard"
            return RedirectResponse(url=next_path, status_code=303)

        def _normalize_analyst_token(raw_token: object) -> str:
            token = str(raw_token or "").strip()
            if token.startswith("ANALYST_API_TOKEN="):
                token = token.split("=", 1)[1].strip()
            if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
                token = token[1:-1].strip()
            return token

        def _demo_login_link() -> str:
            if not _demo_enabled():
                return ""
            return (
                '<div class="demo-entry">'
                '<a href="/demo">Open the public demo</a>'
                '<span>Live mailbox access, paid API checks, feedback learning, '
                'and account management stay locked behind analyst login.</span>'
                '</div>'
            )

        def _product_demo_nav_links() -> str:
            if not _demo_enabled():
                return ""
            return '<a href="/agent-demo">Agent demo</a><a href="/demo">Public demo</a>'

        def _product_hero_actions() -> str:
            if _demo_enabled():
                return (
                    '<a class="primary-action" href="/agent-demo">Open agent demo</a>'
                    '<a class="secondary-action" href="/app">Try the app shell</a>'
                )
            return (
                '<a class="primary-action" href="/app">Open user app</a>'
                '<a class="secondary-action" href="/login">Analyst login</a>'
            )

        def _render_login(next_path: str, error_message: str = "") -> HTMLResponse:
            login_path = Path("./templates/login.html")
            html_content = (
                login_path.read_text(encoding="utf-8")
                .replace("{{NEXT_PATH}}", html.escape(next_path, quote=True))
                .replace("{{ERROR_MESSAGE}}", html.escape(error_message, quote=True))
                .replace("{{DEMO_LINK}}", _demo_login_link())
            )
            status_code = 401 if error_message else 200
            return HTMLResponse(content=_inject_shared(html_content), status_code=status_code)

        def _is_secure_request(request: Request) -> bool:
            forwarded_proto = request.headers.get("x-forwarded-proto", "")
            scheme = (forwarded_proto.split(",")[0].strip() or request.url.scheme).lower()
            return scheme == "https"

        def _set_auth_cookies(response, request: Request) -> None:
            session_cookie = self.token_verifier.create_session_cookie()
            csrf_token = self.token_verifier.create_csrf_token()
            secure_cookie = _is_secure_request(request)
            response.set_cookie(
                SESSION_COOKIE_NAME,
                session_cookie,
                max_age=SESSION_MAX_AGE_SECONDS,
                httponly=True,
                secure=secure_cookie,
                samesite="strict",
            )
            response.set_cookie(
                CSRF_COOKIE_NAME,
                csrf_token,
                max_age=SESSION_MAX_AGE_SECONDS,
                httponly=False,
                secure=secure_cookie,
                samesite="strict",
            )

        def _get_saas_store() -> SaaSStore:
            if self._saas_store is None:
                db_path = getattr(self.config, "saas_db_path", "data/saas.db")
                self._saas_store = SaaSStore(db_path)
            return self._saas_store

        def _password_reset_mailer() -> SMTPPasswordResetMailer:
            return SMTPPasswordResetMailer(getattr(self.config, "smtp", None))

        password_reset_attempts: dict[str, deque[float]] = {}

        def _check_password_reset_rate_limit(request: Request, email: str) -> None:
            window_seconds = 3600
            max_attempts = 5
            client_host = request.client.host if request.client else "unknown"
            key = f"{client_host}:{email.strip().lower()}"
            now = monotonic()
            attempts = password_reset_attempts.setdefault(key, deque())
            while attempts and now - attempts[0] > window_seconds:
                attempts.popleft()
            if len(attempts) >= max_attempts:
                raise HTTPException(
                    status_code=429,
                    detail="Too many password reset requests. Try again later.",
                )
            attempts.append(now)

        def _set_user_auth_cookies(response, request: Request, context) -> None:
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            session_cookie = self.saas_session_manager.create_session_cookie(
                user_id=context.user_id,
                email=context.email,
                org_id=context.org_id,
            )
            csrf_token = self.saas_session_manager.create_csrf_token()
            secure_cookie = _is_secure_request(request)
            response.set_cookie(
                USER_SESSION_COOKIE_NAME,
                session_cookie,
                max_age=USER_SESSION_MAX_AGE_SECONDS,
                httponly=True,
                secure=secure_cookie,
                samesite="strict",
            )
            response.set_cookie(
                USER_CSRF_COOKIE_NAME,
                csrf_token,
                max_age=USER_SESSION_MAX_AGE_SECONDS,
                httponly=False,
                secure=secure_cookie,
                samesite="strict",
            )

        def _clear_user_auth_cookies(response) -> None:
            response.delete_cookie(USER_SESSION_COOKIE_NAME)
            response.delete_cookie(USER_CSRF_COOKIE_NAME)

        def _current_user_context(request: Request, *, require_csrf: bool = False):
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            if require_csrf:
                verify_user_csrf(request)
            payload = self.saas_session_manager.session_payload(
                request.cookies.get(USER_SESSION_COOKIE_NAME)
            )
            if payload is None:
                raise HTTPException(status_code=401, detail="User login required")
            context = _get_saas_store().get_account_context(str(payload["sub"]))
            if context is None or context.org_id != payload.get("org_id"):
                raise HTTPException(status_code=401, detail="User login required")
            return context

        def _saas_session_payload(request: Request) -> dict:
            if not self.saas_session_manager.enabled:
                return {
                    "auth_enabled": False,
                    "authenticated": False,
                    "public_signup_enabled": bool(
                        getattr(self.config, "saas_public_signup_enabled", False)
                    ),
                    "account": None,
                }
            payload = self.saas_session_manager.session_payload(
                request.cookies.get(USER_SESSION_COOKIE_NAME)
            )
            context = _get_saas_store().get_account_context(str(payload["sub"])) if payload else None
            return {
                "auth_enabled": True,
                "authenticated": context is not None,
                "public_signup_enabled": bool(
                    getattr(self.config, "saas_public_signup_enabled", False)
                ),
                "account": context.to_dict() if context else None,
                "csrf_cookie": USER_CSRF_COOKIE_NAME,
                "csrf_header": "x-csrf-token",
            }

        def _external_url(request: Request, path: str) -> str:
            base_url = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
            if base_url:
                return f"{base_url}{path}"
            forwarded_proto = request.headers.get("x-forwarded-proto", "")
            forwarded_host = request.headers.get("x-forwarded-host", "")
            scheme = (forwarded_proto.split(",")[0].strip() or request.url.scheme).lower()
            host = (
                forwarded_host.split(",")[0].strip()
                or request.headers.get("host")
                or request.url.netloc
            )
            return f"{scheme}://{host}{path}"

        async def _json_object_body(request: Request) -> dict:
            try:
                payload = await request.json()
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
            if not isinstance(payload, dict):
                raise HTTPException(status_code=400, detail="JSON object body required")
            return payload

        def _stripe_subscription_price_id(subscription: dict) -> str | None:
            items = subscription.get("items") or {}
            data = items.get("data") if isinstance(items, dict) else []
            if not data:
                return None
            price = (data[0] or {}).get("price") or {}
            return price.get("id")

        def _stripe_period_end_iso(subscription: dict) -> str | None:
            raw = subscription.get("current_period_end")
            if not raw:
                return None
            try:
                from datetime import datetime, timezone
                return datetime.fromtimestamp(int(raw), tz=timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                return None

        def _metadata_value(payload: dict, key: str) -> str:
            metadata = payload.get("metadata")
            if isinstance(metadata, dict):
                return str(metadata.get(key, "") or "")
            return ""

        def _resolve_stripe_org_id(store: SaaSStore, payload: dict) -> str | None:
            org_id = _metadata_value(payload, "org_id") or str(payload.get("client_reference_id", "") or "")
            if org_id:
                return org_id
            customer_id = str(payload.get("customer", "") or "")
            if customer_id:
                by_customer = store.get_org_id_for_stripe_customer(customer_id)
                if by_customer:
                    return by_customer
            subscription_id = str(payload.get("subscription", "") or payload.get("id", "") or "")
            if subscription_id:
                return store.get_org_id_for_stripe_subscription(subscription_id)
            return None

        def _apply_stripe_subscription(store: SaaSStore, subscription: dict) -> bool:
            org_id = _resolve_stripe_org_id(store, subscription)
            if not org_id:
                logger.warning("Stripe subscription event has no matching organization")
                return False
            price_id = _stripe_subscription_price_id(subscription)
            plan_slug = (
                _metadata_value(subscription, "plan_slug")
                or (plan_slug_for_price_id(price_id) if price_id else None)
            )
            if not plan_slug:
                logger.warning("Stripe subscription event has unknown price %s", price_id)
                return False
            store.set_subscription(
                org_id=org_id,
                plan_slug=plan_slug,
                status=str(subscription.get("status", "") or "incomplete"),
                stripe_customer_id=str(subscription.get("customer", "") or "") or None,
                stripe_subscription_id=str(subscription.get("id", "") or "") or None,
                current_period_end=_stripe_period_end_iso(subscription),
            )
            return True

        def _handle_stripe_event(event: dict) -> dict:
            store = _get_saas_store()
            event_type = str(event.get("type", ""))
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            obj = data.get("object") if isinstance(data, dict) else {}
            if not isinstance(obj, dict):
                return {"processed": False, "reason": "event object missing"}

            if event_type == "checkout.session.completed":
                org_id = _resolve_stripe_org_id(store, obj)
                plan_slug = _metadata_value(obj, "plan_slug")
                customer_id = str(obj.get("customer", "") or "")
                subscription_id = str(obj.get("subscription", "") or "")
                if not org_id or not plan_slug:
                    logger.warning("Checkout session completed without org or plan metadata")
                    return {"processed": False, "reason": "missing metadata"}
                store.set_subscription(
                    org_id=org_id,
                    plan_slug=plan_slug,
                    status="active",
                    stripe_customer_id=customer_id or None,
                    stripe_subscription_id=subscription_id or None,
                    current_period_end=None,
                )
                return {"processed": True, "event_type": event_type}

            if event_type in {
                "customer.subscription.created",
                "customer.subscription.updated",
                "customer.subscription.deleted",
            }:
                return {
                    "processed": _apply_stripe_subscription(store, obj),
                    "event_type": event_type,
                }

            return {"processed": False, "event_type": event_type}

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request, next: str = "/dashboard"):
            """Serve the dashboard login page."""
            if _has_valid_html_session(request):
                return _login_success_redirect(next)
            return _render_login(next)

        @app.post("/login")
        async def login_submit(request: Request):
            """Accept the analyst token and set browser session cookies."""
            form = await request.form()
            token = _normalize_analyst_token(form.get("token", ""))
            next_path = str(form.get("next", "/dashboard"))
            if not self.token_verifier.enabled or token != self.token_verifier.expected_token:
                return _render_login(next_path, "Invalid analyst token")
            response = _login_success_redirect(next_path)
            _set_auth_cookies(response, request)
            return response

        @app.post("/api/auth/login")
        async def api_login(request: Request):
            payload = await _json_object_body(request)
            token = _normalize_analyst_token(payload.get("token", ""))
            if not self.token_verifier.enabled or token != self.token_verifier.expected_token:
                raise HTTPException(status_code=401, detail="Invalid analyst token")
            response = JSONResponse({"status": "ok"})
            _set_auth_cookies(response, request)
            return response

        @app.post("/api/auth/logout", dependencies=[Depends(require_token)])
        async def api_logout():
            response = JSONResponse({"status": "ok"})
            response.delete_cookie(SESSION_COOKIE_NAME)
            response.delete_cookie(CSRF_COOKIE_NAME)
            return response

        @app.get("/api/auth/session")
        async def api_session(request: Request):
            """Return browser session state for dashboard UI polish."""
            if not self.token_verifier.enabled:
                return {
                    "auth_enabled": False,
                    "authenticated": True,
                    "expires_at": None,
                    "max_age_seconds": SESSION_MAX_AGE_SECONDS,
                    "public_demo_mode": _demo_enabled(),
                }
            payload = self.token_verifier.session_payload(
                request.cookies.get(SESSION_COOKIE_NAME)
            )
            return {
                "auth_enabled": True,
                "authenticated": payload is not None,
                "expires_at": payload.get("exp") if payload else None,
                "max_age_seconds": SESSION_MAX_AGE_SECONDS,
                "public_demo_mode": _demo_enabled(),
            }

        @app.get("/app", response_class=HTMLResponse)
        async def saas_app_page():
            """Serve the user-login SaaS shell."""
            app_path = Path("./templates/saas_app.html")
            return HTMLResponse(content=_inject_shared(
                app_path.read_text(encoding="utf-8")
            ))

        @app.get("/product", response_class=HTMLResponse)
        async def product_page():
            """Serve the public product shell for the payment scam firewall."""
            product_path = Path("./templates/product.html")
            html_content = (
                product_path.read_text(encoding="utf-8")
                .replace("{{DEMO_NAV_LINKS}}", _product_demo_nav_links())
                .replace("{{HERO_ACTIONS}}", _product_hero_actions())
            )
            return HTMLResponse(content=_inject_shared(
                html_content
            ))

        @app.get("/api/saas/session")
        async def api_saas_session(request: Request):
            """Return normal-user session, plan, and signup state."""
            return _saas_session_payload(request)

        @app.post("/api/saas/auth/signup")
        async def api_saas_signup(request: Request):
            """Create a free-tier user account when public signup is enabled."""
            if not getattr(self.config, "saas_public_signup_enabled", False):
                raise HTTPException(
                    status_code=403,
                    detail="Public signup is not enabled on this deployment",
                )
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            payload = await _json_object_body(request)
            email = str(payload.get("email", ""))
            password = str(payload.get("password", ""))
            org_name = str(payload.get("org_name", "") or "")
            try:
                context = _get_saas_store().create_user_with_org(
                    email=email,
                    password=password,
                    org_name=org_name or None,
                    plan_slug="free",
                )
            except DuplicateEmailError:
                raise HTTPException(status_code=409, detail="An account already exists for this email")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

            response = JSONResponse({"status": "ok", "account": context.to_dict()})
            _set_user_auth_cookies(response, request, context)
            return response

        @app.post("/api/saas/auth/login")
        async def api_saas_login(request: Request):
            """Log in a normal SaaS user with email/password."""
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            payload = await _json_object_body(request)
            try:
                context = _get_saas_store().authenticate(
                    str(payload.get("email", "")),
                    str(payload.get("password", "")),
                )
            except InvalidCredentialsError:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            response = JSONResponse({"status": "ok", "account": context.to_dict()})
            _set_user_auth_cookies(response, request, context)
            return response

        @app.post("/api/saas/auth/password-reset/request")
        async def api_saas_password_reset_request(request: Request):
            """Request a password reset email without leaking account existence."""
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            payload = await _json_object_body(request)
            email = str(payload.get("email", "")).strip()
            if not email:
                raise HTTPException(status_code=400, detail="Email is required")
            _check_password_reset_rate_limit(request, email)

            mailer = _password_reset_mailer()
            delivery_configured = mailer.enabled
            if delivery_configured:
                token = _get_saas_store().create_password_reset_token(
                    email,
                    ttl_minutes=getattr(self.config, "password_reset_token_ttl_minutes", 30),
                )
                if token:
                    from urllib.parse import quote
                    ttl_minutes = getattr(self.config, "password_reset_token_ttl_minutes", 30)
                    reset_url = _external_url(request, f"/app?reset_token={quote(token)}")
                    try:
                        mailer.send_password_reset(
                            PasswordResetEmail(
                                to_email=email,
                                reset_url=reset_url,
                                ttl_minutes=ttl_minutes,
                            )
                        )
                    except EmailDeliveryError as exc:
                        logger.warning("Password reset email delivery failed: %s", exc)
                        raise HTTPException(
                            status_code=503,
                            detail="Password reset email could not be sent",
                        ) from exc

            return {
                "status": "ok",
                "email_delivery_configured": delivery_configured,
                "message": (
                    "If this email belongs to an account, a password reset link "
                    "will be sent."
                ),
            }

        @app.post("/api/saas/auth/password-reset/confirm")
        async def api_saas_password_reset_confirm(request: Request):
            """Set a new password from a one-time reset token."""
            if not self.saas_session_manager.enabled:
                raise HTTPException(
                    status_code=503,
                    detail="User sessions are not configured on this server",
                )
            payload = await _json_object_body(request)
            token = str(payload.get("token", "")).strip()
            new_password = str(payload.get("password", ""))
            if not token:
                raise HTTPException(status_code=400, detail="Reset token is required")
            try:
                context = _get_saas_store().reset_password_with_token(token, new_password)
            except PasswordResetTokenError:
                raise HTTPException(status_code=400, detail="Invalid or expired reset link")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

            response = JSONResponse({"status": "ok", "account": context.to_dict()})
            _set_user_auth_cookies(response, request, context)
            return response

        @app.post("/api/saas/auth/logout")
        async def api_saas_logout(request: Request):
            """Log out a normal SaaS user."""
            _current_user_context(request, require_csrf=True)
            response = JSONResponse({"status": "ok"})
            _clear_user_auth_cookies(response)
            return response

        @app.get("/api/saas/plans")
        async def api_saas_plans(request: Request):
            """Return plan catalog and account-scoped usage for a signed-in user."""
            context = _current_user_context(request)
            payload = plan_payload(current_plan=context.plan_slug)
            payload["usage"] = {
                "manual_scan": {
                    "used": context.monthly_scan_used,
                    "quota": context.monthly_scan_quota,
                    "remaining": context.monthly_scan_remaining,
                }
            }
            payload["account"] = context.to_dict()
            return payload

        @app.get("/api/saas/scans")
        async def api_saas_scans(request: Request, limit: int = Query(20, ge=1, le=100)):
            """Return tenant-scoped scan history for the signed-in user's organization."""
            context = _current_user_context(request)
            return {
                "account": context.to_dict(),
                "results": _get_saas_store().list_scan_results(context.org_id, limit=limit),
            }

        @app.post("/api/saas/billing/checkout")
        async def api_saas_billing_checkout(request: Request):
            """Create a Stripe Checkout Session for a subscription upgrade."""
            context = _current_user_context(request, require_csrf=True)
            payload = await _json_object_body(request)
            target_plan = str(payload.get("plan", "")).strip().lower()
            try:
                from src.billing.plans import get_plan
                plan = get_plan(target_plan)
            except KeyError:
                raise HTTPException(status_code=400, detail="Unknown plan")
            if plan.slug == "free":
                raise HTTPException(status_code=400, detail="Free does not need checkout")

            missing = missing_checkout_env(plan, os.environ)
            if missing:
                return JSONResponse(
                    status_code=503,
                    content={
                        "billing_available": False,
                        "reason": "Stripe Billing is not configured on this deployment.",
                        "missing_env": missing,
                        "recommended_integration": (
                            "Stripe Billing + Checkout Sessions in subscription mode, "
                            "then mirror webhook subscription state into the database."
                        ),
                        "account": context.to_dict(),
                    },
                )

            store = _get_saas_store()
            try:
                price_id = price_id_for_plan(plan, os.environ)
                stripe_config = stripe_config_from_env(os.environ)
                stripe_client = StripeBillingClient(stripe_config.secret_key)
                customer_id = context.stripe_customer_id
                if not customer_id:
                    customer = stripe_client.create_customer(
                        email=context.email,
                        name=context.org_name,
                        metadata={"org_id": context.org_id, "user_id": context.user_id},
                    )
                    customer_id = str(customer.get("id", "") or "")
                    if not customer_id:
                        raise StripeAPIError("Stripe did not return a customer ID")
                    store.set_org_stripe_customer(
                        org_id=context.org_id,
                        stripe_customer_id=customer_id,
                    )

                session = stripe_client.create_checkout_session(
                    customer_id=customer_id,
                    price_id=price_id,
                    org_id=context.org_id,
                    user_id=context.user_id,
                    plan_slug=plan.slug,
                    success_url=_external_url(
                        request,
                        "/app?billing=success&session_id={CHECKOUT_SESSION_ID}",
                    ),
                    cancel_url=_external_url(request, "/app?billing=cancelled"),
                )
                if not session.get("id") or not session.get("url"):
                    raise StripeAPIError("Stripe did not return a Checkout Session URL")
            except StripeConfigError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except StripeAPIError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"Stripe Billing request failed: {exc}",
                ) from exc

            updated_context = store.get_account_context(context.user_id) or context
            return {
                "billing_available": True,
                "checkout_url": session.get("url"),
                "session_id": session.get("id"),
                "plan": plan.slug,
                "account": updated_context.to_dict(),
            }

        @app.post("/api/saas/billing/portal")
        async def api_saas_billing_portal(request: Request):
            """Create a short-lived Stripe Customer Portal session."""
            context = _current_user_context(request, require_csrf=True)
            if not context.stripe_customer_id:
                raise HTTPException(
                    status_code=409,
                    detail="This organization has no Stripe customer yet. Start checkout first.",
                )
            try:
                stripe_config = stripe_config_from_env(os.environ)
                stripe_client = StripeBillingClient(stripe_config.secret_key)
                portal = stripe_client.create_portal_session(
                    customer_id=context.stripe_customer_id,
                    return_url=_external_url(request, "/app?billing=portal"),
                )
                if not portal.get("url"):
                    raise StripeAPIError("Stripe did not return a Customer Portal URL")
            except StripeConfigError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except StripeAPIError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"Stripe Customer Portal request failed: {exc}",
                ) from exc

            return {
                "billing_available": True,
                "portal_url": portal.get("url"),
                "account": context.to_dict(),
            }

        @app.post("/api/stripe/webhook")
        async def api_stripe_webhook(request: Request):
            """Verify Stripe webhook signatures and mirror subscription state."""
            stripe_config = stripe_config_from_env(os.environ)
            raw_body = await request.body()
            try:
                event = verify_stripe_webhook(
                    raw_body,
                    request.headers.get("stripe-signature"),
                    stripe_config.webhook_secret,
                )
                result = _handle_stripe_event(event)
            except StripeConfigError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except StripeWebhookError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            return {"received": True, **result}

        @app.post("/api/saas/analyze/upload")
        async def api_saas_analyze_upload(request: Request, file: UploadFile = File(...)):
            """Analyze an uploaded email for a signed-in user with plan gates."""
            context = _current_user_context(request, require_csrf=True)
            store = _get_saas_store()
            scan_access = store.check_entitlement(
                org_id=context.org_id,
                user_id=context.user_id,
                feature_slug="manual_scan",
                enforce_scan_quota=True,
            )
            if not scan_access.available:
                return JSONResponse(status_code=402, content={"locked": scan_access.to_dict()})

            raw = await file.read()
            if not raw:
                raise HTTPException(status_code=400, detail="Empty file uploaded")

            from src.extractors.eml_parser import EMLParser
            parser = EMLParser()
            email = parser.parse_bytes(raw)
            if email is None:
                raise HTTPException(status_code=422, detail="Could not parse email file")

            def feature_gate(feature_slug: str) -> dict:
                return store.check_entitlement(
                    org_id=context.org_id,
                    user_id=context.user_id,
                    feature_slug=feature_slug,
                    enforce_scan_quota=False,
                ).to_dict()

            from datetime import datetime, timezone
            scan_job_id = store.create_scan_job(
                org_id=context.org_id,
                user_id=context.user_id,
                source="manual_upload",
            )
            try:
                result = await self.pipeline.analyze(email, feature_gate=feature_gate)
                timestamp = datetime.now(timezone.utc).isoformat()
                response_payload = _api_payload_from_pipeline(email, result, timestamp)
                payment = response_payload.get("payment_protection") or {}
                store.record_usage_event(
                    org_id=context.org_id,
                    user_id=context.user_id,
                    feature_slug="manual_scan",
                    quantity=1,
                    idempotency_key=scan_job_id,
                )
                store.record_scan_result(
                    org_id=context.org_id,
                    user_id=context.user_id,
                    scan_job_id=scan_job_id,
                    email_id=result.email_id,
                    verdict=result.verdict.value,
                    payment_decision=payment.get("decision") if isinstance(payment, dict) else None,
                    result=response_payload,
                )
                store.complete_scan_job(scan_job_id, "completed")
            except Exception:
                store.complete_scan_job(scan_job_id, "failed")
                raise

            updated_context = store.get_account_context(context.user_id)
            response_payload["account"] = updated_context.to_dict() if updated_context else context.to_dict()
            response_payload["feature_locks"] = [
                item
                for item in response_payload["analyzer_results"].values()
                if (item.get("details") or {}).get("message") == "feature_locked"
            ]
            return response_payload

        @app.get("/demo", response_class=HTMLResponse)
        async def public_demo():
            """Serve the safe public demo page without opening analyst APIs."""
            if not _demo_enabled():
                return RedirectResponse(url="/product", status_code=303)
            demo_path = Path("./templates/demo.html")
            return HTMLResponse(content=_inject_shared(
                demo_path.read_text(encoding="utf-8")
            ))

        @app.get("/agent-demo", response_class=HTMLResponse)
        async def agent_demo():
            """Serve the sample-only agent payment analysis page."""
            if not _demo_enabled():
                return RedirectResponse(url="/product", status_code=303)
            demo_path = Path("./templates/agent_demo.html")
            return HTMLResponse(content=_inject_shared(
                demo_path.read_text(encoding="utf-8")
            ))

        @app.get("/api/demo/status")
        async def api_demo_status():
            """Return public demo limitations. Never exposes mailbox or paid API data."""
            if not _demo_enabled():
                raise HTTPException(status_code=404, detail="Public demo mode is not enabled")
            return {
                "demo_mode": True,
                "paid_api_access": False,
                "live_analysis_enabled": False,
                "mailbox_access_enabled": False,
                "feedback_learning_enabled": False,
                "account_management_enabled": False,
                "user_mailboxes": "not_connected_in_public_demo",
                "message": (
                    "Public demo mode uses fixed sample content only. Analyst login is "
                    "required for live analysis, mailbox monitoring, paid API-backed "
                    "checks, feedback learning, agent uploads, and account management."
                ),
            }

        @app.get("/api/demo/agent-payment-analysis")
        async def api_demo_agent_payment_analysis(
            decision: str | None = Query(default=None),
        ):
            """Return fixed sample agent-tool outputs for the public demo page."""
            if not _demo_enabled():
                raise HTTPException(status_code=404, detail="Public demo mode is not enabled")
            allowed_decisions = {"SAFE", "VERIFY", "DO_NOT_PAY"}
            if decision is not None and decision not in allowed_decisions:
                raise HTTPException(status_code=400, detail="Unknown payment decision")
            try:
                from src.agent_tools.payment_email import analyze_demo_payment_samples

                return await analyze_demo_payment_samples(decision=decision)
            except Exception as exc:
                logger.warning("Agent demo sample analysis failed: %s", exc)
                raise HTTPException(
                    status_code=503,
                    detail="Agent demo samples are unavailable",
                ) from exc

        @app.get("/api/demo/plans")
        async def api_demo_plans():
            """Return public, non-secret plan and feature-lock metadata."""
            if not _demo_enabled():
                raise HTTPException(status_code=404, detail="Public demo mode is not enabled")
            return plan_payload(current_plan="free")

        @app.get("/", response_class=HTMLResponse)
        async def public_home():
            """Send visitors to the public product page, not the analyst console."""
            return RedirectResponse(url="/product", status_code=303)

        @app.get("/analyze", response_class=HTMLResponse)
        async def index():
            """Serve the main upload/analyze page."""
            index_path = Path("./templates/index.html")
            return HTMLResponse(content=_inject_shared(
                index_path.read_text(encoding="utf-8")
            ))

        @app.post("/api/analyze/upload", dependencies=[Depends(require_token)])
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

                payment_protection = None
                if "payment_fraud" in analyzer_results:
                    payment_protection = analyzer_results["payment_fraud"].get("details")

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
                    "payment_protection": payment_protection,
                    "extracted_urls": extracted_urls_list,
                    "reasoning": reasoning_text,
                    "body_preview": (email.body_plain or "")[:2000],
                    # body_html is attacker-controlled. Sanitize server-side
                    # (script/style/iframe/event-handlers stripped) BEFORE it
                    # ever reaches the dashboard. The dashboard ALSO wraps it
                    # in a sandboxed `<iframe srcdoc>` with no allow flags as
                    # the actual security boundary; this is defense in depth.
                    # See src/security/html_sanitizer.py for the policy.
                    "body_html": sanitize_email_html(email.body_html or "")[:5000],
                }

                # Store in upload results for monitor page
                self._upload_results.append(monitor_record)
                if len(self._upload_results) > 200:
                    self._upload_results.pop(0)

                # Also write to results.jsonl for the Full Log tab AND
                # update the persistent email_id lookup index so the
                # feedback endpoint can resolve this email's sender
                # across restarts. See ADR 0002.
                try:
                    import json as _json
                    log_path = Path("data/results.jsonl")
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(log_path, "ab") as f:
                        line_offset = f.tell()
                        f.write(
                            _json.dumps(monitor_record, default=str).encode("utf-8")
                            + b"\n"
                        )
                    self.email_index.add(result.email_id, line_offset)
                except Exception as _log_err:
                    logger.warning(f"Failed to write result to log: {_log_err}")

                return {
                    "email_id": result.email_id,
                    "verdict": result.verdict.value,
                    "overall_score": result.overall_score,
                    "overall_confidence": result.overall_confidence,
                    "timestamp": timestamp,
                    "analyzer_results": analyzer_results,
                    "payment_protection": payment_protection,
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
                "build_sha": build_sha,
                "static_asset_version": static_asset_version,
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

            Implementation lives in src/diagnostics/api_checks.py — single
            source of truth shared with diagnose_apis.py CLI tool. Cycle 10
            audit item #10 closed the three-way duplication that previously
            existed here.
            """
            from src.diagnostics import run_all_checks
            from src.diagnostics.api_checks import summarize

            results = await run_all_checks(config_api=self.config.api)
            return {
                "summary": summarize(results)["headline"],
                "services": {r.service: r.to_dict() for r in results},
                "notes": {
                    "url_detonation": "not implemented (no browser sandbox)",
                    "urlscan": "works but fire-and-forget design means confidence=0 always",
                },
            }

        @app.get("/status", response_class=HTMLResponse)
        async def status_page():
            """Serve the API/system status page."""
            status_path = Path("./templates/status.html")
            return HTMLResponse(content=_inject_shared(
                status_path.read_text(encoding="utf-8")
            ))

        @app.get("/api/config", dependencies=[Depends(require_token)])
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
            return HTMLResponse(content=_inject_shared(
                monitor_path.read_text(encoding="utf-8")
            ))

        @app.get("/api/monitor/stats", dependencies=[Depends(require_token)])
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

        @app.get("/api/monitor/log", dependencies=[Depends(require_token)])
        async def monitor_log(
            limit: int = Query(100, ge=1, le=2000),
            compact: bool = False,
        ):
            """Return recent results from the JSONL log file."""
            log_path = Path("data/results.jsonl")
            entries = _tail_jsonl_records(log_path, limit)
            if compact:
                entries = [_compact_monitor_record(entry) for entry in entries]
            return {"entries": entries, "count": len(entries)}

        @app.get("/api/monitor/email/{email_id}", dependencies=[Depends(require_token)])
        async def monitor_email_detail(email_id: str):
            """Return full details for a specific analyzed email."""
            # IMAP monitor results live in memory only (no persistence
            # for that path yet) — try them first.
            if self._monitor is not None:
                for record in reversed(self._monitor._recent_results):
                    if record.get("email_id") == email_id:
                        return record

            # Persistent lookup: ADR 0002. Survives restart and the
            # 200-cap roll on _upload_results.
            indexed = self.email_index.lookup(email_id)
            if indexed is not None:
                return indexed

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
            payload = await _json_object_body(request)
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

        @app.get("/api/monitor/alerts", dependencies=[Depends(require_token)])
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
            return HTMLResponse(content=_inject_shared(
                accounts_path.read_text(encoding="utf-8")
            ))

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

            payload = await _json_object_body(request)
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
            payload = await _json_object_body(request)
            email_or_type = payload.get("email") or payload.get("identifier", "")
            if not email_or_type:
                raise HTTPException(status_code=400, detail="email or identifier required")
            remove_account_from_file(email_or_type)
            return {"status": "removed", "identifier": email_or_type}

        @app.post("/api/accounts/browse", dependencies=[Depends(require_token)])
        async def api_browse_inbox(request: Request):
            """
            Browse an email inbox without storing anything.

            Connects to IMAP, fetches recent email headers (Subject, From,
            Date, UID), and returns them as a scannable list. The caller
            can then POST selected UIDs to /api/accounts/analyze-selected.
            """
            import imaplib, ssl, email as email_mod
            from email.utils import parsedate_to_datetime

            payload = await _json_object_body(request)
            host = payload.get("host", "").strip()
            user = payload.get("user", "").strip()
            password = payload.get("password", "")
            port = int(payload.get("port", 993))
            folder = payload.get("folder", "INBOX")
            limit = min(int(payload.get("limit", 50)), 100)

            if not all([host, user, password]):
                raise HTTPException(status_code=400, detail="host, user, and password required")

            conn = None
            try:
                ctx = ssl.create_default_context()
                conn = imaplib.IMAP4_SSL(host=host, port=port, ssl_context=ctx)
                conn.login(user, password)
                status, _ = conn.select(folder, readonly=True)
                if status != "OK":
                    raise HTTPException(status_code=400, detail=f"Cannot open folder: {folder}")

                # Fetch recent UIDs (last 7 days)
                from datetime import datetime, timedelta, timezone
                since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%d-%b-%Y")
                status, data = conn.uid("search", None, f"(SINCE {since})")
                if status != "OK":
                    return {"emails": [], "total": 0}

                uids = data[0].decode().split()
                # Take the most recent ones
                uids = uids[-limit:] if len(uids) > limit else uids
                uids.reverse()  # newest first

                emails = []
                if uids:
                    uid_range = ",".join(uids)
                    status, data = conn.uid(
                        "fetch", uid_range,
                        "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] RFC822.SIZE)"
                    )
                    if status == "OK" and data:
                        i = 0
                        while i < len(data):
                            item = data[i]
                            if isinstance(item, tuple) and len(item) == 2:
                                meta_line = item[0].decode("utf-8", errors="replace") if isinstance(item[0], bytes) else str(item[0])
                                header_bytes = item[1]

                                # Parse UID from response
                                uid_match = None
                                import re
                                uid_m = re.search(r'UID\s+(\d+)', meta_line)
                                if uid_m:
                                    uid_match = uid_m.group(1)

                                # Parse size
                                size = 0
                                size_m = re.search(r'RFC822\.SIZE\s+(\d+)', meta_line)
                                if size_m:
                                    size = int(size_m.group(1))

                                # Parse headers
                                msg = email_mod.message_from_bytes(header_bytes)
                                from_addr = msg.get("From", "")
                                subject = msg.get("Subject", "(no subject)")
                                date_str = msg.get("Date", "")

                                # Decode encoded headers
                                from email.header import decode_header
                                try:
                                    parts = decode_header(subject)
                                    subject = "".join(
                                        p.decode(c or "utf-8", errors="replace") if isinstance(p, bytes) else p
                                        for p, c in parts
                                    )
                                except Exception:
                                    pass
                                try:
                                    parts = decode_header(from_addr)
                                    from_addr = "".join(
                                        p.decode(c or "utf-8", errors="replace") if isinstance(p, bytes) else p
                                        for p, c in parts
                                    )
                                except Exception:
                                    pass

                                # Parse date
                                date_iso = ""
                                try:
                                    date_iso = parsedate_to_datetime(date_str).isoformat()
                                except Exception:
                                    date_iso = date_str

                                emails.append({
                                    "uid": uid_match or "?",
                                    "from": from_addr,
                                    "subject": subject,
                                    "date": date_iso,
                                    "size": size,
                                })
                            i += 1

                return {"emails": emails, "total": len(uids), "folder": folder}

            except imaplib.IMAP4.error as e:
                raise HTTPException(status_code=401, detail=f"IMAP error: {e}")
            except Exception as e:
                logger.error(f"Browse inbox failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
            finally:
                if conn:
                    try:
                        conn.close()
                        conn.logout()
                    except Exception:
                        pass

        @app.post("/api/accounts/analyze-selected", dependencies=[Depends(require_token)])
        async def api_analyze_selected(request: Request):
            """
            Analyze specific emails by UID from an IMAP account.

            Fetches full RFC822 for each selected UID, runs through the
            pipeline, and stores results — same as the monitor would.
            """
            import imaplib, ssl

            payload = await _json_object_body(request)
            host = payload.get("host", "").strip()
            user = payload.get("user", "").strip()
            password = payload.get("password", "")
            port = int(payload.get("port", 993))
            folder = payload.get("folder", "INBOX")
            uids = payload.get("uids", [])

            if not all([host, user, password]):
                raise HTTPException(status_code=400, detail="host, user, and password required")
            if not uids:
                raise HTTPException(status_code=400, detail="No emails selected (uids required)")
            if len(uids) > 20:
                raise HTTPException(status_code=400, detail="Maximum 20 emails per batch")

            conn = None
            results = []
            try:
                ctx = ssl.create_default_context()
                conn = imaplib.IMAP4_SSL(host=host, port=port, ssl_context=ctx)
                conn.login(user, password)
                conn.select(folder, readonly=True)

                from src.extractors.eml_parser import EMLParser
                parser = EMLParser()

                for uid in uids:
                    try:
                        status, data = conn.uid("fetch", str(uid), "(RFC822)")
                        if status != "OK" or not data or data[0] is None:
                            results.append({"uid": uid, "error": "Failed to fetch"})
                            continue

                        raw_bytes = data[0][1]
                        if isinstance(raw_bytes, str):
                            raw_bytes = raw_bytes.encode("utf-8", errors="replace")

                        email_obj = parser.parse_bytes(raw_bytes)
                        if email_obj is None:
                            results.append({"uid": uid, "error": "Failed to parse"})
                            continue

                        result = await self.pipeline.analyze(email_obj)

                        # Build monitor-compatible record (same as upload path)
                        from datetime import datetime, timezone

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

                        payment_protection = None
                        if "payment_fraud" in analyzer_results:
                            payment_protection = analyzer_results["payment_fraud"].get("details")

                        extracted_urls_list = [
                            {"url": u.url, "source": u.source.value, "source_detail": u.source_detail}
                            if hasattr(u, 'source') else {"url": u.url if hasattr(u, 'url') else str(u), "source": "unknown", "source_detail": ""}
                            for u in (result.extracted_urls or [])
                        ]

                        timestamp = datetime.now(timezone.utc).isoformat()
                        monitor_record = {
                            "timestamp": timestamp,
                            "email_id": result.email_id,
                            "account": user,
                            "provider": "imap-browse",
                            "from": email_obj.from_address or "unknown",
                            "display_name": email_obj.from_display_name or "",
                            "reply_to": email_obj.reply_to or "",
                            "to": email_obj.to_addresses or [],
                            "subject": email_obj.subject or "",
                            "verdict": result.verdict.value,
                            "score": result.overall_score,
                            "confidence": result.overall_confidence,
                            "quarantined": False,
                            "analyzer_results": analyzer_results,
                            "payment_protection": payment_protection,
                            "extracted_urls": extracted_urls_list,
                            "reasoning": result.reasoning if isinstance(result.reasoning, str) else str(result.reasoning),
                            "body_preview": (email_obj.body_plain or "")[:2000],
                            "body_html": sanitize_email_html(email_obj.body_html or "")[:5000],
                        }

                        # Store
                        self._upload_results.append(monitor_record)
                        if len(self._upload_results) > 200:
                            self._upload_results.pop(0)

                        try:
                            import json as _json
                            log_path = Path("data/results.jsonl")
                            log_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(log_path, "ab") as f:
                                line_offset = f.tell()
                                f.write(_json.dumps(monitor_record, default=str).encode("utf-8") + b"\n")
                            self.email_index.add(result.email_id, line_offset)
                        except Exception as _log_err:
                            logger.warning(f"Failed to write result to log: {_log_err}")

                        results.append({
                            "uid": uid,
                            "email_id": result.email_id,
                            "verdict": result.verdict.value,
                            "score": result.overall_score,
                            "subject": email_obj.subject or "",
                            "from": email_obj.from_address or "",
                            "payment_protection": payment_protection,
                        })

                    except Exception as e:
                        logger.error(f"Failed to analyze UID {uid}: {e}", exc_info=True)
                        results.append({"uid": uid, "error": str(e)})

                return {"results": results, "analyzed": len([r for r in results if "verdict" in r])}

            except imaplib.IMAP4.error as e:
                raise HTTPException(status_code=401, detail=f"IMAP error: {e}")
            except Exception as e:
                logger.error(f"Analyze selected failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
            finally:
                if conn:
                    try:
                        conn.close()
                        conn.logout()
                    except Exception:
                        pass

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
                payload = await _json_object_body(request)
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
                        # False negative — resolve sender via the
                        # persistent lookup index (ADR 0002). Survives
                        # restart and 200-cap roll. The previous
                        # in-memory scan silently no-op'd after restart;
                        # see audit #9.
                        indexed_record = self.email_index.lookup(email_id)
                        sender = indexed_record.get("from", "") if indexed_record else ""
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
                        # False positive — resolve sender via the
                        # persistent lookup index (ADR 0002).
                        indexed_record = self.email_index.lookup(email_id)
                        sender = indexed_record.get("from", "") if indexed_record else ""
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

        # Include dashboard routes. The HTMLAuthRedirectMiddleware turns
        # unauthenticated browser page loads into /login redirects, while
        # the dependency protects JSON endpoints and direct requests.
        app.include_router(self.dashboard.router, dependencies=[Depends(require_token)])

        # ── Middleware: inject shared fragment into all HTML responses ──
        # This catches dashboard (Jinja-rendered) and any other HTML pages
        # that aren't served via the _inject_shared() helper above.
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import Response as StarletteResponse
        import io

        class SharedHTMLMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                response = await call_next(request)
                content_type = response.headers.get("content-type", "")
                # Only process HTML responses that haven't been injected yet
                if "text/html" in content_type:
                    body_parts = []
                    async for chunk in response.body_iterator:
                        if isinstance(chunk, bytes):
                            body_parts.append(chunk)
                        else:
                            body_parts.append(chunk.encode("utf-8"))
                    body = b"".join(body_parts).decode("utf-8")
                    # Only inject if not already present (avoid double-injection)
                    if "data-phishdetect-shared" not in body and "</head>" in body:
                        body = _inject_shared(body)
                    else:
                        body = _version_static_urls(body)
                    # Strip content-length so HTMLResponse recalculates it
                    # after injection makes the body longer. Stale content-length
                    # causes Cloudflare 520 errors.
                    new_headers = {
                        k: v for k, v in response.headers.items()
                        if k.lower() != "content-length"
                    }
                    return HTMLResponse(
                        content=body,
                        status_code=response.status_code,
                        headers=new_headers,
                    )
                return response

        app.add_middleware(SharedHTMLMiddleware)

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

    # ── purge ────────────────────────────────────────────────────
    purge_parser = subparsers.add_parser(
        "purge",
        help="Purge old rows from stored analysis and feedback data.",
    )
    purge_parser.add_argument(
        "--target",
        choices=["jsonl", "alerts", "feedback", "saas", "sender-profiles", "all"],
        default="jsonl",
        help="Data store to purge. Default preserves the legacy JSONL-only behavior.",
    )
    purge_parser.add_argument(
        "--older-than",
        type=int,
        default=None,
        help="Retention in days. Rows older than this are deleted. "
             "Defaults to PipelineConfig.data_retention_days (30 unless overridden).",
    )
    purge_parser.add_argument(
        "--path",
        default="data/results.jsonl",
        help="Path to the JSONL file to purge (default: data/results.jsonl).",
    )
    purge_parser.add_argument(
        "--feedback-db",
        default="data/feedback.db",
        help="Path to the feedback SQLite DB to purge.",
    )
    purge_parser.add_argument(
        "--alerts-path",
        default="data/alerts.jsonl",
        help="Path to the alert JSONL file to purge.",
    )
    purge_parser.add_argument(
        "--saas-db",
        default="data/saas.db",
        help="Path to the SaaS account SQLite DB to purge.",
    )
    purge_parser.add_argument(
        "--sender-profiles-db",
        default="data/sender_profiles.db",
        help="Path to the sender profiling SQLite DB to purge.",
    )
    purge_parser.add_argument(
        "--keep-recent-feedback",
        type=int,
        default=0,
        help="Always keep this many newest feedback labels even if older than the cutoff.",
    )
    purge_parser.add_argument(
        "--strict",
        action="store_true",
        help="Also drop rows with unparseable timestamps. Default keeps them.",
    )
    purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be dropped without modifying the file.",
    )
    purge_parser.add_argument(
        "--by-address",
        default=None,
        help="Erase rows mentioning this email address or email_id instead of purging by age.",
    )

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

    elif args.command == "purge":
        from src.automation.retention import (
            erase_subject_from_alerts_jsonl,
            erase_subject_from_feedback_db,
            erase_subject_from_results_jsonl,
            erase_subject_from_saas_db,
            erase_subject_from_sender_profiles_db,
            purge_alerts_jsonl,
            purge_feedback_db,
            purge_results_jsonl,
            purge_saas_db,
            purge_sender_profiles_db,
        )
        config = PipelineConfig.from_env()
        max_age = args.older_than if args.older_than is not None else config.data_retention_days

        if args.by_address:
            if args.target in ("jsonl", "all"):
                erasure = erase_subject_from_results_jsonl(
                    args.path,
                    args.by_address,
                    dry_run=args.dry_run,
                )
                prefix = "[DRY RUN] " if args.dry_run else ""
                print(f"{prefix}Erased subject from {erasure.path}")
                print(f"  subject: {erasure.subject}")
                print(f"  kept:    {erasure.kept}")
                print(f"  dropped: {erasure.dropped}")
            if args.target in ("alerts", "all"):
                alert_erasure = erase_subject_from_alerts_jsonl(
                    args.alerts_path,
                    args.by_address,
                    dry_run=args.dry_run,
                )
                prefix = "[DRY RUN] " if args.dry_run else ""
                print(f"{prefix}Erased subject from alerts {alert_erasure.path}")
                print(f"  subject: {alert_erasure.subject}")
                print(f"  kept:    {alert_erasure.kept}")
                print(f"  dropped: {alert_erasure.dropped}")
            if args.target in ("feedback", "all"):
                feedback_erasure = asyncio.run(erase_subject_from_feedback_db(
                    args.feedback_db,
                    args.by_address,
                    dry_run=args.dry_run,
                ))
                prefix = "[DRY RUN] " if args.dry_run else ""
                print(f"{prefix}Erased subject from feedback DB {feedback_erasure.path}")
                print(f"  subject: {feedback_erasure.subject}")
                print(f"  kept:    {feedback_erasure.kept}")
                print(f"  dropped: {feedback_erasure.dropped}")
            if args.target in ("saas", "all"):
                saas_erasure = erase_subject_from_saas_db(
                    args.saas_db,
                    args.by_address,
                    dry_run=args.dry_run,
                )
                prefix = "[DRY RUN] " if args.dry_run else ""
                print(f"{prefix}Erased subject from SaaS DB {saas_erasure.path}")
                print(f"  subject: {saas_erasure.subject}")
                print(f"  kept:    {saas_erasure.kept}")
                print(f"  dropped: {saas_erasure.dropped}")
            if args.target in ("sender-profiles", "all"):
                sender_erasure = erase_subject_from_sender_profiles_db(
                    args.sender_profiles_db,
                    args.by_address,
                    dry_run=args.dry_run,
                )
                prefix = "[DRY RUN] " if args.dry_run else ""
                print(f"{prefix}Erased subject from sender profiles {sender_erasure.path}")
                print(f"  subject: {sender_erasure.subject}")
                print(f"  kept:    {sender_erasure.kept}")
                print(f"  dropped: {sender_erasure.dropped}")
            return

        if args.target in ("jsonl", "all") and args.dry_run:
            # Dry run: copy the file to a tempfile, purge that, report stats
            import shutil, tempfile
            src_path = Path(args.path)
            if not src_path.exists():
                print(f"No file at {src_path} - nothing to purge.")
                src_path = None
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".jsonl", delete=False
            ) as tmp:
                tmp_path = Path(tmp.name)
            if src_path is not None:
                shutil.copy2(src_path, tmp_path)
            try:
                stats = purge_results_jsonl(
                    tmp_path,
                    max_age_days=max_age,
                    keep_unparseable=not args.strict,
                )
                print(f"[DRY RUN] {args.path} (no changes written)")
                print(f"  cutoff:      {stats.cutoff.isoformat()}")
                print(f"  would keep:  {stats.kept}")
                print(f"  would drop:  {stats.dropped}")
                print(f"  unparseable: {stats.unparseable} ({'kept' if not args.strict else 'dropped'})")
                print(f"  bytes:       {stats.bytes_before} -> {stats.bytes_after}")
            finally:
                tmp_path.unlink(missing_ok=True)
        elif args.target in ("jsonl", "all"):
            stats = purge_results_jsonl(
                args.path,
                max_age_days=max_age,
                keep_unparseable=not args.strict,
            )
            print(f"Purged {stats.path}")
            print(f"  cutoff:      {stats.cutoff.isoformat()}")
            print(f"  kept:        {stats.kept}")
            print(f"  dropped:     {stats.dropped}")
            print(f"  unparseable: {stats.unparseable}")
            print(f"  bytes:       {stats.bytes_before} -> {stats.bytes_after}")

        if args.target in ("alerts", "all"):
            if args.dry_run:
                import shutil, tempfile
                src_path = Path(args.alerts_path)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
                    tmp_path = Path(tmp.name)
                if src_path.exists():
                    shutil.copy2(src_path, tmp_path)
                try:
                    alert_stats = purge_alerts_jsonl(
                        tmp_path,
                        max_age_days=max_age,
                        keep_unparseable=not args.strict,
                    )
                    print(f"[DRY RUN] {args.alerts_path} (no changes written)")
                    print(f"  cutoff:      {alert_stats.cutoff.isoformat()}")
                    print(f"  would keep:  {alert_stats.kept}")
                    print(f"  would drop:  {alert_stats.dropped}")
                    print(f"  unparseable: {alert_stats.unparseable} ({'kept' if not args.strict else 'dropped'})")
                finally:
                    tmp_path.unlink(missing_ok=True)
            else:
                alert_stats = purge_alerts_jsonl(
                    args.alerts_path,
                    max_age_days=max_age,
                    keep_unparseable=not args.strict,
                )
                print(f"Purged alerts {alert_stats.path}")
                print(f"  cutoff:      {alert_stats.cutoff.isoformat()}")
                print(f"  kept:        {alert_stats.kept}")
                print(f"  dropped:     {alert_stats.dropped}")
                print(f"  unparseable: {alert_stats.unparseable}")

        if args.target in ("feedback", "all"):
            feedback_stats = asyncio.run(purge_feedback_db(
                args.feedback_db,
                max_age_days=max_age,
                keep_recent=args.keep_recent_feedback,
                dry_run=args.dry_run,
            ))
            prefix = "[DRY RUN] " if args.dry_run else ""
            print(f"{prefix}Feedback DB {feedback_stats.path}")
            print(f"  cutoff:      {feedback_stats.cutoff.isoformat()}")
            print(f"  keep recent: {feedback_stats.keep_recent}")
            print(f"  kept:        {feedback_stats.kept}")
            print(f"  dropped:     {feedback_stats.dropped}")

        if args.target in ("saas", "all"):
            saas_stats = purge_saas_db(
                args.saas_db,
                max_age_days=max_age,
                dry_run=args.dry_run,
            )
            prefix = "[DRY RUN] " if args.dry_run else ""
            print(f"{prefix}SaaS DB {saas_stats.path}")
            print(f"  cutoff:  {saas_stats.cutoff.isoformat()}")
            print(f"  kept:    {saas_stats.kept}")
            print(f"  dropped: {saas_stats.dropped}")

        if args.target in ("sender-profiles", "all"):
            sender_stats = purge_sender_profiles_db(
                args.sender_profiles_db,
                max_age_days=max_age,
                dry_run=args.dry_run,
            )
            prefix = "[DRY RUN] " if args.dry_run else ""
            print(f"{prefix}Sender profiles DB {sender_stats.path}")
            print(f"  cutoff:  {sender_stats.cutoff.isoformat()}")
            print(f"  kept:    {sender_stats.kept}")
            print(f"  dropped: {sender_stats.dropped}")

    else:
        if len(sys.argv) == 1:
            parser.print_help()
        else:
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()

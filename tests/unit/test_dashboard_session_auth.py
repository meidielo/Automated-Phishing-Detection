from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import PhishingDetectionApp
from src.config import PipelineConfig
from src.feedback.email_lookup import EmailLookupIndex
from src.models import AnalyzerResult, PipelineResult, Verdict
from src.reporting.dashboard import PhishingDashboard
from src.security.web_security import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, TokenVerifier


def _build_app_with_token(token: str = "secret"):
    app_wrapper = PhishingDetectionApp.__new__(PhishingDetectionApp)
    app_wrapper.config = PipelineConfig(analyst_api_token=token)
    app_wrapper.pipeline = MagicMock()
    app_wrapper.report_gen = MagicMock()
    app_wrapper.ioc_exporter = MagicMock()
    app_wrapper.sigma_exporter = MagicMock()
    app_wrapper.dashboard = PhishingDashboard(template_dir="./templates")
    app_wrapper.token_verifier = TokenVerifier(token)
    app_wrapper._monitor = None
    app_wrapper._upload_results = []
    app_wrapper.email_index = EmailLookupIndex(jsonl_path="data/results.jsonl")
    return app_wrapper.create_fastapi_app()


def test_dashboard_redirects_to_login_without_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/dashboard")

    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_dashboard_uses_self_hosted_chart_asset_after_login():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/dashboard"})

    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert '/static/vendor/chart.umd.js' in response.text
    assert '/static/dashboard.css' in response.text
    assert '/static/dashboard.js' in response.text
    assert '/static/shared.css' in response.text
    assert '/static/shared.js' in response.text
    assert '<style>' not in response.text
    assert '<script>' not in response.text
    assert 'onclick=' not in response.text
    assert 'onchange=' not in response.text
    assert "cdn.jsdelivr" not in response.text
    assert 'id="verdictFallback"' in response.text
    assert 'id="trendsFallback"' in response.text

    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_dashboard_serves_self_hosted_chart_asset_without_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/static/vendor/chart.umd.js")

    assert response.status_code == 200
    assert "Chart.js v4.4.0" in response.text[:200]

    source_map = client.get("/static/vendor/chart.umd.js.map")
    assert source_map.status_code == 200
    assert '"version":3' in source_map.text[:100]


def test_dashboard_static_assets_are_served_without_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    for asset_path, expected in [
        ("/static/dashboard.css", ".chart-wrap"),
        ("/static/dashboard.js", "function renderTable"),
        ("/static/dashboard-report.css", ".report-progress"),
        ("/static/shared.css", ".feedback-modal"),
        ("/static/shared.js", "product-feedback-open"),
    ]:
        response = client.get(asset_path)
        assert response.status_code == 200
        assert expected in response.text


def test_analyze_page_uses_global_feedback_control_not_inline_panel():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/"})

    response = client.get("/")

    assert response.status_code == 200
    assert '/static/shared.css' in response.text
    assert '/static/shared.js' in response.text
    assert 'class="project-feedback"' not in response.text
    assert "Project feedback" not in response.text
    assert "mailto:meidie@mdpstudio.com.au" not in response.text


def test_generated_dashboard_report_pages_use_static_css_and_escape_content():
    dashboard = PhishingDashboard(template_dir="./missing-templates")
    fallback = dashboard._generate_fallback_dashboard()
    stats = dashboard._generate_stats_page(
        {
            "total_emails": 1,
            "verdict_distribution": {"CLEAN": 1},
            "average_score": 0.25,
            "emails_last_24h": 1,
        }
    )
    detail = dashboard._generate_email_detail_page(
        PipelineResult(
            email_id='email"><script>alert(1)</script>',
            verdict=Verdict.SUSPICIOUS,
            overall_score=0.5,
            overall_confidence=0.7,
            analyzer_results={
                "header<script>": AnalyzerResult(
                    analyzer_name="header",
                    risk_score=0.5,
                    confidence=0.8,
                    details={},
                )
            },
            extracted_urls=[],
            iocs={},
            reasoning="<script>alert(1)</script>",
        )
    )

    for html in [fallback, stats, detail]:
        assert '<link rel="stylesheet" href="/static/dashboard-report.css">' in html
        assert "<style" not in html
        assert " style=" not in html
        assert "<script>" not in html

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail


def test_session_status_reports_browser_session_expiry():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    logged_out = client.get("/api/auth/session")
    assert logged_out.status_code == 200
    assert logged_out.json()["authenticated"] is False

    client.post("/login", data={"token": "secret", "next": "/dashboard"})
    logged_in = client.get("/api/auth/session")

    payload = logged_in.json()
    assert payload["auth_enabled"] is True
    assert payload["authenticated"] is True
    assert isinstance(payload["expires_at"], int)
    assert payload["max_age_seconds"] > 0


def test_login_sets_secure_session_and_csrf_cookies():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/login",
        data={"token": "secret", "next": "/dashboard"},
    )

    assert response.status_code == 303
    set_cookie = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME in set_cookie
    assert CSRF_COOKIE_NAME in set_cookie
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie


def test_login_uses_non_secure_cookies_on_local_http():
    client = TestClient(
        _build_app_with_token(),
        base_url="http://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/login",
        data={"token": "secret", "next": "/dashboard"},
    )

    assert response.status_code == 303
    set_cookie = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME in set_cookie
    assert CSRF_COOKIE_NAME in set_cookie
    assert "Secure" not in set_cookie


def test_login_escapes_next_value_in_form():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get('/login?next=/dashboard"><script>alert(1)</script>')

    assert response.status_code == 200
    assert 'value="/dashboard&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"' in response.text
    assert 'value="/dashboard"><script>alert(1)</script>"' not in response.text


def test_session_post_requires_csrf_header():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/dashboard"})

    response = client.post("/api/auth/logout")

    assert response.status_code == 403


def test_session_post_accepts_csrf_header():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/dashboard"})
    csrf = client.cookies.get(CSRF_COOKIE_NAME)

    response = client.post(
        "/api/auth/logout",
        headers={
            "X-CSRF-Token": csrf,
            "Origin": "https://testserver",
        },
    )

    assert response.status_code == 200

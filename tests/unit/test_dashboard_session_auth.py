from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import PhishingDetectionApp
from src.config import PipelineConfig
from src.feedback.email_lookup import EmailLookupIndex
from src.models import AnalyzerResult, PipelineResult, Verdict
from src.reporting.dashboard import PhishingDashboard
from src.security.web_security import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, TokenVerifier
from src.saas.auth import SaaSSessionManager


def _build_app_with_token(
    token: str = "secret",
    public_demo_mode: bool = False,
    saas_db_path: str = "data/test_saas_session.db",
    saas_public_signup_enabled: bool = False,
):
    app_wrapper = PhishingDetectionApp.__new__(PhishingDetectionApp)
    app_wrapper.config = PipelineConfig(
        analyst_api_token=token,
        public_demo_mode=public_demo_mode,
        saas_db_path=saas_db_path,
        saas_session_secret=f"{token}-saas-session",
        saas_public_signup_enabled=saas_public_signup_enabled,
    )
    app_wrapper.pipeline = MagicMock()
    app_wrapper.report_gen = MagicMock()
    app_wrapper.ioc_exporter = MagicMock()
    app_wrapper.sigma_exporter = MagicMock()
    app_wrapper.dashboard = PhishingDashboard(template_dir="./templates")
    app_wrapper.token_verifier = TokenVerifier(token)
    app_wrapper.saas_session_manager = SaaSSessionManager(f"{token}-saas-session")
    app_wrapper._saas_store = None
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
        ("/static/agent-demo.css", ".agent-workbench"),
        ("/static/agent-demo.js", "/api/demo/agent-payment-analysis"),
        ("/static/demo.css", ".demo-page"),
        ("/static/saas.css", ".saas-shell"),
        ("/static/saas.js", "/api/saas/session"),
        ("/static/shared.css", ".feedback-modal"),
        ("/static/shared.js", "product-feedback-open"),
    ]:
        response = client.get(asset_path)
        assert response.status_code == 200
        assert expected in response.text


def test_public_demo_is_not_available_by_default():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/demo")
    agent_demo = client.get("/agent-demo")
    status = client.get("/api/demo/status")
    agent_status = client.get("/api/demo/agent-payment-analysis")

    assert response.status_code == 404
    assert agent_demo.status_code == 404
    assert status.status_code == 404
    assert agent_status.status_code == 404


def test_public_demo_opens_without_session_when_enabled():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/demo")

    assert response.status_code == 200
    assert "Public demo mode" in response.text
    assert "without mailbox or paid API access" in response.text
    assert "No live mailbox" in response.text
    assert "/static/demo.css" in response.text


def test_agent_demo_opens_and_returns_committed_samples_when_enabled():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    page = client.get("/agent-demo")
    api = client.get("/api/demo/agent-payment-analysis")

    payload = api.json()
    assert page.status_code == 200
    assert "Payment email investigation" in page.text
    assert "/static/agent-demo.css" in page.text
    assert "/static/agent-demo.js" in page.text
    assert api.status_code == 200
    assert payload["demo_mode"] is True
    assert payload["sample_count"] == 3
    assert {sample["decision"] for sample in payload["samples"]} == {
        "SAFE",
        "VERIFY",
        "DO_NOT_PAY",
    }
    assert all(sample["source_type"] == "demo" for sample in payload["samples"])


def test_user_app_shell_opens_without_analyst_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/app")

    assert response.status_code == 200
    assert "/static/saas.css" in response.text
    assert "/static/saas.js" in response.text
    assert "PhishDetect account" in response.text


def test_public_demo_status_declares_locked_capabilities():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/api/demo/status")

    payload = response.json()
    assert response.status_code == 200
    assert payload["demo_mode"] is True
    assert payload["paid_api_access"] is False
    assert payload["live_analysis_enabled"] is False
    assert payload["mailbox_access_enabled"] is False
    assert payload["feedback_learning_enabled"] is False
    assert payload["account_management_enabled"] is False
    assert payload["user_mailboxes"] == "not_connected_in_public_demo"


def test_public_demo_plan_catalog_declares_free_locks():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/api/demo/plans")

    payload = response.json()
    features = {feature["slug"]: feature for feature in payload["features"]}
    assert response.status_code == 200
    assert payload["current_plan"] == "free"
    assert payload["billing_recommendation"] == "Stripe Billing + Checkout Sessions + Customer Portal"
    assert features["payment_rules"]["available"] is True
    assert features["url_reputation"]["available"] is False
    assert features["url_reputation"]["required_plan_name"] == "Starter"
    assert features["url_detonation"]["required_plan_name"] == "Pro"


def test_public_demo_plan_catalog_is_not_available_by_default():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/api/demo/plans")

    assert response.status_code == 404


def test_public_demo_does_not_bypass_real_analysis_or_dashboard_auth():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    upload = client.post(
        "/api/analyze/upload",
        files={"file": ("sample.eml", b"Subject: hi\r\n\r\nbody", "message/rfc822")},
    )
    dashboard = client.get("/dashboard")

    assert upload.status_code == 401
    assert dashboard.status_code == 303
    assert dashboard.headers["location"].startswith("/login?next=")


def test_login_page_links_public_demo_only_when_enabled():
    plain_client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    demo_client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    plain = plain_client.get("/login")
    demo = demo_client.get("/login")

    assert 'href="/demo"' not in plain.text
    assert 'href="/demo"' in demo.text
    assert "paid API checks" in demo.text


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
    assert payload["public_demo_mode"] is False


def test_session_status_reports_public_demo_mode():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/api/auth/session")

    assert response.status_code == 200
    assert response.json()["public_demo_mode"] is True


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

from __future__ import annotations

from pathlib import Path
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


def test_public_root_redirects_to_product_not_admin_login():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/")

    assert response.status_code == 303
    assert response.headers["location"] == "/product"


def test_saas_app_login_shell_uses_link_based_auth_navigation():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/app")

    assert response.status_code == 200
    assert 'id="authTitle"' in response.text
    assert 'href="/app" class="active" aria-current="page">User app</a>' in response.text
    assert 'href="/trust">Trust</a>' in response.text
    assert 'href="/login">Analyst login</a>' not in response.text
    assert 'href="/demo">Demo</a>' not in response.text
    assert "Don't have an account yet?" in response.text
    assert ">Create account</button>" in response.text
    assert "Forgot password?" in response.text
    assert 'data-auth-mode="signup"' in response.text
    assert 'data-auth-mode="reset"' in response.text
    assert "Analyze payment-risk emails before money leaves the business" not in response.text
    assert "auth-product-shot" not in response.text
    assert "data-auth-tab" not in response.text
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_saas_app_upgrade_options_are_hidden_until_requested():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/app")
    css = Path("static/saas.css").read_text(encoding="utf-8")
    js = Path("static/saas.js").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert 'id="upgradeButton"' in response.text
    assert 'id="pricingSection"' in response.text
    assert 'class="pricing-section hidden"' in response.text
    assert 'id="closePricingButton"' in response.text
    assert 'id="billingCycle"' in response.text
    assert 'data-billing-interval="monthly"' in response.text
    assert 'data-billing-interval="yearly"' in response.text
    assert "Save 20%" in response.text
    assert 'data-upgrade-trigger' in js
    assert "selectedBillingInterval" in js
    assert "billing_interval: selectedBillingInterval" in js
    assert "billingIntervalLabel()" in js
    assert 'const planOrder = ["free", "starter", "pro", "business"]' in js
    assert "targetRank < currentRank" in js
    assert "Plan coverage" in js
    assert "You are already on the highest plan" in js
    assert "AUD / month" not in js
    assert "currency-pill" not in response.text
    assert "currency-pill" not in css
    assert 'plan-icon' not in js
    assert "Product style alignment" in css
    assert "--saas-bg: var(--bg-primary);" in css
    assert ".saas-topbar" in css
    assert "grid-template-columns: minmax(0, 420px);" in css
    assert ".auth-copy {\n  display: none;\n}" in css


def test_saas_app_manual_upload_uses_drop_zone():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/app")
    css = Path("static/saas.css").read_text(encoding="utf-8")
    js = Path("static/saas.js").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert 'id="scanDropZone"' in response.text
    assert 'class="scan-file-input"' in response.text
    assert 'id="emailFile" class="scan-file-input" name="file" type="file" accept=".eml,message/rfc822">' in response.text
    assert "Drop your .eml file here, or click to browse" in response.text
    assert 'id="scanSubmitButton" type="submit" disabled' in response.text
    assert 'id="historyNotice" hidden' in response.text
    assert ".scan-drop-zone" in css
    assert "function setScanFile" in js
    assert "function renderSelectedFile" in js
    assert "function renderAnalyzingResult" in js
    assert "function renderAnalyzerEvidence" in js
    assert "Analyzer evidence" in js
    assert "data-delete-scan" in js
    assert "DELETE" in js
    assert "function resetTransientWorkspace" in js
    assert "Previous previews are cleared" in js
    assert "Fresh result for" in js
    assert "is-analyzing" in js
    assert ".result-loading" in css
    assert ".loading-spinner" in css
    assert ".scan-drop-zone.is-analyzing" in css
    assert "drag-over" in js


def test_analyze_page_redirects_to_login_without_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/analyze")

    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")
    assert response.headers["location"].endswith("next=/analyze")


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
    assert 'id="verdictLegend"' in response.text
    assert 'id="trendsFallback"' in response.text

    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_dashboard_without_trailing_slash_serves_after_login():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/dashboard"})

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Email Analysis Dashboard" in response.text


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
        ("/static/dashboard.css", ".verdict-legend-row"),
        ("/static/dashboard.js", "function renderVerdictLegend"),
        ("/static/dashboard-report.css", ".report-progress"),
        ("/static/agent-demo.css", ".agent-workbench"),
        ("/static/agent-demo.js", "/api/demo/agent-payment-analysis"),
        ("/static/demo.css", ".demo-page"),
        ("/static/product.css", ".product-hero"),
        ("/static/saas.css", ".saas-shell"),
        ("/static/saas.js", "/api/saas/session"),
        ("/static/shared.css", ".feedback-modal"),
        ("/static/shared.js", "product-feedback-open"),
    ]:
        response = client.get(asset_path)
        assert response.status_code == 200
        assert expected in response.text


def test_disabled_public_demo_pages_redirect_to_product_by_default():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/demo")
    agent_demo = client.get("/agent-demo")
    status = client.get("/api/demo/status")
    agent_status = client.get("/api/demo/agent-payment-analysis")

    assert response.status_code == 303
    assert response.headers["location"] == "/product"
    assert agent_demo.status_code == 303
    assert agent_demo.headers["location"] == "/product"
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
    assert "PhishAnalyze workspace" in response.text


def test_user_app_fetches_preserve_same_origin_referrer_for_csrf():
    script = Path("static/saas.js").read_text(encoding="utf-8")

    assert script.count('referrerPolicy: "same-origin"') >= 2
    assert 'await apiJson("/api/saas/auth/logout", { method: "POST", body: "{}" });' in script
    assert "await loadSession();" in script
    assert "Logout failed. Refresh and try again." in script


def test_html_static_asset_urls_are_versioned(monkeypatch):
    monkeypatch.setenv("APP_BUILD_SHA", "testbuild123")
    monkeypatch.setenv("STATIC_ASSET_VERSION", "testbuild123")
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/app")
    trust = client.get("/trust")
    health = client.get("/api/health")

    assert response.status_code == 200
    assert '/static/saas.css?v=testbuild123' in response.text
    assert '/static/saas.js?v=testbuild123' in response.text
    assert '/static/shared.css?v=testbuild123' in response.text
    assert '/static/shared.js?v=testbuild123' in response.text
    assert '/static/product.css?v=testbuild123' in trust.text
    assert '/static/shared.css?v=testbuild123' in trust.text
    assert health.json()["build_sha"] == "testbuild123"
    assert health.json()["static_asset_version"] == "testbuild123"


def test_product_shell_opens_without_analyst_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/product")

    assert response.status_code == 200
    assert "PhishAnalyze payment-risk firewall" in response.text
    assert 'href="/agent-demo"' not in response.text
    assert 'href="/demo"' not in response.text
    assert 'href="/login">Analyst login</a>' not in response.text
    assert 'href="/trust">Trust</a>' in response.text
    assert 'href="/app">Open user app</a>' in response.text
    assert 'href="/trust">Trust and privacy</a>' in response.text
    assert "/static/product.css" in response.text
    assert "/static/product-dashboard.png" in response.text
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_trust_page_opens_without_analyst_session():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/trust")

    assert response.status_code == 200
    assert "Trust and privacy" in response.text
    assert "Uploads are for analysis, not model training" in response.text
    assert "Analyst pages remain private owner tools" in response.text
    assert 'href="/login">Analyst login</a>' not in response.text
    assert "/static/product.css" in response.text
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_product_shell_links_demo_pages_only_when_demo_is_enabled():
    client = TestClient(
        _build_app_with_token(public_demo_mode=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.get("/product")

    assert response.status_code == 200
    assert 'href="/agent-demo">Agent demo</a>' in response.text
    assert 'href="/demo">Public demo</a>' in response.text
    assert 'href="/agent-demo">Open agent demo</a>' in response.text


def test_shared_controls_use_icon_theme_and_page_scoped_logout():
    css = Path("static/shared.css").read_text(encoding="utf-8")
    script = Path("static/shared.js").read_text(encoding="utf-8")

    assert "function themeIcon(nextTheme)" in script
    assert "aria-label', label" in script
    assert "if (isAnalystPage()) installAnalystLogout(nav);" in script
    assert "var isSaasApi = path.startsWith('/api/saas/');" in script
    assert "!isSaasApi && method !== 'GET'" in script
    assert "response.status === 401 && isApi && !isSaasApi" in script
    assert "Product-aligned analyst shell" in css
    assert "body > nav" in css
    assert "body > .page" in css


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

    assert 'href="/app"' in plain.text
    assert 'href="/demo"' not in plain.text
    assert 'href="/demo"' in demo.text
    assert "paid API checks" in demo.text


def test_analyze_page_uses_global_feedback_control_not_inline_panel():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/analyze"})

    response = client.get("/analyze")

    assert response.status_code == 200
    assert "<title>Analyze - PhishAnalyze</title>" in response.text
    assert "Email Risk Analyzer" in response.text
    assert 'id="drop-zone"' in response.text
    assert "Drop your .eml file here, or click to browse" in response.text
    assert "height: 56px;" in response.text
    assert "font-size: 26px;" in response.text
    assert "min-height: 220px;" in response.text
    assert "font-size: 52px;" not in response.text
    assert "min-height: 356px;" not in response.text
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


def test_login_trims_copied_token_whitespace():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/login",
        data={"token": "  secret\r\n", "next": "/dashboard"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_login_accepts_copied_env_line_token():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/login",
        data={"token": "ANALYST_API_TOKEN=secret", "next": "/dashboard"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_api_login_trims_copied_token_whitespace():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post("/api/auth/login", json={"token": "\nsecret  "})

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_login_accepts_quoted_token_value():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post("/api/auth/login", json={"token": '"secret"'})

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_login_rate_limits_failed_analyst_tokens():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )

    statuses = [
        client.post("/api/auth/login", json={"token": "wrong"}).status_code
        for _ in range(11)
    ]

    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


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


def test_monitor_stats_reports_saved_account_reconnect_state(monkeypatch):
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/monitor"})

    import src.automation.multi_account_monitor as multi_account_monitor

    monkeypatch.setattr(
        multi_account_monitor,
        "list_accounts",
        lambda: [{"type": "imap", "user": "meidie@example.com", "password": "********"}],
    )

    response = client.get("/api/monitor/stats")

    assert response.status_code == 200
    payload = response.json()
    assert payload["account_status"] == "credential_error"
    assert payload["configured_account_count"] == 1
    assert payload["active_account_count"] == 0
    assert payload["imap_configured"] is True
    assert "different key" in payload["account_message"].lower()
    assert "fresh app password" in payload["account_message"].lower()


def test_monitor_page_guides_mailbox_reconnect():
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/monitor"})

    response = client.get("/monitor")

    assert response.status_code == 200
    body = response.text
    assert "Reconnect Email" in body
    assert "showReconnectForm" in body
    assert "Re-enter the Gmail app password below using the same email address" in body


def test_detonate_url_endpoint_sanitizes_raw_screenshot_bytes(monkeypatch):
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/monitor"})
    csrf = client.cookies.get(CSRF_COOKIE_NAME)

    import main as main_module
    import src.analyzers.url_detonation as url_detonation

    monkeypatch.setattr(main_module.default_ssrf_guard, "assert_safe", lambda url: None)

    async def fake_detonate(url: str):
        return {
            "url": url,
            "page_loaded": True,
            "screenshot_bytes": b"\x89PNG\r\n",
            "screenshot_b64": "base64-image",
        }

    monkeypatch.setattr(url_detonation, "detonate_single_url", fake_detonate)

    response = client.post(
        "/api/detonate-url",
        json={"url": "https://example.com"},
        headers={
            "X-CSRF-Token": csrf,
            "Origin": "https://testserver",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["screenshot_b64"] == "base64-image"
    assert "screenshot_bytes" not in payload


def test_detonate_url_endpoint_does_not_return_raw_html_errors(monkeypatch):
    client = TestClient(
        _build_app_with_token(),
        base_url="https://testserver",
        follow_redirects=False,
    )
    client.post("/login", data={"token": "secret", "next": "/monitor"})
    csrf = client.cookies.get(CSRF_COOKIE_NAME)

    import main as main_module
    import src.analyzers.url_detonation as url_detonation

    monkeypatch.setattr(main_module.default_ssrf_guard, "assert_safe", lambda url: None)

    async def fake_detonate(_url: str):
        raise RuntimeError(
            '<!DOCTYPE html><html><body>Internal Server Error</body></html>'
        )

    monkeypatch.setattr(url_detonation, "detonate_single_url", fake_detonate)

    response = client.post(
        "/api/detonate-url",
        json={"url": "https://example.com"},
        headers={
            "X-CSRF-Token": csrf,
            "Origin": "https://testserver",
        },
    )

    assert response.status_code == 500
    assert "<!DOCTYPE html>" not in response.text
    assert "<html" not in response.text.lower()
    assert "HTML error page" in response.json()["detail"]

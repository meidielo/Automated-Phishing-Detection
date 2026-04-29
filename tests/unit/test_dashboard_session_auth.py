from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import PhishingDetectionApp
from src.config import PipelineConfig
from src.feedback.email_lookup import EmailLookupIndex
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

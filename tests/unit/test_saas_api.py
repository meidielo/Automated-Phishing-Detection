from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import PhishingDetectionApp
from src.billing.entitlements import locked_analyzer_result
from src.config import PipelineConfig
from src.feedback.email_lookup import EmailLookupIndex
from src.models import AnalyzerResult, PipelineResult, Verdict
from src.reporting.dashboard import PhishingDashboard
from src.saas.auth import SaaSSessionManager, USER_CSRF_COOKIE_NAME
from src.security.web_security import TokenVerifier


def _build_saas_app(tmp_path, *, signup_enabled: bool):
    app_wrapper = PhishingDetectionApp.__new__(PhishingDetectionApp)
    app_wrapper.config = PipelineConfig(
        analyst_api_token="analyst-secret",
        saas_db_path=str(tmp_path / "saas.db"),
        saas_session_secret="saas-secret-for-tests",
        saas_public_signup_enabled=signup_enabled,
    )
    app_wrapper.pipeline = MagicMock()
    app_wrapper.pipeline.analyze.side_effect = _fake_analyze
    app_wrapper.report_gen = MagicMock()
    app_wrapper.ioc_exporter = MagicMock()
    app_wrapper.sigma_exporter = MagicMock()
    app_wrapper.dashboard = PhishingDashboard(template_dir="./templates")
    app_wrapper.token_verifier = TokenVerifier("analyst-secret")
    app_wrapper.saas_session_manager = SaaSSessionManager("saas-secret-for-tests")
    app_wrapper._saas_store = None
    app_wrapper._monitor = None
    app_wrapper._upload_results = []
    app_wrapper.email_index = EmailLookupIndex(jsonl_path=str(tmp_path / "results.jsonl"))
    return app_wrapper.create_fastapi_app()


async def _fake_analyze(email, feature_gate=None):
    url_reputation_decision = feature_gate("url_reputation")
    return PipelineResult(
        email_id=email.email_id,
        verdict=Verdict.SUSPICIOUS,
        overall_score=0.42,
        overall_confidence=0.8,
        analyzer_results={
            "payment_fraud": AnalyzerResult(
                analyzer_name="payment_fraud",
                risk_score=0.52,
                confidence=0.9,
                details={"decision": "VERIFY"},
            ),
            "url_reputation": locked_analyzer_result(
                "url_reputation",
                url_reputation_decision,
            ),
        },
        extracted_urls=[],
        iocs={"headers": {}},
        reasoning="test reasoning",
        timestamp=datetime.now(timezone.utc),
    )


def _signup(client: TestClient):
    return client.post(
        "/api/saas/auth/signup",
        json={
            "email": "owner@example.com",
            "password": "correct horse battery",
            "org_name": "Example Finance",
        },
    )


def _upload(client: TestClient):
    csrf = client.cookies.get(USER_CSRF_COOKIE_NAME)
    return client.post(
        "/api/saas/analyze/upload",
        headers={
            "x-csrf-token": csrf,
            "origin": "https://testserver",
        },
        files={
            "file": (
                "sample.eml",
                b"From: vendor@example.com\r\nSubject: Invoice update\r\n\r\nPlease verify payment details.",
                "message/rfc822",
            )
        },
    )


def test_saas_signup_disabled_by_default(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=False),
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = _signup(client)

    assert response.status_code == 403


def test_saas_signup_session_plans_upload_and_history(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    signup = _signup(client)
    session = client.get("/api/saas/session")
    plans = client.get("/api/saas/plans")
    upload = _upload(client)
    history = client.get("/api/saas/scans")

    assert signup.status_code == 200
    assert session.json()["authenticated"] is True
    assert plans.json()["account"]["plan_slug"] == "free"
    assert upload.status_code == 200
    assert upload.json()["account"]["monthly_scan_used"] == 1
    assert upload.json()["feature_locks"][0]["details"]["required_plan_name"] == "Starter"
    assert history.json()["results"][0]["payment_decision"] == "VERIFY"


def test_saas_manual_scan_quota_returns_locked_response(tmp_path):
    client = TestClient(
        _build_saas_app(tmp_path, signup_enabled=True),
        base_url="https://testserver",
        follow_redirects=False,
    )

    assert _signup(client).status_code == 200
    statuses = [_upload(client).status_code for _ in range(6)]

    assert statuses[:5] == [200, 200, 200, 200, 200]
    assert statuses[5] == 402

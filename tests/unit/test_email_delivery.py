import json
import urllib.parse

from src.config import ZohoMailConfig
from src.saas.email_delivery import PasswordResetEmail, ZohoPasswordResetMailer


class _FakeResponse:
    def __init__(self, payload: dict | None = None, status: int = 200):
        self.payload = payload or {}
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_zoho_password_reset_mailer_refreshes_token_and_sends_mail(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        if request.full_url.endswith("/oauth/v2/token"):
            return _FakeResponse({"access_token": "access-token"})
        return _FakeResponse(status=200)

    monkeypatch.setattr("src.saas.email_delivery.urllib.request.urlopen", fake_urlopen)
    mailer = ZohoPasswordResetMailer(
        ZohoMailConfig(
            client_id="client-id",
            client_secret="client-secret",
            refresh_token="refresh-token",
            accounts_base="https://accounts.zoho.com.au",
            account_id="700123",
            from_email="alerts@example.com",
            api_base="https://mail.zoho.com.au",
            enable_direct_send=True,
        )
    )

    mailer.send_password_reset(
        PasswordResetEmail(
            to_email="owner@example.com",
            reset_url="https://phishanalyze.example.test/analyze?reset_token=token",
            ttl_minutes=30,
        )
    )

    token_request, mail_request = requests
    token_body = urllib.parse.parse_qs(token_request.data.decode("utf-8"))
    mail_body = json.loads(mail_request.data.decode("utf-8"))

    assert mailer.enabled is True
    assert token_request.full_url == "https://accounts.zoho.com.au/oauth/v2/token"
    assert token_body["grant_type"] == ["refresh_token"]
    assert token_body["client_id"] == ["client-id"]
    assert mail_request.full_url == "https://mail.zoho.com.au/api/accounts/700123/messages"
    assert mail_request.headers["Authorization"] == "Zoho-oauthtoken access-token"
    assert mail_body["fromAddress"] == "alerts@example.com"
    assert mail_body["toAddress"] == "owner@example.com"
    assert "reset_token=token" in mail_body["content"]

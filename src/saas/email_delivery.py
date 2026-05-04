"""Transactional delivery for SaaS account emails."""

from __future__ import annotations

import json
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr

from src.config import SMTPConfig, ZohoMailConfig


class EmailDeliveryError(RuntimeError):
    """Raised when a transactional email could not be sent."""


@dataclass(frozen=True)
class PasswordResetEmail:
    to_email: str
    reset_url: str
    ttl_minutes: int


class SMTPPasswordResetMailer:
    """Send password reset emails through a standard SMTP server."""

    def __init__(self, config: SMTPConfig | None) -> None:
        self.config = config or SMTPConfig()

    @property
    def enabled(self) -> bool:
        return bool(
            self.config.host
            and self.config.port
            and self.config.username
            and self.config.password
            and self.config.from_email
        )

    def send_password_reset(self, email: PasswordResetEmail) -> None:
        if not self.enabled:
            raise EmailDeliveryError("SMTP password reset delivery is not configured")

        message = EmailMessage()
        message["Subject"] = "Reset your PhishAnalyze password"
        message["From"] = formataddr((self.config.from_name, self.config.from_email))
        message["To"] = email.to_email
        message.set_content(
            "\n".join(
                [
                    "A password reset was requested for your PhishAnalyze account.",
                    "",
                    f"Reset your password here: {email.reset_url}",
                    "",
                    f"This link expires in {email.ttl_minutes} minutes.",
                    "If you did not request this, you can ignore this email.",
                ]
            )
        )

        try:
            if self.config.use_ssl:
                with smtplib.SMTP_SSL(self.config.host, self.config.port, timeout=20) as smtp:
                    self._send(smtp, message)
            else:
                with smtplib.SMTP(self.config.host, self.config.port, timeout=20) as smtp:
                    if self.config.starttls:
                        smtp.starttls()
                    self._send(smtp, message)
        except Exception as exc:
            raise EmailDeliveryError("Failed to send password reset email") from exc

    def _send(self, smtp, message: EmailMessage) -> None:
        smtp.login(self.config.username, self.config.password)
        smtp.send_message(message)


class ZohoPasswordResetMailer:
    """Send password reset emails through the Zoho Mail REST API."""

    def __init__(self, config: ZohoMailConfig | None) -> None:
        self.config = config or ZohoMailConfig()

    @property
    def enabled(self) -> bool:
        return bool(
            self.config.enable_direct_send
            and self.config.client_id
            and self.config.client_secret
            and self.config.refresh_token
            and self.config.account_id
            and self.config.from_email
        )

    def send_password_reset(self, email: PasswordResetEmail) -> None:
        if not self.enabled:
            raise EmailDeliveryError("Zoho password reset delivery is not configured")

        token = self._access_token()
        endpoint = (
            f"{self.config.api_base.rstrip('/')}/api/accounts/"
            f"{urllib.parse.quote(str(self.config.account_id), safe='')}/messages"
        )
        content = "\n".join(
            [
                "A password reset was requested for your PhishAnalyze account.",
                "",
                f"Reset your password here: {email.reset_url}",
                "",
                f"This link expires in {email.ttl_minutes} minutes.",
                "If you did not request this, you can ignore this email.",
            ]
        )
        payload = {
            "fromAddress": self.config.from_email,
            "toAddress": email.to_email,
            "subject": "Reset your PhishAnalyze password",
            "content": content,
            "mailFormat": "plaintext",
        }
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Zoho-oauthtoken {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status >= 400:
                    raise EmailDeliveryError("Zoho Mail rejected the reset email")
        except EmailDeliveryError:
            raise
        except Exception as exc:
            raise EmailDeliveryError("Failed to send password reset email through Zoho") from exc

    def _access_token(self) -> str:
        params = urllib.parse.urlencode(
            {
                "refresh_token": self.config.refresh_token,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "refresh_token",
            }
        )
        endpoint = f"{self.config.accounts_base.rstrip('/')}/oauth/v2/token?{params}"
        request = urllib.request.Request(
            endpoint,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            error = _zoho_error_code(body)
            raise EmailDeliveryError(f"Zoho OAuth token refresh failed: {error}") from exc
        except Exception as exc:
            raise EmailDeliveryError("Zoho OAuth token refresh failed") from exc

        token = str(payload.get("access_token", ""))
        if not token:
            error = str(payload.get("error", "missing_access_token"))
            raise EmailDeliveryError(f"Zoho OAuth token refresh failed: {error}")
        return token


def _zoho_error_code(body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return "http_error"
    return str(payload.get("error", "http_error"))

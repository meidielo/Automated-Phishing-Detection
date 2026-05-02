"""SMTP delivery for SaaS account emails."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr

from src.config import SMTPConfig


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

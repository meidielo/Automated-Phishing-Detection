"""Signed browser sessions for normal SaaS users."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

USER_SESSION_COOKIE_NAME = "phishdetect_user_session"
USER_CSRF_COOKIE_NAME = "phishdetect_user_csrf"
USER_CSRF_HEADER_NAME = "x-csrf-token"
USER_SESSION_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


class SaaSSessionManager:
    """Create and verify signed user session cookies."""

    def __init__(self, secret: str | None) -> None:
        self.secret = secret or ""

    @property
    def enabled(self) -> bool:
        return bool(self.secret)

    def create_session_cookie(
        self,
        *,
        user_id: str,
        email: str,
        org_id: str,
        now: int | None = None,
        max_age_seconds: int = USER_SESSION_MAX_AGE_SECONDS,
    ) -> str:
        if not self.enabled:
            raise RuntimeError("cannot create user session without SAAS_SESSION_SECRET")
        issued_at = int(now if now is not None else time.time())
        payload = {
            "sub": user_id,
            "email": email,
            "org_id": org_id,
            "iat": issued_at,
            "exp": issued_at + max_age_seconds,
            "nonce": secrets.token_urlsafe(16),
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)
        signature = _sign(payload_b64.encode("ascii"), self.secret)
        return f"{payload_b64}.{signature}"

    def session_payload(self, value: str | None, *, now: int | None = None) -> dict | None:
        if not self.enabled or not value or "." not in value:
            return None
        payload_b64, signature = value.rsplit(".", 1)
        expected = _sign(payload_b64.encode("ascii"), self.secret)
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return None
        expires_at = payload.get("exp")
        if not isinstance(expires_at, int):
            return None
        current = int(now if now is not None else time.time())
        if current > expires_at:
            return None
        if not payload.get("sub") or not payload.get("org_id"):
            return None
        return payload

    @staticmethod
    def create_csrf_token() -> str:
        return secrets.token_urlsafe(32)


def verify_user_csrf(request: Request) -> None:
    """Validate double-submit CSRF token and same-origin headers."""
    if request.method.upper() in SAFE_METHODS:
        return

    header_token = request.headers.get(USER_CSRF_HEADER_NAME)
    cookie_token = request.cookies.get(USER_CSRF_COOKIE_NAME)
    if not header_token or not cookie_token or not hmac.compare_digest(header_token, cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or invalid CSRF token",
        )

    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if origin:
        if _same_origin(request, origin):
            return
    elif referer and _same_origin(request, referer):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Missing or invalid Origin/Referer header",
    )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _sign(data: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).digest()
    return _b64url_encode(digest)


def _request_origin_tuple(request: Request) -> tuple[str, str]:
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    forwarded_host = request.headers.get("x-forwarded-host", "")
    scheme = (forwarded_proto.split(",")[0].strip() or request.url.scheme).lower()
    host = (
        forwarded_host.split(",")[0].strip()
        or request.headers.get("host")
        or request.url.netloc
    ).lower()
    return scheme, host


def _same_origin(request: Request, value: str) -> bool:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return False
    expected_scheme, expected_host = _request_origin_tuple(request)
    return parsed.scheme.lower() == expected_scheme and parsed.netloc.lower() == expected_host

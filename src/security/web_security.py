"""
Web security primitives for the FastAPI dashboard and API surface in main.py.

Three independent pieces, all importable separately:

1. `TokenVerifier` - FastAPI dependency that enforces either
   `Authorization: Bearer <token>` or a signed browser session cookie
   created by `/login`. Session-cookie requests use SameSite cookies,
   a double-submit CSRF token, and Origin/Referer checks for
   state-changing methods.

2. `add_security_headers_middleware` — installs middleware that attaches
   CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
   and Strict-Transport-Security to every response.

3. `SSRFGuard` — DNS-resolves a URL and refuses to fetch it if the
   resolved IP is in a private/loopback/link-local/CGNAT/metadata range.
   Used by the on-demand URL detonation endpoint to prevent cloud metadata
   IMDS exfiltration (Capital One 2019 class).

These are the P0 items from the security audit. The threat model
(`THREAT_MODEL.md` §6 R1, R3) tracks which residual risks they close.

═══════════════════════════════════════════════════════════════════════════
CSRF SESSION-AUTH CONTRACT
═══════════════════════════════════════════════════════════════════════════

TokenVerifier accepts cookie/session auth for browser dashboard users.
Because browsers auto-attach cookies to cross-origin requests, session auth
must keep these controls together:

    [ ] SameSite=Strict on the session cookie
    [ ] Secure flag on the session cookie
    [ ] HttpOnly flag on the session cookie
    [ ] CSRF token on every state-changing request (double-submit cookie
        pattern or per-request synchronizer token), validated server-side
    [ ] Origin / Referer header check on POST routes as defense in depth
    [ ] Tests that prove a forged cross-origin POST is rejected

This checklist is the contract. Reviewers: block any future session-auth
change that removes one of these controls.
"""
from __future__ import annotations

import ipaddress
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import time
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "phishdetect_session"
CSRF_COOKIE_NAME = "phishdetect_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def _session_max_age_from_env() -> int:
    raw = os.getenv("SESSION_MAX_AGE_SECONDS", str(8 * 60 * 60))
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid SESSION_MAX_AGE_SECONDS=%r; using 8 hours", raw)
        return 8 * 60 * 60
    if value <= 0:
        logger.warning("SESSION_MAX_AGE_SECONDS must be positive; using 8 hours")
        return 8 * 60 * 60
    return value


SESSION_MAX_AGE_SECONDS = _session_max_age_from_env()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Bearer token authentication
# ─────────────────────────────────────────────────────────────────────────────


class TokenVerifier:
    """
    Holds the configured token and produces a FastAPI dependency that
    validates incoming requests against it.

    Wrapped in a class instead of a free function so the token can be
    captured at app-construction time without globals.
    """

    def __init__(self, expected_token: Optional[str]):
        self.expected_token = expected_token

    @property
    def enabled(self) -> bool:
        """True iff a token is configured and enforcement is active."""
        return bool(self.expected_token)

    def create_session_cookie(
        self,
        *,
        now: Optional[int] = None,
        max_age_seconds: int = SESSION_MAX_AGE_SECONDS,
    ) -> str:
        """Create a signed, expiring session cookie value."""
        if not self.enabled:
            raise RuntimeError("cannot create a session cookie without ANALYST_API_TOKEN")
        issued_at = int(now if now is not None else time.time())
        payload = {
            "iat": issued_at,
            "exp": issued_at + max_age_seconds,
            "nonce": secrets.token_urlsafe(16),
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)
        signature = _sign(payload_b64.encode("ascii"), self.expected_token or "")
        return f"{payload_b64}.{signature}"

    def session_payload(self, value: Optional[str], *, now: Optional[int] = None) -> Optional[dict]:
        """Return a valid signed session payload, or None."""
        if not self.enabled or not value or "." not in value:
            return None
        payload_b64, signature = value.rsplit(".", 1)
        expected = _sign(payload_b64.encode("ascii"), self.expected_token or "")
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
        return payload

    def verify_session_cookie(self, value: Optional[str], *, now: Optional[int] = None) -> bool:
        """Return True if a signed session cookie is valid and unexpired."""
        return self.session_payload(value, now=now) is not None

    @staticmethod
    def create_csrf_token() -> str:
        return secrets.token_urlsafe(32)

    async def __call__(
        self,
        request: Request,
        authorization: Optional[str] = Header(None),
    ) -> str:
        """
        FastAPI dependency. Raises 401 on any failure.

        The behaviour is intentionally identical to
        `src/feedback/feedback_api.py::verify_bearer_token` so an analyst
        configures one token and it works against both routers. Browser
        session-cookie auth is accepted too, with CSRF validation for
        state-changing requests.
        """
        if not self.enabled:
            # If no token is configured, the caller must have explicitly
            # opted into insecure mode at startup. We still reject any
            # attempt to authenticate so callers can detect the dev posture.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured on this server",
            )

        if authorization:
            parts = authorization.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization header format",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            token = parts[1]
            if not hmac.compare_digest(token, self.expected_token or ""):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return token

        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if self.verify_session_cookie(session_cookie):
            if request.method.upper() not in SAFE_METHODS:
                _verify_csrf(request)
            return "session"

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header or valid session cookie",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Security headers middleware
# ─────────────────────────────────────────────────────────────────────────────


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


def _verify_csrf(request: Request) -> None:
    header_token = request.headers.get(CSRF_HEADER_NAME)
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Attach standard browser security headers to every response.

    CSP keeps inline JS/CSS temporarily allowed for older templates that
    have not been split into static assets yet. The main dashboard ships a
    stricter per-response CSP from src/reporting/dashboard.py after moving
    its JS/CSS and shared theme/auth fragment to /static.
    """

    DEFAULT_CSP = (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", self.DEFAULT_CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        # Only meaningful over HTTPS; harmless over HTTP because browsers ignore it.
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        return response


def add_security_headers_middleware(app: FastAPI) -> None:
    """Attach the security headers middleware to a FastAPI app."""
    app.add_middleware(SecurityHeadersMiddleware)


# ─────────────────────────────────────────────────────────────────────────────
# 3. SSRF guard
# ─────────────────────────────────────────────────────────────────────────────


class SSRFBlockedError(ValueError):
    """Raised when a URL fails SSRF validation."""


# Networks the URL detonator must never fetch from. Centralised here so the
# threat-model doc and the test suite can reference the same source of truth.
DENY_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "this network"
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),        # loopback v4
    ipaddress.ip_network("169.254.0.0/16"),     # link-local + AWS/GCP/Azure IMDS
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918
    ipaddress.ip_network("198.18.0.0/15"),      # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # multicast
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
    ipaddress.ip_network("255.255.255.255/32"), # broadcast
    ipaddress.ip_network("::1/128"),            # loopback v6
    ipaddress.ip_network("fc00::/7"),           # unique local v6
    ipaddress.ip_network("fe80::/10"),          # link-local v6
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped v6
]

# Cloud metadata services live inside 169.254.169.254 (AWS/GCP/Azure/Oracle)
# and 100.100.100.200 (Alibaba). Both are already covered by the deny ranges
# above, but kept in this comment so future-me doesn't reinvent them.


class SSRFGuard:
    """
    Validate a URL is safe for the URL detonator to visit.

    The check is a three-layer defence:
        1. Scheme allowlist (http, https only)
        2. Host parseable, no userinfo
        3. DNS resolution to an IP that is NOT in any deny network

    A URL that passes still must be fetched through a client that follows
    redirects manually and re-runs this check on each hop. The class
    provides `assert_safe()` for both the initial check and per-redirect
    revalidation.
    """

    ALLOWED_SCHEMES = ("http", "https")

    def assert_safe(self, url: str) -> str:
        """
        Validate the URL or raise SSRFBlockedError.

        Returns the URL string for chaining: `safe = guard.assert_safe(u)`.
        """
        if not url or not isinstance(url, str):
            raise SSRFBlockedError("URL must be a non-empty string")

        parsed = urlparse(url)
        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            raise SSRFBlockedError(
                f"URL scheme {parsed.scheme!r} not allowed (only http/https)"
            )

        if parsed.username or parsed.password:
            raise SSRFBlockedError("URL must not contain userinfo")

        host = parsed.hostname
        if not host:
            raise SSRFBlockedError("URL has no host")

        # Resolve all A/AAAA records — a single hostname can map to many IPs
        # and we have to refuse if ANY of them is in the deny list.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as e:
            raise SSRFBlockedError(f"DNS resolution failed for {host!r}: {e}")

        resolved = {info[4][0] for info in infos}
        if not resolved:
            raise SSRFBlockedError(f"No IPs resolved for {host!r}")

        for ip_str in resolved:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                raise SSRFBlockedError(f"Unparseable resolved IP {ip_str!r}")
            for network in DENY_NETWORKS:
                if ip.version == network.version and ip in network:
                    raise SSRFBlockedError(
                        f"Resolved IP {ip} for host {host!r} is in deny network {network}"
                    )

        return url


# Module-level singleton — most callers want one shared instance.
default_ssrf_guard = SSRFGuard()

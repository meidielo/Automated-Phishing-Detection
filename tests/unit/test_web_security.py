"""
Tests for src/security/web_security.py — bearer auth, SSRF guard, headers.

These cover the P0 fixes from the security audit:
- Bearer token verification rejects missing / malformed / wrong tokens
- SSRFGuard blocks every documented private/loopback/metadata range
- SSRFGuard catches the hostname-based loopback trick (`localhost` → 127.0.0.1)
- SecurityHeadersMiddleware attaches all the required headers
"""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from src.security.web_security import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    DENY_NETWORKS,
    SESSION_COOKIE_NAME,
    SSRFBlockedError,
    SSRFGuard,
    SecurityHeadersMiddleware,
    TokenVerifier,
    add_security_headers_middleware,
)


# ─── TokenVerifier ───────────────────────────────────────────────────────────


class TestTokenVerifier:
    @staticmethod
    def _request(method: str = "GET", cookie: str = "", host: str = "testserver"):
        from starlette.requests import Request

        headers = [(b"host", host.encode("ascii"))]
        if cookie:
            headers.append((b"cookie", cookie.encode("ascii")))
        return Request({
            "type": "http",
            "method": method,
            "path": "/protected",
            "headers": headers,
            "scheme": "http",
            "server": (host, 80),
            "client": ("127.0.0.1", 12345),
        })

    def test_disabled_when_no_token(self):
        v = TokenVerifier(None)
        assert not v.enabled

        v = TokenVerifier("")
        assert not v.enabled

    def test_enabled_when_token_set(self):
        v = TokenVerifier("secret")
        assert v.enabled

    def test_disabled_dependency_returns_503(self):
        v = TokenVerifier(None)
        with pytest.raises(Exception) as exc_info:
            asyncio.run(v(self._request(), authorization="Bearer secret"))
        assert getattr(exc_info.value, "status_code", None) == 503

    def test_missing_header_rejected(self):
        v = TokenVerifier("secret")
        with pytest.raises(Exception) as exc_info:
            asyncio.run(v(self._request(), authorization=None))
        assert getattr(exc_info.value, "status_code", None) == 401

    def test_malformed_header_rejected(self):
        v = TokenVerifier("secret")
        for bad in ("secret", "Basic secret", "Bearer", "Bearer  extra parts"):
            with pytest.raises(Exception) as exc_info:
                asyncio.run(v(self._request(), authorization=bad))
            assert getattr(exc_info.value, "status_code", None) == 401, f"failed for {bad!r}"

    def test_wrong_token_rejected(self):
        v = TokenVerifier("secret")
        with pytest.raises(Exception) as exc_info:
            asyncio.run(v(self._request(), authorization="Bearer wrong"))
        assert getattr(exc_info.value, "status_code", None) == 401

    def test_correct_token_accepted(self):
        v = TokenVerifier("secret")
        result = asyncio.run(v(self._request(), authorization="Bearer secret"))
        assert result == "secret"

    def test_case_insensitive_bearer(self):
        v = TokenVerifier("secret")
        result = asyncio.run(v(self._request(), authorization="bearer secret"))
        assert result == "secret"

    def test_session_cookie_accepted_for_get(self):
        v = TokenVerifier("secret")
        session_cookie = v.create_session_cookie()
        request = self._request(cookie=f"{SESSION_COOKIE_NAME}={session_cookie}")

        result = asyncio.run(v(request, authorization=None))

        assert result == "session"

    def test_expired_session_cookie_rejected(self):
        v = TokenVerifier("secret")
        session_cookie = v.create_session_cookie(now=1000, max_age_seconds=10)

        assert not v.verify_session_cookie(session_cookie, now=1011)

    def test_session_post_requires_csrf(self):
        v = TokenVerifier("secret")
        session_cookie = v.create_session_cookie()
        request = self._request(
            method="POST",
            cookie=f"{SESSION_COOKIE_NAME}={session_cookie}",
        )

        with pytest.raises(Exception) as exc_info:
            asyncio.run(v(request, authorization=None))

        assert getattr(exc_info.value, "status_code", None) == 403

    def test_session_post_accepts_csrf_and_same_origin(self):
        v = TokenVerifier("secret")
        session_cookie = v.create_session_cookie()
        csrf_token = v.create_csrf_token()
        from starlette.requests import Request

        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/protected",
            "headers": [
                (b"host", b"testserver"),
                (b"origin", b"http://testserver"),
                (CSRF_HEADER_NAME.encode("ascii"), csrf_token.encode("ascii")),
                (
                    b"cookie",
                    f"{SESSION_COOKIE_NAME}={session_cookie}; {CSRF_COOKIE_NAME}={csrf_token}".encode("ascii"),
                ),
            ],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        })

        result = asyncio.run(v(request, authorization=None))

        assert result == "session"

    def test_session_post_rejects_cross_origin(self):
        v = TokenVerifier("secret")
        session_cookie = v.create_session_cookie()
        csrf_token = v.create_csrf_token()
        from starlette.requests import Request

        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/protected",
            "headers": [
                (b"host", b"testserver"),
                (b"origin", b"http://evil.example"),
                (CSRF_HEADER_NAME.encode("ascii"), csrf_token.encode("ascii")),
                (
                    b"cookie",
                    f"{SESSION_COOKIE_NAME}={session_cookie}; {CSRF_COOKIE_NAME}={csrf_token}".encode("ascii"),
                ),
            ],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        })

        with pytest.raises(Exception) as exc_info:
            asyncio.run(v(request, authorization=None))

        assert getattr(exc_info.value, "status_code", None) == 403


# ─── TokenVerifier integration with FastAPI ──────────────────────────────────


class TestTokenVerifierWithFastAPI:
    def _build_app(self, token: str | None) -> TestClient:
        app = FastAPI()
        verifier = TokenVerifier(token)

        @app.get("/protected", dependencies=[Depends(verifier)])
        def protected():
            return {"ok": True}

        @app.get("/open")
        def open_route():
            return {"ok": True}

        return TestClient(app)

    def test_protected_route_blocks_no_token(self):
        client = self._build_app("secret")
        r = client.get("/protected")
        assert r.status_code == 401

    def test_protected_route_allows_correct_token(self):
        client = self._build_app("secret")
        r = client.get("/protected", headers={"Authorization": "Bearer secret"})
        assert r.status_code == 200

    def test_open_route_unaffected(self):
        client = self._build_app("secret")
        r = client.get("/open")
        assert r.status_code == 200


# ─── SSRFGuard ───────────────────────────────────────────────────────────────


class TestSSRFGuardSchemeFilter:
    def setup_method(self):
        self.guard = SSRFGuard()

    def test_rejects_ftp(self):
        with pytest.raises(SSRFBlockedError, match="scheme"):
            self.guard.assert_safe("ftp://example.com")

    def test_rejects_file(self):
        with pytest.raises(SSRFBlockedError, match="scheme"):
            self.guard.assert_safe("file:///etc/passwd")

    def test_rejects_gopher(self):
        with pytest.raises(SSRFBlockedError, match="scheme"):
            self.guard.assert_safe("gopher://internal/")

    def test_rejects_empty_string(self):
        with pytest.raises(SSRFBlockedError):
            self.guard.assert_safe("")

    def test_rejects_userinfo(self):
        # Mock DNS so we hit the userinfo check
        with patch("socket.getaddrinfo") as m:
            m.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
            with pytest.raises(SSRFBlockedError, match="userinfo"):
                self.guard.assert_safe("https://user:pass@example.com/")


class TestSSRFGuardLoopback:
    def setup_method(self):
        self.guard = SSRFGuard()

    def test_blocks_127_0_0_1(self):
        with pytest.raises(SSRFBlockedError, match="127.0.0.0/8"):
            self.guard.assert_safe("http://127.0.0.1/")

    def test_blocks_other_loopback(self):
        with pytest.raises(SSRFBlockedError, match="127.0.0.0/8"):
            self.guard.assert_safe("http://127.5.5.5/")

    def test_blocks_ipv6_loopback(self):
        with pytest.raises(SSRFBlockedError, match="::1/128"):
            self.guard.assert_safe("http://[::1]/")

    def test_blocks_hostname_resolving_to_loopback(self):
        # `localhost` resolves to a loopback address (127.0.0.1 or ::1
        # depending on the system's resolver order) — the textbook bypass
        # attempt that DNS-aware SSRF guards must catch.
        with pytest.raises(SSRFBlockedError, match=r"(127|::1)"):
            self.guard.assert_safe("http://localhost/")


class TestSSRFGuardRFC1918:
    def setup_method(self):
        self.guard = SSRFGuard()

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
    ])
    def test_blocks_rfc1918(self, ip):
        with pytest.raises(SSRFBlockedError):
            self.guard.assert_safe(f"http://{ip}/")


class TestSSRFGuardCloudMetadata:
    def setup_method(self):
        self.guard = SSRFGuard()

    def test_blocks_aws_imds(self):
        # 169.254.169.254 is the AWS/GCP/Azure metadata endpoint
        with pytest.raises(SSRFBlockedError, match="169.254"):
            self.guard.assert_safe("http://169.254.169.254/latest/meta-data/")

    def test_blocks_link_local(self):
        with pytest.raises(SSRFBlockedError, match="169.254"):
            self.guard.assert_safe("http://169.254.0.1/")


class TestSSRFGuardOther:
    def setup_method(self):
        self.guard = SSRFGuard()

    def test_blocks_cgnat(self):
        with pytest.raises(SSRFBlockedError, match="100.64"):
            self.guard.assert_safe("http://100.64.0.1/")

    def test_blocks_multicast(self):
        with pytest.raises(SSRFBlockedError, match="224"):
            self.guard.assert_safe("http://224.0.0.1/")

    def test_blocks_unique_local_ipv6(self):
        with pytest.raises(SSRFBlockedError, match="fc00"):
            self.guard.assert_safe("http://[fc00::1]/")

    def test_dns_failure_blocked(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            with pytest.raises(SSRFBlockedError, match="DNS"):
                self.guard.assert_safe("http://this-host-does-not-resolve.invalid/")


class TestSSRFGuardAllowsPublic:
    def setup_method(self):
        self.guard = SSRFGuard()

    def test_public_ip_allowed(self):
        # 8.8.8.8 is Google DNS — public, not in any deny range
        with patch("socket.getaddrinfo") as m:
            m.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
            result = self.guard.assert_safe("https://dns.google/")
            assert result == "https://dns.google/"

    def test_returns_url_for_chaining(self):
        with patch("socket.getaddrinfo") as m:
            m.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]  # example.com
            result = self.guard.assert_safe("https://example.com/path")
            assert result == "https://example.com/path"


class TestSSRFGuardMultiAddressHostname:
    """A hostname can resolve to multiple IPs; ALL must be safe."""

    def setup_method(self):
        self.guard = SSRFGuard()

    def test_blocks_if_any_resolved_ip_is_private(self):
        # One public, one private — must reject
        with patch("socket.getaddrinfo") as m:
            m.return_value = [
                (2, 1, 6, "", ("8.8.8.8", 0)),
                (2, 1, 6, "", ("10.0.0.5", 0)),  # rebind attack target
            ]
            with pytest.raises(SSRFBlockedError, match="10.0"):
                self.guard.assert_safe("https://multi-resolve.example/")


# ─── DENY_NETWORKS sanity check ──────────────────────────────────────────────


class TestDenyNetworks:
    def test_metadata_ip_covered(self):
        import ipaddress
        meta = ipaddress.ip_address("169.254.169.254")
        assert any(meta.version == n.version and meta in n for n in DENY_NETWORKS)

    def test_loopback_covered(self):
        import ipaddress
        for ip in ("127.0.0.1", "127.255.255.254"):
            assert any(
                ipaddress.ip_address(ip).version == n.version
                and ipaddress.ip_address(ip) in n
                for n in DENY_NETWORKS
            )


# ─── Security headers middleware ─────────────────────────────────────────────


class TestSecurityHeadersMiddleware:
    def setup_method(self):
        app = FastAPI()
        add_security_headers_middleware(app)

        @app.get("/")
        def root():
            return {"ok": True}

        self.client = TestClient(app)

    def test_csp_present(self):
        r = self.client.get("/")
        assert "Content-Security-Policy" in r.headers
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "frame-src 'none'" in csp
        assert "object-src 'none'" in csp

    def test_x_frame_options_deny(self):
        r = self.client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_nosniff(self):
        r = self.client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy_no_referrer(self):
        r = self.client.get("/")
        assert r.headers.get("Referrer-Policy") == "no-referrer"

    def test_hsts_present(self):
        r = self.client.get("/")
        assert "Strict-Transport-Security" in r.headers
        assert "max-age=" in r.headers["Strict-Transport-Security"]

    def test_permissions_policy_present(self):
        r = self.client.get("/")
        assert "Permissions-Policy" in r.headers

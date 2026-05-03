from __future__ import annotations

import pytest

import src.analyzers.url_detonation as url_detonation
from src.analyzers.url_detonation import URLDetonationAnalyzer
from src.security.web_security import SSRFBlockedError


class _FakeBrowser:
    def is_connected(self):
        return True

    async def close(self):
        return None


class _FakeChromium:
    def __init__(self):
        self.connected = None
        self.cdp_connected = None
        self.launched = False

    async def connect(self, endpoint, timeout=None):
        self.connected = (endpoint, timeout)
        return _FakeBrowser()

    async def connect_over_cdp(self, endpoint, timeout=None):
        self.cdp_connected = (endpoint, timeout)
        return _FakeBrowser()

    async def launch(self, **kwargs):
        self.launched = True
        return _FakeBrowser()


class _FakePlaywright:
    def __init__(self):
        self.chromium = _FakeChromium()
        self.stopped = False

    async def stop(self):
        self.stopped = True


class _FakeStarter:
    def __init__(self, fake_playwright):
        self.fake_playwright = fake_playwright

    async def start(self):
        return self.fake_playwright


@pytest.mark.asyncio
async def test_real_detonator_uses_remote_playwright_endpoint(monkeypatch):
    import playwright.async_api

    fake = _FakePlaywright()
    monkeypatch.setattr(
        playwright.async_api,
        "async_playwright",
        lambda: _FakeStarter(fake),
    )

    analyzer = URLDetonationAnalyzer(
        timeout_ms=1234,
        browser_ws_endpoint="ws://browser-sandbox:3000/",
    )
    await analyzer._ensure_browser()

    assert fake.chromium.connected == ("ws://browser-sandbox:3000/", 1234)
    assert not fake.chromium.launched


@pytest.mark.asyncio
async def test_real_detonator_uses_remote_cdp_endpoint(monkeypatch):
    import playwright.async_api

    fake = _FakePlaywright()
    monkeypatch.setattr(
        playwright.async_api,
        "async_playwright",
        lambda: _FakeStarter(fake),
    )

    analyzer = URLDetonationAnalyzer(
        timeout_ms=4321,
        browser_cdp_endpoint="http://browser-sandbox:9222/",
    )
    await analyzer._ensure_browser()

    assert fake.chromium.cdp_connected == ("http://browser-sandbox:9222/", 4321)
    assert not fake.chromium.launched


def test_real_detonator_reconnects_after_closed_browser_errors():
    assert URLDetonationAnalyzer._should_reconnect_browser(
        RuntimeError("TargetClosedError: Browser.new_context: Target page, context or browser has been closed")
    )
    assert URLDetonationAnalyzer._should_reconnect_browser(
        RuntimeError("WebSocket connection closed")
    )
    assert not URLDetonationAnalyzer._should_reconnect_browser(
        RuntimeError("navigation timeout")
    )


@pytest.mark.asyncio
async def test_real_detonator_blocks_initial_private_url_without_browser(monkeypatch):
    analyzer = URLDetonationAnalyzer()
    browser_started = False

    async def fail_if_started():
        nonlocal browser_started
        browser_started = True

    monkeypatch.setattr(analyzer, "_ensure_browser", fail_if_started)

    result = await analyzer.detonate_url("http://127.0.0.1/admin")

    assert browser_started is False
    assert result["page_loaded"] is False
    assert result["risk_indicators"] == ["ssrf_blocked_initial_url"]
    assert result["ssrf_blocked_requests"][0]["url"] == "http://127.0.0.1/admin"


class _Route:
    def __init__(self):
        self.aborted = False
        self.continued = False

    async def abort(self):
        self.aborted = True

    async def continue_(self):
        self.continued = True


class _Request:
    def __init__(self, url: str):
        self.url = url


class _RoutePage:
    def __init__(self):
        self.url = "https://example.com"
        self.route_handler = None
        self.blocked_route = None

    def on(self, *_args, **_kwargs):
        return None

    async def route(self, _pattern, handler):
        self.route_handler = handler

    async def goto(self, url, **_kwargs):
        self.url = url
        self.blocked_route = _Route()
        await self.route_handler(
            self.blocked_route,
            _Request("http://169.254.169.254/latest/meta-data/"),
        )
        raise RuntimeError("net::ERR_FAILED")

    async def screenshot(self, **_kwargs):
        return b"png"


class _RouteContext:
    def __init__(self, page):
        self.page = page
        self.closed = False

    async def new_page(self):
        return self.page

    async def close(self):
        self.closed = True


class _RouteBrowser:
    def __init__(self, page):
        self.page = page

    def is_connected(self):
        return True

    async def new_context(self, **_kwargs):
        return _RouteContext(self.page)


@pytest.mark.asyncio
async def test_real_detonator_blocks_redirect_or_subresource_requests(monkeypatch):
    page = _RoutePage()
    analyzer = URLDetonationAnalyzer()
    analyzer._browser = _RouteBrowser(page)

    def fake_assert_safe(target_url: str) -> str:
        if "169.254.169.254" in target_url:
            raise SSRFBlockedError("metadata IP blocked")
        return target_url

    monkeypatch.setattr(url_detonation.default_ssrf_guard, "assert_safe", fake_assert_safe)

    result = await analyzer.detonate_url("https://example.com")

    assert page.blocked_route.aborted is True
    assert result["page_loaded"] is False
    assert result["error"] == "Navigation blocked by SSRF guard"
    assert result["ssrf_blocked_requests"][0]["url"] == "http://169.254.169.254/latest/meta-data/"
    assert "ssrf_blocked_request" in result["risk_indicators"]

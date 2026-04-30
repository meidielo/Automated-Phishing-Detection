from __future__ import annotations

import pytest

from src.analyzers.url_detonation import URLDetonationAnalyzer


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

#!/usr/bin/env python3
"""Headless browser smoke test for the dashboard chart surface.

The script starts the FastAPI app in-process, logs in through the browser
session flow, and verifies that Chart.js renders under the dashboard's strict
CSP. It intentionally avoids `main.py serve` so CI does not start real mailbox
monitoring from a developer's local `data/accounts.json`.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.request

import uvicorn
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


DEFAULT_TOKEN = "ci-dashboard-browser-token"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(base_url: str, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/health", timeout=2) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # pragma: no cover - only failure path
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"server did not become healthy: {last_error}")


def _start_server(host: str, port: int):
    os.environ.setdefault("ANALYST_API_TOKEN", DEFAULT_TOKEN)

    from main import PhishingDetectionApp

    app_wrapper = PhishingDetectionApp()
    token = app_wrapper.config.analyst_api_token or os.environ.get("ANALYST_API_TOKEN") or DEFAULT_TOKEN
    app = app_wrapper.create_fastapi_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="dashboard-smoke-uvicorn", daemon=True)
    thread.start()
    return server, thread, token


def _run_browser_check(base_url: str, token: str) -> dict:
    console_errors: list[str] = []
    page_errors: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on(
            "console",
            lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
        )
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))

        login_response = page.goto(f"{base_url}/login?next=/dashboard", wait_until="networkidle")
        if not login_response or login_response.status >= 400:
            raise RuntimeError(f"login page failed with status {login_response.status if login_response else 'none'}")

        page.fill('input[name="token"]', token)
        with page.expect_navigation(wait_until="networkidle"):
            page.click('button[type="submit"]')

        response = page.goto(f"{base_url}/dashboard/", wait_until="networkidle")
        if not response or response.status >= 400:
            raise RuntimeError(f"dashboard failed with status {response.status if response else 'none'}")

        page.wait_for_selector("#verdictChart", state="attached")
        page.wait_for_selector("#trendsChart", state="attached")
        page.wait_for_function(
            "() => document.getElementById('tableArea') && "
            "document.getElementById('tableArea').textContent.trim().length > 0"
        )

        result = page.evaluate(
            """() => {
              const visible = (id) => {
                const el = document.getElementById(id);
                if (!el) return false;
                const box = el.getBoundingClientRect();
                return !el.hidden && box.width > 0 && box.height > 0;
              };
              return {
                chartLoaded: !!window.Chart,
                verdictCanvasVisible: visible('verdictChart'),
                verdictLegendVisible: visible('verdictLegend'),
                verdictLegendText: (document.getElementById('verdictLegend') || {}).textContent || '',
                trendsCanvasVisible: visible('trendsChart'),
                verdictFallbackHidden: document.getElementById('verdictFallback').hidden,
                trendsFallbackHidden: document.getElementById('trendsFallback').hidden,
                tableAreaPresent: !!document.getElementById('tableArea'),
                sharedCssLoaded: !!document.querySelector('link[href^="/static/shared.css"]'),
                dashboardCssLoaded: !!document.querySelector('link[href^="/static/dashboard.css"]'),
                dashboardJsLoaded: !!document.querySelector('script[src^="/static/dashboard.js"]'),
              };
            }"""
        )
        result["csp"] = response.headers.get("content-security-policy", "")
        result["consoleErrors"] = console_errors
        result["pageErrors"] = page_errors
        browser.close()

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run dashboard browser smoke check.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    token = os.environ.get("ANALYST_API_TOKEN") or DEFAULT_TOKEN
    os.environ["ANALYST_API_TOKEN"] = token
    port = args.port or _free_port()
    base_url = f"http://{args.host}:{port}"

    server, thread, token = _start_server(args.host, port)
    try:
        _wait_for_health(base_url, args.timeout)
        result = _run_browser_check(base_url, token)
    finally:
        server.should_exit = True
        thread.join(timeout=5)

    failures = []
    for key in (
        "chartLoaded",
        "verdictCanvasVisible",
        "verdictLegendVisible",
        "trendsCanvasVisible",
        "verdictFallbackHidden",
        "trendsFallbackHidden",
        "tableAreaPresent",
        "sharedCssLoaded",
        "dashboardCssLoaded",
        "dashboardJsLoaded",
    ):
        if not result.get(key):
            failures.append(key)
    if "'unsafe-inline'" in result.get("csp", ""):
        failures.append("strict dashboard CSP")
    if result.get("consoleErrors"):
        failures.append("browser console errors")
    if result.get("pageErrors"):
        failures.append("browser page errors")
    if "Clean" not in result.get("verdictLegendText", ""):
        failures.append("verdict legend labels")

    print(json.dumps(result, indent=2, sort_keys=True))
    if failures:
        print("Dashboard browser check failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

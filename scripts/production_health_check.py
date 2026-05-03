#!/usr/bin/env python3
"""Production health probe with optional webhook alerting."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse


DEFAULT_USER_AGENT = os.getenv(
    "PHISHANALYZE_HEALTHCHECK_USER_AGENT",
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
)


def _require_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Only http(s) URLs are supported: {url}")
    return url


def _request_json(url: str, *, token: str = "", timeout: float = 5.0) -> tuple[int, dict]:
    url = _require_http_url(url)
    headers = {
        "Accept": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error": raw}
        return exc.code, payload


def _post_webhook(url: str, payload: dict, timeout: float = 5.0) -> None:
    url = _require_http_url(url)
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        response.read()


def run_check(
    base_url: str,
    *,
    token: str = "",
    require_monitor_running: bool = False,
    max_monitor_age_seconds: int = 300,
    timeout: float = 5.0,
) -> dict:
    base_url = base_url.rstrip("/")
    failures: list[str] = []
    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "failures": failures,
    }

    status, health = _request_json(f"{base_url}/api/health", timeout=timeout)
    report["health"] = {"status_code": status, "payload": health}
    if status != 200 or health.get("status") != "healthy":
        failures.append("health endpoint is not healthy")

    if token:
        status, monitor = _request_json(f"{base_url}/api/monitor/stats", token=token, timeout=timeout)
        report["monitor"] = {"status_code": status, "payload": monitor}
        if status != 200:
            failures.append("monitor stats endpoint is not reachable")
        else:
            if require_monitor_running and not monitor.get("running"):
                failures.append("mailbox monitor is not running")
            stats = monitor.get("stats") or {}
            if stats.get("errors", 0):
                failures.append(f"monitor has {stats.get('errors')} recorded error(s)")
            last_poll = stats.get("last_poll")
            if require_monitor_running and last_poll:
                try:
                    parsed = datetime.fromisoformat(last_poll.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
                    report["monitor"]["last_poll_age_seconds"] = int(age)
                    if age > max_monitor_age_seconds:
                        failures.append(f"last monitor poll is older than {max_monitor_age_seconds}s")
                except ValueError:
                    failures.append("monitor last_poll timestamp is not parseable")
    elif require_monitor_running:
        failures.append("ANALYST_API_TOKEN is required to verify monitor status")

    report["ok"] = not failures
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Check production service health and optionally send alerts.")
    parser.add_argument("--base-url", default=os.getenv("PHISHDETECT_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--token", default=os.getenv("ANALYST_API_TOKEN", ""))
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--require-monitor-running", action="store_true")
    parser.add_argument("--max-monitor-age-seconds", type=int, default=300)
    parser.add_argument("--alert-webhook", default=os.getenv("ALERT_WEBHOOK_URL", ""))
    args = parser.parse_args()

    started = time.monotonic()
    try:
        report = run_check(
            args.base_url,
            token=args.token,
            require_monitor_running=args.require_monitor_running,
            max_monitor_age_seconds=args.max_monitor_age_seconds,
            timeout=args.timeout,
        )
    except Exception as exc:
        report = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "base_url": args.base_url,
            "ok": False,
            "failures": [str(exc)],
        }
    report["duration_ms"] = int((time.monotonic() - started) * 1000)

    if not report["ok"] and args.alert_webhook:
        try:
            _post_webhook(args.alert_webhook, report, timeout=args.timeout)
            report["alert_sent"] = True
        except Exception as exc:  # pragma: no cover - depends on external webhook
            report["alert_sent"] = False
            report["alert_error"] = str(exc)

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Small production load/error probe for a running dashboard and mailbox monitor."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse


AUTH_ENDPOINTS = (
    "/api/monitor/stats",
    "/api/monitor/log?limit=50&compact=true",
)


def _require_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Only http(s) URLs are supported: {url}")
    return url


def _get(url: str, token: str, timeout: float) -> tuple[int, float, str]:
    url = _require_http_url(url)
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            response.read()
            return response.status, (time.monotonic() - started) * 1000, ""
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, (time.monotonic() - started) * 1000, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, (time.monotonic() - started) * 1000, str(exc)


def _json_get(url: str, token: str, timeout: float) -> dict:
    url = _require_http_url(url)
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8") or "{}")


def run_load_probe(
    base_url: str,
    *,
    token: str,
    duration_seconds: int,
    concurrency: int,
    timeout: float,
    require_monitor_running: bool,
) -> dict:
    base_url = base_url.rstrip("/")
    endpoints = ["/api/health"]
    if token:
        endpoints.extend(AUTH_ENDPOINTS)
    elif require_monitor_running:
        raise RuntimeError("ANALYST_API_TOKEN is required when --require-monitor-running is set")

    monitor_before = None
    if token:
        monitor_before = _json_get(f"{base_url}/api/monitor/stats", token, timeout)
        if require_monitor_running and not monitor_before.get("running"):
            raise RuntimeError("mailbox monitor is not running")

    deadline = time.monotonic() + duration_seconds

    def worker(worker_id: int) -> list[tuple[int, float, str]]:
        results: list[tuple[int, float, str]] = []
        i = worker_id
        while time.monotonic() < deadline:
            endpoint = endpoints[i % len(endpoints)]
            results.append(_get(f"{base_url}{endpoint}", token, timeout))
            i += concurrency
        return results

    all_results: list[tuple[int, float, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker, i) for i in range(concurrency)]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    statuses: dict[str, int] = {}
    failures: list[str] = []
    latencies = [latency for _, latency, _ in all_results]
    for status, _, error in all_results:
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        if status != 200:
            failures.append(error or f"HTTP {status}")

    monitor_after = _json_get(f"{base_url}/api/monitor/stats", token, timeout) if token else None
    if require_monitor_running and monitor_after and not monitor_after.get("running"):
        failures.append("mailbox monitor stopped during load probe")

    total = len(all_results)
    error_rate = (len(failures) / total) if total else 1.0
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "duration_seconds": duration_seconds,
        "concurrency": concurrency,
        "requests": total,
        "status_counts": statuses,
        "error_rate": error_rate,
        "latency_ms": {
            "min": round(min(latencies), 2) if latencies else None,
            "median": round(statistics.median(latencies), 2) if latencies else None,
            "p95": round(statistics.quantiles(latencies, n=20)[18], 2) if len(latencies) >= 20 else None,
            "max": round(max(latencies), 2) if latencies else None,
        },
        "sample_failures": failures[:5],
        "monitor_before": monitor_before,
        "monitor_after": monitor_after,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a small load/error probe against a running deployment.")
    parser.add_argument("--base-url", default=os.getenv("PHISHDETECT_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--token", default=os.getenv("ANALYST_API_TOKEN", ""))
    parser.add_argument("--duration-seconds", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--require-monitor-running", action="store_true")
    args = parser.parse_args()

    report = run_load_probe(
        args.base_url,
        token=args.token,
        duration_seconds=args.duration_seconds,
        concurrency=args.concurrency,
        timeout=args.timeout,
        require_monitor_running=args.require_monitor_running,
    )
    report["ok"] = report["error_rate"] <= args.max_error_rate
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

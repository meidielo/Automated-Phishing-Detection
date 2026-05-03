"""
Live API diagnostic checks for the phishing-detection pipeline.

Single source of truth for what was previously three drifting copies:
- `diagnose_apis.py` (CLI tool, prints colored output)
- `test_apis.py` (CLI tool, prints simpler output)
- `/api/diagnose` endpoint in `main.py` (returns JSON)

Each service has one check function returning a `CheckResult` dataclass.
Callers format the results — this module does no I/O beyond the actual
HTTP requests, no `print()`, no logging beyond debug.

Adding a new service:
1. Write `async def check_<service>(api_key) -> CheckResult`
2. Add it to the `_CHECK_REGISTRY` dict
3. Update tests with a mock for the new check
"""
from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


# Default per-check timeout in seconds. Diagnostic calls should be quick;
# anything over this is reported as a failure rather than allowed to hang.
DEFAULT_TIMEOUT_S = 12


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    WARN = "warn"


@dataclass
class CheckResult:
    """Structured result of one API health check."""

    service: str
    status: CheckStatus
    message: str = ""
    http_status: Optional[int] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ─── individual checks ─────────────────────────────────────────────────────


async def check_virustotal(api_key: str, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    if not api_key:
        return CheckResult("virustotal", CheckStatus.SKIP, "no API key configured")
    test_url = "https://www.google.com"
    url_id = base64.urlsafe_b64encode(test_url.encode()).decode().rstrip("=")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    return CheckResult("virustotal", CheckStatus.PASS, "API operational", http_status=200)
                if r.status == 404:
                    return CheckResult(
                        "virustotal", CheckStatus.PASS,
                        "key valid; test URL not in DB (expected)",
                        http_status=404,
                    )
                if r.status == 401:
                    return CheckResult("virustotal", CheckStatus.FAIL, "invalid API key", http_status=401)
                if r.status == 429:
                    return CheckResult("virustotal", CheckStatus.WARN, "rate limited", http_status=429)
                return CheckResult("virustotal", CheckStatus.FAIL, f"HTTP {r.status}", http_status=r.status)
    except asyncio.TimeoutError:
        return CheckResult("virustotal", CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult("virustotal", CheckStatus.FAIL, f"exception: {e}")


async def check_google_safebrowsing(api_key: str, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    if not api_key:
        return CheckResult("google_safebrowsing", CheckStatus.SKIP, "no API key configured")
    payload = {
        "client": {"clientId": "phishing-detector-diag", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/s/phishing.html"}],
        },
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    matches = len(data.get("matches", []))
                    return CheckResult(
                        "google_safebrowsing", CheckStatus.PASS,
                        f"API operational ({matches} test threats found)",
                        http_status=200, extra={"threats_found": matches},
                    )
                if r.status == 403:
                    return CheckResult(
                        "google_safebrowsing", CheckStatus.FAIL,
                        "API key invalid OR Safe Browsing API not enabled in Google Cloud Console",
                        http_status=403,
                    )
                if r.status == 400:
                    body = await r.text()
                    return CheckResult(
                        "google_safebrowsing", CheckStatus.FAIL,
                        f"bad request: {body[:120]}", http_status=400,
                    )
                return CheckResult("google_safebrowsing", CheckStatus.FAIL, f"HTTP {r.status}", http_status=r.status)
    except asyncio.TimeoutError:
        return CheckResult("google_safebrowsing", CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult("google_safebrowsing", CheckStatus.FAIL, f"exception: {e}")


async def check_urlscan(api_key: str, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    if not api_key:
        return CheckResult("urlscan", CheckStatus.SKIP, "no API key configured")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
                headers={"API-Key": api_key},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    return CheckResult(
                        "urlscan", CheckStatus.PASS,
                        "API operational (note: pipeline uses fire-and-forget, confidence=0 by design)",
                        http_status=200,
                    )
                if r.status == 401:
                    return CheckResult("urlscan", CheckStatus.FAIL, "invalid API key", http_status=401)
                return CheckResult("urlscan", CheckStatus.FAIL, f"HTTP {r.status}", http_status=r.status)
    except asyncio.TimeoutError:
        return CheckResult("urlscan", CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult("urlscan", CheckStatus.FAIL, f"exception: {e}")


async def check_abuseipdb(api_key: str, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    if not api_key:
        return CheckResult("abuseipdb", CheckStatus.SKIP, "no API key configured")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    score = data.get("data", {}).get("abuseConfidenceScore", "?")
                    return CheckResult(
                        "abuseipdb", CheckStatus.PASS,
                        f"API operational (8.8.8.8 abuse score = {score})",
                        http_status=200, extra={"test_ip_score": score},
                    )
                if r.status == 401:
                    return CheckResult("abuseipdb", CheckStatus.FAIL, "invalid API key", http_status=401)
                if r.status == 429:
                    return CheckResult("abuseipdb", CheckStatus.WARN, "rate limited", http_status=429)
                return CheckResult("abuseipdb", CheckStatus.FAIL, f"HTTP {r.status}", http_status=r.status)
    except asyncio.TimeoutError:
        return CheckResult("abuseipdb", CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult("abuseipdb", CheckStatus.FAIL, f"exception: {e}")


async def check_anthropic(api_key: str, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    if not api_key:
        return CheckResult("anthropic_llm", CheckStatus.SKIP, "no API key configured")
    payload = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 5,
        "messages": [{"role": "user", "content": "hi"}],
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    return CheckResult("anthropic_llm", CheckStatus.PASS, "API operational", http_status=200)
                if r.status == 401:
                    return CheckResult("anthropic_llm", CheckStatus.FAIL, "invalid API key", http_status=401)
                if r.status == 429:
                    return CheckResult("anthropic_llm", CheckStatus.WARN, "rate limited", http_status=429)
                return CheckResult("anthropic_llm", CheckStatus.FAIL, f"HTTP {r.status}", http_status=r.status)
    except asyncio.TimeoutError:
        return CheckResult("anthropic_llm", CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult("anthropic_llm", CheckStatus.FAIL, f"exception: {e}")


async def _check_openai_compatible_llm(
    *,
    service: str,
    api_key: str,
    base_url: str,
    model: str,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> CheckResult:
    if not api_key:
        return CheckResult(service, CheckStatus.SKIP, "no API key configured")

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Return the word ok."}],
        "max_tokens": 5,
        "temperature": 0,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "content-type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                if r.status == 200:
                    return CheckResult(
                        service,
                        CheckStatus.PASS,
                        "API operational",
                        http_status=200,
                    )
                if r.status in {401, 403}:
                    return CheckResult(
                        service,
                        CheckStatus.FAIL,
                        "invalid API key",
                        http_status=r.status,
                    )
                if r.status == 429:
                    return CheckResult(
                        service,
                        CheckStatus.WARN,
                        "rate limited",
                        http_status=429,
                    )
                return CheckResult(
                    service,
                    CheckStatus.FAIL,
                    f"HTTP {r.status}",
                    http_status=r.status,
                )
    except asyncio.TimeoutError:
        return CheckResult(service, CheckStatus.FAIL, f"timeout ({timeout}s)")
    except Exception as e:
        return CheckResult(service, CheckStatus.FAIL, f"exception: {e}")


async def check_deepseek(
    api_key: str,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> CheckResult:
    return await _check_openai_compatible_llm(
        service="deepseek_llm",
        api_key=api_key,
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
        timeout=timeout,
    )


async def check_moonshot(
    api_key: str,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> CheckResult:
    return await _check_openai_compatible_llm(
        service="moonshot_llm",
        api_key=api_key,
        base_url="https://api.moonshot.ai/v1",
        model="kimi-k2.6",
        timeout=timeout,
    )


# ─── registry + orchestrator ───────────────────────────────────────────────


# Maps env-var name → (service display name, check function).
# Adding a new service: append a row here and write the corresponding
# `check_<service>` function above. The CLI tools and the dashboard
# endpoint pick up the new check automatically.
_CHECK_REGISTRY: list[tuple[str, callable]] = [
    ("VIRUSTOTAL_API_KEY", check_virustotal),
    ("GOOGLE_SAFE_BROWSING_API_KEY", check_google_safebrowsing),
    ("URLSCAN_API_KEY", check_urlscan),
    ("ABUSEIPDB_API_KEY", check_abuseipdb),
    ("ANTHROPIC_API_KEY", check_anthropic),
    ("DEEPSEEK_API_KEY", check_deepseek),
    ("MOONSHOT_API_KEY", check_moonshot),
]


async def run_all_checks(
    config_api=None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> list[CheckResult]:
    """
    Run every registered diagnostic check concurrently.

    Args:
        config_api: optional `APIConfig` instance. If supplied, keys are
            read from there. If None, keys are read from environment
            variables. The CLI tools pass None; the FastAPI endpoint
            passes self.config.api so it picks up YAML overrides.
        timeout: per-check timeout in seconds.

    Returns:
        List of `CheckResult` in registry order. Same shape regardless
        of which call site invoked it.
    """
    import os

    def _key_for(env_name: str) -> str:
        if config_api is not None:
            provider = (getattr(config_api, "llm_provider", "") or "").lower()
            if env_name == "DEEPSEEK_API_KEY":
                return getattr(config_api, "deepseek_key", "") or (
                    getattr(config_api, "llm_api_key", "") if provider == "deepseek" else ""
                )
            if env_name == "MOONSHOT_API_KEY":
                return getattr(config_api, "moonshot_key", "") or (
                    getattr(config_api, "llm_api_key", "") if provider in {"moonshot", "kimi"} else ""
                )
            field_name = {
                "VIRUSTOTAL_API_KEY": "virustotal_key",
                "GOOGLE_SAFE_BROWSING_API_KEY": "google_safebrowsing_key",
                "URLSCAN_API_KEY": "urlscan_key",
                "ABUSEIPDB_API_KEY": "abuseipdb_key",
                "ANTHROPIC_API_KEY": "anthropic_key",
                "DEEPSEEK_API_KEY": "deepseek_key",
                "MOONSHOT_API_KEY": "moonshot_key",
            }.get(env_name)
            return getattr(config_api, field_name, "") if field_name else ""
        provider = (os.getenv("LLM_PROVIDER", "") or "").lower()
        if env_name == "DEEPSEEK_API_KEY":
            return os.getenv("DEEPSEEK_API_KEY", "") or (
                os.getenv("LLM_API_KEY", "") if provider == "deepseek" else ""
            )
        if env_name == "MOONSHOT_API_KEY":
            return os.getenv("MOONSHOT_API_KEY", "") or (
                os.getenv("LLM_API_KEY", "") if provider in {"moonshot", "kimi"} else ""
            )
        return os.getenv(env_name, "")

    coros = [
        check_fn(_key_for(env_name), timeout=timeout)
        for env_name, check_fn in _CHECK_REGISTRY
    ]
    return await asyncio.gather(*coros, return_exceptions=False)


def summarize(results: list[CheckResult]) -> dict:
    """
    Return a small summary dict for inclusion in API responses.

    Counts pass/fail/skip/warn and computes an "operational" headline.
    """
    counts = {s.value: 0 for s in CheckStatus}
    for r in results:
        counts[r.status.value] += 1
    operational = counts["pass"] + counts["warn"]
    configured = sum(1 for r in results if r.status != CheckStatus.SKIP)
    return {
        "headline": f"{operational}/{configured} configured services operational",
        "counts": counts,
        "total": len(results),
    }

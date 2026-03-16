#!/usr/bin/env python3
"""
API Diagnostic Tool — Tests each external service with a REAL request.
No mocks, no defaults. Shows you exactly what works and what doesn't.

Usage: python diagnose_apis.py
"""
import asyncio
import os
import sys
import json
import time
from pathlib import Path

# Load .env manually
env_path = Path(".env")
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())


PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
SKIP = "\033[93m[SKIP]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

TEST_URL = "http://testsafebrowsing.appspot.com/s/phishing.html"  # Known Google test phishing URL
TEST_URL_CLEAN = "https://www.google.com"
TEST_IP = "8.8.8.8"  # Google DNS — should be clean in AbuseIPDB


async def test_virustotal():
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        print(f"  {SKIP} VirusTotal: No API key configured")
        return

    print(f"  {INFO} VirusTotal: Testing with key {key[:8]}...")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            # Use URL lookup (not scan) — faster, no rate limit issues
            import base64
            url_id = base64.urlsafe_b64encode(TEST_URL_CLEAN.encode()).decode().rstrip("=")
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": key},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    data = json.loads(body)
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    print(f"  {PASS} VirusTotal: HTTP 200 — Analysis stats: {stats}")
                elif status == 401:
                    print(f"  {FAIL} VirusTotal: HTTP 401 — Invalid API key")
                elif status == 404:
                    print(f"  {PASS} VirusTotal: HTTP 404 — URL not in database (key is valid, URL just not scanned yet)")
                elif status == 429:
                    print(f"  {FAIL} VirusTotal: HTTP 429 — Rate limited (key works but quota exceeded)")
                else:
                    print(f"  {FAIL} VirusTotal: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} VirusTotal: Exception — {e}")


async def test_google_safebrowsing():
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not key:
        print(f"  {SKIP} Safe Browsing: No API key configured")
        return

    print(f"  {INFO} Safe Browsing: Testing with key {key[:8]}...")
    try:
        import aiohttp
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": TEST_URL}],
            },
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    data = json.loads(body)
                    matches = data.get("matches", [])
                    if matches:
                        print(f"  {PASS} Safe Browsing: HTTP 200 — Found {len(matches)} threat(s) for test URL (WORKING!)")
                    else:
                        print(f"  {PASS} Safe Browsing: HTTP 200 — No threats found (API works, test URL may be delisted)")
                elif status == 400:
                    print(f"  {FAIL} Safe Browsing: HTTP 400 — Bad request: {body[:200]}")
                elif status == 403:
                    print(f"  {FAIL} Safe Browsing: HTTP 403 — API key invalid or Safe Browsing API not enabled in Google Cloud Console")
                else:
                    print(f"  {FAIL} Safe Browsing: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} Safe Browsing: Exception — {e}")


async def test_urlscan():
    key = os.getenv("URLSCAN_API_KEY", "")
    if not key:
        print(f"  {SKIP} URLScan: No API key configured")
        return

    print(f"  {INFO} URLScan: Testing with key {key[:8]}...")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            # Just search for a known URL — doesn't consume scan quota
            async with session.get(
                f"https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
                headers={"API-Key": key},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    data = json.loads(body)
                    results = data.get("results", [])
                    print(f"  {PASS} URLScan: HTTP 200 — Search returned {len(results)} result(s)")
                    print(f"  {INFO} URLScan: NOTE — scan submission is fire-and-forget (30-60s), so this analyzer always returns 0.0 confidence by design")
                elif status == 401:
                    print(f"  {FAIL} URLScan: HTTP 401 — Invalid API key")
                elif status == 429:
                    print(f"  {FAIL} URLScan: HTTP 429 — Rate limited")
                else:
                    print(f"  {FAIL} URLScan: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} URLScan: Exception — {e}")


async def test_abuseipdb():
    key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not key:
        print(f"  {SKIP} AbuseIPDB: No API key configured")
        return

    print(f"  {INFO} AbuseIPDB: Testing with key {key[:8]}...")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": TEST_IP, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    data = json.loads(body)
                    abuse_score = data.get("data", {}).get("abuseConfidenceScore", "?")
                    total_reports = data.get("data", {}).get("totalReports", "?")
                    print(f"  {PASS} AbuseIPDB: HTTP 200 — IP {TEST_IP}: abuse_score={abuse_score}, reports={total_reports}")
                elif status == 401:
                    print(f"  {FAIL} AbuseIPDB: HTTP 401 — Invalid API key")
                elif status == 429:
                    print(f"  {FAIL} AbuseIPDB: HTTP 429 — Rate limited (daily quota exceeded)")
                else:
                    print(f"  {FAIL} AbuseIPDB: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} AbuseIPDB: Exception — {e}")


async def test_anthropic_llm():
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        print(f"  {SKIP} Anthropic LLM: No API key configured")
        return

    print(f"  {INFO} Anthropic LLM: Testing with key {key[:12]}...")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Say OK"}],
                },
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    print(f"  {PASS} Anthropic LLM: HTTP 200 — Model responded successfully")
                elif status == 401:
                    print(f"  {FAIL} Anthropic LLM: HTTP 401 — Invalid API key")
                elif status == 403:
                    print(f"  {FAIL} Anthropic LLM: HTTP 403 — Key lacks permission")
                elif status == 529:
                    print(f"  {PASS} Anthropic LLM: HTTP 529 — API overloaded (key is valid, just busy)")
                else:
                    print(f"  {FAIL} Anthropic LLM: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} Anthropic LLM: Exception — {e}")


async def test_hybrid_analysis():
    key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
    if not key:
        print(f"  {SKIP} Hybrid Analysis: No API key configured")
        return

    print(f"  {INFO} Hybrid Analysis: Testing with key {key[:8]}...")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://www.hybrid-analysis.com/api/v2/key/current",
                headers={"api-key": key, "accept": "application/json", "user-agent": "Falcon Sandbox"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                status = resp.status
                body = await resp.text()
                if status == 200:
                    data = json.loads(body)
                    print(f"  {PASS} Hybrid Analysis: HTTP 200 — Key valid, type: {data.get('auth_level_name', '?')}")
                elif status == 401 or status == 403:
                    print(f"  {FAIL} Hybrid Analysis: HTTP {status} — Invalid API key")
                else:
                    print(f"  {FAIL} Hybrid Analysis: HTTP {status} — {body[:200]}")
    except Exception as e:
        print(f"  {FAIL} Hybrid Analysis: Exception — {e}")


async def test_analyzer_clients():
    """Test the actual analyzer client implementations."""
    print("\n" + "=" * 60)
    print("PART 2: Testing actual analyzer client classes")
    print("=" * 60)

    api_config_keys = {
        "virustotal_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "google_safebrowsing_key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
        "urlscan_key": os.getenv("URLSCAN_API_KEY", ""),
        "abuseipdb_key": os.getenv("ABUSEIPDB_API_KEY", ""),
    }

    # Test VirusTotal client
    if api_config_keys["virustotal_key"]:
        try:
            from src.analyzers.clients.virustotal import VirusTotalClient
            client = VirusTotalClient(api_config_keys["virustotal_key"])
            result = await client.scan_url(TEST_URL_CLEAN)
            print(f"  {INFO} VT Client.scan_url() → risk={result.risk_score}, conf={result.confidence}, details={result.details}")
            if result.confidence > 0:
                print(f"  {PASS} VirusTotal client returns real data")
            else:
                print(f"  {FAIL} VirusTotal client returns confidence=0 — something wrong in client code")
        except Exception as e:
            print(f"  {FAIL} VirusTotal client exception: {e}")

    # Test Safe Browsing client
    if api_config_keys["google_safebrowsing_key"]:
        try:
            from src.analyzers.clients.google_safebrowsing import GoogleSafeBrowsingClient
            client = GoogleSafeBrowsingClient(api_config_keys["google_safebrowsing_key"])
            result = await client.check_url(TEST_URL)
            print(f"  {INFO} SB Client.check_url() → risk={result.risk_score}, conf={result.confidence}, details={result.details}")
            if result.confidence > 0:
                print(f"  {PASS} Safe Browsing client returns real data")
            else:
                print(f"  {FAIL} Safe Browsing client returns confidence=0 — something wrong in client code")
        except Exception as e:
            print(f"  {FAIL} Safe Browsing client exception: {e}")

    # Test AbuseIPDB client
    if api_config_keys["abuseipdb_key"]:
        try:
            from src.analyzers.clients.abuseipdb import AbuseIPDBClient
            client = AbuseIPDBClient(api_config_keys["abuseipdb_key"])
            result = await client.check_ip(TEST_IP)
            print(f"  {INFO} AIPDB Client.check_ip() → risk={result.risk_score}, conf={result.confidence}, details={result.details}")
            if result.confidence > 0:
                print(f"  {PASS} AbuseIPDB client returns real data")
            else:
                print(f"  {FAIL} AbuseIPDB client returns confidence=0 — something wrong in client code")
        except Exception as e:
            print(f"  {FAIL} AbuseIPDB client exception: {e}")


async def main():
    print("=" * 60)
    print("PHISHING DETECTOR — API DIAGNOSTIC")
    print("Testing REAL HTTP requests to each service")
    print("=" * 60)
    print()

    print("PART 1: Direct HTTP requests to APIs")
    print("-" * 40)

    await test_virustotal()
    print()
    await test_google_safebrowsing()
    print()
    await test_urlscan()
    print()
    await test_abuseipdb()
    print()
    await test_anthropic_llm()
    print()
    await test_hybrid_analysis()

    await test_analyzer_clients()

    print()
    print("=" * 60)
    print("PART 3: Analyzer status summary")
    print("=" * 60)
    print("""
  header_analysis    → REAL — Pure Python, no API needed. Always works.
  domain_intelligence→ REAL — Uses WHOIS lookups (no API key needed). Always works.
  brand_impersonation→ REAL — Pure Python fuzzy matching. Always works.
  attachment_analysis→ REAL — Pure Python content analysis. Always works.
  sender_profiling   → REAL — Pure Python historical analysis. Always works.
  nlp_intent         → DEPENDS — Uses Anthropic/OpenAI LLM. Works if API key is valid.
  url_reputation     → DEPENDS — Needs VirusTotal/SafeBrowsing/AbuseIPDB to return real data.
                        URLScan is ALWAYS fire-and-forget (confidence=0 by design).
  url_detonation     → NOT IMPLEMENTED — Browser sandbox not built yet. Always skipped.
    """)


if __name__ == "__main__":
    asyncio.run(main())

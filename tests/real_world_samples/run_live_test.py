#!/usr/bin/env python3
"""
Live phishing test: fetches REAL active phishing URLs from public threat feeds,
wraps them in realistic .eml emails, runs them through the full pipeline
(with all API keys and analyzers), and generates a detailed report.

Sources:
  - OpenPhish public feed (live phishing URLs)
  - Phishing.Database (community-verified phishing URLs)
  - abuse.ch URLhaus API (malware/phishing URL database)

Usage:
  cd "Automated Phishing Detection"
  python tests/real_world_samples/run_live_test.py

Requires internet access and API keys configured in .env
"""
import asyncio
import json
import os
import sys
import time
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Load .env file so API keys are available
try:
    from dotenv import load_dotenv
    load_dotenv(project_root / ".env")
except ImportError:
    # No python-dotenv; try manual .env loading
    env_path = project_root / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and not key.startswith("#"):
                    os.environ.setdefault(key, val)

# ---------------------------------------------------------------------------
# 1. Fetch live phishing URLs
# ---------------------------------------------------------------------------

FEED_URLS = [
    # OpenPhish community feed
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    # Phishing.Database active-today list
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
    # Phishing.Database active NOW
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-today.txt",
    # abuse.ch URLhaus — plain-text feed of recent malware/phishing URLs (no auth required)
    "https://urlhaus.abuse.ch/downloads/text_recent/",
]

# Map known brand domains to brand info for realistic .eml construction
BRAND_PATTERNS = {
    "microsoft": {"from_name": "Microsoft Account Team", "from_user": "account-security-noreply", "subject": "Unusual sign-in activity on your account"},
    "paypal": {"from_name": "PayPal Security", "from_user": "service", "subject": "Your account access has been limited"},
    "apple": {"from_name": "Apple Support", "from_user": "noreply", "subject": "Your Apple ID has been locked"},
    "google": {"from_name": "Google Security Alert", "from_user": "no-reply", "subject": "Critical security alert for your Google Account"},
    "facebook": {"from_name": "Facebook Security", "from_user": "security", "subject": "We noticed an unusual login to your account"},
    "amazon": {"from_name": "Amazon.com", "from_user": "auto-confirm", "subject": "Your Amazon order confirmation"},
    "netflix": {"from_name": "Netflix", "from_user": "info", "subject": "Update your payment information"},
    "dhl": {"from_name": "DHL Express", "from_user": "noreply", "subject": "Your shipment is pending delivery"},
    "fedex": {"from_name": "FedEx Delivery", "from_user": "tracking", "subject": "Your package delivery update"},
    "chase": {"from_name": "Chase Alert", "from_user": "alerts", "subject": "Unusual activity detected on your account"},
    "wells": {"from_name": "Wells Fargo Alert", "from_user": "alerts", "subject": "Important: Verify your account information"},
    "bank": {"from_name": "Online Banking Security", "from_user": "security", "subject": "Important: Verify your banking details"},
    "instagram": {"from_name": "Instagram", "from_user": "security", "subject": "We noticed a login from a new device"},
    "linkedin": {"from_name": "LinkedIn", "from_user": "messages-noreply", "subject": "You have a new connection request"},
    "dropbox": {"from_name": "Dropbox", "from_user": "no-reply", "subject": "Someone shared a file with you"},
    "docusign": {"from_name": "DocuSign", "from_user": "dse_na3", "subject": "Please review and sign this document"},
    "office": {"from_name": "Microsoft Office 365", "from_user": "notification", "subject": "Action required: Verify your account"},
    "outlook": {"from_name": "Microsoft Outlook", "from_user": "no-reply", "subject": "Your mailbox is almost full"},
    "usps": {"from_name": "USPS Informed Delivery", "from_user": "USPSInformedDelivery", "subject": "Your package delivery has been rescheduled"},
    "ups": {"from_name": "UPS My Choice", "from_user": "auto-notify", "subject": "UPS Delivery Notification"},
    "citi": {"from_name": "Citi Alert", "from_user": "alerts", "subject": "Alert: Transaction needs your attention"},
    "webmail": {"from_name": "IT Support", "from_user": "admin", "subject": "Your mailbox quota has been exceeded"},
    "login": {"from_name": "Account Security", "from_user": "no-reply", "subject": "Confirm your identity to continue"},
    "verify": {"from_name": "Account Verification", "from_user": "verify", "subject": "Action required: Verify your account"},
    "secure": {"from_name": "Security Team", "from_user": "security", "subject": "Security alert: Suspicious activity detected"},
    "signin": {"from_name": "Account Team", "from_user": "noreply", "subject": "New sign-in to your account"},
}

# Default brand info for unknown phishing URLs
DEFAULT_BRAND = {"from_name": "Account Security Team", "from_user": "security-alert", "subject": "Important: Verify your account information"}


def detect_brand(url: str) -> dict:
    """Detect which brand a phishing URL is impersonating based on URL patterns."""
    url_lower = url.lower()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    for keyword, info in BRAND_PATTERNS.items():
        if keyword in domain or keyword in path:
            return info
    return DEFAULT_BRAND


def build_eml(phishing_url: str, index: int) -> str:
    """Build a realistic .eml file wrapping a real phishing URL."""
    brand = detect_brand(phishing_url)
    parsed = urlparse(phishing_url)
    phish_domain = parsed.netloc

    # Generate consistent message ID
    msg_hash = hashlib.md5(phishing_url.encode()).hexdigest()[:12]
    msg_id = f"<{msg_hash}@{phish_domain}>"

    # Sender uses the phishing domain
    from_addr = f"{brand['from_user']}@{phish_domain}"

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%a, %d %b %Y %H:%M:%S +0000")

    eml = f"""Received: from unknown (HELO {phish_domain}) ({parsed.netloc})
        by mx.victim-corp.com with SMTP; {date_str}
From: "{brand['from_name']}" <{from_addr}>
To: victim@example.com
Subject: {brand['subject']}
Date: {date_str}
Message-ID: {msg_id}
Reply-To: {from_addr}
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html>
<body style="font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,.1)">
<h2 style="color:#333;margin-top:0">{brand['subject']}</h2>
<p style="color:#555;line-height:1.6">Dear Customer,</p>
<p style="color:#555;line-height:1.6">We detected unusual activity on your account. For your security, we need you to verify your identity immediately. Failure to do so within 24 hours will result in permanent account suspension.</p>
<p style="color:#555;line-height:1.6">Please click the button below to verify your account:</p>
<p style="text-align:center;margin:25px 0">
<a href="{phishing_url}" style="background:#d32f2f;color:#fff;padding:14px 36px;text-decoration:none;border-radius:4px;font-weight:bold;font-size:16px;display:inline-block">Verify Now</a>
</p>
<p style="color:#999;font-size:12px;margin-top:30px;border-top:1px solid #eee;padding-top:15px">
This is an automated security notification. If you did not request this action, please verify your account immediately to prevent unauthorized access.
</p>
</div>
</body>
</html>
"""
    return eml


def fetch_phishing_urls(max_urls: int = 10) -> list[dict]:
    """Fetch live phishing URLs from public feeds + abuse.ch URLhaus API."""
    import urllib.request
    import ssl

    all_urls = []
    ctx = ssl.create_default_context()

    # --- Plain-text feeds (OpenPhish, Phishing.Database) ---
    for feed_url in FEED_URLS:
        try:
            print(f"  Fetching: {feed_url[:80]}...")
            req = urllib.request.Request(feed_url, headers={"User-Agent": "PhishAnalyze-Test/1.0"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                urls = [line.strip() for line in text.splitlines() if line.strip() and line.startswith("http")]
                print(f"    Got {len(urls)} URLs")
                all_urls.extend(urls)
        except Exception as e:
            print(f"    Failed: {e}")

    # Deduplicate
    seen = set()
    unique = []
    for u in all_urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)

    # Try to get variety — pick URLs from different domains
    by_domain = {}
    for u in unique:
        d = urlparse(u).netloc
        if d not in by_domain:
            by_domain[d] = u

    selected = list(by_domain.values())[:max_urls]

    # If we don't have enough unique domains, fill from remaining
    if len(selected) < max_urls:
        for u in unique:
            if u not in selected:
                selected.append(u)
            if len(selected) >= max_urls:
                break

    print(f"\n  Selected {len(selected)} unique phishing URLs from {len(unique)} total")
    return [{"url": u, "domain": urlparse(u).netloc, "brand": detect_brand(u)} for u in selected]


# ---------------------------------------------------------------------------
# 2. Pipeline execution
# ---------------------------------------------------------------------------

async def analyze_eml(pipeline, eml_content: str, phish_info: dict, index: int) -> dict:
    """Run a single .eml through the pipeline."""
    from src.extractors.eml_parser import parse_eml_bytes

    start = time.time()

    # Parse .eml from string
    email = parse_eml_bytes(eml_content)
    if not email:
        return {
            "index": index,
            "url": phish_info["url"],
            "domain": phish_info["domain"],
            "error": "Failed to parse .eml",
            "detection_result": "ERROR",
        }

    # Run pipeline
    result = await pipeline.analyze(email)
    elapsed = time.time() - start

    # Extract analyzer results
    analyzer_results = {}
    for name, ar in result.analyzer_results.items():
        details_safe = {}
        if hasattr(ar, 'details') and ar.details:
            for k, v in ar.details.items():
                if isinstance(v, bytes):
                    details_safe[k] = f"<{len(v)} bytes>"
                else:
                    try:
                        json.dumps(v)
                        details_safe[k] = v
                    except (TypeError, ValueError):
                        details_safe[k] = str(v)
        analyzer_results[name] = {
            "risk_score": ar.risk_score if hasattr(ar, 'risk_score') else 0,
            "confidence": ar.confidence if hasattr(ar, 'confidence') else 0,
            "details": details_safe,
        }

    # Extract URLs from IOCs
    extracted_urls = []
    if result.extracted_urls:
        for u in result.extracted_urls:
            if hasattr(u, 'url'):
                extracted_urls.append(u.url)
            elif isinstance(u, dict):
                extracted_urls.append(u.get("url", str(u)))
            else:
                extracted_urls.append(str(u))

    verdict = str(result.verdict.value) if hasattr(result.verdict, 'value') else str(result.verdict)
    score = result.overall_score
    is_flagged = verdict in ("SUSPICIOUS", "LIKELY_PHISHING", "CONFIRMED_PHISHING")
    detection = "TRUE_POSITIVE" if is_flagged else "FALSE_NEGATIVE"

    reasoning = result.reasoning
    if isinstance(reasoning, list):
        reasoning = " ".join(reasoning)

    record = {
        "index": index,
        "phishing_url": phish_info["url"],
        "phishing_domain": phish_info["domain"],
        "detected_brand": phish_info["brand"].get("from_name", "Unknown"),
        "verdict": verdict,
        "score": round(score, 4) if score else 0,
        "confidence": round(result.overall_confidence, 4) if result.overall_confidence else 0,
        "detection_result": detection,
        "elapsed_seconds": round(elapsed, 2),
        "from_address": email.from_address,
        "subject": email.subject,
        "analyzer_results": analyzer_results,
        "extracted_urls": extracted_urls,
        "reasoning": reasoning,
    }

    # Print summary
    status = "✅ DETECTED" if is_flagged else "❌ MISSED"
    print(f"\n  [{index:02d}] {status}")
    print(f"       URL:     {phish_info['url'][:80]}...")
    print(f"       Domain:  {phish_info['domain']}")
    print(f"       Verdict: {verdict} (score: {score:.1%}, conf: {result.overall_confidence:.0%})")
    print(f"       Time:    {elapsed:.1f}s")
    for name, ar in sorted(analyzer_results.items(), key=lambda x: x[1]["risk_score"], reverse=True):
        bar = "█" * int(ar["risk_score"] * 20)
        print(f"       {name:25s} {ar['risk_score']:.0%} {bar}")

    return record


# ---------------------------------------------------------------------------
# 3. Report generation
# ---------------------------------------------------------------------------

def generate_report(results: list, output_dir: Path):
    """Generate markdown report from results."""
    tp = sum(1 for r in results if r["detection_result"] == "TRUE_POSITIVE")
    fn = sum(1 for r in results if r["detection_result"] == "FALSE_NEGATIVE")
    errors = sum(1 for r in results if r["detection_result"] == "ERROR")
    total = len(results)
    tested = total - errors

    # Save JSON
    json_path = output_dir / "live_test_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str, ensure_ascii=False)

    # Build markdown
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    detected = [r for r in results if r["detection_result"] == "TRUE_POSITIVE"]
    missed = [r for r in results if r["detection_result"] == "FALSE_NEGATIVE"]
    errored = [r for r in results if r["detection_result"] == "ERROR"]

    # Analyzer aggregate stats
    analyzer_totals = {}
    for r in results:
        if "analyzer_results" in r:
            for name, ar in r["analyzer_results"].items():
                if name not in analyzer_totals:
                    analyzer_totals[name] = {"scores": [], "confs": []}
                analyzer_totals[name]["scores"].append(ar["risk_score"])
                analyzer_totals[name]["confs"].append(ar["confidence"])

    md = f"""# Live Phishing Feed Test Report

**Date:** {now}
**Pipeline:** PhishAnalyze v1.0
**Feed Sources:** OpenPhish, Phishing.Database, abuse.ch URLhaus (community-verified active phishing URLs)
**Test Type:** Real phishing URLs wrapped in realistic .eml email envelopes

---

## Executive Summary

Tested the PhishAnalyze pipeline against **{tested} real, active phishing URLs** sourced from public threat intelligence feeds. These are URLs that were verified as active phishing sites at the time of testing.

| Metric | Value |
|--------|-------|
| Total URLs Tested | {tested} |
| Detected (True Positives) | {tp} |
| Missed (False Negatives) | {fn} |
| Errors | {errors} |
| **Detection Rate** | **{tp/tested*100:.0f}%** |

"""

    if fn > 0:
        miss_rate = fn / tested * 100
        md += f"""### False Negative Analysis

{fn} phishing URLs ({miss_rate:.0f}%) were **not detected** by the pipeline. These represent real-world evasion scenarios.

"""

    md += """---

## Detected Phishing URLs (True Positives)

| # | Domain | Verdict | Score | Top Analyzer | Notes |
|---|--------|---------|-------|-------------|-------|
"""
    for r in detected:
        top = max(r.get("analyzer_results", {}).items(), key=lambda x: x[1]["risk_score"], default=("none", {"risk_score": 0}))
        md += f"| {r['index']:02d} | `{r['phishing_domain'][:40]}` | {r['verdict']} | {r['score']:.0%} | {top[0]} ({top[1]['risk_score']:.0%}) | {r.get('detected_brand', '')} |\n"

    if missed:
        md += """
---

## Missed Phishing URLs (False Negatives)

| # | Domain | Score | Why Missed |
|---|--------|-------|------------|
"""
        for r in missed:
            # Analyze why missed
            reasons = []
            ar = r.get("analyzer_results", {})
            top_score = max((a["risk_score"] for a in ar.values()), default=0)
            if top_score < 0.3:
                reasons.append("No analyzer scored above 30%")
            for name, a in ar.items():
                if a["risk_score"] == 0 and a["confidence"] == 0:
                    reasons.append(f"{name} returned 0/0 (likely disabled)")
            if not reasons:
                reasons.append(f"Highest analyzer: {top_score:.0%}, below threshold")

            md += f"| {r['index']:02d} | `{r['phishing_domain'][:40]}` | {r['score']:.0%} | {'; '.join(reasons)} |\n"

    md += """
---

## Analyzer Performance (Averaged Across All Samples)

| Analyzer | Avg Risk Score | Avg Confidence | Loaded |
|----------|---------------|----------------|--------|
"""
    for name in sorted(analyzer_totals.keys()):
        stats = analyzer_totals[name]
        avg_score = sum(stats["scores"]) / len(stats["scores"]) if stats["scores"] else 0
        avg_conf = sum(stats["confs"]) / len(stats["confs"]) if stats["confs"] else 0
        loaded = "✅" if avg_conf > 0 else "❌"
        md += f"| {name} | {avg_score:.0%} | {avg_conf:.0%} | {loaded} |\n"

    md += """
---

## Per-Sample Detail

"""
    for r in results:
        if r["detection_result"] == "ERROR":
            md += f"### Sample {r['index']:02d} — ERROR\n\n"
            md += f"**URL:** `{r.get('phishing_url', 'N/A')}`\n"
            md += f"**Error:** {r.get('error', 'Unknown')}\n\n---\n\n"
            continue

        status_emoji = "✅" if r["detection_result"] == "TRUE_POSITIVE" else "❌"
        md += f"### Sample {r['index']:02d} — {status_emoji} {r['verdict']} ({r['score']:.0%})\n\n"
        md += f"**Phishing URL:** `{r['phishing_url']}`\n\n"
        md += f"**Domain:** `{r['phishing_domain']}` | **Brand:** {r.get('detected_brand', 'Unknown')} | **Time:** {r.get('elapsed_seconds', 0)}s\n\n"

        if r.get("analyzer_results"):
            md += "| Analyzer | Score | Confidence | Key Details |\n"
            md += "|----------|-------|------------|-------------|\n"
            for aname, ar in sorted(r["analyzer_results"].items(), key=lambda x: x[1]["risk_score"], reverse=True):
                details_str = ""
                if ar.get("details"):
                    # Pick most interesting details
                    interesting = {k: v for k, v in ar["details"].items()
                                   if k not in ("screenshots", "raw_response") and v}
                    detail_items = list(interesting.items())[:3]
                    details_str = ", ".join(f"{k}: {v}" for k, v in detail_items)
                    if len(details_str) > 80:
                        details_str = details_str[:77] + "..."
                md += f"| {aname} | {ar['risk_score']:.0%} | {ar['confidence']:.0%} | {details_str} |\n"

        if r.get("reasoning"):
            md += f"\n**Reasoning:** {r['reasoning'][:300]}{'...' if len(r.get('reasoning', '')) > 300 else ''}\n"

        md += "\n---\n\n"

    md += f"""
## Recommendations

1. **Install missing dependencies** — If any analyzer shows 0% confidence, it likely failed to load. Run `pip install dnspython` to enable url_reputation, domain_intelligence, and attachment_analysis.

2. **Lower SUSPICIOUS threshold** — If borderline scores (25-30%) appear in false negatives, consider lowering the threshold from 30% to 25%.

3. **Feed integration** — Consider integrating OpenPhish and Phishing.Database feeds as real-time blocklists in the pipeline for known-bad URL matching.

4. **Retrain on feedback** — Use the `/api/feedback/retrain` endpoint to incorporate analyst corrections from this test.

---

*Report generated by `run_live_test.py` on {now}*
*Sources: [OpenPhish](https://openphish.com/), [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), [abuse.ch URLhaus](https://urlhaus.abuse.ch/)*
"""

    md_path = output_dir / "live_feed_test_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\n  Report saved: {md_path}")
    print(f"  JSON saved:   {json_path}")


# ---------------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 70)
    print("LIVE PHISHING FEED TEST")
    print("Fetching real active phishing URLs and testing pipeline detection")
    print("=" * 70)

    # Fetch live URLs
    print("\n[1/4] Fetching live phishing URLs from public feeds...")
    phishing_urls = fetch_phishing_urls(max_urls=10)

    if not phishing_urls:
        print("\n  ERROR: Could not fetch any phishing URLs. Check internet connection.")
        sys.exit(1)

    # Build .eml files
    print(f"\n[2/4] Building {len(phishing_urls)} .eml test files...")
    eml_contents = []
    samples_dir = Path(__file__).parent / "live_samples"
    samples_dir.mkdir(exist_ok=True)

    for i, info in enumerate(phishing_urls, 1):
        eml = build_eml(info["url"], i)
        eml_contents.append(eml)
        # Also save to disk for reference
        safe_domain = info["domain"].replace(".", "_").replace("/", "_")[:50]
        eml_path = samples_dir / f"live_{i:02d}_{safe_domain}.eml"
        with open(eml_path, "w") as f:
            f.write(eml)
        print(f"  [{i:02d}] {info['domain'][:50]:50s} → {info['brand'].get('from_name', 'Unknown')}")

    # Initialize pipeline with full config
    print("\n[3/4] Running pipeline analysis (this may take a while with API calls)...")
    from src.config import PipelineConfig
    from src.orchestrator.pipeline import PhishingPipeline

    config = PipelineConfig.from_env()
    pipeline = PhishingPipeline(config)

    results = []
    for i, (eml_content, info) in enumerate(zip(eml_contents, phishing_urls), 1):
        try:
            record = await analyze_eml(pipeline, eml_content, info, i)
            results.append(record)
        except Exception as e:
            import traceback
            print(f"\n  ❌ ERROR on sample {i}: {e}")
            traceback.print_exc()
            results.append({
                "index": i,
                "phishing_url": info["url"],
                "phishing_domain": info["domain"],
                "error": str(e),
                "detection_result": "ERROR",
            })

    # Generate report
    print("\n[4/4] Generating report...")
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)
    generate_report(results, reports_dir)

    # Print summary
    tp = sum(1 for r in results if r["detection_result"] == "TRUE_POSITIVE")
    fn = sum(1 for r in results if r["detection_result"] == "FALSE_NEGATIVE")
    errors = sum(1 for r in results if r["detection_result"] == "ERROR")
    tested = len(results) - errors

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Tested:    {tested} real phishing URLs")
    print(f"  Detected:  {tp} ({tp/tested*100:.0f}%)" if tested else "  Detected: N/A")
    print(f"  Missed:    {fn}")
    print(f"  Errors:    {errors}")
    print(f"\n  Reports in: {reports_dir}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

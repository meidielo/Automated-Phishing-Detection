# PhishAnalyze Analysis Reports

This directory contains test results and analysis from running the PhishAnalyze pipeline against synthetic phishing campaign patterns and legitimate brand emails.

## Results Summary

**Pipeline:** PhishAnalyze v1.0 (temperature=0, all bugs fixed)
**Test Set:** 22 samples (10 phishing, 12 legitimate)
**Environment:** Windows 11, all API keys active (VirusTotal, URLScan, AbuseIPDB, Anthropic)
**Stable Recall:** 90% (9/10 phishing reliably detected) | **Precision:** 91% (1 false positive) | **F1:** 0.90

Sample_08 (BEC) oscillates near the 30% threshold — treat as unreliable detection.

## Contents

- **batch_test_summary.md** — Executive summary with metrics, known issues, analyzer performance, and bug fix history.

- **sample_analyses.md** — Per-sample write-ups for all 22 test samples with analyzer breakdowns, root cause analysis of the false positive and unstable detection, and comparisons between phishing/legitimate pairs.

- **batch_results.json** — Raw machine-readable results from the latest batch run.

- **project_briefing.md** — Architecture overview, scoring formula, directory structure, API endpoints, dependencies, and known gaps.

- **live_feed_test_report.md** — Results from testing against real active phishing URLs from OpenPhish, Phishing.Database, and abuse.ch URLhaus.

## Known Issues

1. **LinkedIn FP (sample_17):** NLP scores 99% on legitimate LinkedIn engagement language. Unresolved — requires cross-analyzer context sharing. See `lessons-learned.md` in project root.
2. **BEC instability (sample_08):** Scores 31% against 30% threshold. Not a reliable detection.
3. **url_reputation dilution:** VirusTotal returns "clean" with 80% confidence for non-resolving phishing domains, suppressing scores by ~15 points.
4. **Score clustering:** All phishing scores land in SUSPICIOUS (31-53%), none reach LIKELY_PHISHING (60%+).

## Test Samples

Located in `tests/real_world_samples/`:

### Phishing Samples

| # | Campaign Type | Score | Verdict |
|---|--------------|-------|---------|
| 01 | Microsoft credential harvest | 50% | SUSPICIOUS |
| 02 | PayPal account suspension | 41% | SUSPICIOUS |
| 03 | DHL delivery notification | 48% | SUSPICIOUS |
| 04 | Apple ID disabled | 39% | SUSPICIOUS |
| 05 | Netflix payment failed | 53% | SUSPICIOUS |
| 06 | BofA wire transfer | 50% | SUSPICIOUS |
| 07 | Amazon order confirmation | 50% | SUSPICIOUS |
| 08 | Google Workspace BEC | 31% | SUSPICIOUS* |
| 09 | IRS tax refund | 48% | SUSPICIOUS |
| 10 | LinkedIn connection request | 50% | SUSPICIOUS |

*Unstable — see Known Issues.

### Legitimate Samples

| # | Type | Score | Verdict |
|---|------|-------|---------|
| 11 | GitHub notification | 23% | CLEAN |
| 12 | Work email | 13% | CLEAN |
| 13 | Amazon order (real) | 19% | CLEAN |
| 14 | PayPal receipt (real) | 13% | CLEAN |
| 15 | Google security alert (real) | 14% | CLEAN |
| 16 | Netflix newsletter (real) | 17% | CLEAN |
| 17 | LinkedIn digest (real) | 36% | **SUSPICIOUS (FP)** |
| 18 | BofA statement (real) | 12% | CLEAN |
| 19 | DHL tracking (real) | 10% | CLEAN |
| 20 | Stripe invoice (real) | 12% | CLEAN |
| 21 | Substack newsletter (real) | 24% | CLEAN |
| 22 | DocuSign signing (real) | 27% | CLEAN |

## Running Tests

```bash
cd "Automated Phishing Detection"

# Batch test (22 samples)
python tests/real_world_samples/run_batch_test.py

# Live feed test (real active phishing URLs)
python tests/real_world_samples/run_live_test.py
```

Both require API keys in `.env` file. Results saved to `reports/` directory.

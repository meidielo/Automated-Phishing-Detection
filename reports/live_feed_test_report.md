# Live Phishing Feed Test Report

**Date:** 2026-04-02 21:27:52
**Pipeline:** PhishAnalyze v1.0
**Feed Sources:** OpenPhish, Phishing.Database, abuse.ch URLhaus (community-verified active phishing URLs)
**Test Type:** Real phishing URLs wrapped in realistic .eml email envelopes

---

## Executive Summary

Tested the PhishAnalyze pipeline against **10 real, active phishing URLs** sourced from public threat intelligence feeds. These are URLs that were verified as active phishing sites at the time of testing.

| Metric | Value |
|--------|-------|
| Total URLs Tested | 10 |
| Detected (True Positives) | 10 |
| Missed (False Negatives) | 0 |
| Errors | 0 |
| **Detection Rate** | **100%** |

---

## Detected Phishing URLs (True Positives)

| # | Domain | Verdict | Score | Top Analyzer | Notes |
|---|--------|---------|-------|-------------|-------|
| 01 | `yashaitt.github.io` | SUSPICIOUS | 45% | nlp_intent (99%) | Netflix |
| 02 | `www.booking-com-clone-kappa.vercel.app` | SUSPICIOUS | 47% | nlp_intent (99%) | Account Security Team |
| 03 | `f.digitalmaillane.com` | SUSPICIOUS | 48% | nlp_intent (100%) | Account Security Team |
| 04 | `netflix-clone-coral-ten.vercel.app` | SUSPICIOUS | 54% | nlp_intent (99%) | Netflix |
| 05 | `amn1704.github.io` | SUSPICIOUS | 43% | nlp_intent (99%) | Netflix |
| 06 | `roblox.com.py` | SUSPICIOUS | 40% | nlp_intent (99%) | Account Security Team |
| 07 | `net-wok.s3-website.us-east-2.amazonaws.c` | SUSPICIOUS | 56% | nlp_intent (95%) | Amazon.com |
| 08 | `www.robiox.com.py` | SUSPICIOUS | 41% | nlp_intent (99%) | Account Security Team |
| 09 | `ipfs.io` | SUSPICIOUS | 46% | nlp_intent (99%) | Account Security Team |
| 10 | `greamreaper01.github.io` | LIKELY_PHISHING | 62% | nlp_intent (99%) | Netflix |

---

## Analyzer Performance (Averaged Across All Samples)

| Analyzer | Avg Risk Score | Avg Confidence | Loaded |
|----------|---------------|----------------|--------|
| attachment_analysis | 0% | 0% | ❌ |
| brand_impersonation | 26% | 77% | ✅ |
| domain_intelligence | 56% | 80% | ✅ |
| header_analysis | 10% | 50% | ✅ |
| nlp_intent | 99% | 94% | ✅ |
| sender_profiling | 45% | 50% | ✅ |
| url_detonation | 21% | 80% | ✅ |
| url_reputation | 62% | 97% | ✅ |

---

## Per-Sample Detail

### Sample 01 — ✅ SUSPICIOUS (45%)

**Phishing URL:** `https://yashaitt.github.io/Netflix-clone/netflix-signup.html`

**Domain:** `yashaitt.github.io` | **Brand:** Netflix | **Time:** 5.81s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| brand_impersonation | 63% | 70% | signals_found: 1, signals: [{'signal': 'body_brand_mismatch', 'brand': 'bank_... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'yashaitt.github.io': {'risk_score': 0.6,... |
| sender_profiling | 45% | 50% | sender_email: info@yashaitt.github.io, email_count: 1, anomaly_score: 0.44999... |
| url_reputation | 43% | 100% | url_count: 1, urls_analyzed: {'https://yashaitt.github.io/Netflix-clone/netfl... |
| header_analysis | 0% | 50% |  |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://yashaitt.git... |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.449. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.000 (conf: 0.500); url_reputation: 0.433 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.633 (conf: 0.700); attachment_an...

---

### Sample 02 — ✅ SUSPICIOUS (47%)

**Phishing URL:** `http://www.booking-com-clone-kappa.vercel.app/`

**Domain:** `www.booking-com-clone-kappa.vercel.app` | **Brand:** Account Security Team | **Time:** 3.74s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'booking-com-clone-kappa.vercel.app': {'r... |
| sender_profiling | 45% | 50% | sender_email: security-alert@www.booking-com-clone-kappa.vercel.app, email_co... |
| url_reputation | 41% | 94% | url_count: 1, urls_analyzed: {'http://www.booking-com-clone-kappa.vercel.app/... |
| url_detonation | 40% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'http://www.booking-c... |
| header_analysis | 20% | 50% | display_name_spoofing: True |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.466. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.200 (conf: 0.500); url_reputation: 0.415 (conf: 0.940); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.400 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 03 — ✅ SUSPICIOUS (48%)

**Phishing URL:** `http://f.digitalmaillane.com/igit/4/eqbkr2yNb9z085mxd7NqyoN7agkwbNnicNa91NkxNdN6`

**Domain:** `f.digitalmaillane.com` | **Brand:** Account Security Team | **Time:** 6.02s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 100% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| url_reputation | 90% | 100% | url_count: 1, urls_analyzed: {'http://f.digitalmaillane.com/igit/4/eqbkr2yNb9... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'f.digitalmaillane.com': {'risk_score': 0... |
| sender_profiling | 45% | 50% | sender_email: security-alert@f.digitalmaillane.com, email_count: 1, anomaly_s... |
| header_analysis | 20% | 50% | display_name_spoofing: True |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'http://f.digitalmail... |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.482. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.200 (conf: 0.500); url_reputation: 0.900 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 04 — ✅ SUSPICIOUS (54%)

**Phishing URL:** `https://netflix-clone-coral-ten.vercel.app/`

**Domain:** `netflix-clone-coral-ten.vercel.app` | **Brand:** Netflix | **Time:** 6.01s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| url_reputation | 90% | 100% | url_count: 1, urls_analyzed: {'https://netflix-clone-coral-ten.vercel.app/': ... |
| brand_impersonation | 70% | 80% | signals_found: 2, signals: [{'signal': 'body_brand_mismatch', 'brand': 'bank_... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'netflix-clone-coral-ten.vercel.app': {'r... |
| sender_profiling | 45% | 50% | sender_email: info@netflix-clone-coral-ten.vercel.app, email_count: 1, anomal... |
| header_analysis | 0% | 50% |  |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://netflix-clon... |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.539. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.000 (conf: 0.500); url_reputation: 0.900 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.700 (conf: 0.800); attachment_an...

---

### Sample 05 — ✅ SUSPICIOUS (43%)

**Phishing URL:** `https://amn1704.github.io/Project3_Netflix-Landing-Page-Clone/`

**Domain:** `amn1704.github.io` | **Brand:** Netflix | **Time:** 42.05s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| brand_impersonation | 63% | 70% | signals_found: 1, signals: [{'signal': 'body_brand_mismatch', 'brand': 'bank_... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'amn1704.github.io': {'risk_score': 0.6, ... |
| sender_profiling | 45% | 50% | sender_email: info@amn1704.github.io, email_count: 1, anomaly_score: 0.449999... |
| url_reputation | 30% | 82% | url_count: 1, urls_analyzed: {'https://amn1704.github.io/Project3_Netflix-Lan... |
| header_analysis | 0% | 50% |  |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://amn1704.gith... |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.427. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.000 (conf: 0.500); url_reputation: 0.305 (conf: 0.820); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.633 (conf: 0.700); attachment_an...

---

### Sample 06 — ✅ SUSPICIOUS (40%)

**Phishing URL:** `https://roblox.com.py/users/6557110906/profile`

**Domain:** `roblox.com.py` | **Brand:** Account Security Team | **Time:** 14.46s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'roblox.com.py': {'risk_score': 0.6, 'con... |
| url_reputation | 45% | 100% | url_count: 1, urls_analyzed: {'https://roblox.com.py/users/6557110906/profile... |
| sender_profiling | 45% | 50% | sender_email: security-alert@roblox.com.py, email_count: 1, anomaly_score: 0.... |
| header_analysis | 20% | 50% | display_name_spoofing: True |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://roblox.com.p... |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.401. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.200 (conf: 0.500); url_reputation: 0.450 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 07 — ✅ SUSPICIOUS (56%)

**Phishing URL:** `http://net-wok.s3-website.us-east-2.amazonaws.com/`

**Domain:** `net-wok.s3-website.us-east-2.amazonaws.com` | **Brand:** Amazon.com | **Time:** 4.19s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 95% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, reasoning: Mul... |
| url_reputation | 90% | 100% | url_count: 1, urls_analyzed: {'http://net-wok.s3-website.us-east-2.amazonaws.... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'net-wok.s3-website.us-east-2.amazonaws.c... |
| url_detonation | 60% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'http://net-wok.s3-we... |
| sender_profiling | 45% | 50% | sender_email: auto-confirm@net-wok.s3-website.us-east-2.amazonaws.com, email_... |
| header_analysis | 0% | 50% |  |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.556. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.000 (conf: 0.500); url_reputation: 0.900 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.600 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 08 — ✅ SUSPICIOUS (41%)

**Phishing URL:** `https://www.robiox.com.py/users/226332101233/profile`

**Domain:** `www.robiox.com.py` | **Brand:** Account Security Team | **Time:** 9.32s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'robiox.com.py': {'risk_score': 0.6, 'con... |
| url_reputation | 50% | 100% | url_count: 1, urls_analyzed: {'https://www.robiox.com.py/users/226332101233/p... |
| sender_profiling | 45% | 50% | sender_email: security-alert@www.robiox.com.py, email_count: 1, anomaly_score... |
| header_analysis | 20% | 50% | display_name_spoofing: True |
| url_detonation | 0% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://www.robiox.c... |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.410. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.200 (conf: 0.500); url_reputation: 0.500 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.000 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 09 — ✅ SUSPICIOUS (46%)

**Phishing URL:** `https://ipfs.io/ipfs/bafkreigzys3rczbnczb5s7o2r3j5av4izhqvml6gyxah2d6v27apc4rjpy`

**Domain:** `ipfs.io` | **Brand:** Account Security Team | **Time:** 32.11s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 85% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| url_detonation | 60% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'https://ipfs.io/ipfs... |
| sender_profiling | 45% | 50% | sender_email: security-alert@ipfs.io, email_count: 1, anomaly_score: 0.449999... |
| url_reputation | 45% | 96% | url_count: 1, urls_analyzed: {'https://ipfs.io/ipfs/bafkreigzys3rczbnczb5s7o2... |
| header_analysis | 20% | 50% | display_name_spoofing: True |
| domain_intelligence | 20% | 80% | domain_count: 1, domains_analyzed: {'ipfs.io': {'risk_score': 0.2, 'confidenc... |
| brand_impersonation | 0% | 80% | brands_checked: 16 |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.460. Verdict: SUSPICIOUS. Analyzer breakdown: header_analysis: 0.200 (conf: 0.500); url_reputation: 0.448 (conf: 0.960); domain_intelligence: 0.200 (conf: 0.800); url_detonation: 0.600 (conf: 0.800); brand_impersonation: 0.000 (conf: 0.800); attachment_an...

---

### Sample 10 — ✅ LIKELY_PHISHING (62%)

**Phishing URL:** `http://greamreaper01.github.io/Netflix`

**Domain:** `greamreaper01.github.io` | **Brand:** Netflix | **Time:** 3.08s

| Analyzer | Score | Confidence | Key Details |
|----------|-------|------------|-------------|
| nlp_intent | 99% | 95% | intent_category: credential_harvesting, base_risk_score: 0.95, urgency_score:... |
| url_reputation | 90% | 100% | url_count: 1, urls_analyzed: {'http://greamreaper01.github.io/Netflix': {'ris... |
| brand_impersonation | 63% | 70% | signals_found: 1, signals: [{'signal': 'body_brand_mismatch', 'brand': 'bank_... |
| domain_intelligence | 60% | 80% | domain_count: 1, domains_analyzed: {'greamreaper01.github.io': {'risk_score':... |
| url_detonation | 50% | 80% | urls_detonated: 1, urls_loaded: 1, detonation_results: {'http://greamreaper01... |
| sender_profiling | 45% | 50% | sender_email: info@greamreaper01.github.io, email_count: 1, anomaly_score: 0.... |
| header_analysis | 0% | 50% |  |
| attachment_analysis | 0% | 0% | message: no_attachments |

**Reasoning:** Analyzed with 8 analyzers. Weighted score: 0.620. Verdict: LIKELY_PHISHING. Analyzer breakdown: header_analysis: 0.000 (conf: 0.500); url_reputation: 0.900 (conf: 1.000); domain_intelligence: 0.600 (conf: 0.800); url_detonation: 0.500 (conf: 0.800); brand_impersonation: 0.633 (conf: 0.700); attachme...

---


## Recommendations

1. **Install missing dependencies** — If any analyzer shows 0% confidence, it likely failed to load. Run `pip install dnspython` to enable url_reputation, domain_intelligence, and attachment_analysis.

2. **Lower SUSPICIOUS threshold** — If borderline scores (25-30%) appear in false negatives, consider lowering the threshold from 30% to 25%.

3. **Feed integration** — Consider integrating OpenPhish and Phishing.Database feeds as real-time blocklists in the pipeline for known-bad URL matching.

4. **Retrain on feedback** — Use the `/api/feedback/retrain` endpoint to incorporate analyst corrections from this test.

---

*Report generated by `run_live_test.py` on 2026-04-02 21:27:52*
*Sources: [OpenPhish](https://openphish.com/), [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), [abuse.ch URLhaus](https://urlhaus.abuse.ch/)*

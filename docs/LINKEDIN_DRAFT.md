# LinkedIn Draft Posts for Meidie

## Draft A: The Debugging Story

Built an automated phishing detection pipeline with 7 concurrent analyzers, MITRE ATT&CK mapping, and Sigma rule export. On paper, it looked solid. Then I added an eval harness and discovered the detector had 0.20 recall. Essentially broken.

Four audit cycles to find why. The root cause: three instances of the same dilution bug across three different analyzers. Each was reporting "clean with high confidence" on data it hadn't actually analyzed (no attachments, cold start, partial URL coverage). That false confidence dragged down the weighted average on every decision. The same bug class, identified in cycle 4, replicated undetected through cycle 14 because each instance looked different on the surface while the math was identical.

The fixes were surgical. Confidence drops to zero when no real analysis occurred. Recall moved from 0.20 to 0.80 in degraded state (NLP classifier in fallback mode, external APIs not configured). No architecture changes. No new features. Just correcting what was already there.

The project still has gaps. That 0.80 is the floor, measured without live APIs; the real number is pending. The test corpus is 22 samples. Strict recall is 0.20. But I learned that shipping something that passes unit tests is not the same as shipping something that works end-to-end, and that a plausible diagnosis you didn't verify is worse than no diagnosis at all.

Code is here: https://github.com/meidielo/Automated-Phishing-Detection

---

## Draft B: The Recall Collapse

Started with 0.20 recall. That's not a metric. That's a warning sign.

Built an automated phishing detection pipeline using 7 concurrent analyzers, FastAPI, async processing, Docker containerization. Integrated MITRE ATT&CK mapping across 12 sub-techniques. Added Sigma rule export and STIX 2.1 IOC generation. 947 test cases. The architecture was clean.

When I added an evaluation harness, the recall number told a different story. Four audit cycles to diagnose: three instances of the same confidence dilution bug in three different analyzers. Each was voting "clean with high confidence" on data it hadn't processed (missing attachments, cold-start state, partial URL coverage). Same math each time: zero numerator, non-zero denominator, average dragged toward zero. The bug was identified in cycle 4 and still replicated through cycle 14 because each instance wore a different surface.

The fix: confidence drops to zero when no real analysis occurred. Recall moved from 0.20 to 0.80 in degraded state (sklearn fallback, no live APIs). No architectural changes. No new features. The pipeline was already there; I corrected how it reported what it knew.

What still doesn't work: that 0.80 is the floor, not the measurement; live-API numbers are pending. Strict recall is 0.20. The corpus is 22 samples. And I diagnosed the wrong root cause in cycle 12 ("it's the external APIs") before the data proved me wrong in cycle 13.

What I learned: evaluation is not optional. A plausible diagnosis you didn't test is worse than admitting you don't know. Confidence scores are weapons against yourself if you're not careful.

Repository: https://github.com/meidielo/Automated-Phishing-Detection

---

## Draft C: The Confidence Bug

Shipped a phishing detector with 0.20 recall. Here's what happened.

Built an automated detection pipeline with 7 concurrent analyzers, Python FastAPI backend, async processing, Docker deployment. Mapped detections to MITRE ATT&CK across 12 sub-techniques. Generated Sigma rules and STIX 2.1 IOCs. Created 947 tests. Felt solid.

Added an eval harness. Recall was 0.20. Not acceptable. Spent four audit cycles finding out why: three instances of the same confidence dilution bug in three different analyzers (attachment_analysis, sender_profiling, url_detonation). Each reported high confidence on analysis it hadn't performed. That false confidence cascaded through the weighted voting system and collapsed detection accuracy. The bug class was identified in cycle 4. It replicated through cycle 14 because each instance looked different on the surface while the math was the same.

The fix: confidence drops to zero when no real analysis occurred. Recall to 0.80 in degraded state (no live APIs, NLP in fallback mode).

Same code. Same architecture. Same features. Just corrected the confidence calculation. And along the way, I diagnosed the wrong root cause ("it's the external APIs"), got called out by an auditor, traced the actual data, and found the real bug.

Honest assessment: the 0.80 is the floor, measured without live APIs. The corpus is 22 samples. Strict recall is 0.20. I needed four external audits to catch bugs that were structurally identical to one I'd already fixed. Those are the numbers.

The project taught me that evaluation is foundational, not optional. That a plausible explanation you didn't verify is more dangerous than admitting ignorance. And that discipline means building mechanical checks because you know you'll skip the manual ones.

Code: https://github.com/meidielo/Automated-Phishing-Detection

---

## Notes on these drafts:

- All three avoid em dashes and use commas, semicolons, and periods instead
- Character counts are in the 1000-1500 range, appropriate for LinkedIn
- Lead with the honest narrative (the bug, the discovery process) rather than "look what I built"
- Include all specific numbers: 0.20/0.80 recall, 947 tests, 22-sample corpus, 7 analyzers, 12 ATT&CK sub-techniques, 3 bug instances across 3 analyzers
- Each frames 0.80 as degraded-state floor, not final measurement; live-API numbers pending
- Each acknowledges what doesn't work (strict recall 0.20, small corpus, wrong diagnosis in cycle 12)
- Cycle 14 url_detonation finding included in all three drafts
- All end with what the project taught, not a CTA
- Tone is direct, confident, and non-arrogant
- No emojis

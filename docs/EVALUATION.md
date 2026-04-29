# Evaluation Methodology

This document describes how the phishing detection pipeline should be evaluated against real-world corpora, what metrics to report, and what the current honest answer is for each metric. It exists because **a detection project that doesn't say what it catches and what it misses is selling vibes, not detection**.

The goal is not to claim impressive numbers. The goal is to make the methodology reproducible so that anyone — me, a reviewer, an interviewer — can run the same evaluation and get the same numbers, and so that improvements can be measured against a baseline rather than asserted.

---

## 1. Corpora

### 1.1 Phishing-positive corpora

| Corpus                          | Size (approx) | Provenance                                         | Use                              |
| ------------------------------- | ------------- | -------------------------------------------------- | -------------------------------- |
| **Nazario phishing corpus**     | ~25k emails   | Jose Nazario's monthly archive (2004–present)      | Long-tail historical phishing    |
| **PhishTank exports**           | varies        | URLs, not full emails — used for `url_reputation` only | URL-layer baseline           |
| **APWG eCrime archive**         | varies        | APWG members only — not redistributable            | Cited but not redistributable    |
| **Internal sample set**         | ~50 emails    | Hand-curated from `tests/sample_emails/` and `tests/real_world_samples/` | Reproducible smoke tests |

### 1.2 Negative (legitimate) corpora

| Corpus                          | Size (approx) | Provenance                                         | Use                              |
| ------------------------------- | ------------- | -------------------------------------------------- | -------------------------------- |
| **Enron email dataset**         | ~500k emails  | Public release, c. 2003, business correspondence   | Bulk false-positive baseline     |
| **TREC public mail tracks**     | ~50k emails   | TREC 2007 spam track, ham split                    | Diverse legitimate mail          |
| **Synthetic legitimate set**    | growing       | `tests/sample_emails/legitimate/` — hand-curated   | Reproducible negative cases      |

### 1.3 Quality caveats

- **Nazario is biased toward older phishing.** Brand impersonation patterns from 2008 don't reflect 2024 attack tradecraft. Treat as a *recall floor*, not a tradecraft sample.
- **Enron is biased toward American corporate English.** Legitimate transactional mail in other languages and formats is underrepresented; expect higher false positive rates on multilingual inboxes than Enron suggests.
- **PhishTank URLs are post-hoc labeled.** Many were dead by the time of labeling. Run URL-layer evaluation against historical reputation data, not live API calls.

---

## 2. Metrics

### 2.1 Verdict-level metrics

For each verdict (`CLEAN`, `SUSPICIOUS`, `LIKELY_PHISHING`, `CONFIRMED_PHISHING`):

- **Precision** — of all emails the pipeline labeled X, what fraction were actually X?
- **Recall** — of all emails actually X, what fraction did the pipeline catch?
- **F1** — harmonic mean.

The honest target metrics for a defensive deployment are:

| Verdict             | Precision goal | Recall goal | Why                                                                |
| ------------------- | -------------- | ----------- | ------------------------------------------------------------------ |
| CONFIRMED_PHISHING  | ≥ 0.99         | ≥ 0.30      | High precision because this verdict drives auto-block in operator workflows. Recall is secondary; we'd rather miss than mislabel. |
| LIKELY_PHISHING     | ≥ 0.90         | ≥ 0.60      | Drives analyst review. False positives waste analyst time.        |
| SUSPICIOUS          | ≥ 0.70         | ≥ 0.80      | Catch-all bucket; high recall is the point.                       |
| CLEAN               | ≥ 0.95         | ≥ 0.90      | Equivalent to negative-class precision.                           |

The **confidence-capping rule** (verdicts capped to SUSPICIOUS when overall confidence < 0.4, see `decision_engine.py:444`) means SUSPICIOUS will always be the high-recall bucket and CONFIRMED_PHISHING will always be the high-precision bucket *by design*. Evaluate this trade-off, don't fight it.

### 2.2 Analyzer-level metrics

For each analyzer, evaluate independently:

- **Coverage** — of emails where this analyzer's signal is *applicable* (e.g., for URL reputation, emails containing URLs), what fraction did it produce a confidence > 0 result for?
- **Per-analyzer precision/recall** — treating `risk_score >= 0.5` as positive.
- **Failure mode breakdown** — for analyzers that returned `confidence == 0`, why? API timeout? Missing data? Library not installed?

The point of analyzer-level evaluation is to catch silent degradation. If `url_detonator` coverage drops from 95% to 60% because the headless browser is OOM-killing, the verdict-level metrics will degrade gradually, but analyzer coverage shows it immediately.

### 2.3 ATT&CK-level recall

For each technique listed in `docs/MITRE_ATTACK_MAPPING.md`, manually label a small set of corpus emails (~20 per technique) and measure how often the responsible analyzer fires. This is the metric that actually answers "does the pipeline catch what it claims to catch?"

This is labor-intensive and should be run quarterly, not per-PR.

### 2.4 Latency

- **End-to-end p50 / p95 / p99** for the pipeline on a single email
- **Per-analyzer p95**
- **Sandbox detonation timeout rate** (analyzer returned no data because the 120s pipeline timeout fired before the sandbox finished)

Latency matters because the pipeline is async and concurrent. A regression in one analyzer's tail latency drags every verdict.

---

## 3. Procedure

### 3.1 Reproducible run

```bash
# 0. Download raw public corpora once. Generated data is ignored by git.
bash scripts/download_corpora.sh

# 1. Stage a deterministic eval/ML-ready corpus.
python scripts/eval_prepare_corpus.py \
  --corpora-dir data/corpora \
  --output data/eval_corpus \
  --phishing 200 \
  --enron-ham 200 \
  --spamassassin-ham 100 \
  --seed 1337 \
  --clean-output

# 2. Run the pipeline against every staged email.
python scripts/run_eval.py \
  --corpus data/eval_corpus \
  --labels data/eval_corpus/labels.json \
  --output eval_runs

# 3. Inspect false positives, false negatives, and errors.
python scripts/eval_inspect_failures.py \
  --results eval_runs/RUN_ID.jsonl \
  --manifest data/eval_corpus/manifest.jsonl \
  --projection permissive \
  --output data/eval_corpus/failure_report_permissive

python scripts/eval_inspect_failures.py \
  --results eval_runs/RUN_ID.jsonl \
  --manifest data/eval_corpus/manifest.jsonl \
  --projection strict \
  --output data/eval_corpus/failure_report_strict
```

`scripts/eval_prepare_corpus.py` writes a flat `.eml` directory, `labels.json` for `scripts/run_eval.py`, `labels.csv` for ML workflows, `manifest.jsonl` for source provenance, and `summary.json` for reproducibility. `scripts/run_eval.py` writes per-sample JSONL and an aggregate `.summary.json` under `eval_runs/`.

`scripts/eval_inspect_failures.py` writes JSON, CSV, and Markdown reports that rank each failure by top analyzer signal. Use the permissive report to reduce false positives and the strict report to find phishing samples stuck in `SUSPICIOUS`.

The generated corpus is intentionally not committed. Raw external corpora are large, carry licensing constraints, and should be rebuilt from the downloader plus the manifest instead of stored in git.

### 3.2 What to fix the seed on

- API client randomness (jitter on retries) — disable during eval
- LLM intent classifier — pin model version + temperature 0
- Sandbox VM selection — prefer same provider for reproducibility

Without seed control, eval runs aren't comparable across days.

### 3.3 Data leakage

The unit tests in `tests/unit/` use a small set of hand-crafted emails that exist in the repository. **These must not be in the evaluation corpus.** Any overlap inflates metrics by measuring memorization rather than generalization.

---

## 4. Current honest answer

As of commit `c459237`:

- **External corpus preparation is implemented.** Nazario phishing mboxes, Enron sent-mail ham, and SpamAssassin ham can be staged into a labeled `.eml` corpus with reproducible sampling.
- **A public-corpus smoke baseline has been run.** A 15-sample remote run used 5 Nazario phishing emails, 5 Enron ham emails, and 5 SpamAssassin ham emails. It produced permissive TP=5, FP=2, TN=8, FN=0, precision=0.714, recall=1.000, F1=0.833, accuracy=0.867. Strict scoring produced TP=0, FP=0, TN=10, FN=5, F1=0.000, accuracy=0.667.
- **Failure reports exist for that smoke run.** Permissive failures: 2 false positives. Strict failures: 5 false negatives caused by phishing detections staying below the strict LIKELY_PHISHING threshold.
- **This is not a production metric.** A 125-sample run was attempted but exceeded 30 minutes with live analysis enabled. The 15-sample run is a reproducibility and plumbing baseline, not evidence of deployment-quality precision or recall.
- **Unit tests measure code correctness, not detection quality.** They are necessary, not sufficient.

The right reviewer answer is now: "we have the methodology, corpus prep, eval harness, failure inspection, and a small public-corpus smoke baseline. Larger public-corpus metrics still need a longer controlled run from ignored raw data."

---

## 5. Next Evaluation Pass

The next public-corpus run should capture:

- Date of evaluation run
- Commit SHA
- Corpora used (with sizes and version dates)
- Verdict-level confusion matrix
- Per-analyzer metrics table
- ATT&CK technique recall table
- Latency percentiles
- Diff vs. previous baseline, with regressions called out by name

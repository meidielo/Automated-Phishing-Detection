# Roadmap

This document is the single source of truth for what is planned, in progress, and explicitly **not** planned. It exists so that "I thought you were going to build X" conversations have a place to land.

Status is one of:
- **shipped** — in `main`, tested, documented
- **in progress** — branch exists or work is actively underway
- **planned** — decided to do, not started
- **considered, deferred** — looked at, decided not to do (with reason)
- **dropped** — was on a list at some point, no longer pursued (with reason)

---

## Shipped

| Item                                              | Notes                                                            |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| 5-stage async pipeline                            | Ingestion → extraction → analysis → decision → feedback          |
| 7 concurrent analyzers                            | header, URL reputation, domain intel, URL detonator, brand impersonation, NLP intent, attachment sandbox |
| QR decoder (image / PDF / DOCX / rendered HTML)   | `extractors/qr_decoder.py`                                        |
| Magic-byte attachment classification              | `extractors/attachment_handler.py`                                |
| Multi-account IMAP + Gmail/Outlook providers      | `automation/multi_account_monitor.py`                             |
| Secure credential vault                           | `src/security/`                                                   |
| Weighted decision engine with override rules      | `scoring/decision_engine.py`                                      |
| Confidence-based verdict capping                  | Caps to SUSPICIOUS when confidence < 0.4                          |
| Analyst feedback API + logistic regression retraining | `feedback/`                                                  |
| Web dashboard                                     | `reporting/dashboard.py`                                          |
| JSON / HTML reports                               | `reporting/report_generator.py`                                   |
| **STIX 2.1 IOC export**                           | `reporting/ioc_exporter.py`                                       |
| **Sigma rule export (campaign-scoped)**           | `reporting/sigma_exporter.py`                                     |
| **Static Sigma rule library**                     | `sigma_rules/` — 6 hand-written rules                             |
| **MITRE ATT&CK coverage mapping**                 | `docs/MITRE_ATTACK_MAPPING.md`                                    |
| **Threat model**                                  | `THREAT_MODEL.md`                                                 |
| **Security disclosure policy**                    | `SECURITY.md`                                                     |
| **Bearer token auth on all sensitive `/api/*` routes** | `src/security/web_security.py::TokenVerifier`, wired into `main.py` |
| **SSRF guard on `/api/detonate-url`** (DNS-resolved IP denylist for RFC1918, loopback, link-local, CGNAT, cloud metadata) | `src/security/web_security.py::SSRFGuard` |
| **Security headers middleware** (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy) | `src/security/web_security.py::SecurityHeadersMiddleware` |
| **Default loopback bind** with refuse-to-start on non-loopback if `ANALYST_API_TOKEN` unset | `main.py::run_server` |
| **Body HTML XSS hardening** — sandboxed `<iframe srcdoc>` with no allow flags + server-side bleach sanitizer | `templates/monitor.html`, `src/security/html_sanitizer.py` (40 hostile-payload tests) |
| **Dead-domain confidence downgrade in URL reputation** — non-resolving hostnames with clean vendor verdict get confidence capped at 0.3 instead of inflating "clean" signal (~15 point recall gain on phishing corpus) | `src/analyzers/url_reputation.py::_hostname_resolves` (11 regression tests) |
| **AES-256-GCM credential storage with auto-migration** — plaintext IMAP/OAuth secrets in `accounts.json` are detected and re-encrypted on every load | `src/security/credentials.py`, `src/automation/multi_account_monitor.py::_migrate_plaintext_passwords` (12 migration tests + 30+ existing crypto tests) |
| **LLM determinism contract** — temperature=0, top_p=1, model version captured per `PipelineResult` for drift detection | `src/analyzers/clients/anthropic_client.py::AnthropicLLMClient` (10 contract tests) |
| **CSRF trigger checklist** as durable contract in the auth module — any future cookie/session auth must ship CSRF protection in the same PR | `src/security/web_security.py` module docstring |
| **Hash-pinned dependency lock file** (`requirements.lock`) generated via `uv pip compile --generate-hashes`, installed with `pip install --require-hashes` in Dockerfile | `requirements.lock`, `Dockerfile`               |
| **GitHub Actions CI** — full pytest on fresh checkout, flake8 lint, daily `pip-audit` against the lock file (fails on any advisory) | `.github/workflows/ci.yml`                      |
| **`curl`-free Dockerfile healthcheck** using stdlib `urllib.request` — smaller image, smaller attack surface | `Dockerfile`                                    |
| **Bind-mount UID fix** via `docker-entrypoint.sh` — chowns `/app/data` and `/app/logs` to runtime UID then `gosu`s to non-root before exec | `docker-entrypoint.sh`, `Dockerfile`            |
| **Data retention / `purge` CLI subcommand** with `--older-than`, `--strict`, `--dry-run`, and `--by-address`. Closes Privacy Act / GDPR indefinite-retention and per-subject erasure risk. | `src/automation/retention.py`, `main.py purge` |
| **Cross-analyzer calibration pass** (ADR 0001) — two-pass decision engine with corroboration-style calibration rules. Closes the LinkedIn FP that survived four cycles. | `src/scoring/calibration.py`, `src/scoring/social_platform_domains.py`, `src/scoring/decision_engine.py` (29 tests + ADR + rule registry doc) |
| **Override-rule ordering fix (cycle 7 NEW-1)** — `_is_bec_threat` now runs BEFORE `_is_clean_email` so pure-text BEC with passing auth is no longer force-marked CLEAN. Closes a load-bearing accident discovered during cycle 6 implementation. | `src/scoring/decision_engine.py::_check_override_rules` (4 regression tests in `tests/unit/test_decision_engine_override_ordering.py`) |
| **Calibration cap ceiling locked** — explicit tests proving the LinkedIn calibration rule caps verdicts AT SUSPICIOUS, never at CLEAN, and never modifies the underlying weighted score. Defends against the "real LinkedIn with embedded malicious redirect below corroboration threshold" scenario. | `tests/unit/test_calibration.py::TestCalibrationCapCeiling` (3 tests) + ADR §"Why the cap is SUSPICIOUS and not CLEAN" |
| **CI-bites sanity check** — deliberate red branch (run id `24403600695`) confirmed `pull_request` workflow fails the test job loudly when a test breaks. Branch deleted, PR closed without merge. The "two cycles green = converging or blind spot" concern from the cycle 6 review is now resolved. | `.github/workflows/ci.yml`                       |
| **Persistent email_id lookup for analyst feedback (ADR 0002)** — closes audit #9. Feedback endpoint and `/api/monitor/email/{id}` now resolve email_id via an in-memory `email_id → byte_offset` index over `data/results.jsonl` instead of scanning the 200-cap in-memory `_upload_results` list. Survives restart and the 200-cap roll. The display path keeps `_upload_results` unchanged — see ADR §"Why this split". | `src/feedback/email_lookup.py`, `main.py`, `src/automation/retention.py` (20 tests including cross-restart smoking gun) |
| **Diagnostic refactor (audit #10)** — three duplicate API health-check implementations (`diagnose_apis.py`, `test_apis.py`, `/api/diagnose`) consolidated into `src/diagnostics/api_checks.py` with a `CheckResult` dataclass and registry-driven `run_all_checks()`. `test_apis.py` deleted. | `src/diagnostics/` (18 tests covering the SKIP path, registry shape, dispatch, and `summarize()`) |
| **Eval harness with per-sample JSONL storage** — corpus-agnostic `src/eval/harness.py` and `scripts/run_eval.py`. Each run produces one JSONL row per sample (sample_id, true_label, predicted_verdict, per_analyzer_scores, calibration outcome, model_id, commit_sha, TP/FP/TN/FN) plus an aggregate `.summary.json` under `eval_runs/`. Two binary projections (permissive/strict) computed and stored separately. The first baseline against `tests/real_world_samples/` is committed. The harness is the deliverable; numbers are data. | `src/eval/harness.py`, `scripts/run_eval.py`, `eval_runs/` (27 tests covering schema, projection, aggregate arithmetic) |
| **Payment Fraud Firewall** — payment-specific analyzer that turns invoice, supplier, BEC, and bank-detail-change email signals into `SAFE`, `VERIFY`, or `DO_NOT_PAY` business decisions. | `src/analyzers/payment_fraud.py`, wired into pipeline and decision overrides |
| **Payment scam dataset and ML tooling** — ignored local dataset scaffold, synthetic bank-detail-change seed set, public-advisory-derived payment-risk and holdout seed sets, redaction/audit path for real samples, ML JSONL export, payment-decision eval reports, and a TF-IDF + logistic regression train/test/holdout baseline. | `src/eval/payment_dataset.py`, `src/eval/payment_decision_eval.py`, `src/ml/payment_classifier.py`, `scripts/payment_dataset.py`, `scripts/payment_eval.py`, `scripts/payment_train.py` |
| **Payment dataset readiness report** - counts source types, labels, payment decisions, and splits, and warns when non-synthetic coverage is missing for a payment decision. | `scripts/payment_dataset.py readiness`, `src/eval/payment_dataset.py` |
| **Generic public-corpus ML baseline** - trains a TF-IDF + logistic regression classifier from prepared Nazario/Enron/SpamAssassin corpora and writes ignored model metrics. | `src/ml/phishing_classifier.py`, `scripts/phishing_train.py` |
| **Payment ML decision sidecar** - payment analyzer reports model prediction, confidence, probabilities, and rules disagreement without letting synthetic-only ML override payment release. | `src/analyzers/payment_fraud.py`, `src/ml/payment_classifier.py` |
| **Payment demo runner** - compact expected-vs-predicted `SAFE` / `VERIFY` / `DO_NOT_PAY` table for PII-free demo samples. | `src/eval/payment_demo.py`, `scripts/payment_demo.py` |
| **Synthetic SAFE invoice seed class** - payment dataset generator can add routine invoice examples so `SAFE`, `VERIFY`, and `DO_NOT_PAY` all train and evaluate. | `src/eval/payment_dataset.py` |
| **Public-corpus smoke eval baseline** - 15-sample Nazario/Enron/SpamAssassin run on commit `c459237`, with permissive and strict failure reports generated from ignored corpora. | `docs/EVALUATION.md`, `scripts/eval_inspect_failures.py` |
| **Feedback DB retention policy** - `purge --target feedback|all` purges old SQLAlchemy feedback labels by age while optionally keeping N newest records. | `src/automation/retention.py`, `main.py purge` |
| **Browser session auth for dashboard** - `/login` sets signed session and CSRF cookies; the same `TokenVerifier` accepts bearer or browser session auth. | `src/security/web_security.py`, `main.py`, `templates/login.html`, `templates/_shared.html` |
| **Multi-container Docker Compose browser split** - URL detonation connects to a separate `browser-sandbox` Playwright service via `PLAYWRIGHT_WS_ENDPOINT`. | `docker-compose.yml`, `docker-compose.production.yml`, `src/analyzers/url_detonation.py` |
| 1044 tests (49 test modules) | unit + integration |

---

## Planned

Ordered by intended sequence, not priority.

### Real redacted payment samples
The payment dataset has tooling, synthetic seed data, public-advisory-derived `VERIFY`/`DO_NOT_PAY` seed and holdout data, readiness reporting, redaction, eval, demo, and ML training. It still needs real redacted invoice, bank-change, remittance, and supplier-update samples before external product metrics are credible. Target: 20 to 50 real redacted examples across `SAFE`, `VERIFY`, and `DO_NOT_PAY`.

### Audit trail for feedback labels
Append-only log of who relabeled what. Closes residual risk **R2**. Required before the project is honest about being multi-analyst.

### Sigma converter integration
Pipe the static rule library through `sigmac` / `pysigma` in CI to validate rules against multiple SIEM backends (Splunk SPL, Elastic EQL, Sentinel KQL). Currently rules are hand-written and untested against a converter.

### TAXII 2.1 push for STIX bundles
Optional outbound TAXII collection push. STIX export already works; this is the transport layer.

### IOC reputation feedback loop
When an analyst marks an email CONFIRMED_PHISHING, push the URL/domain/hash IOCs back to the local cache as ground truth for future runs. Distinct from logistic regression weight retraining.

---

## In progress

*(none currently — last shipped pass was the detection-engineering reframing: ATT&CK mapping, threat model, Sigma exports.)*

---

## Considered, deferred

These were genuinely evaluated and decided against, at least for now. The reasoning is here so future-me doesn't relitigate.

### Multi-tenant namespace isolation
**Why deferred:** the project is single-operator by design. Adding tenant separation means rewriting the feedback DB schema, the credential vault, and the dashboard. Not worth the complexity until there's a second tenant. Documented as non-goal #4 in `THREAT_MODEL.md`.

### gVisor / Firecracker for browser sandbox
**Why deferred:** Docker container isolation is good enough for a single-operator portfolio deployment. gVisor is the right answer for production, but the operational burden (kernel compat, debuggability) is too high for solo maintenance.

### Real-time stream ingestion via Kafka/Redis Streams
**Why deferred:** the async generator interface in `ingestion/` was deliberately designed to support this, but no operator I'd hand the project to today needs it. README known-limitation #10 already documents the gap honestly.

### LLM-based analyzer for full email body classification (not just intent)
**Why deferred:** `nlp_intent.py` already uses an LLM where a key is configured. A second, broader LLM analyzer would duplicate signal and double the API spend without adding much. The sklearn fallback path also means LLM-only features are not portable.

---

## Dropped

These were on internal "future modules" lists at some point. They are no longer pursued. If you came here looking for them, the answer is "not happening, here's why."

### Resume-context attachment anomaly analyzer
**Status:** dropped.
**Original idea:** detect HR-themed phishing (fake job applications) by combining attachment metadata with subject context — e.g. `.docx` named `resume.docx` from a sender domain that doesn't match a recruiting platform.
**Why dropped:** the existing `attachment_handler` + `nlp_intent` combination already catches this in the cases that matter. A dedicated analyzer would be a thin wrapper around their outputs, not a new signal. Better to harden the two existing components.

### Obfuscation density analyzer
**Status:** dropped.
**Original idea:** score the body of an email by character-class entropy and obfuscation patterns (zero-width chars, RTL overrides, look-alike Cyrillic glyphs) to detect homograph attacks and content evasion.
**Why dropped:** valuable signal in theory, but the false-positive rate on legitimate multilingual mail is high and the implementation requires careful Unicode normalization that interacts with every other text-processing component. Reconsider only if a corpus evaluation (see `docs/EVALUATION.md`) shows a clear gap that this would close. Until then, NLP intent classification is doing enough of this work indirectly.

---

## Not in scope (ever)

Restating the explicit non-goals from `THREAT_MODEL.md` §7 here so they live next to the planned work:

- **Mail filtering / blocking.** Verdicts are advisory. Routing is the operator's job.
- **SOAR functionality.** No automated remediation, ticket creation, or user notification.
- **EDR / post-compromise detection.** T1078 full, T1098, T1606 — out of scope.
- **Multi-tenant SaaS deployment.** Single operator, single trust domain.
- **Active takedown of phishing infrastructure.** Identification only.

---

## How this document is maintained

- A new analyzer or major feature ships → move it from **planned** to **shipped**.
- A planned item gets started → move it to **in progress**, link the branch.
- An idea is rejected → put it in **considered, deferred** with a one-paragraph reason. Don't delete; future-me will ask.
- A previously-tracked idea is killed → move it to **dropped** with rationale. Same reason.

PRs that change `main`-branch behavior should update this doc in the same commit.

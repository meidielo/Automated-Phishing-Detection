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
| Docker Compose deployment                         | orchestrator + browser-sandbox + redis                            |
| 753 tests (24 modules) — includes 34 sigma exporter + 43 web security tests | unit + integration |

---

## Planned

Ordered by intended sequence, not priority.

### Browser session auth for the HTML dashboard
HTML pages (`/`, `/monitor`, `/accounts`, `/dashboard`) load without auth even though their `/api/*` calls are bearer-token protected. A browser user therefore sees an empty dashboard until they manually inject a token. Add cookie/session auth so a `/login` POST sets a session cookie that's accepted by the same `TokenVerifier`. Tracked partial — bearer auth shipped, session layer not.

### Audit trail for feedback labels
Append-only log of who relabeled what. Closes residual risk **R2**. Required before the project is honest about being multi-analyst.

### Automated evaluation harness
Run the pipeline against a labeled corpus and emit precision/recall/F1 per analyzer and per verdict. Methodology lives in `docs/EVALUATION.md`. Today the project has unit tests but no detection-quality metrics on real corpora.

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

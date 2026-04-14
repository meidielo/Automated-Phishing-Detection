# Threat Model

This document is the security-relevant view of the phishing detection pipeline: what it protects, who would attack it, where the trust boundaries are, and which mitigations are already in place vs. which residual risks an operator must accept. It complements `docs/MITRE_ATTACK_MAPPING.md` (which scopes detection coverage) and `SECURITY.md` (which scopes disclosure).

The model uses a STRIDE lens grouped by trust boundary, with a short adversary section up front so the rest reads in the right context.

---

## 1. Assets

In rough order of "what an attacker would target first":

| # | Asset                              | Why it matters                                                                       |
|---|------------------------------------|--------------------------------------------------------------------------------------|
| 1 | **Analyst trust in verdicts**      | If verdicts can be silently flipped (CLEAN→PHISHING or vice-versa), every downstream automated action is poisoned. This is the highest-value target. |
| 2 | **Mailbox credentials**            | IMAP/OAuth credentials in `.env` and the secure vault grant read access to entire mailboxes. |
| 3 | **IOC integrity**                  | STIX/Sigma exports flow into shared TI platforms. A poisoned IOC bundle becomes other people's blocklists. |
| 4 | **Sandbox isolation**              | The headless browser executes attacker-controlled URLs. Container escape compromises the host. |
| 5 | **Feedback labels**                | The retraining loop adjusts analyzer weights. Poisoned labels degrade detection over time. |
| 6 | **Pipeline availability**          | A flooded queue means real phishing waits in line. Not a confidentiality breach but an operational one. |
| 7 | **Third-party API keys**           | VirusTotal/urlscan/AbuseIPDB/etc. — abuse damages reputation and burns quota. |

---

## 2. Adversaries

Four archetypes shape every other section.

### A. Commodity phisher (low skill, high volume)
**Goal:** deliver credential-harvest pages or commodity malware to anyone in the inbox.
**Capability:** templated kits, recycled infrastructure, no targeting.
**Pipeline impact:** this is the design-target adversary. Existing detection covers them well.

### B. BEC operator (medium skill, targeted)
**Goal:** wire fraud or invoice fraud against a specific finance team.
**Capability:** lookalike domains, no malware, no links — pure social engineering. May use compromised legitimate accounts (T1078).
**Pipeline impact:** `nlp_intent` BEC override is the primary signal. Header-clean compromised accounts are a known gap.

### C. Targeted intrusion actor (high skill, surgical)
**Goal:** initial access into the operator's environment.
**Capability:** zero-day URLs, custom payloads, sandbox-aware malware, headless-browser detection on landing pages.
**Pipeline impact:** detection is best-effort. The pipeline is **not** a substitute for endpoint and network defenses against this class.

### D. Malicious analyst / insider
**Goal:** mark malicious mail as benign (or vice-versa) via the feedback API; exfiltrate mailbox content.
**Capability:** legitimate access to the feedback API, dashboard, and stored emails.
**Pipeline impact:** no separation of duties exists today. Trust is binary. Documented as residual risk.

---

## 3. Trust boundaries & data flow

```
                     ┌───────────────────┐
                     │   Adversary mail  │   <-- untrusted, attacker-controlled
                     └─────────┬─────────┘
                               │ SMTP
                               ▼
   ┌─────────────────────────────────────────────────────┐
   │ TB1: External MTA → IMAP mailbox                    │
   │      (operator mailbox provider)                    │
   └─────────────────────────┬───────────────────────────┘
                             │ IMAP/OAuth
                             ▼
   ┌─────────────────────────────────────────────────────┐
   │ Pipeline host (Docker compose: orchestrator+redis+  │
   │ browser-sandbox containers)                         │
   │                                                     │
   │  TB2: Ingestion → Extraction → Analysis             │
   │                                                     │
   │   ┌──────────┐   ┌──────────┐   ┌────────────────┐  │
   │   │ IMAP     │   │ Parsers  │   │ 7 analyzers    │  │
   │   │ fetcher  │──▶│ (eml,    │──▶│ (concurrent)   │  │
   │   └──────────┘   │  hdr, qr)│   └───────┬────────┘  │
   │                  └──────────┘           │           │
   │                                         ▼           │
   │  TB3: Analyzer ↔ Browser sandbox container          │
   │       (URL detonator → headless Chromium)           │
   │                                                     │
   │  TB4: Pipeline → 3rd-party APIs                     │
   │       (VT, urlscan, AbuseIPDB, GSB, HA, WHOIS)      │
   │                                                     │
   │  TB5: Pipeline → SQLite (feedback) + Redis (cache)  │
   │                                                     │
   │  TB6: Feedback API (FastAPI) ← analyst              │
   │                                                     │
   └─────────────────────────┬───────────────────────────┘
                             │ JSON / HTML / STIX / Sigma
                             ▼
                   ┌──────────────────────┐
                   │ Reports & TI exports │
                   └──────────────────────┘
```

The numbered trust boundaries (TB1–TB6) are referenced by the STRIDE table below.

---

## 4. STRIDE per boundary

| Boundary | S(poofing) | T(amper) | R(epudiate) | I(nformation disclosure) | D(oS) | E(levation) |
|----------|------------|----------|-------------|--------------------------|-------|-------------|
| **TB1** External → IMAP | Header forgery (whole point of the project — detect, not prevent) | MTA upstream rewriting Authentication-Results | n/a | mailbox content already considered untrusted-but-readable | mailbox flooding | n/a |
| **TB2** Ingestion → Analysis | n/a | Malformed EML triggering parser bug | n/a | parser stores raw bytes briefly | parser DoS via giant nested archive | parser RCE via crafted MIME |
| **TB3** Analyzer ↔ Sandbox | n/a | Sandbox-rendered DOM forged to mislead `brand_impersonation` | n/a | sandbox sees destination IPs | detonation hang / infinite redirect | container escape from headless browser |
| **TB4** Pipeline → 3rd-party APIs | API endpoint impersonation (TLS pinning not in place) | Response forgery if MitM | n/a | leaks observed URLs/IPs to vendors | API rate-limit DoS | n/a |
| **TB5** Pipeline → DB/cache | n/a | DB write tampering if local FS compromised | n/a | feedback DB contains email metadata | disk full | SQLi (parameterized — verified in `feedback/database.py`) |
| **TB6** Analyst → Feedback API | analyst auth = none/weak by default | poisoned labels degrade weights over time | no audit trail of who labeled what | feedback API exposes stored verdicts | flood `/feedback` to drown signal | privilege escalation if API exposed publicly |

---

## 5. Mitigations already in the codebase

These are real and verifiable. References are file paths.

| Mitigation | Where | Threat addressed |
|---|---|---|
| **Bearer token auth on all sensitive `/api/*` routes** | `src/security/web_security.py::TokenVerifier`, applied in `main.py` and `src/feedback/feedback_api.py` | S-TB6, E-TB6, T-TB6: feedback poisoning, account/credential takeover via dashboard |
| **`run_server()` defaults to 127.0.0.1; refuses non-loopback bind without token** | `main.py::run_server` | S-TB6: blocks accidental internet exposure |
| **SSRF guard on `/api/detonate-url`** | `src/security/web_security.py::SSRFGuard` | T-TB3, I-TB3: cloud-metadata / internal-network exfil via URL detonator |
| **Security headers middleware** (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy) | `src/security/web_security.py::SecurityHeadersMiddleware` | T-TB6, I-TB6: clickjacking, XSS amplification, MIME sniffing |
| Magic-byte attachment classification (not extension-based) | `src/extractors/attachment_handler.py` | T-TB2: spoofed extensions |
| Recursive archive depth limit | `src/extractors/attachment_handler.py` | D-TB2: zip bombs |
| Browser sandbox in dedicated container | `docker-compose.yml`, `Dockerfile` | E-TB3: container escape blast radius |
| Circuit breaker on every external API client | `src/analyzers/clients/base_client.py` | D-TB4, T-TB4: vendor failure / forged hostile responses |
| TTL cache + per-vendor rate limiting | `src/analyzers/clients/base_client.py` | D-TB4: rate limit exhaustion |
| Confidence capping → SUSPICIOUS when data sparse | `src/scoring/decision_engine.py:444` | T-TB2: low-evidence verdicts can't escalate to CONFIRMED |
| Override rules require *positive* corroboration | `src/scoring/decision_engine.py:264` | analyst-trust: CONFIRMED requires hash hit; LIKELY requires multi-vendor URL hit or BEC@>0.8 |
| Parameterized ORM queries | `src/feedback/database.py` | E-TB5: SQLi |
| Secrets via `.env` + secure vault, not hard-coded | `src/security/`, `config.py` | I-TB4: key exposure in repo |
| Graceful degradation when offline | every API client | D-TB4: pipeline doesn't fail hard on outage |

---

## 6. Residual risks (operator must accept or compensate)

Ordered by severity-given-likelihood. Each one is something the project deliberately does not solve.

### R1 — Feedback API authentication
**Severity:** high (was high). **Likelihood:** low (was high if exposed).
**Status: MITIGATED.**
**Description:** All state-changing and information-disclosing endpoints in `main.py` (`/api/feedback`, `/api/feedback/retrain`, `/api/accounts/*`, `/api/detonate-url`, `/api/diagnose`, `/api/system-status`, `/api/monitor/email/{id}`) now require a bearer token via `Depends(TokenVerifier)` from `src/security/web_security.py`. The same token (`ANALYST_API_TOKEN` env var) is enforced by the existing `src/feedback/feedback_api.py` router, so the perimeter is consistent across both code paths. Additionally, `run_server()` now defaults to `127.0.0.1` and **refuses to start** if the operator binds to a non-loopback host without setting `ANALYST_API_TOKEN`. Residual: HTML pages (`/`, `/monitor`, `/accounts`, `/dashboard`) are still loadable without auth — the API behind them is protected, but the templates load. Cookie/session auth for browser users is a roadmap item.

### R2 — Analyst is a single trust principal
**Severity:** high. **Likelihood:** low (depends on operator).
**Description:** No separation of duties between analysts. Any analyst can re-label any verdict. No audit trail of who labeled what.
**Compensating control:** treat the feedback DB as an audit artifact — back it up off-host. Run with a small, trusted analyst pool only.

### R3 — Sandbox is a real headless browser executing attacker URLs
**Severity:** high. **Likelihood:** medium.
**Description:** Even containerized, a Chromium 0-day in the renderer is a real exposure path. The container is the only isolation layer. **Additionally, the on-demand `/api/detonate-url` endpoint is a textbook SSRF primitive if unguarded** — an attacker could use the detonator to map internal networks or hit cloud metadata services (169.254.169.254).
**Compensating controls:**
- `/api/detonate-url` is now SSRF-guarded: every URL is DNS-resolved before fetching and refused if any resolved IP is in a private/loopback/link-local/CGNAT/multicast/IETF-reserved/cloud-metadata range. Implementation in `src/security/web_security.py::SSRFGuard`. Deny networks tested at `tests/unit/test_web_security.py`.
- Endpoint also requires bearer token (R1).
- The browser sandbox runs in a dedicated container per `docker-compose.yml`.
- Residual: a Chromium 0-day still owns the container. gVisor/Firecracker is on the deferred list.

### R4 — Third-party API keys are the project's attack surface for vendors
**Severity:** medium. **Likelihood:** low.
**Description:** Compromise of `.env` leaks VT/urlscan/AbuseIPDB/Hybrid Analysis keys. Vendor abuse → reputation + quota damage, not direct compromise of operator infrastructure.
**Compensating control:** secure vault is wired in, but `.env` is the fallback. Treat the host's filesystem as a secrets boundary.

### R5 — STIX/Sigma exports are not integrity-signed
**Severity:** medium. **Likelihood:** low.
**Description:** Exports are produced and then trusted by downstream consumers. There's no signing or chain-of-custody. A tampered export could insert false IOCs into someone else's blocklist.
**Compensating control:** transport the exports over signed channels (TAXII over mTLS, signed git commits, etc.). The exporter does not own this.

### R6 — Cold-start sender profiling
**Severity:** low. **Likelihood:** high on day one.
**Description:** `sender_profiling` has zero baseline on a new tenant. T1078 detection from header-clean compromised accounts is effectively absent until the baseline matures.
**Compensating control:** documented in ATT&CK mapping; not a security boundary issue, an evidence-completeness issue. Operator should not advertise T1078 coverage on a fresh deployment.

### R7 — Sandbox-aware / geo-gated phishing pages
**Severity:** low (single-target attacks, by definition). **Likelihood:** present in sophisticated kits.
**Description:** Attacker pages that fingerprint headless Chromium or geo-block the detonator's egress will render benign content. The pipeline trusts what it sees.
**Compensating control:** none in-pipeline. Mitigated by `url_reputation` historical hits if the URL is known.

### R8 — Polyglot / sandbox-evading attachments
**Severity:** low. **Likelihood:** rare in commodity, common in targeted.
**Description:** Files that pass magic-byte classification under one type and execute as another, or sleep-loop past sandbox timeout.
**Compensating control:** documented limitation. The override rule for known-malware hashes is the only certainty here.

### R9 — IMAP MTA upstream tampering with Authentication-Results
**Severity:** low. **Likelihood:** very low.
**Description:** The pipeline trusts whatever `Authentication-Results` header the operator's MTA produced. A compromised upstream MTA can lie.
**Compensating control:** trust-on-first-MTA is assumed. Operators integrating with hostile MTA chains should not.

---

## 7. Explicit non-goals

To prevent scope creep and to make the threat model honest:

- **The pipeline is not a mail filter.** It does not block, quarantine, or modify mail flow. Every output is advisory. An operator who wants a filter must wire the verdicts into their MTA themselves.
- **The pipeline is not a SOAR.** No automated remediation, no ticket creation, no user notification. Reports are generated; routing is the operator's job.
- **The pipeline is not an EDR.** Post-compromise activity (T1078 full, T1098, T1606, etc.) is out of scope. See ATT&CK mapping for the exact line.
- **The pipeline is not multi-tenant.** No namespace isolation between different customers' mailboxes. One operator, one trust domain.
- **The pipeline does not perform takedowns.** It identifies infrastructure; it does not act against it.

---

## 8. How to use this document

- **Before deployment:** read §6 in full. Each residual risk is a deployment decision, not a code bug.
- **During incident response:** §3 (data flow) + `docs/MITRE_ATTACK_MAPPING.md` together tell you what the pipeline saw and where it might be blind.
- **When adding analyzers:** add a row to the STRIDE table (§4) and the ATT&CK matrix. If the new analyzer crosses a new trust boundary, add a TB.
- **When reviewing a PR that touches scoring:** the override rules (§5) are load-bearing for analyst trust. Changes there should reference R2 in the PR description.

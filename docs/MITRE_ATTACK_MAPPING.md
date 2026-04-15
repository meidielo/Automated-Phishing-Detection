# MITRE ATT&CK Coverage

This document maps each analyzer in the pipeline to the MITRE ATT&CK techniques it is designed to detect, plus an honest accounting of what it does **not** catch. The goal is to make defensive coverage legible to a SOC reader who already thinks in ATT&CK terms, and to force scope honesty on the project itself.

ATT&CK references are to the Enterprise matrix (v14+). All techniques cited live under the **Initial Access**, **Resource Development**, **Execution**, and **Impact** tactics, with one **Defense Evasion** sub-technique surfaced by the URL detonator.

## TL;DR coverage matrix

The **Pipeline key** column is the analyzer name as it appears on `PipelineResult.analyzer_results` and in the `--format json` output. Use this column when writing detection content (Sigma rules, dashboards, alert routing) that consumes pipeline output. The **Source file** column is for reading the implementation.

| Pipeline key           | Source file (`src/`)                | Primary techniques                                 | Secondary / supporting                    | Tactic                                          |
| ---------------------- | ----------------------------------- | -------------------------------------------------- | ----------------------------------------- | ----------------------------------------------- |
| `header_analysis`      | `extractors/header_analyzer.py`     | T1566.001, T1566.002, T1656                        | T1585.002, T1598.002, T1598.003           | Initial Access, Resource Development            |
| `url_reputation`       | `analyzers/url_reputation.py`       | T1566.002, T1204.001                               | T1583.001, T1583.004                      | Initial Access, User Execution                  |
| `domain_intelligence`  | `analyzers/domain_intel.py`         | T1583.001, T1584.001                               | T1566.002                                 | Resource Development                            |
| `url_detonation`       | `analyzers/url_detonator.py`        | T1566.002, T1204.001, T1027.006 (HTML smuggling)   | T1036.005 (masquerading via redirect)     | Initial Access, User Execution, Defense Evasion |
| `brand_impersonation`  | `analyzers/brand_impersonation.py`  | T1656, T1036.005                                   | T1566.002                                 | Defense Evasion (Impersonation)                 |
| `nlp_intent`           | `analyzers/nlp_intent.py`           | T1534 (Internal Spearphishing), T1656              | T1566.003 (Spearphishing via Service)     | Lateral Movement, Initial Access                |
| `sender_profiling`     | `analyzers/sender_profiling.py`     | T1078 (Valid Accounts) — anomaly signal            | T1534                                     | Initial Access, Lateral Movement                |
| `attachment_analysis`  | `analyzers/attachment_sandbox.py` + `extractors/attachment_handler.py` | T1566.001, T1204.002 | T1027 (Obfuscated Files), T1218 (LOLBins) | Initial Access, User Execution                  |
| *(extractor, no result key)* | `extractors/qr_decoder.py`    | T1566.002 (quishing)                               | T1204.001                                 | Initial Access, User Execution                  |

Note: the key **`domain_intelligence`** (with the full word) is the orchestrator's canonical key, even though the source file is `domain_intel.py` and the analyzer's internal `analyzer_name` field is `"domain_intel"`. The orchestrator's dict-key is what propagates into reports and detection content. Same story for `attachment_analysis` vs source file `attachment_sandbox.py`.

The pipeline is purpose-built for **TA0001 Initial Access via T1566 Phishing**. It does not pretend to detect post-compromise behavior — that's an EDR/SIEM job, not an email analysis job.

---

## Per-analyzer detail

### Header analyzer — `src/extractors/header_analyzer.py`

**Techniques detected**
- **T1566.001 — Spearphishing Attachment**: SPF/DKIM/DMARC failure on a message carrying an attachment is a high-fidelity precursor signal. The analyzer reports the auth triple and flags display-name spoofing and `From`/`Reply-To` mismatch (see `HeaderAnalysisDetail` in `src/models.py:120`).
- **T1566.002 — Spearphishing Link**: Same auth triple, weighted differently when the body carries URLs.
- **T1656 — Impersonation**: Display-name spoofing (`display_name_spoofing` flag) and envelope-from mismatch (`envelope_from_mismatch`) are the two primary impersonation signals derivable from headers alone.
- **T1585.002 — Establish Accounts: Email Accounts**: Indirectly — newly registered free-mail senders combined with auth failure imply throwaway sender infrastructure. Surfaced via `domain_intel` enrichment, not headers in isolation.
- **T1598.002 / .003 — Phishing for Information (Attachment / Link)**: Same code path as T1566 but distinguished downstream by intent classification.

**What it does not catch**
- Auth-passing phishing from compromised legitimate accounts (T1078 Valid Accounts via legitimate mailbox). Headers will look clean. The `sender_profiling` analyzer's behavioral baseline is the only signal here, and it requires a populated baseline.
- Header tampering by upstream MTAs that rewrite `Authentication-Results`. Trust-on-first-MTA is assumed.

### URL reputation — `src/analyzers/url_reputation.py`

**Techniques detected**
- **T1566.002 — Spearphishing Link**: Multi-vendor URL reputation via VirusTotal, urlscan.io, Google Safe Browsing. Override rule fires at `risk_score > 0.3` (`src/scoring/decision_engine.py:330`).
- **T1204.001 — User Execution: Malicious Link**: Same primitive — flagging the link the user would click.
- **T1583.001 / T1583.004 — Acquire Infrastructure: Domains / Server**: Cross-correlated via `domain_intel`. Reputation hits on freshly registered or low-reputation infrastructure are weighted higher.

**What it does not catch**
- Zero-day phishing URLs not yet in any feed. The detonator is the second layer for this case.
- Legitimate site compromise (watering hole / T1189) — the URL is on a clean reputation feed but the page is malicious. Detonator + visual similarity is the only safety net.

### Domain intel — `src/analyzers/domain_intel.py`

**Techniques detected**
- **T1583.001 — Acquire Infrastructure: Domains**: WHOIS age (newly registered ≤ N days), DNS history thinness, and presence on phishing feeds.
- **T1584.001 — Compromise Infrastructure: Domains**: Detected indirectly when a long-aged domain suddenly appears on phishing feeds — handled by `url_reputation` cross-checking, not WHOIS alone.

**What it does not catch**
- Aged domains pre-purchased and parked specifically to defeat WHOIS-age heuristics. This is a real and documented evasion. The visual similarity analyzer is the second line.
- Subdomain takeover scenarios (T1583.001 variant). The pipeline scores the apex domain's reputation, which can be clean.

### URL detonator — `src/analyzers/url_detonator.py`

**Techniques detected**
- **T1566.002 — Spearphishing Link**: Headless-browser detonation captures the actual landing page.
- **T1204.001 — User Execution: Malicious Link**: Detonator follows the redirect chain and screenshots the terminal page — this is the closest the pipeline gets to simulating user execution.
- **T1027.006 — Obfuscated Files or Information: HTML Smuggling**: Detected when a fetched page assembles a download via JavaScript/blob URLs at runtime. The detonator's network capture catches the smuggled payload that static URL reputation cannot.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: Final landing URL frequently masquerades as a known brand path (`/login`, `/auth/sso`). Visual similarity (next analyzer) closes this loop.

**What it does not catch**
- CAPTCHA-gated phishing pages that detect headless browsers and serve benign content.
- Geo-fenced or referrer-checked pages that only render for the targeted user's region/source.
- Time-of-click attacks where the URL is benign at scan time and weaponized later. (Mitigated partially by re-scanning.)

### Brand impersonation — `src/analyzers/brand_impersonation.py`

**Techniques detected**
- **T1656 — Impersonation**: Visual similarity (perceptual hash + SSIM) of detonator screenshots against a configured set of brand reference images.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: Logo-level masquerading. Pairs with header-level display name spoofing for full coverage.

**What it does not catch**
- Brands not in `brand_references/`. Coverage is a literal whitelist of what's loaded.
- Text-only phishing with no visual brand mark.
- Attacks against custom internal-only brands unless the operator has loaded references.

### NLP intent — `src/analyzers/nlp_intent.py`

**Techniques detected**
- **T1534 — Internal Spearphishing**: BEC and wire-fraud intent classification (`IntentCategory.BEC_WIRE_FRAUD` in `src/models.py:38`). High-confidence BEC is an override rule that forces minimum LIKELY_PHISHING regardless of weighted score (`decision_engine.py:280`).
- **T1656 — Impersonation**: Intent classifier picks up "I'm the CEO and need a favor" framing that header analysis would miss when the sender is a legitimate but spoofed display name.
- **T1566.003 — Spearphishing via Service**: Some social-engineering framings (gift card scams, extortion) map here when the lure is non-link, non-attachment. The `IntentCategory.GIFT_CARD_SCAM` and `EXTORTION` enum values exist for this case.

**What it does not catch**
- Intent classification is a probabilistic LLM signal. False positives on legitimate urgent business email (legal, finance) are an accepted cost — this is why the BEC override requires confidence > 0.8.
- Without an LLM key, the sklearn fallback runs at substantially lower accuracy. See `Known Limitations` in README.

### Sender profiling — `src/analyzers/sender_profiling.py`

**Techniques detected**
- **T1078 — Valid Accounts** (anomaly signal only): Behavioral baseline divergence — never-seen sender, unusual hour, sudden language switch — is the only header-clean signal the pipeline has against compromised legitimate accounts.
- **T1534 — Internal Spearphishing**: Same primitive applied to internal senders.

**What it does not catch**
- Cold-start: new tenants have no baseline. Coverage is zero until the profiler accumulates traffic.
- This analyzer is **not in the active scoring weights** (`config.yaml` has `sender_profiling: 0.00` as of cycle 12). Its risk score feeds `_is_clean_email` as a negative override only. Treat its T1078 coverage as advisory, not detective. On cold-start senders (email_count < 3) the analyzer returns `risk_score=0.0, confidence=0.0` so it neither dilutes the weighted score nor blocks the CLEAN override via a spurious "no data" signal — see `src/analyzers/sender_profiling.py` and the cycle 12 commit for the root-cause trace.

### Attachment sandbox + handler — `src/analyzers/attachment_sandbox.py`, `src/extractors/attachment_handler.py`

**Techniques detected**
- **T1566.001 — Spearphishing Attachment**: Magic-byte file classification, macro detection on Office docs, recursive archive expansion, hash lookup against known-malware feeds. Override rule fires on a known-malware hash and forces CONFIRMED_PHISHING (`decision_engine.py:267`).
- **T1204.002 — User Execution: Malicious File**: Same primitive — what the user would double-click.
- **T1027 — Obfuscated Files or Information**: Macro-bearing documents and password-protected archives are surfaced as obfuscation signals before sandbox detonation.
- **T1218 — System Binary Proxy Execution (LOLBins)**: Indirect — sandbox provider reports (Hybrid Analysis, etc.) flag LOLBin chains in the detonation report. Pipeline treats this as a generic "malicious" signal, not LOLBin-specific.

**What it does not catch**
- Sandbox evasion (sleep loops, VM detection, environment fingerprinting). The pipeline trusts the sandbox provider's verdict.
- Polyglot files that pass magic-byte classification as one type and execute as another.
- Latency: 2–10 minutes per file (per README known limitations §6) means the pipeline default 120s timeout will skip sandboxing on large attachments.

### QR decoder — `src/extractors/qr_decoder.py`

**Techniques detected**
- **T1566.002 — Spearphishing Link** ("quishing"): QR-embedded URLs in inline images, PDFs, and rendered HTML are extracted and fed through the URL reputation + detonation pipeline. The `URLSource` enum has dedicated values (`QR_CODE`, `QR_CODE_PDF`, `QR_CODE_DOCX`, `QR_CODE_HTML_RENDERED` in `src/models.py:18`) so downstream analyzers and reports can distinguish quishing.
- **T1204.001 — User Execution: Malicious Link**: A QR code is the highest-friction-to-detect form of T1204.001 because most scanners and gateways don't OCR images.

**What it does not catch**
- Animated / multi-frame QR (`pyzbar` is single-frame).
- QR encoded inside heavily styled inline SVG with text-as-path glyphs the decoder can't rasterize.

---

## Coverage gaps the pipeline acknowledges

These are the techniques an honest reader will ask about. The pipeline does not claim to detect them:

| Technique                                       | Why uncovered                                              | Compensating signal (if any)                  |
| ----------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------- |
| T1078 Valid Accounts (full)                     | Compromised mailbox produces auth-clean mail               | `sender_profiling` baseline (advisory only)   |
| T1189 Drive-by Compromise                       | Out of scope — not email-borne                             | None                                          |
| T1566.003 Spearphishing via Service (full)      | LinkedIn/Twitter DMs aren't ingested                       | Partial — NLP intent on forwarded mail        |
| T1606 Forge Web Credentials                     | Post-compromise                                            | None                                          |
| T1098 Account Manipulation                      | Post-compromise                                            | None                                          |
| Sandbox evasion (T1497)                         | Trust in upstream sandbox provider                         | None                                          |
| Geo-fenced / CAPTCHA-gated phishing             | Detonator runs from a single egress, headless              | None — known limitation                       |

---

## How to use this document

- **For SOC integration**: take the coverage matrix and feed it to your detection engineering team alongside the Sigma rules in `sigma_rules/`. The mapping tells them where this pipeline complements their existing T1566 coverage and where it doesn't.
- **For threat modeling**: pair this with `THREAT_MODEL.md`. The "uncovered techniques" table above is intentionally also the "residual risks" section of the threat model.
- **For honest portfolio framing**: the coverage table is deliberately small. A pipeline that claims to cover 40 techniques is lying. This one covers ~12 sub-techniques across 3 tactics, well.

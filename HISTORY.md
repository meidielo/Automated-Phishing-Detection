# Project History

This file is the 90-second skim of the project's evolution. If you are a reviewer, hiring manager, or future-me coming back after a long pause, read this first.

## Arc summary

The project began as a working phishing detection pipeline with a foundation problem: an external audit identified 21 findings including 7 P0 security and correctness items, and the project's detection metrics rested on code that didn't actually do what the docs claimed. Over **8 cycles** following a strict TEST → AUDIT → UPDATE → COMMIT → FINAL TEST → PUSH → AUDIT loop, every P0 was closed and 9 of 11 P1 items were resolved, with **non-obvious design decisions captured in ADRs before any code was written**. The test suite grew from 676 to 899 (zero regressions across the arc), CI was added and verified to bite via a deliberately-red sanity branch, the threat model was made honest, and detection content (MITRE ATT&CK mapping, Sigma rules, STIX exports) was added to make the project legible as detection engineering rather than a Python classifier.

This file is the index. Each cycle has a one-paragraph summary, the commit hash, the audit items closed, the test delta, and any findings discovered-and-deferred.

## How to read the cycles

Every cycle followed the same workflow:

1. **TEST** — baseline pytest run before any change
2. **AUDIT** — sweep for outdated docs, test-vs-code drift, missing coverage on the changed surface area, related items the change should bring in
3. **UPDATE** — the actual code, docs, and test changes for the cycle
4. **COMMIT** — single focused commit with a detailed message that explains both what landed and what was discovered-and-deferred
5. **FINAL TEST** — full pytest after the changes
6. **PUSH** — to `origin/main`
7. **POST-PUSH AUDIT** — verify CI green, sweep for anything the cycle's writeup missed

Discovered-and-deferred findings are deliberately not silently fixed in scope creep. They go to ROADMAP and become their own future cycle. This is how cycle 6 produced the BEC ordering bug that became cycle 7's headline fix.

ADRs (`docs/adr/`) are written **before any code** for any cycle whose design has a non-obvious decision. The ADR's job is to surface the hard call to the front where it's cheap to change. Two ADRs exist as of cycle 8: ADR 0001 (cross-analyzer calibration, cycle 6) and ADR 0002 (persistent email_id lookup, cycle 8).

---

## Cycle 1 — Reframe as detection engineering

- **Commit:** [`adcd9db`](https://github.com/meidielo/Automated-Phishing-Detection/commit/adcd9db) (2026-04-14)
- **Tests:** 676 → 710 (+34)
- **Audit items closed:** none directly (this was the framing cycle)

The project shipped working code but lacked the artifacts that make a phishing detector legible as **detection engineering**. Cycle 1 added the missing layer: per-analyzer ATT&CK technique mapping with explicit gaps (`docs/MITRE_ATTACK_MAPPING.md`), a STRIDE-per-trust-boundary threat model (`THREAT_MODEL.md`), security disclosure policy (`SECURITY.md`), and a hand-emitted Sigma rule exporter (`src/reporting/sigma_exporter.py`) plus a static rule library covering visual brand impersonation, quishing, newly registered domains, BEC, HTML smuggling, and auth-fail-with-attachment. Wired `--format sigma` and `--format all` into `main.py`.

Cycle 1 also fixed a pre-existing test failure in `test_attachment_sandbox` (the test was the spec; the code had drifted) and an analyzer-key drift caught during the audit pass — `ANALYZER_ATTACK_TAGS` was using per-file `analyzer_name` strings instead of the orchestrator's canonical dict keys.

**Discovered-and-deferred:** none.

---

## Cycle 2 — Harden the web perimeter (P0 wave)

- **Commit:** [`9b5fa65`](https://github.com/meidielo/Automated-Phishing-Detection/commit/9b5fa65) (2026-04-14)
- **Tests:** 710 → 753 (+43)
- **Audit items closed:** P0 #1 (unauth dashboard), P0 #2 (SSRF in `/api/detonate-url`), P0 #3 (model poisoning via `/api/feedback`), P0 #7 (no security headers), #16 (`analyst_api_token` wired)

The audit found that every state-changing and info-disclosing `/api/*` route in `main.py` was unauthenticated, that `/api/detonate-url` had a textbook Capital-One-class SSRF, and that the security headers were missing entirely. Cycle 2 shipped `src/security/web_security.py` with three independent pieces:

1. **`TokenVerifier`** as a FastAPI dependency, bearer-token-checked against `ANALYST_API_TOKEN`. Mirrored the existing enforcement in `src/feedback/feedback_api.py` so one token protects both code paths.
2. **`SSRFGuard`** that DNS-resolves URLs and refuses any IP in 17 deny networks (RFC1918, loopback v4/v6, link-local incl. cloud metadata 169.254.169.254, CGNAT, IETF reserved, multicast). Catches the textbook `localhost → 127.0.0.1` hostname trick.
3. **`SecurityHeadersMiddleware`** attaching CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, HSTS, Permissions-Policy.

Plus: `run_server()` defaults to 127.0.0.1 and **refuses to start** if bound to a non-loopback address without `ANALYST_API_TOKEN` set. THREAT_MODEL R1 marked MITIGATED, R3 updated with SSRF coverage. The bearer auth pattern includes a CSRF trigger checklist as a durable contract in the auth module's docstring — any future cookie/session auth PR is blocked until CSRF protection ships in the same commit.

**Discovered-and-deferred:** none.

---

## Cycle 3 — Session leak + docker docs honesty

- **Commit:** [`c1ef962`](https://github.com/meidielo/Automated-Phishing-Detection/commit/c1ef962) (2026-04-14)
- **Tests:** 753 (no delta — both fixes were observed-vs-documented corrections)
- **Audit items closed:** P1 #8 (session leak in CLI analyze), P1 #17 (docker-compose docs lied)

`PhishingPipeline.close()` existed but `analyze_email_file()` never called it, leaking aiohttp sessions on every single-shot CLI run. Wrapped the analyze call in try/finally. README and THREAT_MODEL claimed `docker-compose` ran three services (orchestrator + browser-sandbox + redis) but `docker-compose.yml` only defined `orchestrator`. Fixed both docs to describe the actual single-container layout, added the multi-container split as a tracked ROADMAP item.

**Discovered-and-deferred:** none.

---

## Cycle 4 — Detection correctness + LLM determinism

- **Commit:** [`8c1c3d2`](https://github.com/meidielo/Automated-Phishing-Detection/commit/8c1c3d2) (2026-04-14)
- **Tests:** 753 → 826 (+73: 11 url_reputation + 40 html_sanitizer + 12 multi_account_monitor + 10 anthropic_client)
- **Audit items closed:** #11 (dead-domain confidence inflation), #5 (stored XSS via `body_html`), #4 ALREADY-DONE (credential encryption was already AES-256-GCM + Argon2id; the audit was wrong but the migration path needed regression coverage), #13 (LLM determinism completion)

Four detection-correctness fixes in one cycle:

- **#11**: `url_reputation` was inflating "no threats found from a non-resolving domain" as 0.8-confidence evidence of safety, suppressing phishing scores by ~15 points across the corpus. Added `_hostname_resolves` and a confidence downgrade to 0.3 when the URL hostname doesn't resolve AND no service flagged it. **Verified the fix is in code, not just documented.**
- **#5**: `body_html` was rendered in an iframe with `sandbox="allow-same-origin"` (the worst possible flag combination). Switched to `<iframe sandbox srcdoc>` with **no allow flags** — the iframe is now its own opaque origin. Server-side bleach sanitization in `src/security/html_sanitizer.py` strips `<script>`/`<style>` content (not just tags), `on*` handlers, `javascript:`/`data:`/`vbscript:` URLs. 40 hostile-payload tests cover script tag, event handlers, SVG-namespace JS, javascript: URLs, data: URIs, meta refresh, style expression(), HTML5 parser quirks.
- **#4 verified**: `src/security/credentials.py` already implemented AES-256-GCM + Argon2id with auto-migration of legacy plaintext on every load. The audit was wrong on this — added 12 regression tests including the strongest property: no plaintext value remains grep-able from the file after migration.
- **#13**: `top_p=1` pinned alongside `temperature=0` in `AnthropicLLMClient`. Return type evolved to `LLMResponse(text, model_id)` NamedTuple. `model_id` captured from the API's actual response (not the configured request) and threaded into `AnalyzerResult.details["llm_model_version"]` so a future Haiku point release that shifts verdict distributions becomes detectable from JSON output.

**Discovered-and-deferred:** none.

---

## Cycle 5 — Supply-chain + privacy + Docker hygiene

- **Commit:** [`36b1a83`](https://github.com/meidielo/Automated-Phishing-Detection/commit/36b1a83) (2026-04-14)
- **Tests:** 826 → 843 (+17 retention)
- **Audit items closed:** #14 (unpinned dependencies), #15 (no retention/purge for `data/results.jsonl`), #18 (curl in Dockerfile healthcheck), #19 (bind-mount UID mismatch)

Four hygiene items, one of which (#14) was reframed from P2 to P1 mid-audit because pinning dependencies in a security tool is a P1 control, not hygiene.

- **#14**: Generated `requirements.lock` (2423 lines, hash-pinned) via `uv pip compile --generate-hashes`. Dockerfile installs with `pip install --require-hashes -r requirements.lock`. New `.github/workflows/ci.yml` with three jobs: full pytest on fresh Ubuntu checkout (the cycle-4-meta "test on a fresh box" gate), flake8 lint, daily `pip-audit` against the lock file. **CI green on first run** — no test was depending on a local environment quirk.
- **#15**: `src/automation/retention.py` with atomic-swap purge primitive (17 tests including the post-purge invariant that no row remains older than the cutoff). New `python main.py purge --older-than N --strict --dry-run` subcommand. New `PipelineConfig.data_retention_days` (default 30). THREAT_MODEL §6a "Privacy exposure" added as a separate risk class from security with a per-risk table covering Privacy Act / GDPR exposure, lawful basis, and right to erasure.
- **#18**: HEALTHCHECK switched from `curl -sf` to `python -c "import urllib.request..."`. Dropped curl from apt-get install.
- **#19**: New `docker-entrypoint.sh` runs as root briefly, chowns `/app/data` and `/app/logs` to UID 1000, then `gosu phishing` exec's CMD. `ENTRYPOINT_SKIP_CHOWN=1` escape hatch for Docker Desktop on Mac/Windows. Closes the silent-fail-on-Linux bind-mount issue.

**Discovered-and-deferred:** none.

---

## Cycle 6 — Cross-analyzer calibration (LinkedIn FP closed)

- **Commit:** [`695621f`](https://github.com/meidielo/Automated-Phishing-Detection/commit/695621f) (2026-04-14)
- **Tests:** 843 → 872 (+29 calibration)
- **Audit items closed:** #12 (LinkedIn FP that survived 4 cycles)
- **ADR:** [`0001-cross-analyzer-context-passing.md`](docs/adr/0001-cross-analyzer-context-passing.md)

The most important architectural change in the project. The motivating bug from `lessons-learned.md`: legitimate LinkedIn engagement notifications scored high on `nlp_intent` (correct in isolation — the language is ambiguous) and low on every other signal (correct in isolation — the email is auth-passing). Single-pass scoring averaged these into a SUSPICIOUS verdict that was the wrong answer. Three earlier fixes (NLP allowlist, threshold raise, NLP retrain) had been considered and rejected.

**ADR 0001 was written before any code.** It resolved the dampen-vs-corroborate question explicitly: corroboration, not multiplication. "Why 50%?" is undefendable; "I require an independent corroborating signal" is. The ADR documented three failure modes upfront (FM1: dumping ground → 10-rule cap enforced by test; FM2: masks analyzer regressions → calibrated/uncalibrated visibility; FM3: allowlist maintenance burden → date-stamped single file with quarterly review).

Implementation: `src/scoring/calibration.py` with `CalibrationOutcome`, `apply_calibration_rules()`, and one rule (`linkedin_social_platform_corroboration`) that fires only when ALL FIVE conditions hold: SPF+DKIM+DMARC pass, From: domain on allowlist, NLP risk ≥ 0.7 with conf ≥ 0.5, AND no other analyzer reports independent risk ≥ 0.5/0.5. The cap is SUSPICIOUS — the underlying weighted score is preserved so a reviewer can still see the NLP signal in `PipelineResult.overall_score`.

29 new tests including 6 table-driven rows (LinkedIn digest positive, typo-squat negative, corroboration-lifts-cap negative, BEC-from-non-allowlisted negative, subdomain-match positive, NLP-too-low negative), 4 end-to-end DecisionEngine integration tests, registry constraint tests (10-rule cap enforced by test), and a defensive "buggy rule must not break apply" test.

**Discovered-and-deferred:** **NEW-1** — `_check_override_rules` evaluated `_is_clean_email` BEFORE `_is_bec_threat`. A pure-text BEC email with passing auth, no URLs, no attachments matches `_is_clean_email`'s preconditions and gets force-marked CLEAN before the BEC override runs. Real BEC samples in `tests/real_world_samples/` slipped through this hole only because they happened to carry at least one URL. Load-bearing accident. **Deferred to cycle 7** rather than swallowed into cycle 6 scope.

---

## Cycle 7 — NEW-1 + cap ceiling lock + CI bites verify

- **Commit:** [`e6a0a3f`](https://github.com/meidielo/Automated-Phishing-Detection/commit/e6a0a3f) (2026-04-15)
- **Tests:** 872 → 879 (+4 NEW-1 regression + 3 cap ceiling)
- **Audit items closed:** NEW-1 (BEC ordering bug from cycle 6 discovery), cap-ceiling lock, CI-bites verification

Three small focused items. The cycle 6 review correctly elevated NEW-1 to P0-adjacent because it invalidated the BEC detection claim — any future pure-text BEC would be silently marked CLEAN.

- **NEW-1 fix**: `_check_override_rules` reordered so `_is_bec_threat` runs **before** `_is_clean_email`. The simpler of two options (the alternative was excluding `bec_wire_fraud` intent from `_is_clean_email`). Smoking-gun regression test in `tests/unit/test_decision_engine_override_ordering.py::test_pure_text_bec_becomes_likely_phishing` — explicitly uses `url_count=0` and `attachment_count=0`. The 24 existing decision_engine tests passed unchanged, proving no test was depending on the buggy ordering.
- **Cap ceiling lock**: 3 tests under `TestCalibrationCapCeiling` lock the SUSPICIOUS-not-CLEAN semantic. The defensible scenario: a real LinkedIn notification with an embedded malicious redirect (LinkedIn tracking URLs have been abused as open redirects in the wild) where `url_reputation` is below the corroboration threshold — calibration still fires but the verdict caps at SUSPICIOUS so the analyst still reviews. ADR 0001 gained a "Why the cap is SUSPICIOUS and not CLEAN" section that cites the locking tests by name.
- **CI bites verification**: pushed a throwaway branch `ci-sanity-check-delete-me` with `assert False` in a new test, opened draft PR #1 (workflow only triggers on `pull_request` to main), watched CI fail loudly. Run id `24403600695` shows the test job FAILED while lint and pip-audit independently SUCCEEDED — proving each gate is independent and bites on its own. PR closed without merge, branch deleted. The "two cycles green = converging or blind spot" concern is now resolved with positive signal.

**Discovered-and-deferred:** none.

---

## Cycle 8 — Persistent email_id lookup (audit #9)

- **Commit:** [`eed7e98`](https://github.com/meidielo/Automated-Phishing-Detection/commit/eed7e98) (2026-04-15)
- **Tests:** 879 → 899 (+20 email_lookup)
- **Audit items closed:** #9 (`_upload_results` 200-cap + restart bug)
- **ADR:** [`0002-persistent-email-id-lookup-for-feedback.md`](docs/adr/0002-persistent-email-id-lookup-for-feedback.md)

The feedback endpoint resolved `email_id → sender` by walking `_upload_results` in reverse — an in-memory list capped at 200 and wiped on restart. Three lookup sites all silently no-op'd after restart or after the 200-cap roll. The endpoint returned HTTP 200 with `actions_taken: []` and the analyst had no way to tell the action was lost.

**ADR 0002 was written before any code.** It split the problem along the cycle-7-reviewer-suggested display-vs-lookup axis: display stays in-memory at 200 (right shape for "render the last 50 uploads"), lookup moves to a persistent index over the existing `data/results.jsonl` (right shape for "find any email since project start"). Three storage options compared with the sidecar JSONL pattern explicitly REJECTED in writing because it creates a drift surface, not because it duplicates data. Five failure modes documented (FM1 staleness window → stat-and-reload retry, FM2 partial-write → walker skips garbage, FM3 retention purge → index `invalidate()` after swap, FM4 concurrent writers → same stat-and-reload mechanism, FM5 memory growth → bounded by retention purge).

Implementation: `src/feedback/email_lookup.py` with thread-safe `EmailLookupIndex` storing `email_id → byte_offset` (~80 bytes per entry, memory bounded by entry count not record size). 20 tests including the smoking gun `test_blocklist_mutation_succeeds_on_pre_restart_email` and the 250-upload property test that proves all records are findable after restart. `purge_results_jsonl` gained an optional `index=` parameter that calls `invalidate()` after the atomic swap. `ci.yml` gained the cycle-7-reviewer-suggested comment explaining why no `push:` trigger for non-main branches, citing the cycle 7 sanity check run id for durability.

**No migration script needed.** Existing `data/results.jsonl` files from prior runs are valid input — the rebuild walker reads them at startup the same way it'd read a freshly-created file.

**Discovered-and-deferred:** none.

---

## What's open

| ID | Severity | Item | Plan |
|---|---|---|---|
| #10 | P1 (originally tier; arguably P2) | Three duplicate API diagnostic implementations: `diagnose_apis.py`, `test_apis.py`, `/api/diagnose`. Maintenance debt, not a correctness issue. | Refactor into one shared implementation under `src/diagnostics/`. Cycle 10 first-hour task before the bigger eval-harness work. |
| #20 | P2 | `templates/report.html` is a 600-line standalone Jinja report; check whether the dashboard modal in `monitor.html` has replaced it and delete if so. | Cycle 11+ |
| #21 | P2 | Legacy CLI flags `--analyze` and `--serve` with `argparse.SUPPRESS`. Pick a deprecation date; remove. | Cycle 11+ |
| #22 | P2 | Inline JS/CSS in `monitor.html` and `dashboard.html`. CSP would benefit from moving JS to `static/js/*.js` so `script-src 'self'` is enforceable. | Cycle 11+ |
| #23 | P2 | `.gitignore` patterns for `*_SUMMARY.md`, `*_GUIDE.md`, etc. suggest throwaway-doc accumulation. Periodic local cleanup. | Cycle 11+ |

Plus the next cycle's planned work (cycle 10):

- **Real eval harness** against Nazario, PhishTank, and Enron-ham corpora producing actual precision/recall/F1 numbers per verdict and per analyzer. The lightweight `scripts/compare_runs.py` from cycle 6 is an offline diff tool, not the harness `docs/EVALUATION.md` describes. Cycle 10's full-day swing.

## What's in the writeup queue

These are draft writeups in `docs/writeups/` whose context is freshest now:

- **`nlp-nondeterminism.md`** — why `temperature=1` silently destroyed test metrics for three cycles before being caught (cycle 4's #13 fix). Useful blog-post-shaped artifact.
- **`calibration-rule-patterns.md`** — the dampen-vs-corroborate decision from ADR 0001 as a pattern comparison. Useful for senior-engineer audiences thinking about the same design space.

## Counters

| Metric | Pre-cycle 1 | Cycle 8 |
|---|---|---|
| Tests | 676 (1 failing) | **899 (0 failing)** |
| Test modules | 22 | **32** |
| ADRs | 0 | **2** |
| Audit P0s open | 7 | **0** |
| Audit P1s open | 11 | **2** |
| Audit P2s open | 4 | **4** |
| CI configured | no | **yes, verified to bite** |
| Threat model | implicit | **STRIDE per trust boundary, 9 residual risks documented** |
| Detection content exports | none | **STIX 2.1 + Sigma rules + ATT&CK mapping** |
| Dependency lock file | none | **hash-pinned, daily `pip-audit`** |
| Privacy posture | implicit | **GDPR-aware retention purge with `--dry-run`** |

## How to use this file

- **Reviewer / hiring manager / interviewer:** read the arc summary at the top, the `What's open` table at the bottom, and any one cycle that interests you. The cycle commits are linked.
- **Future-me coming back after a pause:** the audit-items-closed column tells you what each cycle was actually for. The discovered-and-deferred entries explain why the next cycle exists.
- **Anyone proposing a new cycle:** add a section here when the cycle ships. The pattern is one paragraph + one fixed table of (commit, tests, audit items, ADR if any, discovered-and-deferred). Don't break the template; the template is the artifact.

# Contributing

This file is the project-local conventions guide. The patterns here are the result of seven cycles of audit-driven refactoring (see [`HISTORY.md`](HISTORY.md)). They exist for reasons that are documented either in this file or in the linked artifact. Don't break them without reading the reason.

## Workflow

Every code change follows the same loop:

1. **TEST** — run the full pytest suite first to know the baseline state
2. **AUDIT** — sweep for outdated docs, test/code drift, missing coverage on the changed surface area
3. **UPDATE** — make the change. Add/update tests, docs, ROADMAP entries, MITRE mapping, threat model — whatever is downstream of the change
4. **COMMIT** — one focused commit with a detailed message
5. **FINAL TEST** — re-run the full pytest after the change
6. **PUSH** — to a feature branch or directly to `main` as appropriate
7. **POST-PUSH AUDIT** — verify CI green, sweep again for anything missed

This is not optional discipline; it's why the test suite went 676 → 899 with zero regressions across 8 cycles.

## ADR-first for non-obvious design decisions

If a change has a design question whose answer is not obvious from the code, write an ADR before any code. The ADR's job is to surface the hard call to the front where it's cheap to change. The pattern that exists in the project today:

- ADRs live in `docs/adr/` numbered sequentially: `0001-cross-analyzer-context-passing.md`, `0002-persistent-email-id-lookup-for-feedback.md`, ...
- Each ADR has the sections: **Context**, **Decision**, **Options considered** (with rejected options listed and why), **Failure modes** (numbered FM1, FM2, ...), **Test strategy**, **Migration**, **Consequences**, **Open questions**.
- Reject the obvious-but-wrong patterns explicitly in writing, with the **drift surface** argument when applicable. "Creates two paths that can drift" is a stronger rejection than "duplicates data".
- The ADR is the source of truth for why the code is shaped the way it is. The code can carry comments referencing the ADR for durability.

ADR 0001 and ADR 0002 are the working examples. Read them before writing a third.

## Regression test naming

Tests that close a specific audit finding or bug must have names that **encode the bug, not the function under test**. The failure message is what someone sees in two years when a refactor breaks the test, and they need the full context from the test name alone.

Examples in this project:

| Test name | What it locks |
|---|---|
| `test_pure_text_bec_becomes_likely_phishing` | Cycle 7 NEW-1: BEC override must run before `_is_clean_email` |
| `test_blocklist_mutation_succeeds_on_pre_restart_email` | Cycle 8 audit #9: feedback lookup must survive restart |
| `test_cap_lowers_likely_phishing_to_suspicious` | Cycle 7: calibration cap is SUSPICIOUS, not CLEAN |
| `test_external_append_caught_on_lookup_miss` | Cycle 8 ADR 0002 FM4: stat-and-reload catches concurrent writers |
| `test_truncated_final_line_is_skipped` | Cycle 8 ADR 0002 FM2: partial-write crash tolerance |
| `test_blocks_hostname_resolving_to_loopback` | Cycle 2: SSRF guard catches `localhost → 127.0.0.1` bypass |

The pattern: `test_<observable_property>_<expected_behavior>`. **Not** `test_check_override_rules_step_3` (that name tells you nothing when it fails). The name is the bug report.

## Calibration rules (ADR 0001)

Adding a new pass-2 calibration rule requires:

1. A new function in `src/scoring/calibration.py` with a docstring containing **`Rule ID:`** (enforced by test).
2. The function appended to `REGISTRY`. The cap is **10 rules total**, enforced by `tests/unit/test_calibration.py::test_rule_registry_size_capped`.
3. At least one positive test row (rule fires) AND one negative test row (rule does not fire when conditions miss) in `tests/unit/test_calibration.py::TABLE`.
4. A new row in [`docs/calibration_rules.md`](docs/calibration_rules.md) with motivating sample, plain-English predicate, FP/FN it addresses, test row IDs, and a quarterly review date.

Calibration rules **never re-run analyzers**, **never call the network**, **never consume LLM tokens**, and **never modify the underlying weighted score**. They only modulate the verdict. See ADR 0001 for the full failure-mode list.

## Adding an analyzer

The orchestrator's analyzer name list is in `src/orchestrator/pipeline.py` (around line 321). The **canonical** analyzer name is the dict key the orchestrator uses, NOT the per-file `analyzer_name = "..."` string inside the analyzer module. Cycle 1 caught this drift and the convention is documented in [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md). When you add an analyzer:

- Its key in `ANALYZER_ATTACK_TAGS` (in `src/reporting/sigma_exporter.py`) must match the orchestrator key.
- A new row in [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md) with primary techniques, secondary techniques, and an explicit "what it does NOT catch" section.
- A row in [`THREAT_MODEL.md`](THREAT_MODEL.md) §4 STRIDE table if the analyzer crosses a new trust boundary.
- Tests covering the empty-input contract (no URLs, no attachments, etc. — analyzers must return `confidence=1.0` to vote clean rather than `confidence=0.0` to be skipped, where appropriate).

## Adding a state-changing API endpoint

All sensitive `/api/*` endpoints in `main.py` are bearer-token protected via `Depends(require_token)`. New state-changing endpoints must:

- Add `dependencies=[Depends(require_token)]` to the route decorator.
- If the endpoint accepts a URL for fetching, pass it through `default_ssrf_guard.assert_safe(url)` BEFORE any I/O.
- The CSRF trigger checklist in `src/security/web_security.py` module docstring is the contract: any future cookie/session auth PR is blocked until CSRF protection ships in the same commit.

## Sanitization for stored attacker content

Anything originating from an email body that gets rendered to a browser MUST go through `src/security/html_sanitizer.py::sanitize_email_html()` server-side AND be displayed in `<iframe sandbox srcdoc="...">` with **no allow flags**. The sandbox is the actual security boundary; the bleach sanitizer is defense in depth. See `THREAT_MODEL.md` R3.

## Discovered-and-deferred findings

If a cycle's investigation surfaces a bug or correctness issue that isn't strictly in scope, add it to [`ROADMAP.md`](ROADMAP.md) under "Planned" with a short note about which cycle discovered it and what the proposed fix is. **Do not silently fix it in scope creep.** Cycle 6's NEW-1 (BEC ordering bug) became cycle 7's headline fix because it was deferred properly.

The framing in cycle reports: never call a priority tier "done" until every item in it is closed. Two open P0s is two open P0s, not "P0 done except #4 and #5".

## Commit message shape

Commit messages on cycle commits should include:

- A clear one-line title with the cycle number and what it closes
- A paragraph explaining the motivating bug or finding
- Per-component sections describing what changed and why
- A "Tests" line with old-count → new-count and zero-regression confirmation
- A "Discovered and deferred" section if applicable
- Open audit items unchanged at the bottom (the framing rule)
- The Co-Authored-By trailer

The cycle commits in `git log` are the working examples. Match the shape.

## CI gates

CI runs on `pull_request: branches: [main]` only — not on every personal branch push (verified by cycle 7 sanity check, run id `24403600695`). To trigger CI for a feature branch, open a PR. The three independent jobs are: full pytest on fresh Ubuntu checkout, flake8 lint, daily `pip-audit` against `requirements.lock`. All three are blocking gates by default. Do not add `internal-be-careful-allow-failure: true` to the pip-audit step without an explicit time-bounded justification in the PR description.

## What this file is not

This is not a style guide. Use `flake8` for that (CI blocks on E9, F63, F7, F82). This is not a code-of-conduct. This is the conventions that emerged from real cycles and exist because something broke when they were absent.

# Security Policy

## Reporting a vulnerability

If you've found a security issue in this project, please **do not** open a public GitHub issue. Instead, report it privately so the fix can ship before the details are public.

**How to report:**
- Open a [private security advisory](https://github.com/Meidie/Automated-Phishing-Detection/security/advisories/new) on GitHub, or
- Email the maintainer with the subject line `SECURITY: phishing-detection` and a clear description.

**What to include:**
- Affected component (file path, analyzer name, or endpoint)
- Reproduction steps or a proof-of-concept payload (a sample `.eml` is ideal)
- Impact you observed and impact you believe is reachable
- Whether you've tested against `main` or a specific commit

**Response expectations:**
- Acknowledgement: within a few days
- Triage and severity assessment: shortly after acknowledgement
- Fix or mitigation: depends on severity; critical issues are prioritized
- Public disclosure: coordinated with the reporter once a fix is available

I'm a solo maintainer, not a vendor SOC. I'll do my best on response times but cannot commit to enterprise SLAs.

## Supported versions

This is a portfolio / research project. Only the `main` branch is supported. There are no LTS branches. Fixes are committed to `main`; users running older commits should rebase.

## Scope

### In scope

Vulnerabilities in any of these are in scope and welcome:

- **Parsers** — EML, MIME, attachment handlers, QR decoder, header parser. Crafted inputs that cause RCE, infinite loops, or memory exhaustion.
- **Analyzer pipeline** — race conditions, async deadlocks, SSRF via URL detonation, request smuggling against external APIs.
- **Scoring & override rules** — verdict bypasses where a malicious email reliably scores CLEAN, or where a benign email reliably scores CONFIRMED_PHISHING due to a logic flaw (not just a tunable false-positive).
- **Browser sandbox** — container escape, host filesystem access, host network egress that should be blocked.
- **Feedback API** — auth bypass, IDOR, SQL injection, label-poisoning attacks beyond the documented "no-auth-by-default" residual risk.
- **Secrets handling** — credentials leaking into logs, reports, STIX exports, dashboard responses, or git history.
- **Dependency-chain issues** — vulnerable pinned dependencies in `requirements.txt`.

### Out of scope

These are intentionally not security issues:

- **False positives or false negatives in detection.** The pipeline is probabilistic. Tuning is not a security report. (Exception: a *reliable, weaponizable* bypass of the override rules — that *is* in scope.)
- **Vendor-side issues.** If VirusTotal or urlscan returns a wrong answer, that's not this project's bug.
- **Sandbox-evading malware.** Documented limitation (`THREAT_MODEL.md` §6 R8). Bring a novel evasion against the parser or container, not against an upstream sandbox.
- **Self-DoS via giant attachments.** The handler has size limits; reports must demonstrate bypass of those limits.
- **Anything requiring physical access** to the host running the pipeline.
- **Social engineering of the maintainer.**

## Hardening guidance for operators

If you're running this in any non-laptop context, do at minimum:

1. **The server defaults to binding `127.0.0.1`** (loopback only). To expose it elsewhere, you must set `ANALYST_API_TOKEN` to a high-entropy value AND pass `--host <addr>` explicitly. The server refuses to start with a non-loopback host if the token is unset. For internet exposure, put it behind a reverse proxy with TLS termination.
2. **Use `/login` for browser dashboard access.** It sets a signed session cookie plus a CSRF cookie. API clients can still use `Authorization: Bearer <ANALYST_API_TOKEN>`.
3. **Treat `PUBLIC_DEMO_MODE=true` as sample-only.** It opens `/demo`, not the real dashboard, live upload analysis, mailbox monitoring, feedback learning, paid API-backed checks, or account management. Keep `ANALYST_API_TOKEN` configured.
4. **Treat `/app` public signup as a privacy switch.** Keep `SAAS_PUBLIC_SIGNUP_ENABLED=false` until you are ready to accept visitor email uploads, set a high-entropy `SAAS_SESSION_SECRET`, and have retention/support/abuse handling in place.
5. **Register Stripe webhooks only over HTTPS and keep `STRIPE_WEBHOOK_SECRET` secret.** `/api/stripe/webhook` verifies Stripe signatures before changing subscription state. Do not disable signature checks.
6. **Run the `browser-sandbox` container on its own Docker network.** Do not give it host networking. The default `docker-compose.yml` already separates it; verify before deploying.
7. **Treat `.env` as secret material.** Don't commit it. Don't bake it into images. Mount it at runtime.
8. **Back up runtime data and purge it on a schedule.** Results, alerts, feedback labels, sender profiles, and SaaS scan results can all contain regulated personal data. Use `python scripts/backup_runtime_data.py` for non-secret backups and `python main.py purge --target all --dry-run` before deleting rows.
9. **Monitor uptime and mailbox freshness.** Run `python scripts/production_health_check.py --require-monitor-running` from cron or an external monitor and send failures to a webhook.
10. **Monitor circuit-breaker state.** If every analyzer is open-circuit, the pipeline is effectively producing CLEAN verdicts on real phishing. Alert on this.
11. **Pin the brand reference set.** Treat `brand_references/` as detection content under change control. Anyone who can write to that directory can blind the visual similarity analyzer.

## Coordinated disclosure

I'm happy to coordinate disclosure timelines with reporters, credit researchers in release notes (or keep them anonymous, your call), and work with downstream consumers if a vulnerability affects their TI workflows.

If you've made a good-faith effort to report a vulnerability privately and haven't gotten a response, you're welcome to escalate by opening a GitHub issue that says only "I sent a security report, please check your inbox." Do not include details in the issue.

## Acknowledgements

Thanks to anyone who's reported issues responsibly. (None to acknowledge yet — be the first.)

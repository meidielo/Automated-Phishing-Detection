# Security Audit Notes - 2026-05-03

Scope: repository code, MCP/agent tool surfaces, SaaS auth and billing routes,
Docker production deployment config, docs, tracked-secret hygiene, and the
current test/browser/dependency gates.

## Fixed in this pass

- Added hard size limits before manual/API upload parsing and before local
  agent-tool `.eml` parsing.
- Added timeout and stdout/stderr caps to the desktop MCP bridge.
- Tightened MCP bridge input validation for `.eml` paths and boolean metadata
  flags.
- Switched analyst bearer-token checks to constant-time comparison.
- Added same-origin `Origin`/`Referer` enforcement before SaaS signup, login,
  and password-reset routes set user cookies.
- Changed production Compose env-file loading to raw mode so secrets containing
  `$` are not re-expanded by Docker Compose.
- Updated deployment scripts to use `${APP_ENV_FILE:-.env}` consistently.
- Updated docs for auth boundaries, MCP limits, current SaaS pricing, and the
  current test count.
- Closed the remaining SSRF path in browser URL detonation by checking the
  initial URL plus every Playwright navigation, redirect, and subresource
  request.
- Closed SSRF redirect resolution in the URL extractor helper by re-checking
  every HEAD request target and every redirect hop.
- Enabled Jinja autoescaping for generated HTML reports and escaped the
  fallback HTML renderer for email-controlled fields.
- Added login failure throttling for analyst token login and SaaS
  email/password login.
- Cleaned dependency and static-audit gates to zero high/medium Bandit
  findings, with remaining findings low severity only.
- Updated the feedback API example docs to keep the default bind on loopback
  instead of `0.0.0.0`.
- Updated production health/load probes to send a configurable browser-compatible
  user-agent so Cloudflare browser-signature rules do not block uptime checks.

## Audit Evidence

- Full unit/integration suite: `1218 passed`.
- Focused security regression suite: `181 passed`.
- Gemini live LLM provider benchmark: `gemini-3-flash-preview` completed
  15/15 with 0 errors and beat `gemini-3.1-pro-preview` on this label task;
  no Gemini model reached the 90% tier-assignment threshold on the current
  small eval slice.
- OpenAI live LLM provider benchmark: `gpt-5.4-mini` completed 15/15 with
  0 errors and beat `gpt-5.5` on this label task at materially lower cost;
  `gpt-5.5` is supported but should stay an explicit benchmark candidate.
- Dashboard browser smoke check: charts loaded, strict dashboard CSP observed,
  no console/page errors.
- MCP live smoke demo: `analyze_payment_email` returned `DO_NOT_PAY`, masked
  payment identifiers, and did not return body, raw headers, or attachment
  content.
- Python dependency audit against `requirements.lock`: no known vulnerabilities
  found.
- Bandit static scan: `0 high`, `0 medium`, `80 low`, `18 skipped`.
- Tracked-secret scan found placeholders/test strings only. Runtime `.env`
  remains untracked and must stay that way.
- Docker Compose production config validates against `.env.production`; remote
  Docker Compose is new enough for raw env-file mode.
- Desktop MCP bridge JavaScript syntax check passes with `node --check`.
- Public production health check passes against
  `https://phishanalyze.mdpstudio.com.au/api/health`.
- Public unauthenticated load probe against `/api/health`: `32` requests,
  `0.0` error rate.

## Remaining Operator Actions

- Add the chosen production LLM key later. `LLM_PROVIDER=deepseek` remains the
  cost-first default for Starter/Pro/Business from the local pilot; Gemini,
  OpenAI GPT-5.x, Anthropic, and Moonshot/Kimi should stay Enterprise review
  candidates until a larger real-redacted eval justifies the extra cost.
- Keep `ACCOUNTS_ENCRYPTION_KEY` stable. If the monitor says reconnect, re-enter
  the mailbox app password once with the stable key set.
- Keep `SAAS_PUBLIC_SIGNUP_ENABLED=false` until privacy, abuse handling, and
  support workflows are ready for public users.
- Move the older analyst templates (`/monitor`, `/status`, `/analyze`,
  `/accounts`) fully out of inline JS/CSS before dropping fallback
  `unsafe-inline` from the global CSP. Public `/product`, `/app`, and the main
  dashboard already use stricter static-asset CSP paths.

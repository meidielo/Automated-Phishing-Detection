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

## Audit Evidence

- Full unit/integration suite: `1178 passed`.
- Focused SaaS/MCP/operation suite: `35 passed`.
- Dashboard browser smoke check: charts loaded, strict dashboard CSP observed,
  no console/page errors.
- MCP live smoke demo: `analyze_payment_email` returned `DO_NOT_PAY`, masked
  payment identifiers, and did not return body, raw headers, or attachment
  content.
- Python dependency audit against `requirements.lock`: no known vulnerabilities
  found.
- Tracked-secret scan found placeholders/test strings only. Runtime `.env`
  remains untracked and must stay that way.
- Docker Compose production config validates against `.env.production`; remote
  Docker Compose is new enough for raw env-file mode.

## Remaining Operator Actions

- Add the chosen LLM key later. `LLM_PROVIDER=deepseek` is the cost-first
  default; Moonshot/Kimi can also use the OpenAI-compatible path.
- Keep `ACCOUNTS_ENCRYPTION_KEY` stable. If the monitor says reconnect, re-enter
  the mailbox app password once with the stable key set.
- Keep `SAAS_PUBLIC_SIGNUP_ENABLED=false` until privacy, abuse handling, and
  support workflows are ready for public users.
- Move the older analyst templates (`/monitor`, `/status`, `/analyze`,
  `/accounts`) fully out of inline JS/CSS before dropping fallback
  `unsafe-inline` from the global CSP. Public `/product`, `/app`, and the main
  dashboard already use stricter static-asset CSP paths.

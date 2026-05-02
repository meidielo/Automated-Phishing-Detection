# SaaS Account, Database, and Billing Architecture

This document defines the product direction for turning the single-operator
phishing detector into a user-login product. The current public demo is
sample-only. The repository now includes a SQLite-backed SaaS foundation for
normal user login, organization-scoped scan storage, plan limits, and locked
analyzer responses. Public signup remains disabled by default so operators do
not accidentally accept visitor email uploads before privacy, abuse, and support
controls are ready.

## Product Model

Use normal account login for users. Keep the analyst token only for owner/admin
operations.

Recommended flow:

1. User creates an account or signs in.
2. User belongs to one organization.
3. Organization has one Stripe customer and one active subscription state.
4. Every mailbox, scan, result, feedback label, and usage row is scoped by
   `org_id` and, where useful, `user_id`.
5. Expensive analyzers check entitlements before running.
6. Locked analyzers return structured lock metadata so the UI can show the tier
   required instead of failing silently.

Stripe should use Billing APIs with Checkout Sessions in subscription mode.
Use Stripe Customer Portal for upgrades, cancellation, and payment method
updates. Do not build manual renewal loops.

## Current Implementation

Implemented foundation:

- `/app` serves the normal user account shell.
- `/api/saas/auth/signup`, `/api/saas/auth/login`, and
  `/api/saas/auth/logout` use signed user sessions plus CSRF protection.
- `/api/saas/auth/password-reset/request` and
  `/api/saas/auth/password-reset/confirm` implement a normal reset-password
  flow with one-time hashed reset tokens and SMTP delivery. The request route
  returns the same generic response for known and unknown emails.
- `src/saas/database.py` creates `users`, `organizations`, `memberships`,
  `password_reset_tokens`, `subscriptions`, `mail_accounts`, `scan_jobs`,
  `scan_results`, `usage_events`, `feature_locks`, and `audit_logs`.
- `/api/saas/analyze/upload` stores results in `scan_results`, not the shared
  analyst `data/results.jsonl` log.
- The pipeline accepts a per-request `feature_gate`; locked analyzers return
  `feature_locked` metadata with the required tier before paid API clients are
  loaded.
- Free accounts are limited to 5 manual scans/month and core payment checks.
- `python main.py purge --target saas` and `--target all` purge old SaaS scan,
  usage, lock, and audit rows under the same retention window as other runtime
  artifacts.
- `/api/saas/billing/checkout` creates hosted Stripe Checkout Sessions in
  subscription mode when `STRIPE_SECRET_KEY` and the target plan price ID are
  configured and accepted by Stripe. Missing config or rejected runtime keys
  return a safe billing-unavailable response.
- `/api/saas/billing/portal` creates Stripe Customer Portal Sessions for
  organizations that already have a Stripe customer.
- `/api/stripe/webhook` verifies Stripe signatures and mirrors
  `checkout.session.completed` plus `customer.subscription.*` events into the
  local `subscriptions` table.

Not implemented yet:

- Production Postgres migrations.
- Per-user mailbox OAuth or IMAP token storage.

## Initial Plans

Plan entitlements live in `src/billing/plans.py` so the UI, API gates, usage
checks, and Stripe webhook handlers share one catalog.

| Plan | Price | Monthly scans | Mailboxes | Intended use |
|---|---:|---:|---:|---|
| Free | AUD 0 | 5 | 0 | Demo visitors and tiny manual checks |
| Starter | AUD 19 | 100 | 1 | Freelancers and very small teams |
| Pro | AUD 49 | 1000 | 3 | SMEs that receive invoices by email |
| Business | AUD 149 | 5000 | 10 | Finance teams and agencies |

Free includes manual scans, header checks, payment rules, and account-scoped
history. Starter unlocks reputation, domain, brand, and sender-profile checks.
Pro unlocks mailbox monitoring, LLM BEC reasoning, attachment sandboxing, and browser URL
detonation. Business adds team audit controls and higher budgets.

## Database Tables

Recommended production database: Postgres. SQLite is acceptable only for local
development and single-operator demos.

| Table | Purpose | Key fields |
|---|---|---|
| `users` | Login identity | `id`, `email`, `password_hash` or OAuth subject, `created_at` |
| `password_reset_tokens` | One-time password reset links | `user_id`, `token_hash`, `expires_at`, `used_at` |
| `organizations` | Billing and tenant boundary | `id`, `name`, `stripe_customer_id`, `created_at` |
| `memberships` | User to org mapping | `user_id`, `org_id`, `role` |
| `subscriptions` | Stripe mirror | `org_id`, `stripe_subscription_id`, `plan_slug`, `status`, `current_period_end` |
| `mail_accounts` | User-owned mailbox config | `org_id`, `user_id`, `provider`, encrypted token refs, `status` |
| `scan_jobs` | Queued or completed scan requests | `org_id`, `user_id`, `mail_account_id`, `status`, `source`, `created_at` |
| `scan_results` | Private analysis output | `org_id`, `scan_job_id`, `email_id`, `verdict`, `payment_decision`, `result_json` |
| `usage_events` | Quota and billing meter | `org_id`, `feature_slug`, `quantity`, `occurred_at`, `idempotency_key` |
| `feature_locks` | Optional audit of blocked actions | `org_id`, `user_id`, `feature_slug`, `required_plan`, `created_at` |
| `audit_logs` | Security and admin trace | `org_id`, `actor_user_id`, `action`, `target_type`, `target_id`, `created_at` |

Tenant isolation rule: every query for user-visible data must include `org_id`
from the authenticated session. Tests must prove user A cannot read user B's
mailboxes, scans, feedback labels, usage rows, subscription state, or audit logs.

The current SQLite store follows that rule for SaaS scan history. The analyst
dashboard and legacy mailbox monitor are still single-operator surfaces guarded
by `ANALYST_API_TOKEN`.

## Usage Gate

Before running an analyzer, the server should evaluate:

1. Is the user authenticated?
2. Which `org_id` is active?
3. Which `plan_slug` is active and paid?
4. Does the plan include this `feature_slug`?
5. Is monthly scan quota remaining?
6. Is a cached result available that avoids a paid API call?
7. Has the org hit a spend safety limit?

If blocked, return a response shaped like:

```json
{
  "available": false,
  "feature_slug": "url_detonation",
  "required_plan": "pro",
  "required_plan_name": "Pro",
  "reason": "Browser URL detonation is available on Pro."
}
```

The frontend should show the result as a locked analyzer row, not as an error.

## Auth Staging

Safe implementation order:

1. Add database schema and tenant-scoped query helpers. **Done for the SaaS path.**
2. Add account login with signed user sessions and CSRF. **Done.**
3. Add password reset via SMTP with hashed one-time tokens. **Done.**
4. Move user scan results from `results.jsonl` display paths into
   `scan_results`. **Done for `/api/saas/analyze/upload`.**
5. Add usage tracking and feature gates. **Done for manual scans and analyzers.**
6. Add Stripe Checkout and webhook subscription sync. **Done for the SaaS path.**
7. Add per-user mailbox connection.
8. Add tenant isolation tests before enabling real mailbox access.

Do not connect visitor mailboxes until steps 1, 2, 4, and 8 are complete.

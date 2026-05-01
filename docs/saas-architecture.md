# SaaS Account, Database, and Billing Architecture

This document defines the product direction for turning the single-operator
phishing detector into a user-login product. The current public demo is
sample-only. A real SaaS launch must add tenant isolation before letting users
connect mailboxes or store private scan results.

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

## Initial Plans

Plan entitlements live in `src/billing/plans.py` so the UI, API gates, usage
checks, and Stripe webhook handlers share one catalog.

| Plan | Price | Monthly scans | Mailboxes | Intended use |
|---|---:|---:|---:|---|
| Free | AUD 0 | 5 | 0 | Demo visitors and tiny manual checks |
| Starter | AUD 19 | 100 | 1 | Freelancers and very small teams |
| Pro | AUD 49 | 1000 | 3 | SMEs that receive invoices by email |
| Business | AUD 149 | 5000 | 10 | Finance teams and agencies |

Free should not run paid API-backed analyzers. Starter unlocks reputation and
domain checks. Pro unlocks mailbox monitoring, LLM BEC reasoning, and browser
URL detonation. Business adds team audit controls and higher budgets.

## Database Tables

Recommended production database: Postgres. SQLite is acceptable only for local
development and single-operator demos.

| Table | Purpose | Key fields |
|---|---|---|
| `users` | Login identity | `id`, `email`, `password_hash` or OAuth subject, `created_at` |
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

1. Add database schema and tenant-scoped query helpers.
2. Add account login with signed user sessions and CSRF.
3. Move scan results from `results.jsonl` display paths into `scan_results`.
4. Add usage tracking and feature gates.
5. Add Stripe Checkout and webhook subscription sync.
6. Add per-user mailbox connection.
7. Add tenant isolation tests before enabling real mailbox access.

Do not connect visitor mailboxes until steps 1, 2, 3, and 7 are complete.

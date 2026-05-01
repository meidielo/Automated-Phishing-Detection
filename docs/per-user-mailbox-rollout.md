# Per-User Mailbox Rollout

The product needs a hard split between the public demo and real mailbox access.

Public demo:

- Fixed committed sample emails only
- No visitor mailbox connection
- No paid API use
- No feedback training
- No account management

Real product:

- Each user connects their own mailbox
- Tokens or IMAP secrets are encrypted outside the plain SaaS DB
- Every scan result is scoped by `org_id` and `user_id`
- Mailbox polling never writes into the shared analyst `data/results.jsonl`

## Current Foundation

The SaaS store already has tenant-scoped users, organizations, memberships,
subscriptions, scan jobs, scan results, usage events, feature locks, and audit
logs.

This rollout adds safe mailbox metadata helpers around the existing
`mail_accounts` table:

- `register_mail_account`
- `list_mail_accounts`
- `set_mail_account_status`

Those helpers store provider, external account id, token reference, status, and
audit events. They do not accept raw passwords or OAuth tokens. `encrypted_token_ref`
must point to a vault/secret record, not hold plaintext credentials.

## Implementation Order

1. **OAuth/IMAP connection flow**
   - Gmail and Outlook should use OAuth.
   - Generic IMAP should require an app password and explicit user consent.
   - Never accept mailbox credentials in public demo mode.

2. **Secret storage**
   - Store encrypted token material in a vault layer.
   - Store only `encrypted_token_ref` in `mail_accounts`.
   - Rotate or disable tokens from the same account settings surface.

3. **Mailbox polling**
   - Poll by `mail_account_id`, `org_id`, and `user_id`.
   - Write to `scan_jobs` and `scan_results`.
   - Enforce plan gates before paid analyzers run.

4. **User interface**
   - Show connected mailboxes under the account shell.
   - Show status: `pending`, `active`, `error`, or `disabled`.
   - Provide disconnect/disable actions with confirmation.

5. **Abuse and privacy controls**
   - Per-org quotas.
   - Audit log for connect, disable, scan, and token rotation.
   - Data export and erasure by org/user/mail account.

## Hard Boundary

Do not connect Meidie's real mailbox or enter mailbox credentials during demo
work unless he explicitly provides the account flow and confirms the data being
transmitted. Public demo routes must remain sample-only.

# Agent Payment Three-case Transcript

Command:

```powershell
.\.venv\Scripts\python.exe scripts\agent_payment_demo.py
```

Output:

```text
Agent-ready Payment Scam Firewall demo
Scenario: an AI agent receives three invoice/payment emails and calls
the local analyze_payment_email MCP tool before finance releases money.

1. Normal invoice, saved supplier record
   Subject: April catering invoice and receipt
   Tool decision: SAFE
   Risk/confidence: 0.080 / 0.730
   Agent action: Proceed through the normal payment approval workflow.
   Evidence: no material scam signals
   First verification step: Continue normal payment approval checks.

2. Supplier portal update pending verification
   Subject: Supplier portal bank detail update pending verification
   Tool decision: VERIFY
   Risk/confidence: 0.548 / 0.800
   Agent action: Hold payment until the supplier or executive is verified out of band.
   Evidence: bank detail change request, mandatory supplier verification
   First verification step: Do not use phone numbers, links, or reply-to addresses from this email for verification.

3. Urgent bank-detail redirect
   Subject: Urgent updated bank details for outstanding invoice
   Tool decision: DO_NOT_PAY
   Risk/confidence: 0.854 / 1.000
   Agent action: Block payment release and complete independent verification.
   Evidence: bank detail change request, mandatory supplier verification, payment urgency pressure, approval bypass language
   First verification step: Do not use phone numbers, links, or reply-to addresses from this email for verification.

Demo safety rails:
- Uses committed sample emails only.
- Does not connect a mailbox.
- Does not call paid APIs.
- Does not return full email bodies, raw headers, or attachment content.
```

Decision summary:

| Scenario | Source file | Decision | Risk | Confidence | Action |
|---|---|---:|---:|---:|---|
| Normal invoice | `safe_invoice.eml` | `SAFE` | `0.080` | `0.730` | Proceed through normal approval. |
| Supplier portal update | `verify_supplier_portal.eml` | `VERIFY` | `0.548` | `0.800` | Hold for out-of-band verification. |
| Bank-detail redirect | `do_not_pay_bank_redirect.eml` | `DO_NOT_PAY` | `0.854` | `1.000` | Block payment release. |

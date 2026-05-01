# Agent Payment Demo Transcript

This is the intended live demo flow after connecting the MCP server to an agent
client.

## Setup

Start the live smoke client:

```bash
python scripts/agent_mcp_live_demo.py
```

The script launches `scripts/payment_mcp_server.py` over stdio, runs the MCP
`initialize` lifecycle, discovers tools with `tools/list`, then calls
`analyze_payment_email` through `tools/call`.

## Demo Flow

User prompt:

```text
Investigate this invoice email before finance pays it:
demo_samples/agent_payment/do_not_pay_bank_redirect.eml
```

Agent action:

```text
Call analyze_payment_email with include_email_metadata=false.
```

Expected agent summary:

```text
Decision: DO_NOT_PAY
Risk/confidence: high risk, high confidence
Action: block payment release and complete independent verification.
Evidence:
- bank detail change language
- mandatory supplier verification context
- urgent payment pressure
- approval bypass language
- reply-to domain mismatch
- SPF/DMARC authentication failure
- bank details in the email body
Safety: the tool did not return full email body, raw headers, or attachment
content. Payment identifiers are masked.
```

Human verification steps:

```text
1. Do not use phone numbers, links, or reply-to addresses from this email.
2. Call the supplier using a saved accounting-system contact.
3. Require second-person approval for the bank-detail change.
4. Compare the details with the last approved supplier record.
5. Record verifier name, date, and approval outcome before releasing funds.
```

## Why This Demo Works

It shows the product wedge without pretending to be a full mailbox product:

- The agent has a real tool contract.
- The tool returns a finance decision, not only a phishing score.
- The evidence is explainable.
- The safety boundary is explicit.
- No live mailbox, paid API, or payment action is required.

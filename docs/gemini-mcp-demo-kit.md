# Gemini MCP Demo Kit

This is the shareable proof package for the agent-native payment scam firewall
slice.

## One-line Pitch

Payment Scam Firewall is an MCP security layer that lets AI accounting agents
decide whether payment emails should be paid, verified, or blocked before money
moves.

## What The Demo Proves

The demo shows Gemini acting as an accounts payable agent. Gemini does not
guess from the raw email. It calls the local `payment-scam-firewall` MCP server,
receives a structured `SAFE`, `VERIFY`, or `DO_NOT_PAY` result, and turns that
tool result into an AP team note.

The important product proof is the boundary:

- The agent calls a specialized local security tool.
- The decision is structured and machine-readable.
- The human-facing note is grounded in tool evidence.
- Full email bodies, raw headers, attachment contents, and unmasked payment
  identifiers are not returned.

## Canonical Recording

The real screen recording is stored locally and intentionally kept out of git:

```text
reports/demo_recordings/windows_gemini_mcp_demo_capture.mp4
```

The product page uses a committed GIF exported from that recording:

```text
static/gemini-mcp-proof-slow.gif
```

The static screenshot thumbnail is kept as a lightweight fallback asset:

```text
static/gemini-mcp-proof.png
```

Keep large recording files in `reports/demo_recordings/` locally. The gitignore
keeps `.mp4`, `.png`, and `.jsonl` captures from being committed by accident.

## Final Gemini Prompt

Use this prompt when recording the AP-agent demo:

```text
You are acting as an accounts payable agent. Use only the payment-scam-firewall MCP tool result as evidence to decide whether demo_samples/agent_payment/do_not_pay_bank_redirect.eml should be paid, verified, or blocked. Write a short AP team note with: decision, reason, evidence, and next step. Do not add claims that are not present in the tool result. Keep evidence wording close to the tool output.
```

## Recording Flow

1. Run `/mcp`.
2. Show `payment-scam-firewall - Ready (1 tool)`.
3. Paste the final Gemini prompt.
4. Wait for the MCP tool call.
5. Show the `DO_NOT_PAY` structured result.
6. Show the final AP team note.

## Expected Demo Result

The `do_not_pay_bank_redirect.eml` sample should produce:

```text
Decision: DO_NOT_PAY
Risk score: 0.854
Confidence: 1.0
Next action: Block payment release and complete independent verification.
```

Grounding evidence should include:

- `bank_detail_change_request`
- `approval_bypass_language`
- `sender_authentication_failed`
- `reply_to_domain_mismatch`
- `payment_urgency_pressure`

## Three-case Proof

Use the three committed samples to show the tool is not a block-only demo:

| Sample | Expected decision | Product meaning |
|---|---:|---|
| `safe_invoice.eml` | `SAFE` | Normal payment workflow can continue. |
| `verify_supplier_portal.eml` | `VERIFY` | Payment should wait for out-of-band supplier verification. |
| `do_not_pay_bank_redirect.eml` | `DO_NOT_PAY` | Payment release should be blocked. |

Run:

```powershell
.\.venv\Scripts\python.exe scripts\agent_payment_demo.py
```

The committed transcript is in:

```text
docs/agent-payment-three-case-transcript.md
```

## Demo Safety Rails

- The demo uses committed sample emails only.
- It does not connect to a mailbox.
- It does not call paid APIs.
- It does not release payments.
- It does not write training feedback labels.
- It does not expose full email bodies, raw headers, or attachment contents.

## Where To Use This

Use the recording and transcript for portfolio, pitch, assignment, or product
validation. The strongest framing is:

```text
An AI accounting agent should not decide from raw payment emails. It should call
a specialized security tool, receive a structured payment decision, and produce
a business-readable action note.
```

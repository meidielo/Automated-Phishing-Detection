# Agent Payment Tool

The first agent-native product slice is a narrow payment email investigation
tool:

```text
analyze_payment_email(email_path) -> SAFE | VERIFY | DO_NOT_PAY + evidence
```

It wraps the existing `payment_fraud` analyzer and returns structured evidence
without exposing full email bodies, raw headers, or attachment content.

## Contract

Input:

```json
{
  "email_path": "path/to/payment-email.eml",
  "include_email_metadata": true
}
```

Output:

```json
{
  "tool": "analyze_payment_email",
  "schema_version": "1.0",
  "decision": "VERIFY",
  "risk_score": 0.548,
  "confidence": 0.8,
  "summary": "Payment request has fraud indicators and requires independent verification.",
  "agent_next_action": "Hold payment until the supplier or executive is verified out of band.",
  "signals": [
    {
      "name": "bank_detail_change_request",
      "severity": "high",
      "evidence": "Bank or payment detail change language found: updated bank details",
      "recommendation": "Verify the change using a saved supplier contact before paying.",
      "risk_weight": 0.3
    }
  ],
  "extracted_payment_fields": {},
  "verification_steps": [],
  "safety": {
    "body_returned": false,
    "raw_headers_returned": false,
    "attachment_content_returned": false,
    "payment_identifiers_masked_by_analyzer": true
  }
}
```

## CLI

```bash
python scripts/agent_payment_tool.py demo_samples/agent_payment/do_not_pay_bank_redirect.eml --pretty
```

Use `--no-metadata` when an agent only needs the decision payload.

Run the narrative demo:

```bash
python scripts/agent_payment_demo.py
```

It analyzes three committed samples:

- `demo_samples/agent_payment/safe_invoice.eml`
- `demo_samples/agent_payment/verify_supplier_portal.eml`
- `demo_samples/agent_payment/do_not_pay_bank_redirect.eml`

Run the live MCP smoke demo:

```bash
python scripts/agent_mcp_live_demo.py
```

That script starts `scripts/payment_mcp_server.py` over stdio, runs
`initialize`, discovers `analyze_payment_email` with `tools/list`, and calls it
with `tools/call`. The captured storyline is in
[`docs/agent-payment-demo-transcript.md`](agent-payment-demo-transcript.md).

## MCP Server

Run the stdio MCP server:

```bash
python scripts/payment_mcp_server.py
```

It exposes one tool named `analyze_payment_email`. The server implements the
MCP lifecycle enough for local agent clients: `initialize`, `ping`,
`tools/list`, and `tools/call`.

The implementation follows the MCP 2025-06-18 shape:

- JSON-RPC messages over stdio are newline-delimited.
- Tool discovery uses `tools/list`.
- Tool invocation uses `tools/call`.
- Structured output is returned in `structuredContent` and mirrored as JSON
  text for compatibility.

## Claude Desktop Setup

Claude Desktop now prefers desktop extensions for broad distribution. This repo
contains a local-development MCPB bundle in:

```text
desktop_extension/payment-scam-firewall
```

The bundle starts a small Node server and bridges to the Python CLI in this
repository. It asks for:

- the project folder
- the Python executable with this repo's dependencies installed

Build the `.mcpb` archive from the repo root:

```powershell
$zip = "desktop_extension\payment-scam-firewall-0.1.0.zip"
$mcpb = "desktop_extension\payment-scam-firewall-0.1.0.mcpb"
Compress-Archive -Path desktop_extension\payment-scam-firewall\* -DestinationPath $zip -Force
Move-Item $zip $mcpb -Force
```

For direct stdio development without installing the extension, use the config
snippet in:

```text
docs/mcp/claude-desktop-payment-scam-firewall.json
```

The snippet uses this local virtualenv Python executable:

```text
C:\Users\meidi\Documents\personal project\Automated Phishing Detection\.venv\Scripts\python.exe
```

And starts this MCP server:

```text
C:\Users\meidi\Documents\personal project\Automated Phishing Detection\scripts\payment_mcp_server.py
```

Windows JSON notes:

- Keep paths double-escaped as `\\` inside JSON.
- Keep `command` as the Python executable and the server path in `args`.
- The server resolves the repo root from its own script path, so it does not
  require a `cwd` field.
- After changing config, restart the MCP client and inspect connected tools.

## Claude Code Setup

Add the stdio server:

```powershell
claude mcp add --transport stdio payment-scam-firewall -- "C:\Users\meidi\Documents\personal project\Automated Phishing Detection\.venv\Scripts\python.exe" "C:\Users\meidi\Documents\personal project\Automated Phishing Detection\scripts\payment_mcp_server.py"
```

Verify it:

```powershell
claude mcp list
claude mcp get payment-scam-firewall
```

Inside Claude Code, use `/mcp` to check server status and tool availability.
The official Claude Code MCP docs require all options such as `--transport`,
`--env`, and `--scope` before the server name, then `--` before the command
that starts the server.

For SDK or project-file demos, use:

```text
docs/mcp/claude-code-project.mcp.example.json
```

Copy that file to `.mcp.json` only when you want the project to auto-load the
server in a compatible MCP client.

## Gemini CLI Setup

The same MCP server works in Gemini CLI. The local Windows demo uses a
project-level Gemini config with machine-specific absolute paths, so keep it
untracked.

Install Gemini CLI:

```powershell
npm.cmd install -g @google/gemini-cli
```

Project config shape:

```json
{
  "mcpServers": {
    "payment-scam-firewall": {
      "command": "C:\\Users\\meidi\\Documents\\personal project\\Automated Phishing Detection\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\meidi\\Documents\\personal project\\Automated Phishing Detection\\scripts\\payment_mcp_server.py"
      ],
      "timeout": 60000
    }
  }
}
```

Verify it inside Gemini CLI:

```text
/mcp
```

Expected status:

```text
payment-scam-firewall - Ready (1 tool)
```

Then run the AP-agent prompt from
[`docs/gemini-mcp-demo-kit.md`](gemini-mcp-demo-kit.md). The three-case CLI
proof transcript is in
[`docs/agent-payment-three-case-transcript.md`](agent-payment-three-case-transcript.md).

## Raw JSON-RPC Smoke Call

PowerShell example:

```powershell
$server = ".\.venv\Scripts\python.exe"
$script = "scripts\payment_mcp_server.py"
$sample = "demo_samples\agent_payment\do_not_pay_bank_redirect.eml"
$messages = @(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual-smoke","version":"1.0"}}}',
  '{"jsonrpc":"2.0","method":"notifications/initialized"}',
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
  ('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_payment_email","arguments":{"email_path":"' + $sample.Replace('\', '\\') + '","include_email_metadata":false}}}')
)
$messages -join "`n" | & $server $script
```

References:

- https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- https://code.claude.com/docs/en/mcp
- https://platform.claude.com/docs/en/agent-sdk/mcp
- https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop

## Public Demo

When `PUBLIC_DEMO_MODE=true`, the sample-only UI is available at:

```text
/agent-demo
```

The UI calls:

```text
/api/demo/agent-payment-analysis
```

That endpoint only runs fixed committed samples from `demo_samples/agent_payment`.
It does not connect a mailbox, accept public uploads, call paid APIs, or write
feedback labels.

## Product Shell

The public product shell is available at:

```text
/product
```

It positions the product as an agent-ready payment scam firewall, links to the
agent demo, and uses the existing dashboard screenshot as the visual asset.

## Per-User Mailbox Boundary

Real mailbox support is tracked in:

```text
docs/per-user-mailbox-rollout.md
```

The SaaS DB now has safe metadata helpers for mailbox records:

- `register_mail_account`
- `list_mail_accounts`
- `set_mail_account_status`

These helpers store provider/status/token-reference metadata only. They do not
accept or store raw mailbox credentials. Live OAuth/IMAP authorization still
requires a separate user-consented flow.

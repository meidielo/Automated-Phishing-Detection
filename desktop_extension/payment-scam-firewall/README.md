# Payment Scam Firewall Desktop Extension

This MCPB bundle is a Claude Desktop bridge for the local Payment Scam Firewall
project.

It starts a small Node MCP server and calls the repo's Python CLI:

```text
scripts/agent_payment_tool.py
```

The bundle asks for two local paths during install:

- Project folder containing this repository
- Python executable with the project's dependencies installed

The MCPB itself does not bundle the full Python app or virtual environment. It
is a local development/demo package for Meidie's machine, not a public
redistributable extension.

## Build

From the repo root:

```powershell
$zip = "desktop_extension\payment-scam-firewall-0.1.0.zip"
$mcpb = "desktop_extension\payment-scam-firewall-0.1.0.mcpb"
Compress-Archive -Path desktop_extension\payment-scam-firewall\* -DestinationPath $zip -Force
Move-Item $zip $mcpb -Force
```

## Smoke Test

Run the bridge directly with Node:

```powershell
$env:PAYMENT_FIREWALL_PROJECT_ROOT = "C:\Users\meidi\Documents\personal project\Automated Phishing Detection"
$env:PAYMENT_FIREWALL_PYTHON = "C:\Users\meidi\Documents\personal project\Automated Phishing Detection\.venv\Scripts\python.exe"
node desktop_extension\payment-scam-firewall\server\index.js
```

Then send newline-delimited JSON-RPC messages for `initialize`, `tools/list`,
and `tools/call`.

#!/usr/bin/env python3
"""Run a live JSON-RPC smoke demo against the local MCP server process."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE = PROJECT_ROOT / "demo_samples" / "agent_payment" / "do_not_pay_bank_redirect.eml"


def _request(message_id: int, method: str, params: dict | None = None) -> dict:
    message = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _run_server(messages: list[dict]) -> list[dict]:
    server = PROJECT_ROOT / "scripts" / "payment_mcp_server.py"
    proc = subprocess.run(
        [sys.executable, str(server)],
        cwd=PROJECT_ROOT,
        input="\n".join(json.dumps(message) for message in messages) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "MCP server exited with an error")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _print_transcript(responses: list[dict]) -> None:
    tools = responses[1]["result"]["tools"]
    tool_result = responses[2]["result"]["structuredContent"]
    print("Live MCP client smoke demo")
    print("Client started scripts/payment_mcp_server.py over stdio.")
    print(f"Discovered tools: {', '.join(tool['name'] for tool in tools)}")
    print(f"Called analyze_payment_email on: {tool_result['source_file']}")
    print(f"Decision: {tool_result['decision']}")
    print(f"Risk/confidence: {tool_result['risk_score']:.3f} / {tool_result['confidence']:.3f}")
    print(f"Agent action: {tool_result['agent_next_action']}")
    print("Evidence:")
    for signal in tool_result.get("signals", [])[:5]:
        print(f"- {signal['name']}: {signal['evidence']}")
    print("Safety:")
    for key, value in tool_result["safety"].items():
        print(f"- {key}: {value}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a live MCP initialize/list/call flow against the local server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--json", action="store_true", help="Print raw JSON-RPC responses")
    args = parser.parse_args()

    sample = args.sample.resolve()
    messages = [
        _request(
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agent-mcp-live-demo", "version": "1.0"},
            },
        ),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _request(2, "tools/list"),
        _request(
            3,
            "tools/call",
            {
                "name": "analyze_payment_email",
                "arguments": {
                    "email_path": str(sample),
                    "include_email_metadata": False,
                },
            },
        ),
    ]
    try:
        responses = _run_server(messages)
    except Exception as exc:
        print(f"agent_mcp_live_demo error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(responses, indent=2, sort_keys=True))
    else:
        _print_transcript(responses)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

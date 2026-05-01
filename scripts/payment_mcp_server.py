#!/usr/bin/env python3
"""Minimal stdio MCP server for the Payment Scam Firewall agent tool."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent_tools.payment_email import (  # noqa: E402
    TOOL_INPUT_SCHEMA,
    TOOL_NAME,
    TOOL_OUTPUT_SCHEMA,
    analyze_payment_email_file,
)


PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = {
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
}


def _response(message_id: str | int | None, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _error(
    message_id: str | int | None,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        payload["error"]["data"] = data
    return payload


def _tool_definition() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "title": "Payment Email Scam Analyzer",
        "description": (
            "Analyze a local .eml invoice or payment email and return a "
            "SAFE, VERIFY, or DO_NOT_PAY decision with evidence and "
            "verification steps. The tool does not return full email bodies, "
            "raw headers, or attachment contents."
        ),
        "inputSchema": TOOL_INPUT_SCHEMA,
        "outputSchema": TOOL_OUTPUT_SCHEMA,
    }


def _initialize_result(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    protocol_version = (
        requested
        if requested in SUPPORTED_PROTOCOL_VERSIONS
        else PROTOCOL_VERSION
    )
    return {
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {
            "name": "payment-scam-firewall",
            "title": "Payment Scam Firewall MCP Server",
            "version": "0.1.0",
        },
        "instructions": (
            "Use analyze_payment_email only on local .eml files that the user "
            "intended to inspect. Treat VERIFY and DO_NOT_PAY as human-review "
            "payment holds, not automatic payment actions."
        ),
    }


async def _call_tool(params: dict[str, Any]) -> dict[str, Any]:
    if params.get("name") != TOOL_NAME:
        raise ValueError(f"Unknown tool: {params.get('name')}")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")
    email_path = arguments.get("email_path")
    if not isinstance(email_path, str) or not email_path:
        raise ValueError("email_path is required")
    include_metadata = bool(arguments.get("include_email_metadata", True))

    try:
        result = await analyze_payment_email_file(
            email_path,
            include_email_metadata=include_metadata,
        )
    except Exception as exc:
        return {
            "content": [{"type": "text", "text": str(exc)}],
            "isError": True,
        }

    text = json.dumps(result, sort_keys=True)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": False,
    }


async def handle_jsonrpc_message(message: Any) -> Any:
    """Handle one JSON-RPC message or batch for tests and stdio."""
    if isinstance(message, list):
        responses = []
        for item in message:
            response = await handle_jsonrpc_message(item)
            if response is not None:
                responses.append(response)
        return responses if responses else None

    if not isinstance(message, dict):
        return _error(None, -32600, "Invalid Request")

    message_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    is_notification = "id" not in message

    if is_notification:
        return None
    if not isinstance(params, dict):
        return _error(message_id, -32602, "params must be an object")

    if method == "initialize":
        return _response(message_id, _initialize_result(params))
    if method == "ping":
        return _response(message_id, {})
    if method == "tools/list":
        return _response(message_id, {"tools": [_tool_definition()]})
    if method == "tools/call":
        try:
            result = await _call_tool(params)
        except ValueError as exc:
            return _error(message_id, -32602, str(exc))
        return _response(message_id, result)
    return _error(message_id, -32601, f"Method not found: {method}")


async def run_stdio() -> None:
    """Run newline-delimited JSON-RPC over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _error(None, -32700, f"Parse error: {exc.msg}")
        else:
            response = await handle_jsonrpc_message(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(run_stdio())

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.agent_tools.payment_email import (
    analyze_demo_payment_samples,
    analyze_payment_email_file,
)
from src.eval.payment_dataset import seed_synthetic_bank_change_dataset


PAYMENT_REDIRECT_EML = """From: Accounts Team <accounts@trustedvendor.example>
Reply-To: payments@trustedvendor-payments.example
To: finance@example.com
Subject: Urgent updated bank details for April invoice
Date: Mon, 27 Apr 2026 10:00:00 +0000
Message-ID: <payment-redirect@example.test>

Hi Finance,

Please use our new bank details for invoice INV-2042 today.
Do not use the old account details. Payment must be redirected to:
BSB: 123-456
Account number: 123456789
Amount: $18,450.00

Please process without delay.
"""


def _write_sample(tmp_path: Path, body: str = PAYMENT_REDIRECT_EML) -> Path:
    path = tmp_path / "payment-redirect.eml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_agent_payment_tool_returns_sanitized_decision(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "PAYMENT_DECISION_MODEL_PATH",
        str(tmp_path / "missing-payment-model.joblib"),
    )
    sample = _write_sample(tmp_path)

    payload = await analyze_payment_email_file(sample)

    assert payload["tool"] == "analyze_payment_email"
    assert payload["decision"] == "DO_NOT_PAY"
    assert payload["risk_score"] > 0.4
    assert payload["safety"]["body_returned"] is False
    assert payload["safety"]["raw_headers_returned"] is False
    assert "body_plain" not in json.dumps(payload)
    assert '"raw_headers":' not in json.dumps(payload)
    assert "model_path" not in payload["ml_decision"]
    assert any(signal["name"] == "bank_detail_change_request" for signal in payload["signals"])


def test_agent_payment_cli_prints_json(tmp_path):
    sample = _write_sample(tmp_path)

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/agent_payment_tool.py",
            str(sample),
            "--no-metadata",
        ],
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["decision"] == "DO_NOT_PAY"
    assert "email" not in payload


def test_agent_payment_demo_script_prints_three_decisions():
    proc = subprocess.run(
        [sys.executable, "scripts/agent_payment_demo.py"],
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert "Agent-ready Payment Scam Firewall demo" in proc.stdout
    assert "Tool decision: SAFE" in proc.stdout
    assert "Tool decision: VERIFY" in proc.stdout
    assert "Tool decision: DO_NOT_PAY" in proc.stdout


def test_agent_payment_mcp_stdio_exposes_and_calls_tool(tmp_path):
    sample = _write_sample(tmp_path)
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "analyze_payment_email",
                "arguments": {
                    "email_path": str(sample),
                    "include_email_metadata": False,
                },
            },
        },
    ]

    proc = subprocess.run(
        [sys.executable, "scripts/payment_mcp_server.py"],
        cwd=Path(__file__).resolve().parents[2],
        input="\n".join(json.dumps(message) for message in messages) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert len(responses) == 3
    assert responses[0]["result"]["capabilities"]["tools"]["listChanged"] is False
    assert responses[1]["result"]["tools"][0]["name"] == "analyze_payment_email"
    tool_result = responses[2]["result"]
    assert tool_result["isError"] is False
    assert tool_result["structuredContent"]["decision"] == "DO_NOT_PAY"


def test_analyze_demo_payment_samples_uses_fixed_dataset(tmp_path):
    dataset = tmp_path / "payment_scam_dataset"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=6,
        legit_count=6,
        safe_count=6,
        seed=1337,
        clean=True,
    )

    payload = asyncio.run(analyze_demo_payment_samples(dataset_dir=dataset))

    assert payload["demo_mode"] is True
    assert payload["live_mailbox_used"] is False
    assert payload["paid_api_used"] is False
    assert {sample["decision"] for sample in payload["samples"]} == {
        "SAFE",
        "VERIFY",
        "DO_NOT_PAY",
    }


def test_analyze_demo_payment_samples_uses_committed_agent_samples():
    payload = asyncio.run(analyze_demo_payment_samples())

    assert payload["demo_mode"] is True
    assert payload["sample_count"] == 3
    assert [(sample["expected_decision"], sample["decision"]) for sample in payload["samples"]] == [
        ("SAFE", "SAFE"),
        ("VERIFY", "VERIFY"),
        ("DO_NOT_PAY", "DO_NOT_PAY"),
    ]
    assert all(sample["source_type"] == "demo" for sample in payload["samples"])

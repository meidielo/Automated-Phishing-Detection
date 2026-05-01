#!/usr/bin/env python3
"""Run the narrated agent payment investigation demo."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent_tools.payment_email import analyze_demo_payment_samples  # noqa: E402


def _signal_names(sample: dict) -> str:
    signals = [
        signal.get("name", "").replace("_", " ")
        for signal in sample.get("signals", [])
        if signal.get("name")
    ]
    return ", ".join(signals[:4]) if signals else "no material scam signals"


def _print_narrative(payload: dict) -> None:
    print("Agent-ready Payment Scam Firewall demo")
    print("Scenario: an AI agent receives three invoice/payment emails and calls")
    print("the local analyze_payment_email MCP tool before finance releases money.\n")

    for index, sample in enumerate(payload.get("samples", []), start=1):
        email = sample.get("email") or {}
        print(f"{index}. {sample.get('title', sample.get('scenario', 'Sample'))}")
        print(f"   Subject: {email.get('subject', 'unknown')}")
        print(f"   Tool decision: {sample['decision']}")
        print(f"   Risk/confidence: {sample['risk_score']:.3f} / {sample['confidence']:.3f}")
        print(f"   Agent action: {sample['agent_next_action']}")
        print(f"   Evidence: {_signal_names(sample)}")
        steps = sample.get("verification_steps") or []
        if steps:
            print(f"   First verification step: {steps[0]}")
        print()

    print("Demo safety rails:")
    print("- Uses committed sample emails only.")
    print("- Does not connect a mailbox.")
    print("- Does not call paid APIs.")
    print("- Does not return full email bodies, raw headers, or attachment content.")


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a polished sample-only agent payment investigation demo.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full structured demo payload instead of the narrative.",
    )
    args = parser.parse_args()

    try:
        payload = await analyze_demo_payment_samples()
    except Exception as exc:
        print(f"agent_payment_demo error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_narrative(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

#!/usr/bin/env python3
"""Run the agent-facing payment email tool from the command line."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent_tools.payment_email import analyze_payment_email_file  # noqa: E402


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a .eml payment email and print the agent JSON payload.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("email_file", type=Path, help="Path to a local .eml file")
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Omit email metadata from the JSON payload",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    args = parser.parse_args()

    try:
        payload = await analyze_payment_email_file(
            args.email_file,
            include_email_metadata=not args.no_metadata,
        )
    except Exception as exc:
        print(f"agent_payment_tool error: {exc}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

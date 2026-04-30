#!/usr/bin/env python3
"""
Run a compact Payment Scam Firewall demo from the labeled local dataset.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.payment_dataset import DEFAULT_DATASET_DIR  # noqa: E402
from src.eval.payment_demo import format_payment_demo_table, run_payment_demo  # noqa: E402


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Show expected vs predicted payment decisions for demo samples.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--limit-per-decision", type=int, default=1)
    args = parser.parse_args()

    rows = await run_payment_demo(
        args.dataset,
        limit_per_decision=args.limit_per_decision,
    )
    print(f"Payment Scam Firewall demo: {args.dataset}")
    print(format_payment_demo_table(rows))
    mismatches = [row for row in rows if not row.match]
    if mismatches:
        print(f"\nMismatches: {len(mismatches)}")
        return 1
    print("\nAll demo decisions matched expected labels.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

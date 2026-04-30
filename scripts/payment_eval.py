#!/usr/bin/env python3
"""
Evaluate SAFE / VERIFY / DO_NOT_PAY decisions for a payment-scam dataset.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.payment_dataset import DEFAULT_DATASET_DIR  # noqa: E402
from src.eval.payment_decision_eval import evaluate_payment_decisions  # noqa: E402


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate payment-fraud business decisions against labels.csv.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument(
        "--output-prefix",
        type=Path,
        default=None,
        help="Report prefix. Writes .json, .csv, and .md files.",
    )
    parser.add_argument("--split", default=None, help="Only evaluate rows from this split, e.g. holdout")
    parser.add_argument("--source-type", default=None, help="Only evaluate rows from this source type")
    args = parser.parse_args()

    summary = await evaluate_payment_decisions(
        args.dataset,
        args.output_prefix,
        split=args.split,
        source_type=args.source_type,
    )
    print(f"Payment decision eval: {summary.dataset_dir}")
    if args.split:
        print(f"  split:      {args.split}")
    if args.source_type:
        print(f"  source:     {args.source_type}")
    print(f"  rows:       {summary.row_count}")
    print(f"  correct:    {summary.correct}")
    print(f"  mismatches: {summary.mismatches}")
    print(f"  accuracy:   {summary.accuracy:.3f}")
    print("  matrix:")
    for expected, predictions in sorted(summary.confusion_matrix.items()):
        for predicted, count in sorted(predictions.items()):
            print(f"    {expected} -> {predicted}: {count}")
    print("  by source:")
    for source_type, metrics in sorted(summary.by_source_type.items()):
        print(f"    {source_type}: {metrics['correct']}/{metrics['rows']} ({metrics['accuracy']:.3f})")
    print("  by split:")
    for split, metrics in sorted(summary.by_split.items()):
        print(f"    {split}: {metrics['correct']}/{metrics['rows']} ({metrics['accuracy']:.3f})")
    print(f"  json:       {summary.json_path}")
    print(f"  csv:        {summary.csv_path}")
    print(f"  markdown:   {summary.markdown_path}")
    return 1 if summary.mismatches else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

#!/usr/bin/env python3
"""
Train and test a baseline payment-decision ML classifier.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.payment_dataset import DEFAULT_DATASET_DIR  # noqa: E402
from src.ml.payment_classifier import DEFAULT_MODEL_DIR, train_payment_classifier  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train/test a TF-IDF + logistic regression classifier on the payment dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--ml-jsonl", type=Path, default=None)
    parser.add_argument("--target", choices=["payment_decision", "binary_label"], default="payment_decision")
    args = parser.parse_args()

    metrics = train_payment_classifier(
        dataset_dir=args.dataset,
        output_dir=args.output_dir,
        target=args.target,
        ml_jsonl=args.ml_jsonl,
    )
    print(f"Payment ML training complete: {args.dataset}")
    print(f"  target:       {metrics.target}")
    print(f"  train rows:   {metrics.train_rows}")
    print(f"  val rows:     {metrics.validation_rows}")
    print(f"  test rows:    {metrics.test_rows}")
    print(f"  classes:      {', '.join(metrics.classes)}")
    print(f"  test accuracy:{metrics.test_accuracy: .3f}")
    print("  matrix:")
    for expected, predictions in sorted(metrics.confusion_matrix.items()):
        for predicted, count in sorted(predictions.items()):
            print(f"    {expected} -> {predicted}: {count}")
    print(f"  model:        {metrics.model_path}")
    print(f"  metrics:      {metrics.metrics_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Train/test a baseline generic phishing classifier from an eval corpus."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.phishing_classifier import (  # noqa: E402
    DEFAULT_CORPUS_DIR,
    DEFAULT_MODEL_DIR,
    train_phishing_classifier,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train/test a TF-IDF + logistic regression classifier on a prepared phishing corpus.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_DIR)
    parser.add_argument("--labels-csv", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    metrics = train_phishing_classifier(
        corpus_dir=args.corpus,
        labels_csv=args.labels_csv,
        output_dir=args.output_dir,
        seed=args.seed,
    )
    print(f"Generic phishing ML training complete: {args.corpus}")
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

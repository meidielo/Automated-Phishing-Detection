"""
Train and evaluate a baseline payment-decision classifier.

This is intentionally separate from the rules-based payment analyzer. The
rules produce explainable operational decisions. This module gives the payment
dataset a reproducible ML training loop so dataset growth can be measured.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline

from src.eval.payment_dataset import DEFAULT_DATASET_DIR, export_ml_jsonl


DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "payment_classifier"


@dataclass(frozen=True)
class PaymentMLRecord:
    filename: str
    text: str
    label: str
    binary_label: str
    payment_decision: str
    scenario: str
    source_type: str
    split: str


@dataclass(frozen=True)
class PaymentMLMetrics:
    model_path: Path
    metrics_path: Path
    dataset_path: Path
    target: str
    train_rows: int
    validation_rows: int
    test_rows: int
    classes: list[str]
    test_accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    classification_report: dict


def load_payment_ml_records(path: Path) -> list[PaymentMLRecord]:
    records: list[PaymentMLRecord] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            records.append(
                PaymentMLRecord(
                    filename=row["filename"],
                    text=row["text"],
                    label=row["label"],
                    binary_label=row["binary_label"],
                    payment_decision=row["payment_decision"],
                    scenario=row["scenario"],
                    source_type=row["source_type"],
                    split=row.get("split") or "unassigned",
                )
            )
    return records


def _records_for_split(records: list[PaymentMLRecord], split: str) -> list[PaymentMLRecord]:
    return [record for record in records if record.split == split]


def _fallback_split(records: list[PaymentMLRecord]) -> tuple[list[PaymentMLRecord], list[PaymentMLRecord], list[PaymentMLRecord]]:
    ordered = sorted(records, key=lambda record: record.filename)
    train: list[PaymentMLRecord] = []
    validation: list[PaymentMLRecord] = []
    test: list[PaymentMLRecord] = []
    by_class: dict[str, list[PaymentMLRecord]] = {}
    for record in ordered:
        by_class.setdefault(record.payment_decision, []).append(record)
    for class_records in by_class.values():
        total = len(class_records)
        for index, record in enumerate(class_records):
            ratio = index / max(total, 1)
            if ratio < 0.8:
                train.append(record)
            elif ratio < 0.9:
                validation.append(record)
            else:
                test.append(record)
    return train, validation, test


def split_records(records: list[PaymentMLRecord]) -> tuple[list[PaymentMLRecord], list[PaymentMLRecord], list[PaymentMLRecord]]:
    train = _records_for_split(records, "train")
    validation = _records_for_split(records, "validation")
    test = _records_for_split(records, "test")
    if train and test:
        return train, validation, test
    return _fallback_split(records)


def _target_values(records: list[PaymentMLRecord], target: str) -> list[str]:
    if target == "payment_decision":
        return [record.payment_decision for record in records]
    if target == "binary_label":
        return [record.binary_label for record in records]
    raise ValueError("target must be payment_decision or binary_label")


def _texts(records: list[PaymentMLRecord]) -> list[str]:
    return [record.text for record in records]


def _confusion_as_dict(classes: list[str], expected: list[str], predicted: list[str]) -> dict[str, dict[str, int]]:
    matrix = confusion_matrix(expected, predicted, labels=classes)
    result: dict[str, dict[str, int]] = {}
    for row_index, expected_label in enumerate(classes):
        row = {}
        for col_index, predicted_label in enumerate(classes):
            count = int(matrix[row_index][col_index])
            if count:
                row[predicted_label] = count
        result[expected_label] = row
    return result


def _build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=5000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def train_payment_classifier(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    output_dir: Path = DEFAULT_MODEL_DIR,
    *,
    target: str = "payment_decision",
    ml_jsonl: Optional[Path] = None,
) -> PaymentMLMetrics:
    dataset_dir = Path(dataset_dir)
    output_dir = Path(output_dir)
    ml_jsonl = ml_jsonl or export_ml_jsonl(dataset_dir).output_path
    records = load_payment_ml_records(ml_jsonl)
    if not records:
        raise ValueError("payment ML dataset has no rows")

    train, validation, test = split_records(records)
    if not train or not test:
        raise ValueError("payment ML dataset needs train and test rows")

    y_train = _target_values(train, target)
    y_test = _target_values(test, target)
    class_counts = Counter(y_train)
    if len(class_counts) < 2:
        raise ValueError(f"training split needs at least two classes, got {dict(class_counts)}")

    model = _build_pipeline()
    model.fit(_texts(train), y_train)
    predicted = model.predict(_texts(test)).tolist()
    classes = sorted(set(y_train) | set(y_test) | set(predicted))

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / f"{target}_model.joblib"
    metrics_path = output_dir / f"{target}_metrics.json"
    joblib.dump(model, model_path)

    report = classification_report(
        y_test,
        predicted,
        labels=classes,
        output_dict=True,
        zero_division=0,
    )
    metrics = PaymentMLMetrics(
        model_path=model_path,
        metrics_path=metrics_path,
        dataset_path=Path(ml_jsonl),
        target=target,
        train_rows=len(train),
        validation_rows=len(validation),
        test_rows=len(test),
        classes=classes,
        test_accuracy=round(float(accuracy_score(y_test, predicted)), 3),
        confusion_matrix=_confusion_as_dict(classes, y_test, predicted),
        classification_report=report,
    )
    payload = asdict(metrics)
    payload["model_path"] = str(metrics.model_path)
    payload["metrics_path"] = str(metrics.metrics_path)
    payload["dataset_path"] = str(metrics.dataset_path)
    metrics_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metrics

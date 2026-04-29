"""
Train and evaluate a baseline generic phishing classifier.

This module is intentionally small and reproducible. It consumes the
ML-ready corpus emitted by ``scripts/eval_prepare_corpus.py`` and writes
ignored model artifacts under ``models/phishing_classifier/``.
"""
from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS_DIR = PROJECT_ROOT / "data" / "eval_corpus"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / "phishing_classifier"
ALLOWED_LABELS = {"CLEAN", "PHISHING"}


@dataclass(frozen=True)
class PhishingMLRecord:
    filename: str
    text: str
    label: str
    source_corpus: str
    source_path: str
    split: str = "unassigned"


@dataclass(frozen=True)
class PhishingMLMetrics:
    model_path: Path
    metrics_path: Path
    corpus_dir: Path
    labels_path: Path
    train_rows: int
    validation_rows: int
    test_rows: int
    classes: list[str]
    test_accuracy: float
    confusion_matrix: dict[str, dict[str, int]]
    classification_report: dict
    by_source_corpus: dict[str, int]
    by_split: dict[str, int]


def _email_text_for_ml(sample_path: Path) -> str:
    message = BytesParser(policy=policy.default).parsebytes(sample_path.read_bytes())
    sections: list[str] = []
    for header in ("Subject", "From", "Reply-To", "To"):
        value = message.get(header)
        if value:
            sections.append(f"{header}: {value}")

    body_chunks: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        try:
            body_chunks.append(str(part.get_content()))
        except LookupError:
            payload = part.get_payload(decode=True) or b""
            body_chunks.append(payload.decode("utf-8", errors="replace"))

    body = "\n".join(chunk.strip() for chunk in body_chunks if chunk.strip())
    if body:
        sections.append(f"Body:\n{body}")
    return "\n\n".join(sections).strip()


def load_phishing_ml_records(
    corpus_dir: Path = DEFAULT_CORPUS_DIR,
    labels_csv: Optional[Path] = None,
) -> list[PhishingMLRecord]:
    corpus_dir = Path(corpus_dir)
    labels_csv = Path(labels_csv) if labels_csv else corpus_dir / "labels.csv"
    if not labels_csv.exists():
        raise FileNotFoundError(f"labels.csv not found: {labels_csv}")

    records: list[PhishingMLRecord] = []
    with labels_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            filename = row.get("filename", "")
            label = row.get("label", "")
            if label not in ALLOWED_LABELS:
                raise ValueError(f"label must be one of {sorted(ALLOWED_LABELS)}, got {label!r}")
            sample_path = corpus_dir / filename
            if not sample_path.exists():
                raise FileNotFoundError(f"sample file not found: {sample_path}")
            records.append(
                PhishingMLRecord(
                    filename=filename,
                    text=_email_text_for_ml(sample_path),
                    label=label,
                    source_corpus=row.get("source_corpus", ""),
                    source_path=row.get("source_path", ""),
                    split=row.get("split") or "unassigned",
                )
            )
    return records


def split_records(
    records: list[PhishingMLRecord],
    *,
    seed: int = 42,
    train_ratio: float = 0.8,
    validation_ratio: float = 0.1,
) -> tuple[list[PhishingMLRecord], list[PhishingMLRecord], list[PhishingMLRecord]]:
    explicit_train = [record for record in records if record.split == "train"]
    explicit_validation = [record for record in records if record.split == "validation"]
    explicit_test = [record for record in records if record.split == "test"]
    if explicit_train and explicit_test:
        return explicit_train, explicit_validation, explicit_test

    rng = random.Random(seed)
    train: list[PhishingMLRecord] = []
    validation: list[PhishingMLRecord] = []
    test: list[PhishingMLRecord] = []
    by_label: dict[str, list[PhishingMLRecord]] = defaultdict(list)
    for record in records:
        by_label[record.label].append(record)

    for label_records in by_label.values():
        shuffled = list(label_records)
        rng.shuffle(shuffled)
        total = len(shuffled)
        if total < 2:
            train.extend(shuffled)
            continue
        train_cutoff = max(1, int(total * train_ratio))
        validation_cutoff = min(total - 1, train_cutoff + int(total * validation_ratio))
        train.extend(shuffled[:train_cutoff])
        validation.extend(shuffled[train_cutoff:validation_cutoff])
        test.extend(shuffled[validation_cutoff:])

    return train, validation, test


def _build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    max_features=20000,
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


def train_phishing_classifier(
    corpus_dir: Path = DEFAULT_CORPUS_DIR,
    output_dir: Path = DEFAULT_MODEL_DIR,
    *,
    labels_csv: Optional[Path] = None,
    seed: int = 42,
) -> PhishingMLMetrics:
    corpus_dir = Path(corpus_dir)
    labels_path = Path(labels_csv) if labels_csv else corpus_dir / "labels.csv"
    output_dir = Path(output_dir)
    records = load_phishing_ml_records(corpus_dir, labels_path)
    if not records:
        raise ValueError("phishing ML corpus has no rows")

    train, validation, test = split_records(records, seed=seed)
    if not train or not test:
        raise ValueError("phishing ML corpus needs train and test rows")

    y_train = [record.label for record in train]
    y_test = [record.label for record in test]
    if len(set(y_train)) < 2:
        raise ValueError("training split needs at least two classes")

    model = _build_pipeline()
    model.fit([record.text for record in train], y_train)
    predicted = model.predict([record.text for record in test]).tolist()
    classes = sorted(set(y_train) | set(y_test) | set(predicted))

    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "phishing_model.joblib"
    metrics_path = output_dir / "phishing_metrics.json"
    joblib.dump(model, model_path)

    metrics = PhishingMLMetrics(
        model_path=model_path,
        metrics_path=metrics_path,
        corpus_dir=corpus_dir,
        labels_path=labels_path,
        train_rows=len(train),
        validation_rows=len(validation),
        test_rows=len(test),
        classes=classes,
        test_accuracy=round(float(accuracy_score(y_test, predicted)), 3),
        confusion_matrix=_confusion_as_dict(classes, y_test, predicted),
        classification_report=classification_report(
            y_test,
            predicted,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
        by_source_corpus=dict(sorted(Counter(record.source_corpus for record in records).items())),
        by_split={
            "train": len(train),
            "validation": len(validation),
            "test": len(test),
        },
    )

    payload = asdict(metrics)
    payload["model_path"] = str(metrics.model_path)
    payload["metrics_path"] = str(metrics.metrics_path)
    payload["corpus_dir"] = str(metrics.corpus_dir)
    payload["labels_path"] = str(metrics.labels_path)
    metrics_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metrics

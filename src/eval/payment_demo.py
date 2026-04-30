"""
Demo helpers for the Payment Scam Firewall.

The demo intentionally runs the same payment analyzer against labeled dataset
samples instead of using canned strings. That keeps the output connected to the
auditable dataset workflow.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from src.analyzers.payment_fraud import PaymentFraudAnalyzer
from src.eval.payment_dataset import (
    DEFAULT_DATASET_DIR,
    LABELS_CSV,
    SAMPLES_DIR,
    validate_dataset,
)
from src.extractors.eml_parser import EMLParser


DEMO_DECISIONS = ("SAFE", "VERIFY", "DO_NOT_PAY")
SOURCE_PRIORITY = {
    "redacted": 0,
    "public": 1,
    "internal": 2,
    "synthetic": 3,
    "real": 4,
}
SPLIT_PRIORITY = {
    "holdout": 0,
    "test": 1,
    "validation": 2,
    "train": 3,
    "unassigned": 4,
}


@dataclass(frozen=True)
class PaymentDemoRow:
    filename: str
    expected_decision: str
    predicted_decision: str
    scenario: str
    source_type: str
    split: str
    risk_score: float
    confidence: float
    signals: list[str]

    @property
    def match(self) -> bool:
        return self.expected_decision == self.predicted_decision


def read_payment_labels(dataset_dir: Path = DEFAULT_DATASET_DIR) -> list[dict[str, str]]:
    labels_path = Path(dataset_dir) / LABELS_CSV
    with labels_path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _demo_sort_key(row: dict[str, str]) -> tuple[int, int, int, str]:
    pii_rank = 0 if row.get("contains_real_pii") == "no" else 1
    source_rank = SOURCE_PRIORITY.get(row.get("source_type", ""), 99)
    split_rank = SPLIT_PRIORITY.get(row.get("split", ""), 99)
    return pii_rank, source_rank, split_rank, row.get("filename", "")


def select_demo_label_rows(
    rows: list[dict[str, str]],
    *,
    limit_per_decision: int = 1,
    decisions: tuple[str, ...] = DEMO_DECISIONS,
) -> list[dict[str, str]]:
    if limit_per_decision < 1:
        raise ValueError("limit_per_decision must be at least 1")

    selected: list[dict[str, str]] = []
    for decision in decisions:
        candidates = [
            row for row in rows
            if row.get("payment_decision") == decision
        ]
        selected.extend(sorted(candidates, key=_demo_sort_key)[:limit_per_decision])
    return selected


def _signal_names(details: dict) -> list[str]:
    names: list[str] = []
    for signal in details.get("signals", []):
        if isinstance(signal, dict):
            name = signal.get("name")
        else:
            name = getattr(signal, "name", None)
        if name:
            names.append(str(name))
    return names


async def run_payment_demo(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    *,
    limit_per_decision: int = 1,
) -> list[PaymentDemoRow]:
    dataset_dir = Path(dataset_dir)
    validation = validate_dataset(dataset_dir)
    if validation.errors:
        raise ValueError("payment dataset is invalid: " + "; ".join(validation.errors[:5]))

    selected = select_demo_label_rows(
        read_payment_labels(dataset_dir),
        limit_per_decision=limit_per_decision,
    )
    selected_decisions = {row.get("payment_decision") for row in selected}
    missing = [decision for decision in DEMO_DECISIONS if decision not in selected_decisions]
    if missing:
        raise ValueError("dataset has no demo row for: " + ", ".join(missing))

    parser = EMLParser()
    analyzer = PaymentFraudAnalyzer()
    demo_rows: list[PaymentDemoRow] = []
    for row in selected:
        sample_path = dataset_dir / SAMPLES_DIR / row["filename"]
        email = parser.parse_file(sample_path)
        if email is None:
            raise ValueError(f"failed to parse payment sample: {sample_path}")

        result = await analyzer.analyze(email)
        details = result.details
        demo_rows.append(
            PaymentDemoRow(
                filename=row["filename"],
                expected_decision=row["payment_decision"],
                predicted_decision=str(details.get("decision", "ERROR")),
                scenario=row["scenario"],
                source_type=row["source_type"],
                split=row["split"],
                risk_score=round(float(result.risk_score), 3),
                confidence=round(float(result.confidence), 3),
                signals=_signal_names(details)[:4],
            )
        )
    return demo_rows


def format_payment_demo_table(rows: list[PaymentDemoRow]) -> str:
    headers = ["Expected", "Predicted", "Risk", "Conf", "Source", "Split", "Scenario", "Signals"]
    body = [
        [
            row.expected_decision,
            row.predicted_decision,
            f"{row.risk_score:.3f}",
            f"{row.confidence:.3f}",
            row.source_type,
            row.split,
            row.scenario,
            ", ".join(row.signals) or "-",
        ]
        for row in rows
    ]
    widths = [
        max(len(str(item)) for item in column)
        for column in zip(headers, *body)
    ]
    lines = [
        "  ".join(value.ljust(width) for value, width in zip(headers, widths)),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(value.ljust(width) for value, width in zip(row, widths))
        for row in body
    )
    return "\n".join(lines)

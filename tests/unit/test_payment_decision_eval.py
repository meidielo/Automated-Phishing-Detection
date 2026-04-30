from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.eval.payment_dataset import add_sample, init_dataset, seed_synthetic_bank_change_dataset
from src.eval.payment_decision_eval import evaluate_payment_decisions


def _write_eml(path: Path, subject: str, body: str) -> Path:
    path.write_text(
        "\n".join(
            [
                "From: accounts@supplier.example",
                "To: ap@example.com",
                f"Subject: {subject}",
                "",
                body,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.asyncio
async def test_payment_decision_eval_writes_reports_for_seed_dataset(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        seed=1337,
        clean=True,
    )

    summary = await evaluate_payment_decisions(dataset)

    assert summary.row_count == 20
    assert summary.correct == 20
    assert summary.mismatches == 0
    assert summary.accuracy == 1.0
    assert summary.confusion_matrix == {
        "DO_NOT_PAY": {"DO_NOT_PAY": 10},
        "VERIFY": {"VERIFY": 10},
    }
    assert summary.by_source_type == {
        "synthetic": {
            "accuracy": 1.0,
            "correct": 20,
            "mismatches": 0,
            "rows": 20,
        }
    }
    assert set(summary.by_split) == {"test", "train", "validation"}
    assert summary.json_path and summary.json_path.exists()
    assert summary.csv_path and summary.csv_path.exists()
    assert summary.markdown_path and summary.markdown_path.exists()

    payload = json.loads(summary.json_path.read_text(encoding="utf-8"))
    assert payload["accuracy"] == 1.0
    assert payload["by_source_type"]["synthetic"]["rows"] == 20
    assert len(payload["rows"]) == 20

    with summary.csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 20
    assert "source_type" in rows[0]
    markdown = summary.markdown_path.read_text(encoding="utf-8")
    assert "Accuracy By Source Type" in markdown
    assert "Accuracy By Split" in markdown
    assert "No mismatches." in markdown


@pytest.mark.asyncio
async def test_payment_decision_eval_can_filter_split(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        safe_count=10,
        seed=1337,
        clean=True,
    )

    summary = await evaluate_payment_decisions(dataset, split="test")

    assert summary.row_count == 3
    assert summary.by_split == {
        "test": {
            "accuracy": 1.0,
            "correct": 3,
            "mismatches": 0,
            "rows": 3,
        }
    }
    assert {row.split for row in summary.rows} == {"test"}


@pytest.mark.asyncio
async def test_payment_decision_eval_reports_mismatch(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(
        tmp_path / "non_payment.eml",
        subject="Team meeting",
        body="Reminder for the planning meeting tomorrow.",
    )
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
        source_type="synthetic",
        split="test",
        contains_real_pii="no",
    )

    summary = await evaluate_payment_decisions(dataset)

    assert summary.row_count == 1
    assert summary.correct == 0
    assert summary.mismatches == 1
    assert summary.confusion_matrix == {"DO_NOT_PAY": {"SAFE": 1}}
    assert summary.rows[0].predicted_decision == "SAFE"

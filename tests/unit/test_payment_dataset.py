from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.eval.payment_dataset import (
    add_sample,
    export_eval_labels,
    init_dataset,
    seed_synthetic_bank_change_dataset,
    validate_dataset,
)


def _write_eml(path: Path, subject: str = "Invoice") -> Path:
    path.write_text(
        "\n".join(
            [
                "From: accounts@supplier.example",
                "To: ap@example.com",
                f"Subject: {subject}",
                "",
                "Please process the attached invoice.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_init_dataset_creates_structure(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")

    assert (dataset / "samples").is_dir()
    assert (dataset / "incoming").is_dir()
    assert (dataset / "exports").is_dir()
    assert (dataset / "reports").is_dir()
    assert (dataset / "labels.csv").exists()
    assert (dataset / "README.md").exists()


def test_add_sample_validates_and_exports_eval_labels(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(tmp_path / "invoice.eml")

    target = add_sample(
        dataset_dir=dataset,
        source=sample,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
        source_type="synthetic",
        split="train",
        verified_by="test",
        contains_real_pii="no",
        notes="unit test",
    )

    assert target.exists()
    result = validate_dataset(dataset)
    assert result.ok
    assert result.row_count == 1

    labels_path = export_eval_labels(dataset)
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    assert labels == {target.name: "PHISHING"}

    with (dataset / "labels.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["payment_decision"] == "DO_NOT_PAY"


def test_validate_catches_missing_file_and_bad_label(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    (dataset / "labels.csv").write_text(
        "filename,label,payment_decision,scenario,source_type,split,verified_by,contains_real_pii,notes\n"
        "missing.eml,BAD,SAFE,non_payment,real,train,,,bad\n",
        encoding="utf-8",
    )

    result = validate_dataset(dataset)

    assert not result.ok
    assert any("sample file not found" in error for error in result.errors)
    assert any("label must be one of" in error for error in result.errors)


def test_add_sample_rejects_payment_scam_with_safe_decision(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(tmp_path / "invoice.eml")

    target = add_sample(
        dataset_dir=dataset,
        source=sample,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
    )
    assert target.exists()

    rows = list(csv.DictReader((dataset / "labels.csv").open("r", encoding="utf-8", newline="")))
    rows[0]["payment_decision"] = "SAFE"
    with (dataset / "labels.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    result = validate_dataset(dataset)

    assert not result.ok
    assert any("PAYMENT_SCAM cannot have SAFE" in error for error in result.errors)


def test_add_sample_rejects_non_eml(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = tmp_path / "invoice.txt"
    sample.write_text("not eml", encoding="utf-8")

    with pytest.raises(ValueError, match="must be .eml"):
        add_sample(
            dataset_dir=dataset,
            source=sample,
            label="PAYMENT_SCAM",
            payment_decision="DO_NOT_PAY",
            scenario="bank_detail_change",
        )


def test_seed_synthetic_bank_change_dataset_creates_balanced_seed(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"

    summary = seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=4,
        legit_count=4,
        seed=7,
        clean=True,
    )

    assert summary.total_count == 8
    result = validate_dataset(dataset)
    assert result.ok
    assert result.row_count == 8
    assert summary.eval_labels_path.exists()

    labels = json.loads(summary.eval_labels_path.read_text(encoding="utf-8"))
    assert sorted(labels.values()).count("PHISHING") == 4
    assert sorted(labels.values()).count("CLEAN") == 4

    with (dataset / "labels.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {row["source_type"] for row in rows} == {"synthetic"}
    assert {row["contains_real_pii"] for row in rows} == {"no"}
    assert {row["payment_decision"] for row in rows} == {"DO_NOT_PAY", "VERIFY"}
    assert all((dataset / "samples" / row["filename"]).exists() for row in rows)


def test_seed_synthetic_clean_requires_payment_dataset_name(tmp_path: Path):
    unsafe_dataset = tmp_path / "not_the_dataset"
    unsafe_dataset.mkdir()

    with pytest.raises(ValueError, match="non-payment dataset"):
        seed_synthetic_bank_change_dataset(
            dataset_dir=unsafe_dataset,
            scam_count=1,
            legit_count=1,
            clean=True,
        )

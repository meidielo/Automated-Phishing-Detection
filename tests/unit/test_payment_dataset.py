from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from src.eval.payment_dataset import (
    add_sample,
    audit_dataset_pii,
    export_ml_jsonl,
    export_eval_labels,
    init_dataset,
    redact_eml,
    scan_redaction_findings,
    seed_public_advisory_payment_examples,
    seed_synthetic_bank_change_dataset,
    summarize_dataset_readiness,
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


def test_seed_synthetic_can_add_safe_invoice_class(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"

    summary = seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=4,
        legit_count=4,
        safe_count=4,
        seed=7,
        clean=True,
    )

    assert summary.safe_count == 4
    assert summary.total_count == 12

    with (dataset / "labels.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {row["payment_decision"] for row in rows} == {"DO_NOT_PAY", "SAFE", "VERIFY"}
    safe_rows = [row for row in rows if row["payment_decision"] == "SAFE"]
    assert {row["scenario"] for row in safe_rows} == {"legitimate_invoice"}
    assert {row["label"] for row in safe_rows} == {"LEGITIMATE_PAYMENT"}


def test_seed_public_advisory_payment_examples_adds_realish_decisions(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"

    summary = seed_public_advisory_payment_examples(
        dataset_dir=dataset,
        do_not_pay_count=10,
        verify_count=10,
    )

    assert summary.total_count == 20
    assert summary.scam_count == 10
    assert summary.legitimate_count == 10
    result = validate_dataset(dataset)
    assert result.ok
    assert audit_dataset_pii(dataset) == []

    with (dataset / "labels.csv").open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {row["source_type"] for row in rows} == {"public"}
    assert {row["contains_real_pii"] for row in rows} == {"no"}
    assert {row["payment_decision"] for row in rows} == {"DO_NOT_PAY", "VERIFY"}
    assert {row["label"] for row in rows} == {"LEGITIMATE_PAYMENT", "PAYMENT_SCAM"}
    assert {row["split"] for row in rows} == {"train", "validation", "test"}


def test_public_advisory_seed_can_satisfy_decision_readiness_with_safe_samples(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment_scam_dataset_seed")
    safe_sample = _write_eml(tmp_path / "safe_invoice.eml")
    safe_sample.write_text(
        "\n".join(
            [
                "From: Billing <billing@supplier.example>",
                "To: AP <accounts-payable@demo-business.example>",
                "Subject: Routine invoice",
                "",
                "Invoice INV-0000 is ready in the saved supplier portal.",
                "No bank details have changed.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    add_sample(
        dataset_dir=dataset,
        source=safe_sample,
        label="LEGITIMATE_PAYMENT",
        payment_decision="SAFE",
        scenario="legitimate_invoice",
        source_type="redacted",
        split="train",
        contains_real_pii="no",
    )

    seed_public_advisory_payment_examples(
        dataset_dir=dataset,
        do_not_pay_count=10,
        verify_count=10,
    )

    report = summarize_dataset_readiness(dataset, min_realish_samples=20)

    assert report.realish_count == 21
    assert report.pii_free_realish_count == 21
    assert report.by_payment_decision == {"DO_NOT_PAY": 10, "SAFE": 1, "VERIFY": 10}
    assert report.recommendations == []
    assert report.ready_for_product_metrics


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


def test_redact_eml_removes_obvious_payment_pii(tmp_path: Path):
    source = tmp_path / "raw_payment.eml"
    source.write_text(
        "\n".join(
            [
                "From: Jane Supplier <jane@supplier-real.com>",
                "To: Alex AP <alex@buyer-real.com>",
                "Reply-To: payment-team@gmail.com",
                "Subject: Invoice INV-98231 bank details",
                "",
                "Please pay AUD $18,750.00 for invoice INV-98231.",
                "New BSB: 123-456",
                "Account number: 987654321",
                "Call +61 412 345 678 if needed.",
                "Portal: https://supplier-real.com/pay?id=secret",
                "",
            ]
        ),
        encoding="utf-8",
    )
    output = tmp_path / "redacted.eml"

    summary = redact_eml(source, output)

    text = output.read_text(encoding="utf-8")
    assert summary.findings_after == 0
    assert "supplier-real.com" not in text
    assert "buyer-real.com" not in text
    assert "gmail.com" not in text
    assert "123-456" not in text
    assert "987654321" not in text
    assert "+61 412 345 678" not in text
    assert "mailbox1@domain1.example" in text
    assert "mailbox3@domain3.example" in text
    assert "000-000" in text
    assert "account number: 00000000" in text.lower()
    assert scan_redaction_findings(output) == []


def test_validate_flags_redacted_sample_with_obvious_pii(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(tmp_path / "invoice.eml")
    sample.write_text(
        "\n".join(
            [
                "From: Jane <jane@real-supplier.com>",
                "To: ap@example.com",
                "Subject: Bank details",
                "",
                "Use BSB 123-456 and account number 123456789.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
        source_type="redacted",
        split="train",
        contains_real_pii="no",
    )

    result = validate_dataset(dataset)

    assert not result.ok
    assert any("PII audit found" in error for error in result.errors)


def test_export_ml_jsonl_writes_redacted_training_rows(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=2,
        legit_count=2,
        seed=7,
        clean=True,
    )

    summary = export_ml_jsonl(dataset)

    rows = [
        json.loads(line)
        for line in summary.output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert summary.row_count == 4
    assert len(rows) == 4
    assert {row["binary_label"] for row in rows} == {"PHISHING", "CLEAN"}
    assert {row["payment_decision"] for row in rows} == {"DO_NOT_PAY", "VERIFY"}
    assert all(row["text"] for row in rows)


def test_export_ml_jsonl_refuses_rows_not_marked_pii_free(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(tmp_path / "invoice.eml")
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="LEGITIMATE_PAYMENT",
        payment_decision="VERIFY",
        scenario="legitimate_invoice",
        source_type="real",
        split="train",
        contains_real_pii="unknown",
    )

    with pytest.raises(ValueError, match="contains_real_pii=no"):
        export_ml_jsonl(dataset)


def test_readiness_flags_synthetic_only_dataset(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=2,
        legit_count=2,
        seed=7,
        clean=True,
    )

    report = summarize_dataset_readiness(dataset, min_realish_samples=2)

    assert report.row_count == 4
    assert report.by_source_type == {"synthetic": 4}
    assert report.realish_count == 0
    assert not report.ready_for_product_metrics
    assert any("redacted real/public/internal" in item for item in report.recommendations)


def test_readiness_counts_redacted_realish_samples(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    sample = _write_eml(tmp_path / "invoice.eml")
    add_sample(
        dataset_dir=dataset,
        source=sample,
        label="LEGITIMATE_PAYMENT",
        payment_decision="SAFE",
        scenario="legitimate_invoice",
        source_type="redacted",
        split="train",
        contains_real_pii="no",
    )

    report = summarize_dataset_readiness(dataset, min_realish_samples=1)

    assert report.realish_count == 1
    assert report.pii_free_realish_count == 1
    assert report.by_source_type["redacted"] == 1
    assert any("non-synthetic examples" in item for item in report.recommendations)
    assert not report.ready_for_product_metrics

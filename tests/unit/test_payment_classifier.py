from __future__ import annotations

import json
from pathlib import Path

import joblib
import pytest

from src.eval.payment_dataset import (
    init_dataset,
    seed_public_advisory_payment_examples,
    seed_synthetic_bank_change_dataset,
)
from src.ml.payment_classifier import (
    load_payment_ml_records,
    predict_payment_decision,
    split_records,
    train_payment_classifier,
)


def test_train_payment_classifier_on_seed_dataset(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        seed=1337,
        clean=True,
    )

    metrics = train_payment_classifier(dataset_dir=dataset, output_dir=tmp_path / "model")

    assert metrics.train_rows == 16
    assert metrics.validation_rows == 2
    assert metrics.test_rows == 2
    assert metrics.holdout_rows == 0
    assert metrics.holdout_accuracy is None
    assert metrics.classes == ["DO_NOT_PAY", "VERIFY"]
    assert metrics.test_accuracy == 1.0
    assert metrics.model_path.exists()
    assert metrics.metrics_path.exists()
    assert metrics.confusion_matrix == {
        "DO_NOT_PAY": {"DO_NOT_PAY": 1},
        "VERIFY": {"VERIFY": 1},
    }

    payload = json.loads(metrics.metrics_path.read_text(encoding="utf-8"))
    assert payload["test_accuracy"] == 1.0
    assert payload["holdout_rows"] == 0
    model = joblib.load(metrics.model_path)
    prediction = model.predict(["urgent updated bank details do not use the old account"])[0]
    assert prediction in {"DO_NOT_PAY", "VERIFY"}


def test_train_binary_classifier_on_seed_dataset(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        seed=1337,
        clean=True,
    )

    metrics = train_payment_classifier(
        dataset_dir=dataset,
        output_dir=tmp_path / "model",
        target="binary_label",
    )

    assert metrics.classes == ["CLEAN", "PHISHING"]
    assert metrics.test_accuracy == 1.0


def test_train_payment_classifier_requires_rows(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")

    with pytest.raises(ValueError, match="no rows"):
        train_payment_classifier(dataset_dir=dataset, output_dir=tmp_path / "model")


def test_train_payment_classifier_supports_safe_class(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        safe_count=10,
        seed=1337,
        clean=True,
    )

    metrics = train_payment_classifier(dataset_dir=dataset, output_dir=tmp_path / "model")

    assert metrics.classes == ["DO_NOT_PAY", "SAFE", "VERIFY"]
    assert metrics.confusion_matrix["SAFE"]["SAFE"] >= 1
    prediction = predict_payment_decision(
        "invoice matches purchase order and does not change any payment details",
        model_path=metrics.model_path,
    )
    assert prediction.decision in {"DO_NOT_PAY", "SAFE", "VERIFY"}
    assert set(prediction.class_probabilities) == {"DO_NOT_PAY", "SAFE", "VERIFY"}


def test_train_payment_classifier_reports_holdout_without_training_on_it(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        safe_count=10,
        seed=1337,
        clean=True,
    )
    seed_public_advisory_payment_examples(
        dataset_dir=dataset,
        do_not_pay_count=0,
        verify_count=0,
        holdout_do_not_pay_count=2,
        holdout_verify_count=2,
    )

    metrics = train_payment_classifier(dataset_dir=dataset, output_dir=tmp_path / "model")

    assert metrics.train_rows == 24
    assert metrics.test_rows == 3
    assert metrics.holdout_rows == 4
    assert metrics.holdout_accuracy is not None
    assert metrics.holdout_confusion_matrix


def test_split_records_falls_back_when_no_explicit_test(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset_seed"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=10,
        legit_count=10,
        seed=1337,
        clean=True,
    )
    # Exercise the fallback through exported rows with splits rewritten to unassigned.
    from src.eval.payment_dataset import export_ml_jsonl

    export = export_ml_jsonl(dataset)
    lines = []
    for line in export.output_path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row["split"] = "unassigned"
        lines.append(json.dumps(row))
    fallback_jsonl = tmp_path / "fallback.jsonl"
    fallback_jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records = load_payment_ml_records(fallback_jsonl)
    train, validation, test = split_records(records)

    assert len(train) == 16
    assert len(validation) == 2
    assert len(test) == 2

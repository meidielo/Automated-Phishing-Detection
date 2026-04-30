from __future__ import annotations

from pathlib import Path

import pytest

from src.eval.payment_dataset import seed_synthetic_bank_change_dataset
from src.eval.payment_demo import run_payment_demo, select_demo_label_rows


def _label_row(
    filename: str,
    decision: str,
    source_type: str,
    split: str,
    pii: str = "no",
) -> dict[str, str]:
    return {
        "filename": filename,
        "label": "LEGITIMATE_PAYMENT" if decision != "DO_NOT_PAY" else "PAYMENT_SCAM",
        "payment_decision": decision,
        "scenario": "legitimate_invoice",
        "source_type": source_type,
        "split": split,
        "verified_by": "test",
        "contains_real_pii": pii,
        "notes": "",
    }


def test_select_demo_rows_prefers_pii_free_public_or_redacted_samples():
    rows = [
        _label_row("safe-real.eml", "SAFE", "real", "train", pii="yes"),
        _label_row("safe-redacted.eml", "SAFE", "redacted", "test"),
        _label_row("verify-synthetic.eml", "VERIFY", "synthetic", "train"),
        _label_row("verify-public.eml", "VERIFY", "public", "holdout"),
        _label_row("block-synthetic.eml", "DO_NOT_PAY", "synthetic", "test"),
        _label_row("block-public.eml", "DO_NOT_PAY", "public", "holdout"),
    ]

    selected = select_demo_label_rows(rows)

    assert [row["filename"] for row in selected] == [
        "safe-redacted.eml",
        "verify-public.eml",
        "block-public.eml",
    ]


@pytest.mark.asyncio
async def test_run_payment_demo_uses_dataset_samples(tmp_path: Path):
    dataset = tmp_path / "payment_scam_dataset"
    seed_synthetic_bank_change_dataset(
        dataset_dir=dataset,
        scam_count=6,
        legit_count=6,
        safe_count=6,
        seed=1337,
        clean=True,
    )

    rows = await run_payment_demo(dataset)

    assert {row.expected_decision for row in rows} == {"SAFE", "VERIFY", "DO_NOT_PAY"}
    assert all(row.match for row in rows)

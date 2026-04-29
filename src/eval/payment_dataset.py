"""
Utilities for building a payment-scam dataset.

This dataset is separate from the generic phishing corpus because invoice
fraud and BEC need business-decision labels, not only PHISHING/CLEAN.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from typing import Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "payment_scam_dataset"

LABELS_CSV = "labels.csv"
MANIFEST_JSONL = "manifest.jsonl"
SAMPLES_DIR = "samples"
INCOMING_DIR = "incoming"
EXPORTS_DIR = "exports"
REPORTS_DIR = "reports"

DATASET_COLUMNS = [
    "filename",
    "label",
    "payment_decision",
    "scenario",
    "source_type",
    "split",
    "verified_by",
    "contains_real_pii",
    "notes",
]

ALLOWED_LABELS = {"PAYMENT_SCAM", "LEGITIMATE_PAYMENT", "NON_PAYMENT"}
ALLOWED_DECISIONS = {"SAFE", "VERIFY", "DO_NOT_PAY"}
ALLOWED_SCENARIOS = {
    "bank_detail_change",
    "supplier_impersonation",
    "executive_transfer",
    "overdue_invoice",
    "fake_invoice_attachment",
    "payment_portal_link",
    "legitimate_invoice",
    "legitimate_bank_change_verified",
    "legitimate_remittance",
    "non_payment",
    "other",
}
ALLOWED_SOURCE_TYPES = {"real", "public", "synthetic", "redacted", "internal"}
ALLOWED_SPLITS = {"train", "validation", "test", "holdout", "unassigned"}


@dataclass(frozen=True)
class ValidationResult:
    errors: list[str]
    warnings: list[str]
    row_count: int

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class SeedSummary:
    dataset_dir: Path
    scam_count: int
    legitimate_count: int
    total_count: int
    labels_path: Path
    eval_labels_path: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dataset_readme() -> str:
    return """# Payment Scam Dataset

This ignored local dataset is for invoice fraud, supplier impersonation, BEC,
and legitimate payment email examples.

## Folders

- `incoming/`: drop raw `.eml` files here before labeling.
- `samples/`: labeled `.eml` files copied by `scripts/payment_dataset.py add`.
- `exports/`: generated eval labels and downstream ML exports.
- `reports/`: inspection reports and notes.

## Required labels

Each row in `labels.csv` has:

- `label`: `PAYMENT_SCAM`, `LEGITIMATE_PAYMENT`, or `NON_PAYMENT`
- `payment_decision`: expected business decision, one of `SAFE`, `VERIFY`, `DO_NOT_PAY`
- `scenario`: e.g. `bank_detail_change`, `supplier_impersonation`, `executive_transfer`, `legitimate_invoice`
- `source_type`: `real`, `public`, `synthetic`, `redacted`, or `internal`
- `split`: `train`, `validation`, `test`, `holdout`, or `unassigned`

## Collection rule

Keep real client or personal mail redacted. Do not commit this directory.
Use `PAYMENT_SCAM` only when the sample is confirmed malicious or deliberately
synthetic. Use `LEGITIMATE_PAYMENT` for normal invoices, remittances, and
verified bank-detail changes. Use `NON_PAYMENT` for clean business mail with no
payment context.

## Synthetic seed

Run this for a reproducible development set:

```bash
python scripts/payment_dataset.py seed-synthetic --dataset data/payment_scam_dataset --scam-count 50 --legit-count 50 --seed 1337 --clean
```

Synthetic samples are for pipeline development and ML plumbing only. Replace or
supplement them with redacted real examples before reporting product metrics.
"""


def init_dataset(dataset_dir: Path = DEFAULT_DATASET_DIR) -> Path:
    dataset_dir = Path(dataset_dir)
    for folder in (SAMPLES_DIR, INCOMING_DIR, EXPORTS_DIR, REPORTS_DIR):
        (dataset_dir / folder).mkdir(parents=True, exist_ok=True)

    labels_path = dataset_dir / LABELS_CSV
    if not labels_path.exists():
        with labels_path.open("w", encoding="utf-8", newline="") as fh:
            csv.DictWriter(fh, fieldnames=DATASET_COLUMNS).writeheader()

    manifest_path = dataset_dir / MANIFEST_JSONL
    manifest_path.touch(exist_ok=True)
    (dataset_dir / "README.md").write_text(_dataset_readme(), encoding="utf-8")
    return dataset_dir


def _read_labels(labels_path: Path) -> list[dict[str, str]]:
    if not labels_path.exists():
        return []
    with labels_path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _write_labels(labels_path: Path, rows: list[dict[str, str]]) -> None:
    with labels_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _read_manifest_rows(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists():
        return []
    rows = []
    with manifest_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def _write_manifest_rows(manifest_path: Path, rows: list[dict[str, str]]) -> None:
    with manifest_path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def _safe_filename(scenario: str, digest: str) -> str:
    scenario_part = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in scenario.lower())
    return f"payment_{scenario_part}_{digest[:12]}.eml"


def add_sample(
    dataset_dir: Path,
    source: Path,
    label: str,
    payment_decision: str,
    scenario: str,
    source_type: str = "real",
    split: str = "unassigned",
    verified_by: str = "",
    contains_real_pii: str = "unknown",
    notes: str = "",
) -> Path:
    dataset_dir = init_dataset(dataset_dir)
    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"sample not found: {source}")
    if source.suffix.lower() != ".eml":
        raise ValueError("payment dataset samples must be .eml files")

    _validate_value("label", label, ALLOWED_LABELS)
    _validate_value("payment_decision", payment_decision, ALLOWED_DECISIONS)
    _validate_value("scenario", scenario, ALLOWED_SCENARIOS)
    _validate_value("source_type", source_type, ALLOWED_SOURCE_TYPES)
    _validate_value("split", split, ALLOWED_SPLITS)

    digest = _sha256(source)
    filename = _safe_filename(scenario, digest)
    target = dataset_dir / SAMPLES_DIR / filename
    shutil.copy2(source, target)

    labels_path = dataset_dir / LABELS_CSV
    rows = [row for row in _read_labels(labels_path) if row.get("filename") != filename]
    rows.append(
        {
            "filename": filename,
            "label": label,
            "payment_decision": payment_decision,
            "scenario": scenario,
            "source_type": source_type,
            "split": split,
            "verified_by": verified_by,
            "contains_real_pii": contains_real_pii,
            "notes": notes,
        }
    )
    _write_labels(labels_path, rows)

    manifest = {
        "filename": filename,
        "source_path": str(source),
        "sha256": digest,
        "size_bytes": target.stat().st_size,
    }
    manifest_path = dataset_dir / MANIFEST_JSONL
    manifest_rows = [row for row in _read_manifest_rows(manifest_path) if row.get("filename") != filename]
    manifest_rows.append(manifest)
    _write_manifest_rows(manifest_path, manifest_rows)

    return target


def _validate_value(name: str, value: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}, got {value!r}")


def validate_dataset(dataset_dir: Path = DEFAULT_DATASET_DIR) -> ValidationResult:
    dataset_dir = Path(dataset_dir)
    labels_path = dataset_dir / LABELS_CSV
    errors: list[str] = []
    warnings: list[str] = []

    if not labels_path.exists():
        return ValidationResult(errors=[f"missing labels file: {labels_path}"], warnings=[], row_count=0)

    rows = _read_labels(labels_path)
    seen = set()
    for index, row in enumerate(rows, start=2):
        filename = row.get("filename", "")
        if not filename:
            errors.append(f"row {index}: missing filename")
            continue
        if filename in seen:
            errors.append(f"row {index}: duplicate filename {filename}")
        seen.add(filename)

        sample_path = dataset_dir / SAMPLES_DIR / filename
        if not sample_path.exists():
            errors.append(f"row {index}: sample file not found: {sample_path}")

        _collect_value_error(errors, index, "label", row.get("label", ""), ALLOWED_LABELS)
        _collect_value_error(
            errors,
            index,
            "payment_decision",
            row.get("payment_decision", ""),
            ALLOWED_DECISIONS,
        )
        _collect_value_error(errors, index, "scenario", row.get("scenario", ""), ALLOWED_SCENARIOS)
        _collect_value_error(errors, index, "source_type", row.get("source_type", ""), ALLOWED_SOURCE_TYPES)
        _collect_value_error(errors, index, "split", row.get("split", ""), ALLOWED_SPLITS)

        if row.get("label") == "PAYMENT_SCAM" and row.get("payment_decision") == "SAFE":
            errors.append(f"row {index}: PAYMENT_SCAM cannot have SAFE payment_decision")
        if row.get("label") == "NON_PAYMENT" and row.get("scenario") != "non_payment":
            warnings.append(f"row {index}: NON_PAYMENT usually uses scenario non_payment")

    if not rows:
        warnings.append("dataset has no labeled samples yet")

    return ValidationResult(errors=errors, warnings=warnings, row_count=len(rows))


def _collect_value_error(
    errors: list[str],
    row_index: int,
    name: str,
    value: str,
    allowed: set[str],
) -> None:
    if value not in allowed:
        errors.append(f"row {row_index}: {name} must be one of {sorted(allowed)}, got {value!r}")


def export_eval_labels(dataset_dir: Path = DEFAULT_DATASET_DIR, output: Optional[Path] = None) -> Path:
    dataset_dir = Path(dataset_dir)
    result = validate_dataset(dataset_dir)
    if not result.ok:
        raise ValueError("dataset validation failed: " + "; ".join(result.errors))

    output = output or (dataset_dir / EXPORTS_DIR / "labels.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    labels = {}
    for row in _read_labels(dataset_dir / LABELS_CSV):
        labels[row["filename"]] = "PHISHING" if row["label"] == "PAYMENT_SCAM" else "CLEAN"
    output.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def _assert_safe_clean_target(dataset_dir: Path) -> None:
    resolved = dataset_dir.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError(f"refusing to clean filesystem root: {resolved}")
    if resolved == Path.home().resolve():
        raise ValueError(f"refusing to clean home directory: {resolved}")
    if "payment_scam_dataset" not in resolved.name:
        raise ValueError(f"refusing to clean non-payment dataset path: {resolved}")


def _split_for_index(index: int, total: int) -> str:
    if total <= 1:
        return "train"
    ratio = index / total
    if ratio < 0.8:
        return "train"
    if ratio < 0.9:
        return "validation"
    return "test"


def _synthetic_message(
    subject: str,
    body: str,
    from_address: str,
    message_id: str,
    reply_to: str = "",
    auth_results: str = "",
) -> bytes:
    msg = EmailMessage()
    msg["From"] = from_address
    msg["To"] = "accounts-payable@demo-business.example"
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime(2026, 4, 29, 9, 0, 0, tzinfo=timezone.utc))
    msg["Message-ID"] = message_id
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth_results:
        msg["Authentication-Results"] = auth_results
    msg.set_content(body)
    return msg.as_bytes()


def _synthetic_scam_email(index: int, rng: random.Random) -> tuple[bytes, str]:
    suppliers = [
        "Northline Electrical",
        "BrightBuild Supplies",
        "Melbourne Office Fitouts",
        "Harbour Cleaning Co",
        "Summit IT Services",
    ]
    supplier = suppliers[index % len(suppliers)]
    amount = 1800 + index * 137
    bsb = f"{100 + index % 800}-{200 + (index * 3) % 700}"
    account = f"{70000000 + index * 9137}"
    attacker_box = f"payments.{index}@gmail.com"
    pressure = rng.choice([
        "Please process this today to avoid a payment hold.",
        "This is urgent and must be completed within 24 hours.",
        "Kindly process without delay and do not call the office.",
    ])
    body = (
        f"Hi accounts team,\n\n"
        f"We have updated our bank details for {supplier}. Do not use the old account.\n"
        f"Invoice INV-{2400 + index} is now due for AUD ${amount:,.2f}.\n"
        f"New BSB: {bsb}\n"
        f"New account number: {account}\n\n"
        f"{pressure}\n"
        f"Only reply to this email once payment has been released.\n\n"
        f"Regards,\nSupplier Accounts"
    )
    payload = _synthetic_message(
        subject=f"Urgent updated bank details for invoice INV-{2400 + index}",
        body=body,
        from_address=f"Supplier Accounts <accounts@{supplier.lower().replace(' ', '-')}-billing.example>",
        reply_to=attacker_box,
        auth_results="mx.demo-business.example; spf=fail dkim=fail dmarc=fail",
        message_id=f"<synthetic-payment-scam-{index}@dataset.example>",
    )
    return payload, supplier


def _synthetic_legitimate_email(index: int) -> tuple[bytes, str]:
    suppliers = [
        "Aster Plumbing",
        "Citywide Stationery",
        "Kangaroo Print Group",
        "RMIT Catering Services",
        "Yarra Facilities",
    ]
    supplier = suppliers[index % len(suppliers)]
    amount = 900 + index * 83
    bsb = f"{300 + index % 500}-{400 + (index * 5) % 500}"
    account = f"{40000000 + index * 7211}"
    domain = supplier.lower().replace(" ", "-") + ".example.com"
    body = (
        f"Hi accounts payable,\n\n"
        f"Our bank details for {supplier} have changed in the supplier portal.\n"
        f"Invoice INV-{5200 + index} totals AUD ${amount:,.2f}.\n"
        f"BSB: {bsb}\n"
        f"Account number: {account}\n\n"
        f"Please do not update the payment record from this email alone. "
        f"Confirm through your usual contact or the saved supplier portal before paying.\n\n"
        f"Regards,\n{supplier} Accounts"
    )
    payload = _synthetic_message(
        subject=f"Supplier portal bank detail update for INV-{5200 + index}",
        body=body,
        from_address=f"{supplier} Accounts <accounts@{domain}>",
        auth_results="mx.demo-business.example; spf=pass dkim=pass dmarc=pass",
        message_id=f"<synthetic-legit-bank-change-{index}@dataset.example>",
    )
    return payload, supplier


def seed_synthetic_bank_change_dataset(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    scam_count: int = 50,
    legit_count: int = 50,
    seed: int = 1337,
    clean: bool = False,
) -> SeedSummary:
    dataset_dir = Path(dataset_dir)
    if scam_count < 0 or legit_count < 0:
        raise ValueError("sample counts must be non-negative")
    if clean and dataset_dir.exists():
        _assert_safe_clean_target(dataset_dir)
        shutil.rmtree(dataset_dir)
    init_dataset(dataset_dir)

    rng = random.Random(seed)
    generated_dir = dataset_dir / INCOMING_DIR / "synthetic_bank_change"
    generated_dir.mkdir(parents=True, exist_ok=True)

    for index in range(scam_count):
        payload, supplier = _synthetic_scam_email(index, rng)
        source = generated_dir / f"scam_bank_change_{index:03d}.eml"
        source.write_bytes(payload)
        add_sample(
            dataset_dir=dataset_dir,
            source=source,
            label="PAYMENT_SCAM",
            payment_decision="DO_NOT_PAY",
            scenario="bank_detail_change",
            source_type="synthetic",
            split=_split_for_index(index, scam_count),
            verified_by="synthetic-generator",
            contains_real_pii="no",
            notes=f"Synthetic bank-detail-change scam for {supplier}",
        )

    for index in range(legit_count):
        payload, supplier = _synthetic_legitimate_email(index)
        source = generated_dir / f"legit_bank_change_{index:03d}.eml"
        source.write_bytes(payload)
        add_sample(
            dataset_dir=dataset_dir,
            source=source,
            label="LEGITIMATE_PAYMENT",
            payment_decision="VERIFY",
            scenario="legitimate_bank_change_verified",
            source_type="synthetic",
            split=_split_for_index(index, legit_count),
            verified_by="synthetic-generator",
            contains_real_pii="no",
            notes=f"Synthetic legitimate bank-detail-change notice for {supplier}",
        )

    eval_labels = export_eval_labels(dataset_dir)
    return SeedSummary(
        dataset_dir=dataset_dir,
        scam_count=scam_count,
        legitimate_count=legit_count,
        total_count=scam_count + legit_count,
        labels_path=dataset_dir / LABELS_CSV,
        eval_labels_path=eval_labels,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and maintain the local payment-scam dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create dataset folders and labels.csv")
    init_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)

    add_parser = subparsers.add_parser("add", help="Copy and label one .eml sample")
    add_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    add_parser.add_argument("--source", type=Path, required=True)
    add_parser.add_argument("--label", choices=sorted(ALLOWED_LABELS), required=True)
    add_parser.add_argument("--payment-decision", choices=sorted(ALLOWED_DECISIONS), required=True)
    add_parser.add_argument("--scenario", choices=sorted(ALLOWED_SCENARIOS), required=True)
    add_parser.add_argument("--source-type", choices=sorted(ALLOWED_SOURCE_TYPES), default="real")
    add_parser.add_argument("--split", choices=sorted(ALLOWED_SPLITS), default="unassigned")
    add_parser.add_argument("--verified-by", default="")
    add_parser.add_argument("--contains-real-pii", default="unknown")
    add_parser.add_argument("--notes", default="")

    validate_parser = subparsers.add_parser("validate", help="Validate labels and sample files")
    validate_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)

    export_parser = subparsers.add_parser("export-eval-labels", help="Write labels.json for run_eval.py")
    export_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    export_parser.add_argument("--output", type=Path, default=None)

    seed_parser = subparsers.add_parser("seed-synthetic", help="Generate synthetic bank-detail-change samples")
    seed_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    seed_parser.add_argument("--scam-count", type=int, default=50)
    seed_parser.add_argument("--legit-count", type=int, default=50)
    seed_parser.add_argument("--seed", type=int, default=1337)
    seed_parser.add_argument("--clean", action="store_true", help="Remove the dataset before seeding")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        dataset = init_dataset(args.dataset)
        print(f"Initialized payment dataset at {dataset}")
        return 0

    if args.command == "add":
        target = add_sample(
            dataset_dir=args.dataset,
            source=args.source,
            label=args.label,
            payment_decision=args.payment_decision,
            scenario=args.scenario,
            source_type=args.source_type,
            split=args.split,
            verified_by=args.verified_by,
            contains_real_pii=args.contains_real_pii,
            notes=args.notes,
        )
        print(f"Added sample: {target}")
        return 0

    if args.command == "validate":
        result = validate_dataset(args.dataset)
        print(f"Rows: {result.row_count}")
        for warning in result.warnings:
            print(f"WARN: {warning}")
        for error in result.errors:
            print(f"ERROR: {error}")
        return 0 if result.ok else 1

    if args.command == "export-eval-labels":
        output = export_eval_labels(args.dataset, args.output)
        print(f"Wrote eval labels: {output}")
        return 0

    if args.command == "seed-synthetic":
        summary = seed_synthetic_bank_change_dataset(
            dataset_dir=args.dataset,
            scam_count=args.scam_count,
            legit_count=args.legit_count,
            seed=args.seed,
            clean=args.clean,
        )
        print(f"Seeded synthetic payment dataset at {summary.dataset_dir}")
        print(f"  payment scams:       {summary.scam_count}")
        print(f"  legitimate payments: {summary.legitimate_count}")
        print(f"  total:               {summary.total_count}")
        print(f"  labels:              {summary.labels_path}")
        print(f"  eval labels:         {summary.eval_labels_path}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""
Utilities for building a payment-scam dataset.

This dataset is separate from the generic phishing corpus because invoice
fraud and BEC need business-decision labels, not only PHISHING/CLEAN.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import random
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, getaddresses
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit


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
PII_VALUES = {"yes", "no", "unknown"}

ADDRESS_HEADERS = {"from", "to", "cc", "bcc", "reply-to", "sender", "return-path"}
DROP_HEADERS = {"received", "dkim-signature"}
FIXED_REDACTED_DATE = "Mon, 01 Jan 2024 00:00:00 +0000"

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>'\"]+", re.IGNORECASE)
BSB_RE = re.compile(r"\b\d{3}-\d{3}\b")
ACCOUNT_LINE_RE = re.compile(
    r"\b(account(?:[ \t]+number)?|acct)[ \t]*[:#-]?[ \t]*\d[\d \t-]{5,}\b",
    re.IGNORECASE,
)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
SWIFT_RE = re.compile(
    r"\b((?:SWIFT|BIC)[ \t]*[:#-]?[ \t]*)[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
    re.IGNORECASE,
)
ABN_RE = re.compile(r"(?<![+\d])\b(?:ABN\s*)?\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?61|0)[\s().-]?\d(?:[\s().-]?\d){7,9}\b")
AMOUNT_RE = re.compile(r"\b(?:AUD|USD|EUR|GBP)?\s?\$[\d,]+(?:\.\d{2})?\b", re.IGNORECASE)
INVOICE_REF_RE = re.compile(
    r"\b(invoice|inv|reference|ref)\s*[:#-]?\s*[A-Z0-9][A-Z0-9-]{2,}\b",
    re.IGNORECASE,
)

SAFE_DOMAIN_NAMES = {"example.com", "example.org", "example.net", "localhost"}
SAFE_DOMAIN_SUFFIXES = (".example", ".example.com", ".example.org", ".example.net", ".invalid")


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
    safe_count: int
    total_count: int
    labels_path: Path
    eval_labels_path: Path


@dataclass(frozen=True)
class RedactionFinding:
    filename: str
    kind: str
    line: int
    fingerprint: str


@dataclass(frozen=True)
class RedactionSummary:
    source: Path
    output: Path
    findings_after: int
    attachments_removed: int


@dataclass(frozen=True)
class MLExportSummary:
    output_path: Path
    row_count: int


@dataclass(frozen=True)
class DatasetReadinessReport:
    dataset_dir: Path
    row_count: int
    by_source_type: dict[str, int]
    by_label: dict[str, int]
    by_payment_decision: dict[str, int]
    by_split: dict[str, int]
    realish_count: int
    pii_free_realish_count: int
    errors: list[str]
    warnings: list[str]
    recommendations: list[str]

    @property
    def ready_for_product_metrics(self) -> bool:
        return not self.errors and self.realish_count > 0 and not self.recommendations


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


def _is_safe_placeholder_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")
    return domain in SAFE_DOMAIN_NAMES or domain.endswith(SAFE_DOMAIN_SUFFIXES)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


class _RedactionContext:
    def __init__(self) -> None:
        self.domain_map: dict[str, str] = {}
        self.email_map: dict[str, str] = {}

    def map_domain(self, domain: str) -> str:
        clean = domain.lower().strip(".")
        if _is_safe_placeholder_domain(clean):
            return clean
        if clean not in self.domain_map:
            self.domain_map[clean] = f"domain{len(self.domain_map) + 1}.example"
        return self.domain_map[clean]

    def map_email(self, email_address: str) -> str:
        clean = email_address.strip().lower()
        if clean not in self.email_map:
            domain = clean.rsplit("@", 1)[-1] if "@" in clean else "domain.example"
            self.email_map[clean] = f"mailbox{len(self.email_map) + 1}@{self.map_domain(domain)}"
        return self.email_map[clean]

    def contact_name(self, email_address: str) -> str:
        clean = email_address.strip().lower()
        if clean not in self.email_map:
            self.map_email(clean)
        return f"Contact {list(self.email_map).index(clean) + 1}"


def _redact_email_addresses(text: str, context: _RedactionContext) -> str:
    return EMAIL_RE.sub(lambda match: context.map_email(match.group(0)), text)


def _redact_urls(text: str, context: _RedactionContext) -> str:
    def replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        suffix = ""
        while raw and raw[-1] in ".,);]":
            suffix = raw[-1] + suffix
            raw = raw[:-1]

        parsed = urlsplit(raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}")
        host = parsed.hostname or "redacted.example"
        scheme = parsed.scheme or "https"
        return f"{scheme}://{context.map_domain(host)}/redacted{suffix}"

    return URL_RE.sub(replace, text)


def _redact_text(text: str, context: _RedactionContext) -> str:
    redacted = _redact_urls(text, context)
    redacted = _redact_email_addresses(redacted, context)
    redacted = ACCOUNT_LINE_RE.sub(lambda match: f"{match.group(1)}: 00000000", redacted)
    redacted = BSB_RE.sub("000-000", redacted)
    redacted = IBAN_RE.sub("AA00REDACTED0000000000", redacted)
    redacted = PHONE_RE.sub("+61 0 0000 0000", redacted)
    redacted = SWIFT_RE.sub(lambda match: f"{match.group(1)}AAAAAA00XXX", redacted)
    redacted = ABN_RE.sub("ABN 00 000 000 000", redacted)
    redacted = AMOUNT_RE.sub("AUD $1,000.00", redacted)
    return INVOICE_REF_RE.sub(lambda match: f"{match.group(1)} REDACTED", redacted)


def _redact_address_header(value: str, context: _RedactionContext) -> str:
    redacted_addresses = []
    for _, address in getaddresses([value]):
        if not address:
            continue
        safe_email = context.map_email(address)
        redacted_addresses.append(formataddr((context.contact_name(address), safe_email)))
    if redacted_addresses:
        return ", ".join(redacted_addresses)
    return _redact_text(value, context)


def _set_header(message: EmailMessage, name: str, value: str) -> None:
    if name in message:
        message.replace_header(name, value)
    else:
        message[name] = value


def _redact_message_headers(message: EmailMessage, context: _RedactionContext) -> None:
    for header in list(message.keys()):
        header_lower = header.lower()
        if header_lower in DROP_HEADERS:
            del message[header]
            continue
        if header_lower == "date":
            message.replace_header(header, FIXED_REDACTED_DATE)
            continue
        if header_lower in {"message-id", "in-reply-to", "references"}:
            message.replace_header(header, "<redacted-message@dataset.example>")
            continue
        if header_lower in ADDRESS_HEADERS:
            message.replace_header(header, _redact_address_header(str(message[header]), context))
            continue
        message.replace_header(header, _redact_text(str(message[header]), context))

    _set_header(message, "X-Redacted-For", "payment-scam-dataset")


def _redact_message_payload(message: EmailMessage, context: _RedactionContext) -> int:
    attachments_removed = 0
    for part in message.walk():
        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        if disposition == "attachment" and content_type not in {"text/plain", "text/html"}:
            part.clear()
            part.set_content("[Attachment removed during payment dataset redaction]\n")
            part.add_header("Content-Disposition", "attachment", filename="redacted_attachment.txt")
            attachments_removed += 1
            continue

        if part.get_content_maintype() == "text":
            try:
                content = part.get_content()
            except LookupError:
                content = part.get_payload(decode=True).decode("utf-8", errors="replace")
            part.set_content(_redact_text(content, context), subtype=part.get_content_subtype())

    return attachments_removed


def redact_eml(source: Path, output: Path, overwrite: bool = False) -> RedactionSummary:
    source = Path(source)
    output = Path(output)
    if not source.exists():
        raise FileNotFoundError(f"sample not found: {source}")
    if source.suffix.lower() != ".eml":
        raise ValueError("redaction input must be an .eml file")
    if output.exists() and not overwrite:
        raise FileExistsError(f"redacted output already exists: {output}")

    message = BytesParser(policy=policy.default).parsebytes(source.read_bytes())
    context = _RedactionContext()
    _redact_message_headers(message, context)
    attachments_removed = _redact_message_payload(message, context)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(message.as_bytes(policy=policy.default))
    findings = scan_redaction_findings(output)
    return RedactionSummary(
        source=source,
        output=output,
        findings_after=len(findings),
        attachments_removed=attachments_removed,
    )


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
        pii_value = row.get("contains_real_pii", "").strip().lower() or "unknown"
        _collect_value_error(errors, index, "contains_real_pii", pii_value, PII_VALUES)

        if row.get("label") == "PAYMENT_SCAM" and row.get("payment_decision") == "SAFE":
            errors.append(f"row {index}: PAYMENT_SCAM cannot have SAFE payment_decision")
        if row.get("label") == "NON_PAYMENT" and row.get("scenario") != "non_payment":
            warnings.append(f"row {index}: NON_PAYMENT usually uses scenario non_payment")
        if (
            sample_path.exists()
            and pii_value == "no"
            and row.get("source_type") in {"real", "redacted", "internal"}
        ):
            findings = scan_redaction_findings(sample_path)
            if findings:
                errors.append(
                    f"row {index}: sample marked contains_real_pii=no but PII audit found "
                    f"{len(findings)} possible leaks; run audit-pii for fingerprints"
                )

    if not rows:
        warnings.append("dataset has no labeled samples yet")

    return ValidationResult(errors=errors, warnings=warnings, row_count=len(rows))


def summarize_dataset_readiness(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    *,
    min_realish_samples: int = 20,
) -> DatasetReadinessReport:
    """
    Summarize whether the payment dataset is credible beyond synthetic tests.

    Synthetic samples are useful for ML plumbing and regression tests, but
    they are not enough for product claims. This report makes that visible
    without committing private emails or raw corpora.
    """
    dataset_dir = Path(dataset_dir)
    validation = validate_dataset(dataset_dir)
    rows = _read_labels(dataset_dir / LABELS_CSV) if (dataset_dir / LABELS_CSV).exists() else []

    by_source_type = Counter(row.get("source_type", "") or "missing" for row in rows)
    by_label = Counter(row.get("label", "") or "missing" for row in rows)
    by_payment_decision = Counter(row.get("payment_decision", "") or "missing" for row in rows)
    by_split = Counter(row.get("split", "") or "missing" for row in rows)

    realish_source_types = {"real", "redacted", "internal", "public"}
    realish_rows = [
        row for row in rows
        if row.get("source_type") in realish_source_types
    ]
    pii_free_realish_count = sum(
        1
        for row in realish_rows
        if row.get("contains_real_pii", "").strip().lower() == "no"
    )

    recommendations: list[str] = []
    if not rows:
        recommendations.append("Add labeled payment samples before training ML baselines.")
    if not realish_rows:
        recommendations.append(
            "Add redacted real/public/internal payment examples before reporting product metrics."
        )
    elif len(realish_rows) < min_realish_samples:
        recommendations.append(
            f"Add at least {min_realish_samples - len(realish_rows)} more non-synthetic samples "
            f"to reach the minimum review set of {min_realish_samples}."
        )
    if realish_rows and pii_free_realish_count != len(realish_rows):
        recommendations.append(
            "Mark non-synthetic samples contains_real_pii=no only after redaction audit passes."
        )

    missing_decisions = sorted(ALLOWED_DECISIONS - set(by_payment_decision))
    if missing_decisions:
        recommendations.append(
            "Add examples for missing payment decisions: " + ", ".join(missing_decisions)
        )

    missing_splits = sorted({"train", "validation", "test"} - set(by_split))
    if rows and missing_splits:
        recommendations.append(
            "Assign at least one sample to each core split: " + ", ".join(missing_splits)
        )

    return DatasetReadinessReport(
        dataset_dir=dataset_dir,
        row_count=len(rows),
        by_source_type=dict(sorted(by_source_type.items())),
        by_label=dict(sorted(by_label.items())),
        by_payment_decision=dict(sorted(by_payment_decision.items())),
        by_split=dict(sorted(by_split.items())),
        realish_count=len(realish_rows),
        pii_free_realish_count=pii_free_realish_count,
        errors=validation.errors,
        warnings=validation.warnings,
        recommendations=recommendations,
    )


def _collect_value_error(
    errors: list[str],
    row_index: int,
    name: str,
    value: str,
    allowed: set[str],
) -> None:
    if value not in allowed:
        errors.append(f"row {row_index}: {name} must be one of {sorted(allowed)}, got {value!r}")


def _message_scan_lines(sample_path: Path) -> list[str]:
    message = BytesParser(policy=policy.default).parsebytes(sample_path.read_bytes())
    lines: list[str] = []
    for name, value in message.items():
        lines.append(f"{name}: {value}")

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            lines.append(f"Attachment-Filename: {filename}")
        if part.get_content_maintype() != "text":
            continue
        try:
            content = part.get_content()
        except LookupError:
            content = part.get_payload(decode=True).decode("utf-8", errors="replace")
        lines.extend(str(content).splitlines())
    return lines


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _safe_dummy_number(value: str) -> bool:
    digits = _digits(value)
    return bool(digits) and set(digits) == {"0"}


def _safe_dummy_phone(value: str) -> bool:
    return "0000 0000" in value or _safe_dummy_number(value)


def _safe_dummy_bank_identifier(value: str) -> bool:
    upper = value.upper().replace(" ", "")
    return (
        _safe_dummy_number(value)
        or upper.startswith("AA00REDACTED")
        or "AAAAAA00XXX" in upper
    )


def scan_redaction_findings(sample_path: Path, strict_payment_fields: bool = True) -> list[RedactionFinding]:
    """Return privacy findings without echoing the sensitive value itself."""
    sample_path = Path(sample_path)
    findings: list[RedactionFinding] = []
    for line_number, line in enumerate(_message_scan_lines(sample_path), start=1):
        for match in EMAIL_RE.finditer(line):
            domain = match.group(1)
            if not _is_safe_placeholder_domain(domain):
                findings.append(
                    RedactionFinding(
                        filename=sample_path.name,
                        kind="email",
                        line=line_number,
                        fingerprint=_fingerprint(match.group(0)),
                    )
                )

        for match in URL_RE.finditer(line):
            raw = match.group(0).rstrip(".,);]")
            parsed = urlsplit(raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}")
            host = parsed.hostname or ""
            if host and not _is_safe_placeholder_domain(host):
                findings.append(
                    RedactionFinding(
                        filename=sample_path.name,
                        kind="url",
                        line=line_number,
                        fingerprint=_fingerprint(raw),
                    )
                )

        for match in PHONE_RE.finditer(line):
            if not _safe_dummy_phone(match.group(0)):
                findings.append(
                    RedactionFinding(
                        filename=sample_path.name,
                        kind="phone",
                        line=line_number,
                        fingerprint=_fingerprint(match.group(0)),
                    )
                )

        if not strict_payment_fields:
            continue

        payment_patterns = [
            ("bsb", BSB_RE),
            ("account_number", ACCOUNT_LINE_RE),
            ("iban", IBAN_RE),
            ("swift_bic", SWIFT_RE),
            ("abn", ABN_RE),
        ]
        for kind, pattern in payment_patterns:
            for match in pattern.finditer(line):
                if _safe_dummy_bank_identifier(match.group(0)):
                    continue
                findings.append(
                    RedactionFinding(
                        filename=sample_path.name,
                        kind=kind,
                        line=line_number,
                        fingerprint=_fingerprint(match.group(0)),
                    )
                )

    return findings


def audit_dataset_pii(dataset_dir: Path = DEFAULT_DATASET_DIR) -> list[RedactionFinding]:
    dataset_dir = Path(dataset_dir)
    findings: list[RedactionFinding] = []
    for row in _read_labels(dataset_dir / LABELS_CSV):
        if row.get("source_type") == "synthetic":
            continue
        sample_path = dataset_dir / SAMPLES_DIR / row.get("filename", "")
        if sample_path.exists():
            findings.extend(scan_redaction_findings(sample_path))
    return findings


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


def _email_text_for_ml(sample_path: Path) -> str:
    message = BytesParser(policy=policy.default).parsebytes(sample_path.read_bytes())
    sections: list[str] = []
    for header in ("Subject", "From", "Reply-To", "To"):
        if message.get(header):
            sections.append(f"{header}: {message.get(header)}")

    body_chunks: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        try:
            body_chunks.append(str(part.get_content()))
        except LookupError:
            body_chunks.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
    body = "\n".join(chunk.strip() for chunk in body_chunks if chunk.strip())
    if body:
        sections.append(f"Body:\n{body}")
    return "\n\n".join(sections).strip()


def export_ml_jsonl(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    output: Optional[Path] = None,
    allow_pii: bool = False,
) -> MLExportSummary:
    dataset_dir = Path(dataset_dir)
    result = validate_dataset(dataset_dir)
    if not result.ok:
        raise ValueError("dataset validation failed: " + "; ".join(result.errors))

    rows = _read_labels(dataset_dir / LABELS_CSV)
    if not allow_pii:
        unsafe = [
            row["filename"]
            for row in rows
            if row.get("contains_real_pii", "").strip().lower() != "no"
        ]
        if unsafe:
            raise ValueError(
                "refusing ML export because samples are not marked contains_real_pii=no: "
                + ", ".join(unsafe[:10])
            )

    output = output or (dataset_dir / EXPORTS_DIR / "payment_ml.jsonl")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            sample_path = dataset_dir / SAMPLES_DIR / row["filename"]
            record = {
                "filename": row["filename"],
                "text": _email_text_for_ml(sample_path),
                "label": row["label"],
                "binary_label": "PHISHING" if row["label"] == "PAYMENT_SCAM" else "CLEAN",
                "payment_decision": row["payment_decision"],
                "scenario": row["scenario"],
                "source_type": row["source_type"],
                "split": row["split"],
            }
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return MLExportSummary(output_path=output, row_count=len(rows))


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


def _synthetic_safe_invoice_email(index: int) -> tuple[bytes, str]:
    suppliers = [
        "Metro Office Supplies",
        "Southern Print Works",
        "Collins Street Cleaning",
        "Docklands Courier Service",
        "Northside Maintenance",
    ]
    supplier = suppliers[index % len(suppliers)]
    amount = 220 + index * 41
    domain = supplier.lower().replace(" ", "-") + ".example.com"
    body = (
        f"Hi accounts payable,\n\n"
        f"Please find invoice INV-{7100 + index} for AUD ${amount:,.2f} attached to the portal record.\n"
        f"This invoice matches purchase order PO-{3100 + index} and does not change any payment details.\n"
        f"Please process it through the normal approval queue when it is due.\n\n"
        f"If anything looks different, contact us using the supplier profile already saved in your system.\n\n"
        f"Regards,\n{supplier} Accounts"
    )
    payload = _synthetic_message(
        subject=f"Invoice INV-{7100 + index} for normal approval",
        body=body,
        from_address=f"{supplier} Accounts <accounts@{domain}>",
        auth_results="mx.demo-business.example; spf=pass dkim=pass dmarc=pass",
        message_id=f"<synthetic-safe-invoice-{index}@dataset.example>",
    )
    return payload, supplier


def seed_synthetic_bank_change_dataset(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    scam_count: int = 50,
    legit_count: int = 50,
    safe_count: int = 0,
    seed: int = 1337,
    clean: bool = False,
) -> SeedSummary:
    dataset_dir = Path(dataset_dir)
    if scam_count < 0 or legit_count < 0 or safe_count < 0:
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

    for index in range(safe_count):
        payload, supplier = _synthetic_safe_invoice_email(index)
        source = generated_dir / f"safe_invoice_{index:03d}.eml"
        source.write_bytes(payload)
        add_sample(
            dataset_dir=dataset_dir,
            source=source,
            label="LEGITIMATE_PAYMENT",
            payment_decision="SAFE",
            scenario="legitimate_invoice",
            source_type="synthetic",
            split=_split_for_index(index, safe_count),
            verified_by="synthetic-generator",
            contains_real_pii="no",
            notes=f"Synthetic routine invoice with no bank-detail change for {supplier}",
        )

    eval_labels = export_eval_labels(dataset_dir)
    return SeedSummary(
        dataset_dir=dataset_dir,
        scam_count=scam_count,
        legitimate_count=legit_count,
        safe_count=safe_count,
        total_count=scam_count + legit_count + safe_count,
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
    seed_parser.add_argument("--safe-count", type=int, default=0)
    seed_parser.add_argument("--seed", type=int, default=1337)
    seed_parser.add_argument("--clean", action="store_true", help="Remove the dataset before seeding")

    redact_parser = subparsers.add_parser("redact", help="Create a redacted .eml copy for dataset review")
    redact_parser.add_argument("--source", type=Path, required=True)
    redact_parser.add_argument("--output", type=Path, default=None)
    redact_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    redact_parser.add_argument("--overwrite", action="store_true")

    audit_parser = subparsers.add_parser("audit-pii", help="Scan redacted samples for obvious PII leaks")
    audit_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    audit_parser.add_argument("--sample", type=Path, action="append", default=[])

    ml_parser = subparsers.add_parser("export-ml-jsonl", help="Write redacted JSONL rows for ML experiments")
    ml_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    ml_parser.add_argument("--output", type=Path, default=None)
    ml_parser.add_argument("--allow-pii", action="store_true", help="Allow export of rows not marked PII-free")

    readiness_parser = subparsers.add_parser(
        "readiness",
        help="Summarize dataset balance, source quality, and real-sample readiness",
    )
    readiness_parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    readiness_parser.add_argument("--min-realish-samples", type=int, default=20)
    readiness_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
            safe_count=args.safe_count,
            seed=args.seed,
            clean=args.clean,
        )
        print(f"Seeded synthetic payment dataset at {summary.dataset_dir}")
        print(f"  payment scams:       {summary.scam_count}")
        print(f"  verified changes:    {summary.legitimate_count}")
        print(f"  safe invoices:       {summary.safe_count}")
        print(f"  total:               {summary.total_count}")
        print(f"  labels:              {summary.labels_path}")
        print(f"  eval labels:         {summary.eval_labels_path}")
        return 0

    if args.command == "redact":
        output = args.output
        if output is None:
            output = (
                Path(args.dataset)
                / INCOMING_DIR
                / "redacted"
                / f"{args.source.stem}.redacted{args.source.suffix}"
            )
        summary = redact_eml(args.source, output, overwrite=args.overwrite)
        print(f"Redacted sample: {summary.output}")
        print(f"  attachments removed: {summary.attachments_removed}")
        print(f"  findings after:      {summary.findings_after}")
        if summary.findings_after:
            print("Run audit-pii on the output and manually remove remaining private details before labeling.")
            return 1
        return 0

    if args.command == "audit-pii":
        if args.sample:
            findings = []
            for sample in args.sample:
                findings.extend(scan_redaction_findings(sample))
        else:
            findings = audit_dataset_pii(args.dataset)
        for finding in findings:
            print(
                "PII "
                f"sample={finding.filename} kind={finding.kind} "
                f"line={finding.line} fingerprint={finding.fingerprint}"
            )
        print(f"Findings: {len(findings)}")
        return 1 if findings else 0

    if args.command == "export-ml-jsonl":
        summary = export_ml_jsonl(args.dataset, args.output, allow_pii=args.allow_pii)
        print(f"Wrote ML JSONL: {summary.output_path}")
        print(f"  rows: {summary.row_count}")
        return 0

    if args.command == "readiness":
        report = summarize_dataset_readiness(
            args.dataset,
            min_realish_samples=args.min_realish_samples,
        )
        if args.json:
            payload = {
                "dataset_dir": str(report.dataset_dir),
                "row_count": report.row_count,
                "by_source_type": report.by_source_type,
                "by_label": report.by_label,
                "by_payment_decision": report.by_payment_decision,
                "by_split": report.by_split,
                "realish_count": report.realish_count,
                "pii_free_realish_count": report.pii_free_realish_count,
                "errors": report.errors,
                "warnings": report.warnings,
                "recommendations": report.recommendations,
                "ready_for_product_metrics": report.ready_for_product_metrics,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"Dataset: {report.dataset_dir}")
            print(f"Rows: {report.row_count}")
            print(f"Source types: {report.by_source_type}")
            print(f"Labels: {report.by_label}")
            print(f"Payment decisions: {report.by_payment_decision}")
            print(f"Splits: {report.by_split}")
            print(f"Non-synthetic samples: {report.realish_count}")
            print(f"PII-free non-synthetic samples: {report.pii_free_realish_count}")
            for warning in report.warnings:
                print(f"WARN: {warning}")
            for error in report.errors:
                print(f"ERROR: {error}")
            for recommendation in report.recommendations:
                print(f"RECOMMEND: {recommendation}")
            print(f"Ready for product metrics: {report.ready_for_product_metrics}")
        return 0 if not report.errors else 1

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

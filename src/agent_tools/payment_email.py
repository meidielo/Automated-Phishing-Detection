"""
Agent-facing payment email analysis contract.

This module intentionally exposes a narrow, sanitized surface over the existing
payment_fraud analyzer. It returns the decision evidence an agent needs without
returning full email bodies, raw headers, or unmasked attachment content.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.analyzers.payment_fraud import PaymentFraudAnalyzer
from src.eval.payment_dataset import DEFAULT_DATASET_DIR, SAMPLES_DIR
from src.eval.payment_demo import read_payment_labels, select_demo_label_rows
from src.extractors.eml_parser import EMLParser
from src.models import EmailObject


TOOL_NAME = "analyze_payment_email"
SCHEMA_VERSION = "1.0"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AGENT_DEMO_DIR = PROJECT_ROOT / "demo_samples" / "agent_payment"
DEMO_MANIFEST = "manifest.json"

TOOL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "email_path": {
            "type": "string",
            "description": "Local path to a .eml file to inspect.",
        },
        "include_email_metadata": {
            "type": "boolean",
            "description": "Include sender, recipient, subject, date, and attachment names.",
            "default": True,
        },
    },
    "required": ["email_path"],
    "additionalProperties": False,
}

TOOL_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tool": {"type": "string"},
        "schema_version": {"type": "string"},
        "source_file": {"type": "string"},
        "decision": {"type": "string", "enum": ["SAFE", "VERIFY", "DO_NOT_PAY"]},
        "risk_score": {"type": "number"},
        "confidence": {"type": "number"},
        "summary": {"type": "string"},
        "agent_next_action": {"type": "string"},
        "signals": {"type": "array"},
        "extracted_payment_fields": {"type": "object"},
        "verification_steps": {"type": "array", "items": {"type": "string"}},
        "ml_decision": {"type": "object"},
        "email": {"type": "object"},
        "safety": {"type": "object"},
    },
    "required": [
        "tool",
        "schema_version",
        "decision",
        "risk_score",
        "confidence",
        "summary",
        "signals",
        "verification_steps",
        "safety",
    ],
}


def _as_float(value: Any) -> float:
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return 0.0


def _signal_payload(signal: Any) -> dict[str, Any]:
    if not isinstance(signal, dict):
        return {}
    return {
        "name": str(signal.get("name", "")),
        "severity": str(signal.get("severity", "")),
        "evidence": str(signal.get("evidence", "")),
        "recommendation": str(signal.get("recommendation", "")),
        "risk_weight": _as_float(signal.get("risk_weight")),
    }


def _sanitized_ml_decision(details: dict[str, Any]) -> dict[str, Any]:
    ml_decision = details.get("ml_decision")
    if not isinstance(ml_decision, dict):
        return {"available": False, "reason": "not_reported"}
    return {
        key: value
        for key, value in ml_decision.items()
        if key != "model_path"
    }


def _email_metadata(email: EmailObject) -> dict[str, Any]:
    return {
        "email_id": email.email_id,
        "subject": email.subject or "",
        "from_address": email.from_address or "",
        "from_display_name": email.from_display_name or "",
        "reply_to": email.reply_to or "",
        "to_addresses": email.to_addresses or [],
        "cc_count": len(email.cc_addresses or []),
        "date": email.date.isoformat() if email.date else "",
        "attachment_count": len(email.attachments or []),
        "attachments": [
            {
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "size_bytes": attachment.size_bytes,
                "has_macros": attachment.has_macros,
            }
            for attachment in (email.attachments or [])
        ],
    }


def _next_action(decision: str) -> str:
    if decision == "DO_NOT_PAY":
        return "Block payment release and complete independent verification."
    if decision == "VERIFY":
        return "Hold payment until the supplier or executive is verified out of band."
    return "Proceed through the normal payment approval workflow."


def _validate_email_path(email_path: str | Path) -> Path:
    path = Path(email_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Email path is not a file: {path}")
    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported by this agent tool")
    return path


async def analyze_payment_email_file(
    email_path: str | Path,
    *,
    include_email_metadata: bool = True,
) -> dict[str, Any]:
    """
    Analyze a local .eml file for payment-scam risk.

    The returned payload is designed for agents: compact, structured, and safe
    to pass into model context without full email bodies or raw headers.
    """
    path = _validate_email_path(email_path)
    parser = EMLParser()
    email = parser.parse_file(path)
    if email is None:
        raise ValueError(f"Could not parse email file: {path}")

    analyzer = PaymentFraudAnalyzer()
    result = await analyzer.analyze(email)
    details = result.details or {}
    decision = str(details.get("decision") or "SAFE")
    signals = [
        payload
        for payload in (_signal_payload(signal) for signal in details.get("signals", []))
        if payload.get("name")
    ]

    payload: dict[str, Any] = {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "source_file": path.name,
        "decision": decision,
        "risk_score": _as_float(details.get("risk_score", result.risk_score)),
        "confidence": _as_float(details.get("confidence", result.confidence)),
        "summary": str(details.get("summary") or ""),
        "agent_next_action": _next_action(decision),
        "signals": signals,
        "extracted_payment_fields": details.get("extracted_payment_fields") or {},
        "verification_steps": details.get("verification_steps") or [],
        "ml_decision": _sanitized_ml_decision(details),
        "safety": {
            "body_returned": False,
            "raw_headers_returned": False,
            "attachment_content_returned": False,
            "payment_identifiers_masked_by_analyzer": True,
        },
    }
    if include_email_metadata:
        payload["email"] = _email_metadata(email)
    return payload


async def analyze_demo_payment_samples(
    *,
    dataset_dir: Path | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    """Return fixed sample analyses for the public demo surface."""
    if dataset_dir is None:
        sample_root = DEFAULT_AGENT_DEMO_DIR
        labels = _read_agent_demo_manifest(sample_root)
        decision_key = "expected_decision"
    else:
        sample_root = Path(dataset_dir) / SAMPLES_DIR
        labels = select_demo_label_rows(read_payment_labels(Path(dataset_dir)))
        decision_key = "payment_decision"

    if decision:
        labels = [row for row in labels if row.get(decision_key) == decision]

    samples: list[dict[str, Any]] = []
    for row in labels:
        sample_path = sample_root / row["filename"]
        analysis = await analyze_payment_email_file(sample_path)
        analysis.update({
            "expected_decision": row[decision_key],
            "scenario": row["scenario"],
            "source_type": row["source_type"],
            "split": row["split"],
            "title": row.get("title") or row["scenario"],
        })
        samples.append(analysis)
    return {
        "demo_mode": True,
        "live_mailbox_used": False,
        "paid_api_used": False,
        "sample_count": len(samples),
        "samples": samples,
    }


def _read_agent_demo_manifest(sample_root: Path = DEFAULT_AGENT_DEMO_DIR) -> list[dict[str, str]]:
    manifest_path = sample_root / DEMO_MANIFEST
    if not manifest_path.exists():
        raise FileNotFoundError(f"Agent demo manifest not found: {manifest_path}")
    rows = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("Agent demo manifest must be a list")
    required = {"filename", "expected_decision", "scenario", "source_type", "split"}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Agent demo manifest entries must be objects")
        missing = sorted(required - set(row))
        if missing:
            raise ValueError(
                f"Agent demo manifest entry missing keys: {', '.join(missing)}"
            )
    return rows

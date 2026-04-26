"""Tests for monitor log tailing and dashboard compaction helpers."""

import json

from main import _compact_monitor_record, _tail_jsonl_records


def test_tail_jsonl_records_reads_only_recent_valid_lines(tmp_path):
    log_path = tmp_path / "results.jsonl"
    rows = [
        {"email_id": "old", "verdict": "CLEAN"},
        {"email_id": "middle", "verdict": "SUSPICIOUS"},
        {"email_id": "new", "verdict": "CONFIRMED_PHISHING"},
    ]
    log_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\nnot-json\n",
        encoding="utf-8",
    )

    records = _tail_jsonl_records(log_path, 3)

    assert [record["email_id"] for record in records] == ["new", "middle"]


def test_compact_monitor_record_drops_heavy_details():
    record = {
        "email_id": "email-1",
        "from": "sender@example.com",
        "subject": "Subject",
        "verdict": "CLEAN",
        "score": 0.1,
        "overall_confidence": 0.9,
        "timestamp": "2026-04-27T10:00:00",
        "quarantined": False,
        "analyzer_results": {
            "url_detonation": {"details": {"screenshot_b64": "x" * 1000}},
            "nlp_intent": {"details": {"raw": "large"}},
        },
    }

    compact = _compact_monitor_record(record)

    assert compact == {
        "email_id": "email-1",
        "from": "sender@example.com",
        "subject": "Subject",
        "verdict": "CLEAN",
        "score": 0.1,
        "overall_score": 0.1,
        "overall_confidence": 0.9,
        "timestamp": "2026-04-27T10:00:00",
        "quarantined": False,
        "analyzer_count": 2,
    }

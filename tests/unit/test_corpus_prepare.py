from __future__ import annotations

import json
import mailbox
from email.message import EmailMessage
from pathlib import Path

from src.eval.corpus_prepare import (
    _message_as_bytes,
    iter_spamassassin_spam_candidates,
    prepare_corpus,
)


def _message(subject: str, body: str, sender: str = "sender@example.com") -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "recipient@example.com"
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def _write_nazario_mbox(path: Path, count: int = 3) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mbox = mailbox.mbox(str(path))
    try:
        for index in range(count):
            mbox.add(
                _message(
                    subject=f"Account verification {index}",
                    body=f"Click here to verify your account {index}",
                    sender=f"phish{index}@evil.example",
                )
            )
        mbox.flush()
    finally:
        mbox.close()


def _write_raw_email(path: Path, subject: str = "Normal business mail") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "From: employee@example.com",
                "To: coworker@example.com",
                f"Subject: {subject}",
                "",
                "This is a normal business message.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _build_fake_corpora(root: Path) -> Path:
    corpora = root / "corpora"
    _write_nazario_mbox(corpora / "nazario" / "phishing0.mbox", count=3)

    _write_raw_email(corpora / "enron" / "alice" / "_sent_mail" / "1", "Sent mail 1")
    _write_raw_email(corpora / "enron" / "alice" / "sent_items" / "2", "Sent mail 2")
    _write_raw_email(corpora / "enron" / "bob" / "inbox" / "ignored", "Inbox should not be used")

    _write_raw_email(corpora / "spamassassin" / "easy_ham" / "0001", "Ham 1")
    _write_raw_email(corpora / "spamassassin" / "hard_ham" / "0002", "Ham 2")
    _write_raw_email(corpora / "spamassassin" / "spam" / "ignored", "Spam should not be clean")
    return corpora


def test_prepare_corpus_writes_eval_ready_files(tmp_path: Path):
    corpora = _build_fake_corpora(tmp_path)
    output = tmp_path / "prepared"

    prepared = prepare_corpus(
        corpora_dir=corpora,
        output_dir=output,
        phishing=2,
        enron_ham=2,
        spamassassin_ham=1,
        seed=42,
        clean_output=True,
    )

    assert len(prepared.labels) == 5
    assert prepared.written_counts == {"PHISHING": 2, "CLEAN": 3}
    assert prepared.labels_path.exists()
    assert prepared.labels_csv_path.exists()
    assert prepared.manifest_path.exists()
    assert prepared.summary_path.exists()

    labels = json.loads(prepared.labels_path.read_text(encoding="utf-8"))
    assert labels == prepared.labels
    assert set(labels.values()) == {"PHISHING", "CLEAN"}

    manifest_rows = [
        json.loads(line)
        for line in prepared.manifest_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(manifest_rows) == 5
    assert all((output / row["filename"]).exists() for row in manifest_rows)
    assert all("inbox" not in row["source_path"] for row in manifest_rows)
    assert all("/spam/" not in row["source_path"] for row in manifest_rows)


def test_prepare_corpus_is_deterministic_for_same_seed(tmp_path: Path):
    corpora = _build_fake_corpora(tmp_path)

    first = prepare_corpus(
        corpora_dir=corpora,
        output_dir=tmp_path / "first",
        phishing=2,
        enron_ham=1,
        spamassassin_ham=1,
        seed=1337,
    )
    second = prepare_corpus(
        corpora_dir=corpora,
        output_dir=tmp_path / "second",
        phishing=2,
        enron_ham=1,
        spamassassin_ham=1,
        seed=1337,
    )

    assert first.labels == second.labels
    assert first.manifest_path.read_text(encoding="utf-8") == second.manifest_path.read_text(
        encoding="utf-8"
    )


def test_prepare_corpus_warns_when_sources_are_short(tmp_path: Path):
    corpora = _build_fake_corpora(tmp_path)

    prepared = prepare_corpus(
        corpora_dir=corpora,
        output_dir=tmp_path / "short",
        phishing=10,
        enron_ham=10,
        spamassassin_ham=10,
        seed=1,
    )

    assert prepared.available_counts == {"nazario": 3, "enron_ham": 2, "spamassassin_ham": 2}
    assert len(prepared.warnings) == 3


def test_prepare_corpus_clean_output_removes_stale_files(tmp_path: Path):
    corpora = _build_fake_corpora(tmp_path)
    output = tmp_path / "prepared"
    output.mkdir()
    stale = output / "old.eml"
    stale.write_text("old", encoding="utf-8")

    prepare_corpus(
        corpora_dir=corpora,
        output_dir=output,
        phishing=1,
        enron_ham=1,
        spamassassin_ham=1,
        clean_output=True,
    )

    assert not stale.exists()


def test_mbox_message_serializer_handles_utf8_payload_edge_case():
    msg = mailbox.mboxMessage()
    msg["From"] = "phish@example.com"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "Verification"
    msg.set_type("multipart/mixed")
    msg.set_payload(["non-ascii payload: akun diverifikasi \u2713"])

    payload = _message_as_bytes(msg)

    assert isinstance(payload, bytes)
    assert b"non-ascii payload" in payload


def test_prepare_corpus_handles_non_ascii_mbox_separator(tmp_path: Path):
    corpora = tmp_path / "corpora"
    nazario = corpora / "nazario"
    nazario.mkdir(parents=True)
    (nazario / "phishing0.mbox").write_bytes(
        b"From Jos\xc3\xa9@example.com Sat Jan 01 00:00:00 2026\n"
        b"From: phish@example.com\n"
        b"To: victim@example.com\n"
        b"Subject: Verify\n"
        b"\n"
        b"Click the fake verification link.\n"
    )

    prepared = prepare_corpus(
        corpora_dir=corpora,
        output_dir=tmp_path / "prepared",
        phishing=1,
        enron_ham=0,
        spamassassin_ham=0,
    )

    assert prepared.written_counts == {"PHISHING": 1, "CLEAN": 0}
    [filename] = prepared.labels.keys()
    assert (tmp_path / "prepared" / filename).read_bytes().startswith(b"From: phish@example.com")


def test_iter_spamassassin_spam_candidates_reads_spam_folders_only(tmp_path: Path):
    corpora = _build_fake_corpora(tmp_path)

    candidates = list(iter_spamassassin_spam_candidates(corpora))

    assert len(candidates) == 1
    assert candidates[0].source_corpus == "spamassassin_spam"
    assert candidates[0].label == "PHISHING"
    assert "/spam/" in candidates[0].source_path

"""
Unit tests for the payment fraud analyzer.
"""
from datetime import datetime, timezone

import pytest

from src.analyzers.payment_fraud import PaymentFraudAnalyzer
from src.eval.payment_dataset import seed_synthetic_bank_change_dataset
from src.ml.payment_classifier import train_payment_classifier
from src.models import AttachmentObject, EmailObject


def make_email(
    subject: str,
    body: str,
    from_address: str = "accounts@supplier.com",
    reply_to: str | None = None,
    attachments: list[AttachmentObject] | None = None,
    auth_results: str | None = None,
) -> EmailObject:
    raw_headers = {
        "from": [from_address],
        "to": ["ap@example.com"],
        "subject": [subject],
        "date": ["Mon, 08 Mar 2026 10:00:00 +0000"],
        "message-id": ["<test@example.com>"],
        "received": ["from mail.supplier.com by mx.example.com with SMTP"],
    }
    if auth_results:
        raw_headers["authentication-results"] = [auth_results]

    return EmailObject(
        email_id="payment_test",
        raw_headers=raw_headers,
        from_address=from_address,
        from_display_name="Supplier Accounts",
        reply_to=reply_to,
        to_addresses=["ap@example.com"],
        cc_addresses=[],
        subject=subject,
        body_plain=body,
        body_html="",
        date=datetime(2026, 3, 8, 10, 0, 0, tzinfo=timezone.utc),
        attachments=attachments or [],
        inline_images=[],
        message_id="test@example.com",
        received_chain=["from mail.supplier.com by mx.example.com with SMTP"],
    )


@pytest.mark.asyncio
async def test_no_payment_context_returns_safe():
    analyzer = PaymentFraudAnalyzer()
    email = make_email(
        subject="Team meeting reminder",
        body="Hi, this is a reminder for our planning meeting tomorrow.",
    )

    result = await analyzer.analyze(email)

    assert result.analyzer_name == "payment_fraud"
    assert result.details["decision"] == "SAFE"
    assert result.risk_score < 0.1
    assert result.details["signals"] == []


@pytest.mark.asyncio
async def test_bank_detail_change_blocks_payment_and_masks_fields():
    analyzer = PaymentFraudAnalyzer()
    email = make_email(
        subject="Urgent invoice payment",
        body=(
            "Please use our updated bank details for this invoice. "
            "Amount due $12,450.00. BSB 123-456 Account number 987654321. "
            "Process this today and do not call the office."
        ),
        from_address="accounts@trusted-supplier.com",
        reply_to="payments@attacker-example.com",
        auth_results="mx.example.com; spf=fail dkim=fail dmarc=fail",
    )

    result = await analyzer.analyze(email)
    details = result.details

    assert details["decision"] == "DO_NOT_PAY"
    assert result.risk_score >= 0.78
    assert any(s["name"] == "bank_detail_change_request" for s in details["signals"])
    assert any(s["name"] == "approval_bypass_language" for s in details["signals"])
    assert details["extracted_payment_fields"]["amounts"] == ["$12,450.00"]
    assert "987654321" not in str(details["extracted_payment_fields"])
    assert any("saved contact" in step for step in details["verification_steps"])


@pytest.mark.asyncio
async def test_invoice_with_normal_verification_stays_safe():
    analyzer = PaymentFraudAnalyzer()
    attachment = AttachmentObject(
        filename="invoice-221.pdf",
        content_type="application/pdf",
        magic_type="application/pdf",
        size_bytes=2048,
        content=b"%PDF-1.4",
        is_archive=False,
        has_macros=False,
    )
    email = make_email(
        subject="Invoice INV-221",
        body=(
            "Invoice INV-221 is attached. Payment due $880.00. "
            "BSB 111-222 Account number 12345678. "
            "Purchase order PO-44. Call your usual contact if you need to confirm."
        ),
        attachments=[attachment],
        auth_results="mx.example.com; spf=pass dkim=pass dmarc=pass",
    )

    result = await analyzer.analyze(email)

    assert result.details["decision"] == "SAFE"
    assert result.risk_score < 0.22
    assert result.details["extracted_payment_fields"]["has_payment_fields"] is True


@pytest.mark.asyncio
async def test_legitimate_bank_change_with_portal_verification_requires_verify():
    analyzer = PaymentFraudAnalyzer()
    email = make_email(
        subject="Supplier portal bank detail update",
        body=(
            "Our bank details have changed in the supplier portal. "
            "Invoice INV-5200 totals AUD $1,200.00. "
            "BSB: 300-400 Account number: 40000000. "
            "Please do not update the payment record from this email alone. "
            "Confirm through your usual contact or the saved supplier portal before paying."
        ),
        auth_results="mx.example.com; spf=pass dkim=pass dmarc=pass",
    )

    result = await analyzer.analyze(email)

    assert result.details["decision"] == "VERIFY"
    assert any(s["name"] == "bank_detail_change_request" for s in result.details["signals"])
    assert result.risk_score < 0.78


@pytest.mark.asyncio
async def test_risky_invoice_attachment_blocks_payment():
    analyzer = PaymentFraudAnalyzer()
    attachment = AttachmentObject(
        filename="invoice-april.exe",
        content_type="application/octet-stream",
        magic_type="application/x-msdownload",
        size_bytes=51200,
        content=b"MZ",
        is_archive=False,
        has_macros=False,
    )
    email = make_email(
        subject="Invoice attached",
        body="Please process the attached invoice payment today.",
        attachments=[attachment],
    )

    result = await analyzer.analyze(email)

    assert result.details["decision"] == "DO_NOT_PAY"
    assert any(s["name"] == "dangerous_invoice_attachment" for s in result.details["signals"])


@pytest.mark.asyncio
async def test_payment_ml_decision_is_reported_when_model_exists(tmp_path):
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
    analyzer = PaymentFraudAnalyzer(payment_model_path=metrics.model_path)
    email = make_email(
        subject="Invoice INV-221",
        body=(
            "Invoice INV-221 matches purchase order PO-44. "
            "No payment details have changed. Please process through normal approval."
        ),
    )

    result = await analyzer.analyze(email)

    assert result.details["ml_decision"]["available"] is True
    assert result.details["ml_decision"]["prediction"] in {"DO_NOT_PAY", "SAFE", "VERIFY"}
    assert result.details["ml_decision"]["rules_decision"] == result.details["decision"]
    assert "class_probabilities" in result.details["ml_decision"]

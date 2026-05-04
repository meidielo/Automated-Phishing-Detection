from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.saas.database import (
    DuplicateEmailError,
    InvalidCredentialsError,
    PasswordResetTokenError,
    SaaSStore,
)


def test_signup_creates_user_org_subscription_and_context(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")

    context = store.create_user_with_org(
        email="Owner@Example.com",
        password="correct horse battery",
        org_name="Example Finance",
    )

    assert context.email == "owner@example.com"
    assert context.org_name == "Example Finance"
    assert context.role == "owner"
    assert context.plan_slug == "free"
    assert context.monthly_scan_quota == 5
    assert context.monthly_scan_used == 0


def test_signup_rejects_duplicate_email(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    store.create_user_with_org(email="a@example.com", password="long-password-1")

    with pytest.raises(DuplicateEmailError):
        store.create_user_with_org(email="A@example.com", password="long-password-2")


def test_authenticate_rejects_bad_password(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    store.create_user_with_org(email="a@example.com", password="long-password-1")

    with pytest.raises(InvalidCredentialsError):
        store.authenticate("a@example.com", "wrong-password")


def test_password_reset_token_updates_password_once(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(email="a@example.com", password="long-password-1")

    token = store.create_password_reset_token("A@example.com", ttl_minutes=30)
    reset_context = store.reset_password_with_token(token, "new-long-password-2")

    assert reset_context.user_id == context.user_id
    assert store.authenticate("a@example.com", "new-long-password-2").user_id == context.user_id
    with pytest.raises(InvalidCredentialsError):
        store.authenticate("a@example.com", "long-password-1")
    with pytest.raises(PasswordResetTokenError):
        store.reset_password_with_token(token, "another-long-password-3")


def test_password_reset_token_missing_email_is_generic_none(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")

    assert store.create_password_reset_token("missing@example.com", ttl_minutes=30) is None


def test_password_reset_token_expires(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    store.create_user_with_org(email="a@example.com", password="long-password-1")
    token = store.create_password_reset_token("a@example.com", ttl_minutes=30)
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

    with store._connect() as conn:
        conn.execute("UPDATE password_reset_tokens SET expires_at = ?", (expired,))
        conn.commit()

    with pytest.raises(PasswordResetTokenError):
        store.reset_password_with_token(token, "new-long-password-2")


def test_free_plan_locks_paid_features_and_records_lock(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(email="a@example.com", password="long-password-1")

    decision = store.check_entitlement(
        org_id=context.org_id,
        user_id=context.user_id,
        feature_slug="url_reputation",
    )

    assert decision.available is False
    assert decision.required_plan_name == "Starter"
    assert store.feature_lock_count(context.org_id) == 1


def test_manual_scan_quota_counts_monthly_usage(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(email="a@example.com", password="long-password-1")
    for index in range(5):
        store.record_usage_event(
            org_id=context.org_id,
            user_id=context.user_id,
            feature_slug="manual_scan",
            idempotency_key=f"scan-{index}",
        )

    decision = store.check_entitlement(
        org_id=context.org_id,
        user_id=context.user_id,
        feature_slug="manual_scan",
        enforce_scan_quota=True,
    )

    assert decision.available is False
    assert decision.limit_kind == "quota"
    assert decision.used == 5
    assert decision.remaining == 0


def test_paid_plan_unlocks_starter_features(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(email="a@example.com", password="long-password-1")
    store.set_subscription(org_id=context.org_id, plan_slug="starter")

    decision = store.check_entitlement(
        org_id=context.org_id,
        user_id=context.user_id,
        feature_slug="url_reputation",
    )

    assert decision.available is True
    assert decision.current_plan == "starter"


def test_scan_history_is_tenant_scoped(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    alice = store.create_user_with_org(email="alice@example.com", password="long-password-1")
    bob = store.create_user_with_org(email="bob@example.com", password="long-password-2")
    scan_id = store.create_scan_job(
        org_id=alice.org_id,
        user_id=alice.user_id,
        source="manual_upload",
    )
    store.record_scan_result(
        org_id=alice.org_id,
        user_id=alice.user_id,
        scan_job_id=scan_id,
        email_id="email-1",
        verdict="SUSPICIOUS",
        payment_decision="VERIFY",
        result={"email_id": "email-1"},
    )

    assert len(store.list_scan_results(alice.org_id)) == 1
    assert store.list_scan_results(bob.org_id) == []


def test_admin_overview_is_aggregate_and_redacted(tmp_path):
    store = SaaSStore(tmp_path / "saas.db")
    context = store.create_user_with_org(email="alice@example.com", password="long-password-1")
    store.set_subscription(org_id=context.org_id, plan_slug="pro")
    mailbox = store.register_mail_account(
        org_id=context.org_id,
        user_id=context.user_id,
        provider="gmail",
        external_account_id="alice@example.com",
        encrypted_token_ref="enc:v2:secret",
        status="active",
    )
    scan_id = store.create_scan_job(
        org_id=context.org_id,
        user_id=context.user_id,
        source="manual_upload",
        mail_account_id=mailbox.id,
    )
    store.record_scan_result(
        org_id=context.org_id,
        user_id=context.user_id,
        scan_job_id=scan_id,
        email_id="email-1",
        verdict="SUSPICIOUS",
        payment_decision="VERIFY",
        result={
            "subject": "private invoice",
            "body_preview": "customer secret body",
            "external_account_id": "alice@example.com",
            "encrypted_token_ref": "enc:v2:secret",
            "stripe_customer_id": "cus_secret",
        },
    )

    payload = store.admin_overview()
    serialized = str(payload)

    assert payload["totals"]["users"] == 1
    assert payload["totals"]["organizations"] == 1
    assert payload["totals"]["scans"] == 1
    assert payload["totals"]["mailboxes"] == 1
    assert payload["privacy"]["raw_result_json"] is False
    assert payload["privacy"]["mailbox_credentials"] is False
    assert "private invoice" not in serialized
    assert "customer secret body" not in serialized
    assert "alice@example.com" not in serialized
    assert "enc:v2:secret" not in serialized
    assert "cus_secret" not in serialized

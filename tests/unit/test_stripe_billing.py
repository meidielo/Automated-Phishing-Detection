from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from src.billing.plans import get_plan
from src.billing.stripe_client import (
    StripeAPIError,
    StripeBillingClient,
    StripeWebhookError,
    missing_checkout_env,
    plan_slug_for_price_id,
    price_id_for_plan,
    verify_stripe_webhook,
)


def _signature(payload: bytes, secret: str, timestamp: int) -> str:
    signed = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_price_env_helpers_map_plans_to_price_ids():
    env = {
        "STRIPE_SECRET_KEY": "stripe_secret_for_tests",
        "STRIPE_PRICE_STARTER": "price_starter",
        "STRIPE_PRICE_STARTER_YEARLY": "price_starter_yearly",
        "STRIPE_PRICE_PRO": "price_pro",
        "STRIPE_PRICE_PRO_YEARLY": "price_pro_yearly",
    }

    assert missing_checkout_env(get_plan("starter"), env) == []
    assert price_id_for_plan(get_plan("starter"), env) == "price_starter"
    assert missing_checkout_env(get_plan("starter"), env, billing_interval="yearly") == []
    assert (
        price_id_for_plan(get_plan("starter"), env, billing_interval="yearly")
        == "price_starter_yearly"
    )
    assert plan_slug_for_price_id("price_pro", env) == "pro"
    assert plan_slug_for_price_id("price_pro_yearly", env) == "pro"
    assert plan_slug_for_price_id("price_unknown", env) is None


def test_missing_checkout_env_lists_secret_and_plan_price():
    env = {}

    assert missing_checkout_env(get_plan("business"), env) == [
        "STRIPE_SECRET_KEY",
        "STRIPE_PRICE_BUSINESS",
    ]


def test_missing_checkout_env_lists_yearly_plan_price():
    env = {"STRIPE_SECRET_KEY": "stripe_secret_for_tests"}

    assert missing_checkout_env(get_plan("business"), env, billing_interval="yearly") == [
        "STRIPE_PRICE_BUSINESS_YEARLY",
    ]


def test_verify_stripe_webhook_accepts_valid_signature():
    payload = json.dumps({"id": "evt_123", "type": "checkout.session.completed"}).encode()
    header = _signature(payload, "stripe_webhook_secret_for_tests", 1_700_000_000)

    event = verify_stripe_webhook(
        payload,
        header,
        "stripe_webhook_secret_for_tests",
        now=1_700_000_010,
    )

    assert event["id"] == "evt_123"


def test_verify_stripe_webhook_rejects_bad_signature():
    payload = b'{"id":"evt_123","type":"checkout.session.completed"}'

    with pytest.raises(StripeWebhookError):
        verify_stripe_webhook(
            payload,
            "t=1700000000,v1=bad",
            "stripe_webhook_secret_for_tests",
            now=1_700_000_010,
        )


def test_stripe_client_sends_checkout_session_request(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {"id": "cs_123", "url": "https://checkout.stripe.com/c/session"}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["data"] = dict(kwargs["data"])
        captured["headers"] = kwargs["headers"]
        return Response()

    monkeypatch.setattr("src.billing.stripe_client.requests.post", fake_post)

    client = StripeBillingClient("stripe_secret_for_tests")
    session = client.create_checkout_session(
        customer_id="cus_123",
        price_id="price_123",
        org_id="org_123",
        user_id="usr_123",
        plan_slug="starter",
        success_url="https://example.test/app?billing=success",
        cancel_url="https://example.test/app?billing=cancelled",
    )

    assert session["id"] == "cs_123"
    assert captured["url"].endswith("/v1/checkout/sessions")
    assert captured["data"]["mode"] == "subscription"
    assert captured["data"]["line_items[0][price]"] == "price_123"
    assert captured["data"]["metadata[billing_interval]"] == "monthly"
    assert captured["data"]["subscription_data[metadata][billing_interval]"] == "monthly"
    assert captured["headers"]["Stripe-Version"] == "2026-02-25.clover"


def test_stripe_client_raises_clean_api_error(monkeypatch):
    class Response:
        status_code = 400
        content = b"{}"

        @staticmethod
        def json():
            return {"error": {"message": "No such price"}}

    monkeypatch.setattr(
        "src.billing.stripe_client.requests.post",
        lambda *args, **kwargs: Response(),
    )

    client = StripeBillingClient("stripe_secret_for_tests")
    with pytest.raises(StripeAPIError, match="No such price"):
        client.create_portal_session(
            customer_id="cus_123",
            return_url="https://example.test/app",
        )

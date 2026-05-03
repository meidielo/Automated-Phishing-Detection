"""Small Stripe Billing REST client for subscription Checkout and webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Mapping

import requests

from src.billing.plans import PLAN_CATALOG, Plan

STRIPE_API_BASE = "https://api.stripe.com"
STRIPE_API_VERSION = "2026-02-25.clover"
WEBHOOK_TOLERANCE_SECONDS = 300


class StripeConfigError(RuntimeError):
    """Raised when Stripe is not configured for this deployment."""


class StripeAPIError(RuntimeError):
    """Raised when Stripe returns a non-2xx API response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class StripeWebhookError(ValueError):
    """Raised when a Stripe webhook payload or signature is invalid."""


@dataclass(frozen=True)
class StripeBillingConfig:
    secret_key: str
    webhook_secret: str


class StripeBillingClient:
    """Minimal dependency-light client for the Stripe Billing endpoints we use."""

    def __init__(
        self,
        secret_key: str,
        *,
        api_base: str = STRIPE_API_BASE,
        api_version: str = STRIPE_API_VERSION,
        timeout_seconds: float = 15.0,
    ) -> None:
        if not secret_key:
            raise StripeConfigError("STRIPE_SECRET_KEY is not configured")
        self.secret_key = secret_key
        self.api_base = api_base.rstrip("/")
        self.api_version = api_version
        self.timeout_seconds = timeout_seconds

    def create_customer(self, *, email: str, name: str, metadata: Mapping[str, str]) -> dict:
        return self._post(
            "/v1/customers",
            [
                ("email", email),
                ("name", name),
                *[(f"metadata[{key}]", value) for key, value in metadata.items()],
            ],
        )

    def create_checkout_session(
        self,
        *,
        customer_id: str,
        price_id: str,
        org_id: str,
        user_id: str,
        plan_slug: str,
        success_url: str,
        cancel_url: str,
        billing_interval: str = "monthly",
        adaptive_pricing_enabled: bool = True,
    ) -> dict:
        data = [
            ("mode", "subscription"),
            ("customer", customer_id),
            ("client_reference_id", org_id),
            ("line_items[0][price]", price_id),
            ("line_items[0][quantity]", "1"),
            ("allow_promotion_codes", "true"),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
            ("metadata[org_id]", org_id),
            ("metadata[user_id]", user_id),
            ("metadata[plan_slug]", plan_slug),
            ("metadata[billing_interval]", billing_interval),
            ("subscription_data[metadata][org_id]", org_id),
            ("subscription_data[metadata][user_id]", user_id),
            ("subscription_data[metadata][plan_slug]", plan_slug),
            ("subscription_data[metadata][billing_interval]", billing_interval),
        ]
        if adaptive_pricing_enabled:
            data.append(("adaptive_pricing[enabled]", "true"))
        return self._post(
            "/v1/checkout/sessions",
            data,
        )

    def create_portal_session(self, *, customer_id: str, return_url: str) -> dict:
        return self._post(
            "/v1/billing_portal/sessions",
            [
                ("customer", customer_id),
                ("return_url", return_url),
            ],
        )

    def _post(self, path: str, data: list[tuple[str, str]]) -> dict:
        response = requests.post(
            f"{self.api_base}{path}",
            data=data,
            auth=(self.secret_key, ""),
            headers={"Stripe-Version": self.api_version},
            timeout=self.timeout_seconds,
        )
        try:
            payload = response.json() if response.content else {}
        except ValueError as exc:
            raise StripeAPIError(
                f"Stripe API returned invalid JSON with {response.status_code}",
                status_code=response.status_code,
            ) from exc
        if response.status_code >= 400:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            message = error.get("message") or f"Stripe API request failed with {response.status_code}"
            raise StripeAPIError(message, status_code=response.status_code)
        if not isinstance(payload, dict):
            raise StripeAPIError("Stripe API returned a non-object response")
        return payload


def stripe_config_from_env(env: Mapping[str, str] | None = None) -> StripeBillingConfig:
    source = env if env is not None else os.environ
    return StripeBillingConfig(
        secret_key=source.get("STRIPE_SECRET_KEY", "").strip(),
        webhook_secret=source.get("STRIPE_WEBHOOK_SECRET", "").strip(),
    )


def _price_env_for_interval(plan: Plan, billing_interval: str = "monthly") -> str:
    interval = billing_interval.strip().lower()
    if interval in {"yearly", "annual"}:
        return plan.stripe_yearly_price_env
    if interval == "monthly":
        return plan.stripe_price_env
    raise StripeConfigError(f"Unsupported billing interval: {billing_interval}")


def missing_checkout_env(
    plan: Plan,
    env: Mapping[str, str] | None = None,
    *,
    billing_interval: str = "monthly",
) -> list[str]:
    source = env if env is not None else os.environ
    missing = []
    if not source.get("STRIPE_SECRET_KEY", "").strip():
        missing.append("STRIPE_SECRET_KEY")
    price_env = _price_env_for_interval(plan, billing_interval)
    if price_env and not source.get(price_env, "").strip():
        missing.append(price_env)
    return missing


def price_id_for_plan(
    plan: Plan,
    env: Mapping[str, str] | None = None,
    *,
    billing_interval: str = "monthly",
) -> str:
    source = env if env is not None else os.environ
    price_env = _price_env_for_interval(plan, billing_interval)
    if not price_env:
        raise StripeConfigError(f"{plan.name} does not use Stripe Checkout")
    price_id = source.get(price_env, "").strip()
    if not price_id:
        raise StripeConfigError(f"{price_env} is not configured")
    return price_id


def plan_slug_for_price_id(price_id: str, env: Mapping[str, str] | None = None) -> str | None:
    source = env if env is not None else os.environ
    for plan in PLAN_CATALOG:
        if plan.stripe_price_env and source.get(plan.stripe_price_env, "").strip() == price_id:
            return plan.slug
        if (
            plan.stripe_yearly_price_env
            and source.get(plan.stripe_yearly_price_env, "").strip() == price_id
        ):
            return plan.slug
    return None


def verify_stripe_webhook(
    payload: bytes,
    signature_header: str | None,
    webhook_secret: str,
    *,
    now: int | None = None,
    tolerance_seconds: int = WEBHOOK_TOLERANCE_SECONDS,
) -> dict:
    """Verify Stripe's webhook signature and return the decoded event."""
    if not webhook_secret:
        raise StripeConfigError("STRIPE_WEBHOOK_SECRET is not configured")
    if not signature_header:
        raise StripeWebhookError("Missing Stripe-Signature header")

    parts = _parse_signature_header(signature_header)
    timestamp = parts.get("t")
    signatures = parts.get("v1", [])
    if not timestamp or not signatures:
        raise StripeWebhookError("Stripe-Signature header is missing t or v1")
    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise StripeWebhookError("Stripe-Signature timestamp is invalid") from exc

    current = int(now if now is not None else time.time())
    if abs(current - timestamp_int) > tolerance_seconds:
        raise StripeWebhookError("Stripe-Signature timestamp is outside tolerance")

    try:
        payload_text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StripeWebhookError("Stripe webhook payload is not UTF-8") from exc

    signed_payload = f"{timestamp}.{payload_text}".encode("utf-8")
    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()
    if not any(hmac.compare_digest(expected, signature) for signature in signatures):
        raise StripeWebhookError("Stripe webhook signature verification failed")

    try:
        event = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise StripeWebhookError("Stripe webhook payload is not valid JSON") from exc
    if not isinstance(event, dict) or "type" not in event:
        raise StripeWebhookError("Stripe webhook payload is not an event object")
    return event


def _parse_signature_header(value: str) -> dict[str, str | list[str]]:
    parts: dict[str, str | list[str]] = {}
    for item in value.split(","):
        key, _, raw = item.partition("=")
        if not key or not raw:
            continue
        if key == "v1":
            signatures = parts.setdefault("v1", [])
            if isinstance(signatures, list):
                signatures.append(raw)
        else:
            parts[key] = raw
    return parts

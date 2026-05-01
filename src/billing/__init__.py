"""Billing and entitlement helpers for the product-facing SaaS layer."""

from .plans import (
    FEATURE_CATALOG,
    PLAN_CATALOG,
    get_feature,
    get_plan,
    minimum_plan_for_feature,
    plan_allows_feature,
    plan_payload,
)
from .stripe_client import (
    STRIPE_API_VERSION,
    StripeAPIError,
    StripeBillingClient,
    StripeConfigError,
    StripeWebhookError,
    missing_checkout_env,
    plan_slug_for_price_id,
    price_id_for_plan,
    stripe_config_from_env,
    verify_stripe_webhook,
)

__all__ = [
    "FEATURE_CATALOG",
    "PLAN_CATALOG",
    "STRIPE_API_VERSION",
    "StripeAPIError",
    "StripeBillingClient",
    "StripeConfigError",
    "StripeWebhookError",
    "get_feature",
    "get_plan",
    "missing_checkout_env",
    "minimum_plan_for_feature",
    "plan_allows_feature",
    "plan_slug_for_price_id",
    "plan_payload",
    "price_id_for_plan",
    "stripe_config_from_env",
    "verify_stripe_webhook",
]

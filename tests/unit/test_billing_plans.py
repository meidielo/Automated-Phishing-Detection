import pytest

from src.billing.entitlements import feature_entitlement, locked_analyzer_result
from src.billing.plans import (
    FEATURE_CATALOG,
    PLAN_CATALOG,
    minimum_plan_for_feature,
    plan_allows_feature,
    plan_payload,
)


def test_plan_catalog_has_monotonic_quotas():
    quotas = [plan.scan_quota for plan in PLAN_CATALOG]

    assert quotas == sorted(quotas)
    assert PLAN_CATALOG[0].slug == "free"
    assert PLAN_CATALOG[-1].slug == "business"


def test_expensive_features_are_not_free():
    expensive = [feature for feature in FEATURE_CATALOG if feature.expensive]

    assert expensive
    assert all(feature.minimum_plan != "free" for feature in expensive)


def test_minimum_plan_lookup_returns_plan():
    plan = minimum_plan_for_feature("url_detonation")

    assert plan.slug == "pro"
    assert plan.monthly_price_aud > 0


def test_minimum_plan_lookup_rejects_unknown_feature():
    with pytest.raises(KeyError):
        minimum_plan_for_feature("unknown")


def test_free_plan_payload_locks_paid_api_features():
    payload = plan_payload(current_plan="free")
    features = {feature["slug"]: feature for feature in payload["features"]}

    assert payload["current_plan"] == "free"
    assert features["manual_scan"]["available"] is True
    assert features["header_auth"]["available"] is True
    assert features["payment_rules"]["available"] is True
    assert features["url_reputation"]["available"] is False
    assert features["url_reputation"]["required_plan_name"] == "Starter"
    assert features["attachment_sandbox"]["required_plan_name"] == "Pro"
    assert features["llm_intent"]["available"] is False
    assert features["url_detonation"]["required_plan_name"] == "Pro"


def test_pro_plan_payload_unlocks_pro_but_not_business_features():
    payload = plan_payload(current_plan="pro")
    features = {feature["slug"]: feature for feature in payload["features"]}

    assert features["url_detonation"]["available"] is True
    assert features["mailbox_monitoring"]["available"] is True
    assert features["team_audit"]["available"] is False


def test_plan_allows_feature_uses_catalog_order():
    assert plan_allows_feature("free", "payment_rules") is True
    assert plan_allows_feature("free", "url_reputation") is False
    assert plan_allows_feature("starter", "url_reputation") is True
    assert plan_allows_feature("pro", "attachment_sandbox") is True


def test_manual_scan_quota_locks_after_plan_limit():
    decision = feature_entitlement(
        "free",
        "manual_scan",
        monthly_scan_used=5,
        enforce_scan_quota=True,
    )

    assert decision.available is False
    assert decision.limit_kind == "quota"
    assert decision.required_plan_name == "Starter"


def test_locked_analyzer_result_has_structured_metadata():
    decision = feature_entitlement("free", "url_detonation")
    result = locked_analyzer_result("url_detonation", decision)

    assert result.confidence == 0.0
    assert result.details["message"] == "feature_locked"
    assert result.details["required_plan_name"] == "Pro"

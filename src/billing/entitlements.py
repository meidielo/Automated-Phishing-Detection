"""Plan entitlement checks shared by SaaS routes and analyzer gating."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from src.billing.plans import PLAN_CATALOG, get_feature, get_plan, plan_allows_feature
from src.models import AnalyzerResult


ANALYZER_FEATURES = {
    "header_analysis": "header_auth",
    "url_reputation": "url_reputation",
    "domain_intelligence": "domain_intelligence",
    "url_detonation": "url_detonation",
    "brand_impersonation": "brand_impersonation",
    "attachment_analysis": "attachment_sandbox",
    "nlp_intent": "llm_intent",
    "sender_profiling": "sender_profiling",
    "payment_fraud": "payment_rules",
}


@dataclass(frozen=True)
class EntitlementDecision:
    feature_slug: str
    available: bool
    current_plan: str
    current_plan_name: str
    required_plan: str
    required_plan_name: str
    reason: str
    quota: int | None = None
    used: int = 0
    remaining: int | None = None
    limit_kind: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def next_plan_for_scan_quota(current_plan: str, used: int) -> str | None:
    """Return the next plan that can cover the current monthly scan usage."""
    current_rank = _plan_rank_or_free(current_plan)
    for plan in PLAN_CATALOG[current_rank + 1:]:
        if used < plan.scan_quota:
            return plan.slug
    return None


def feature_entitlement(
    current_plan: str,
    feature_slug: str,
    *,
    monthly_scan_used: int = 0,
    enforce_scan_quota: bool = False,
) -> EntitlementDecision:
    """Evaluate whether a plan can use a feature right now."""
    try:
        current = get_plan(current_plan)
    except KeyError:
        current = get_plan("free")
    feature = get_feature(feature_slug)
    required = get_plan(feature.minimum_plan)

    plan_allowed = plan_allows_feature(current.slug, feature.slug)
    quota = current.scan_quota if feature.slug == "manual_scan" else None
    remaining = None
    if quota is not None:
        remaining = max(quota - monthly_scan_used, 0)

    if not plan_allowed:
        return EntitlementDecision(
            feature_slug=feature.slug,
            available=False,
            current_plan=current.slug,
            current_plan_name=current.name,
            required_plan=required.slug,
            required_plan_name=required.name,
            reason=f"{feature.name} is available on {required.name}.",
            quota=quota,
            used=monthly_scan_used,
            remaining=remaining,
            limit_kind="plan",
        )

    if enforce_scan_quota and feature.slug == "manual_scan" and quota is not None:
        if monthly_scan_used >= quota:
            upgrade_plan_slug = next_plan_for_scan_quota(current.slug, monthly_scan_used)
            upgrade_plan = get_plan(upgrade_plan_slug) if upgrade_plan_slug else current
            return EntitlementDecision(
                feature_slug=feature.slug,
                available=False,
                current_plan=current.slug,
                current_plan_name=current.name,
                required_plan=upgrade_plan.slug,
                required_plan_name=upgrade_plan.name,
                reason=(
                    f"{current.name} includes {quota} manual scans/month. "
                    f"Upgrade to {upgrade_plan.name} for a higher scan budget."
                ),
                quota=quota,
                used=monthly_scan_used,
                remaining=0,
                limit_kind="quota",
            )

    return EntitlementDecision(
        feature_slug=feature.slug,
        available=True,
        current_plan=current.slug,
        current_plan_name=current.name,
        required_plan=required.slug,
        required_plan_name=required.name,
        reason=f"{feature.name} is included in {current.name}.",
        quota=quota,
        used=monthly_scan_used,
        remaining=remaining,
        limit_kind=None,
    )


def locked_analyzer_result(analyzer_name: str, decision: EntitlementDecision | dict) -> AnalyzerResult:
    """Represent a skipped paid analyzer as structured lock metadata."""
    payload = decision.to_dict() if hasattr(decision, "to_dict") else dict(decision)
    return AnalyzerResult(
        analyzer_name=analyzer_name,
        risk_score=0.0,
        confidence=0.0,
        details={
            "message": "feature_locked",
            **payload,
        },
        errors=[payload.get("reason", "Feature is locked for this plan.")],
    )


def _plan_rank_or_free(plan_slug: str) -> int:
    try:
        return [plan.slug for plan in PLAN_CATALOG].index(plan_slug)
    except ValueError:
        return 0

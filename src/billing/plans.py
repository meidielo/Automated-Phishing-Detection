"""Plan and feature entitlement catalog.

This module is intentionally dependency-free. Stripe webhooks, usage DB rows,
and UI rendering should all refer to these stable slugs instead of duplicating
feature gates in templates or API handlers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Plan:
    slug: str
    name: str
    monthly_price_aud: int
    scan_quota: int
    mailbox_quota: int
    stripe_price_env: str
    summary: str
    best_for: str


@dataclass(frozen=True)
class Feature:
    slug: str
    name: str
    description: str
    minimum_plan: str
    category: str
    expensive: bool = False


PLAN_ORDER = ("free", "starter", "pro", "business")

PLAN_CATALOG: tuple[Plan, ...] = (
    Plan(
        slug="free",
        name="Free",
        monthly_price_aud=0,
        scan_quota=5,
        mailbox_quota=0,
        stripe_price_env="",
        summary="Try payment-scam checks without connecting a mailbox or using paid APIs.",
        best_for="Demo visitors and tiny manual checks",
    ),
    Plan(
        slug="starter",
        name="Starter",
        monthly_price_aud=19,
        scan_quota=100,
        mailbox_quota=1,
        stripe_price_env="STRIPE_PRICE_STARTER",
        summary="Manual scans with reputation checks and stored history.",
        best_for="Freelancers and very small teams",
    ),
    Plan(
        slug="pro",
        name="Pro",
        monthly_price_aud=49,
        scan_quota=1000,
        mailbox_quota=3,
        stripe_price_env="STRIPE_PRICE_PRO",
        summary="Mailbox monitoring plus LLM and browser-backed analysis.",
        best_for="SMEs that receive invoices by email",
    ),
    Plan(
        slug="business",
        name="Business",
        monthly_price_aud=149,
        scan_quota=5000,
        mailbox_quota=10,
        stripe_price_env="STRIPE_PRICE_BUSINESS",
        summary="Team controls, audit logs, and higher mailbox/API budgets.",
        best_for="Finance teams and agencies",
    ),
)

FEATURE_CATALOG: tuple[Feature, ...] = (
    Feature(
        slug="header_auth",
        name="Header authentication",
        description="SPF, DKIM, DMARC, reply-to, and sender-domain checks.",
        minimum_plan="free",
        category="Core detection",
    ),
    Feature(
        slug="payment_rules",
        name="Payment scam rules",
        description="Bank-detail change, urgency, invoice, and executive-transfer signals.",
        minimum_plan="free",
        category="Payment firewall",
    ),
    Feature(
        slug="scan_history",
        name="Private scan history",
        description="Database-backed result history scoped to the signed-in user or team.",
        minimum_plan="starter",
        category="Account data",
    ),
    Feature(
        slug="url_reputation",
        name="URL reputation",
        description="VirusTotal, Safe Browsing, AbuseIPDB, and urlscan-backed URL checks.",
        minimum_plan="starter",
        category="Paid API-backed checks",
        expensive=True,
    ),
    Feature(
        slug="domain_intelligence",
        name="Domain intelligence",
        description="WHOIS, domain age, hosting, and suspicious registration signals.",
        minimum_plan="starter",
        category="Paid API-backed checks",
        expensive=True,
    ),
    Feature(
        slug="mailbox_monitoring",
        name="Mailbox monitoring",
        description="Continuous user-owned mailbox polling with per-user result isolation.",
        minimum_plan="pro",
        category="Mailbox automation",
        expensive=True,
    ),
    Feature(
        slug="llm_intent",
        name="LLM BEC reasoning",
        description="LLM-backed social-engineering and payment-intent analysis.",
        minimum_plan="pro",
        category="Paid API-backed checks",
        expensive=True,
    ),
    Feature(
        slug="url_detonation",
        name="Browser URL detonation",
        description="Sandboxed browser visits, redirects, login-form checks, and screenshots.",
        minimum_plan="pro",
        category="Paid API-backed checks",
        expensive=True,
    ),
    Feature(
        slug="team_audit",
        name="Team audit trail",
        description="Team members, role boundaries, feedback-label audit logs, and exports.",
        minimum_plan="business",
        category="Team controls",
    ),
)


def _plan_rank(slug: str) -> int:
    try:
        return PLAN_ORDER.index(slug)
    except ValueError:
        return -1


def minimum_plan_for_feature(feature_slug: str) -> Plan:
    """Return the minimum plan required for a feature slug."""
    feature = next((item for item in FEATURE_CATALOG if item.slug == feature_slug), None)
    if feature is None:
        raise KeyError(f"unknown feature: {feature_slug}")
    plan = next((item for item in PLAN_CATALOG if item.slug == feature.minimum_plan), None)
    if plan is None:
        raise KeyError(f"unknown plan: {feature.minimum_plan}")
    return plan


def plan_payload(current_plan: str = "free") -> dict:
    """Serialize plan catalog with availability for the current plan."""
    current_rank = _plan_rank(current_plan)
    if current_rank < 0:
        current_plan = "free"
        current_rank = _plan_rank(current_plan)

    features = []
    for feature in FEATURE_CATALOG:
        required_rank = _plan_rank(feature.minimum_plan)
        required_plan = minimum_plan_for_feature(feature.slug)
        features.append(
            {
                **asdict(feature),
                "available": current_rank >= required_rank,
                "required_plan_name": required_plan.name,
            }
        )

    return {
        "current_plan": current_plan,
        "plans": [asdict(plan) for plan in PLAN_CATALOG],
        "features": features,
        "billing_recommendation": "Stripe Billing + Checkout Sessions + Customer Portal",
    }

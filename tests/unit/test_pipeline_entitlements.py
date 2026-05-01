from __future__ import annotations

import pytest

from src.billing.entitlements import feature_entitlement
from src.config import PipelineConfig
from src.orchestrator.pipeline import PhishingPipeline


@pytest.mark.asyncio
async def test_pipeline_skips_locked_paid_analyzers_before_loading(sample_email_clean):
    pipeline = PhishingPipeline(PipelineConfig())
    paid_analyzers = {
        "url_reputation",
        "domain_intelligence",
        "url_detonation",
        "brand_impersonation",
        "attachment_analysis",
        "nlp_intent",
        "sender_profiling",
    }

    async def load_analyzer(name):
        if name in paid_analyzers:
            raise AssertionError(f"locked analyzer should not load: {name}")
        return None

    pipeline._load_analyzer = load_analyzer

    results = await pipeline._phase_analysis(
        sample_email_clean,
        {},
        [],
        feature_gate=lambda slug: feature_entitlement("free", slug).to_dict(),
    )

    assert results["url_reputation"].details["message"] == "feature_locked"
    assert results["url_reputation"].details["required_plan_name"] == "Starter"
    assert results["url_detonation"].details["required_plan_name"] == "Pro"
    assert "header_analysis" not in results

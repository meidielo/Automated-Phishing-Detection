from src.config import PipelineConfig
from src.models import AnalyzerResult, Verdict
from src.orchestrator.pipeline import PhishingPipeline


def _pipeline() -> PhishingPipeline:
    return PhishingPipeline(PipelineConfig())


def _header(
    from_address: str,
    risk_score: float = 0.45,
    spf: bool = True,
    dkim: bool = True,
    dmarc: bool = True,
) -> AnalyzerResult:
    domain = from_address.rsplit("@", 1)[1]
    return AnalyzerResult(
        analyzer_name="header_analysis",
        risk_score=risk_score,
        confidence=1.0,
        details={
            "spf_pass": spf,
            "dkim_pass": dkim,
            "dmarc_pass": dmarc,
            "from_address": from_address,
            "from_domain": domain,
        },
    )


def _brand(risk_score: float = 0.85) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name="brand_impersonation",
        risk_score=risk_score,
        confidence=0.9,
        details={
            "signals": [
                {
                    "signal": "display_name_brand_mismatch",
                    "brand": "github",
                    "risk": risk_score,
                }
            ]
        },
    )


def _nlp(risk_score: float = 1.0) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name="nlp_intent",
        risk_score=risk_score,
        confidence=0.85,
        details={"intent_classification": {"category": "credential_harvesting"}},
    )


def _domain_intel(risk_score: float = 0.6) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_name="domain_intelligence",
        risk_score=risk_score,
        confidence=0.8,
        details={},
    )


def _content_heavy_results(from_address: str, **header_kwargs) -> dict[str, AnalyzerResult]:
    return {
        "header_analysis": _header(from_address, **header_kwargs),
        "brand_impersonation": _brand(),
        "nlp_intent": _nlp(),
        "domain_intelligence": _domain_intel(),
    }


def test_trusted_authenticated_domain_dampens_expected_content_signals():
    verdict, score, _, reasoning = _pipeline()._phase_decision(
        _content_heavy_results("notifications@github.com")
    )

    assert verdict is Verdict.CLEAN
    assert score < 0.3
    assert "TRUSTED SENDER" in reasoning
    assert "trusted_domain=github.com" in reasoning


def test_trusted_authenticated_two_part_tld_domain_dampens_content_signals():
    verdict, score, _, reasoning = _pipeline()._phase_decision(
        _content_heavy_results("noreply@ventraip.com.au")
    )

    assert verdict is Verdict.CLEAN
    assert score < 0.3
    assert "TRUSTED SENDER" in reasoning
    assert "trusted_domain=ventraip.com.au" in reasoning


def test_authenticated_unknown_domain_does_not_receive_trusted_dampening():
    verdict, score, _, reasoning = _pipeline()._phase_decision(
        _content_heavy_results("alerts@github-security.example")
    )

    assert verdict is not Verdict.CLEAN
    assert score >= 0.3
    assert "TRUSTED SENDER" not in reasoning


def test_trusted_domain_with_auth_failure_does_not_receive_dampening():
    verdict, score, _, reasoning = _pipeline()._phase_decision(
        _content_heavy_results(
            "no-reply@accounts.google.com",
            risk_score=0.6,
            spf=True,
            dkim=False,
            dmarc=True,
        )
    )

    assert verdict is not Verdict.CLEAN
    assert score >= 0.3
    assert "TRUSTED SENDER" not in reasoning

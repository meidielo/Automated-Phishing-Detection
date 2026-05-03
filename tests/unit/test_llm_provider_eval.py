from __future__ import annotations

from pathlib import Path

import pytest

from scripts import llm_provider_eval as eval_script
from src.eval.payment_dataset import add_sample, init_dataset


def _write_eml(path: Path, subject: str, body: str) -> Path:
    path.write_text(
        "\n".join(
            [
                "From: Supplier Accounts <accounts@supplier.example>",
                "To: ap@example.com",
                f"Subject: {subject}",
                "",
                body,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _summary(key: str, accuracy: float, cost: float, errors: int = 0):
    provider, model = key.split(":", 1)
    rows = 100
    correct = int(rows * accuracy)
    return eval_script.ModelSummary(
        provider=provider,
        model=model,
        rows=rows,
        completed=rows,
        correct=correct,
        errors=errors,
        accuracy=accuracy,
        completed_accuracy=accuracy,
        total_cost_usd=cost,
        avg_cost_per_1000=cost * 10,
        median_latency_ms=100,
        p95_latency_ms=200,
        confusion_matrix={"SAFE": {"SAFE": correct}},
    )


def test_parse_model_spec_uses_priced_catalog():
    model = eval_script.parse_model_spec("deepseek:deepseek-v4-pro")

    assert model.provider == "deepseek"
    assert model.model == "deepseek-v4-pro"
    assert model.input_usd_per_million == 0.435
    assert model.output_usd_per_million == 0.87


def test_parse_model_spec_supports_priced_gemini_catalog():
    model = eval_script.parse_model_spec("gemini:gemini-3.1-pro-preview")

    assert model.provider == "gemini"
    assert model.model == "gemini-3.1-pro-preview"
    assert model.base_url == "https://generativelanguage.googleapis.com/v1beta/openai"
    assert model.input_usd_per_million == 2.00
    assert model.output_usd_per_million == 12.00


def test_parse_model_spec_supports_priced_openai_catalog():
    model = eval_script.parse_model_spec("openai:gpt-5.5")

    assert model.provider == "openai"
    assert model.model == "gpt-5.5"
    assert model.base_url == "https://api.openai.com/v1"
    assert model.input_usd_per_million == 5.00
    assert model.output_usd_per_million == 30.00


def test_parse_model_spec_supports_generic_openai_compatible(monkeypatch):
    monkeypatch.setenv("LLM_API_BASE", "https://router.example/v1")

    model = eval_script.parse_model_spec("openai_compatible:small-model")

    assert model.provider == "openai"
    assert model.model == "small-model"
    assert model.base_url == "https://router.example/v1"
    assert model.input_usd_per_million == 0.0


def test_parse_llm_json_accepts_markdown_and_clamps_confidence():
    decision, confidence, reasoning = eval_script.parse_llm_json(
        '```json\n{"decision":"verify","confidence":1.7,"reasoning":"check supplier"}\n```'
    )

    assert decision == "VERIFY"
    assert confidence == 1.0
    assert reasoning == "check supplier"


def test_read_payment_samples_filters_pii_and_balances(tmp_path: Path):
    dataset = init_dataset(tmp_path / "payment")
    safe = _write_eml(tmp_path / "safe.eml", "Invoice", "Normal invoice for approved PO.")
    verify = _write_eml(tmp_path / "verify.eml", "Portal payment", "Please login to the payment portal.")
    pii = _write_eml(tmp_path / "pii.eml", "Bank change", "New BSB 123-456 and account 1234567.")

    add_sample(
        dataset_dir=dataset,
        source=safe,
        label="LEGITIMATE_PAYMENT",
        payment_decision="SAFE",
        scenario="legitimate_invoice",
        source_type="redacted",
        split="holdout",
        contains_real_pii="no",
    )
    add_sample(
        dataset_dir=dataset,
        source=verify,
        label="PAYMENT_SCAM",
        payment_decision="VERIFY",
        scenario="payment_portal_link",
        source_type="public",
        split="holdout",
        contains_real_pii="no",
    )
    add_sample(
        dataset_dir=dataset,
        source=pii,
        label="PAYMENT_SCAM",
        payment_decision="DO_NOT_PAY",
        scenario="bank_detail_change",
        source_type="real",
        split="holdout",
        contains_real_pii="yes",
    )

    samples = eval_script.read_payment_samples(
        dataset,
        splits=("holdout",),
        source_types=("all",),
        max_samples_per_decision=1,
    )

    assert {sample.expected_decision for sample in samples} == {"SAFE", "VERIFY"}
    assert {sample.contains_real_pii for sample in samples} == {"no"}


def test_openai_compatible_body_uses_kimi_non_thinking_parameters():
    model = eval_script.MODEL_CATALOG["moonshot:kimi-k2.6"]

    body = eval_script.openai_compatible_body(model, "classify")

    assert "temperature" not in body
    assert body["thinking"] == {"type": "disabled"}
    assert body["response_format"] == {"type": "json_object"}


def test_openai_compatible_body_uses_gemini_minimal_reasoning():
    model = eval_script.MODEL_CATALOG["gemini:gemini-3-flash-preview"]

    body = eval_script.openai_compatible_body(model, "classify")

    assert body["temperature"] == 0
    assert body["reasoning_effort"] == "minimal"
    assert body["response_format"] == {"type": "json_object"}


def test_openai_compatible_body_uses_gemini_pro_supported_reasoning():
    model = eval_script.MODEL_CATALOG["gemini:gemini-3.1-pro-preview"]

    body = eval_script.openai_compatible_body(model, "classify")

    assert body["temperature"] == 0
    assert body["reasoning_effort"] == "low"
    assert body["max_tokens"] == 1024


def test_openai_compatible_body_uses_gpt5_supported_parameters():
    model = eval_script.MODEL_CATALOG["openai:gpt-5.5"]

    body = eval_script.openai_compatible_body(model, "classify")

    assert "temperature" not in body
    assert "max_tokens" not in body
    assert body["max_completion_tokens"] == 512
    assert body["reasoning_effort"] == "none"
    assert body["response_format"] == {"type": "json_object"}


def test_available_default_models_includes_gemini_cost_models(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

    keys = [model.key for model in eval_script.available_default_models()]

    assert keys == [
        "gemini:gemini-3.1-pro-preview",
        "gemini:gemini-3.1-flash-lite-preview",
        "gemini:gemini-3-flash-preview",
    ]


def test_available_default_models_includes_openai_cost_models(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")

    keys = [model.key for model in eval_script.available_default_models()]

    assert keys == [
        "openai:gpt-5.5",
        "openai:gpt-5.4-mini",
    ]


@pytest.mark.asyncio
async def test_evaluate_model_dry_run_does_not_require_api_key():
    model = eval_script.MODEL_CATALOG["deepseek:deepseek-v4-flash"]
    sample = eval_script.PaymentSample(
        filename="sample.eml",
        expected_decision="SAFE",
        source_type="synthetic",
        split="holdout",
        contains_real_pii="no",
        subject="Invoice",
        from_header="ap@example.com",
        reply_to="",
        body="Normal invoice.",
        path=Path("sample.eml"),
    )

    results = await eval_script.evaluate_model(
        model,
        [sample],
        run_live=False,
        timeout_seconds=1,
    )

    assert results[0].error == "dry_run"
    assert results[0].prompt_tokens > 0
    assert results[0].cost_usd == 0.0


def test_summarize_results_builds_confusion_and_cost():
    model = eval_script.MODEL_CATALOG["deepseek:deepseek-v4-flash"]
    results = [
        eval_script.LLMCallResult(
            provider="deepseek",
            model="deepseek-v4-flash",
            filename="safe.eml",
            expected_decision="SAFE",
            predicted_decision="SAFE",
            confidence=0.9,
            reasoning="normal invoice",
            latency_ms=100,
            prompt_tokens=100,
            completion_tokens=20,
            cost_usd=eval_script.estimate_cost_usd(model, 100, 20),
        ),
        eval_script.LLMCallResult(
            provider="deepseek",
            model="deepseek-v4-flash",
            filename="verify.eml",
            expected_decision="VERIFY",
            predicted_decision="SAFE",
            confidence=0.6,
            reasoning="missed risk",
            latency_ms=120,
            prompt_tokens=100,
            completion_tokens=20,
            cost_usd=eval_script.estimate_cost_usd(model, 100, 20),
        ),
    ]

    summaries = eval_script.summarize_results(results)

    assert summaries[0].accuracy == 0.5
    assert summaries[0].confusion_matrix["VERIFY"]["SAFE"] == 1
    assert summaries[0].total_cost_usd > 0


def test_recommend_tiers_prefers_cheapest_model_inside_quality_band():
    recommendations = eval_script.recommend_tiers(
        [
            _summary("deepseek:deepseek-v4-flash", 0.99, 0.001),
            _summary("deepseek:deepseek-v4-pro", 1.00, 0.020),
            _summary("moonshot:kimi-k2.6", 0.98, 0.010),
        ],
        min_accuracy=0.90,
        quality_delta=0.02,
    )

    assert recommendations["starter"] == "deepseek:deepseek-v4-flash"
    assert recommendations["pro"] == "deepseek:deepseek-v4-flash"
    assert recommendations["business"] == "deepseek:deepseek-v4-flash"
    assert recommendations["enterprise"] == "deepseek:deepseek-v4-flash"


def test_recommend_tiers_keeps_paid_tiers_on_deepseek_when_margin_is_real():
    recommendations = eval_script.recommend_tiers(
        [
            _summary("deepseek:deepseek-v4-flash", 0.94, 0.001),
            _summary("deepseek:deepseek-v4-pro", 0.99, 0.020),
        ],
        min_accuracy=0.90,
        quality_delta=0.02,
    )

    assert recommendations["starter"] == "deepseek:deepseek-v4-flash"
    assert recommendations["pro"] == "deepseek:deepseek-v4-flash"
    assert recommendations["business"] == "deepseek:deepseek-v4-flash"
    assert recommendations["enterprise"] == "deepseek:deepseek-v4-pro"


def test_recommend_tiers_reserves_non_deepseek_gain_for_enterprise_review():
    recommendations = eval_script.recommend_tiers(
        [
            _summary("deepseek:deepseek-v4-flash", 0.93, 0.001),
            _summary("openai:gpt-5.5", 0.99, 0.070),
        ],
        min_accuracy=0.90,
        quality_delta=0.02,
    )

    assert recommendations["starter"] == "deepseek:deepseek-v4-flash"
    assert recommendations["pro"] == "deepseek:deepseek-v4-flash"
    assert recommendations["business"] == "deepseek:deepseek-v4-flash"
    assert recommendations["enterprise"] == "openai:gpt-5.5"

#!/usr/bin/env python3
"""
Benchmark LLM providers for payment-scam decisions.

The benchmark is intentionally separate from the full phishing pipeline. The
pipeline's payment rules can mask model differences, while this script measures
the LLM decision layer directly on SAFE / VERIFY / DO_NOT_PAY labels.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time
from typing import Any

import aiohttp

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.eval.payment_dataset import DEFAULT_DATASET_DIR, LABELS_CSV, SAMPLES_DIR  # noqa: E402

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - python-dotenv is in requirements.
    load_dotenv = None


DECISIONS = ("SAFE", "VERIFY", "DO_NOT_PAY")
DEFAULT_SOURCE_TYPES = ("public", "redacted", "synthetic")
DEFAULT_SPLITS = ("holdout",)


@dataclass(frozen=True)
class ProviderModel:
    provider: str
    model: str
    base_url: str
    api_key_env: str
    input_usd_per_million: float
    output_usd_per_million: float
    pricing_note: str
    json_mode: bool = True

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.model}"


@dataclass(frozen=True)
class PaymentSample:
    filename: str
    expected_decision: str
    source_type: str
    split: str
    contains_real_pii: str
    subject: str
    from_header: str
    reply_to: str
    body: str
    path: Path


@dataclass(frozen=True)
class LLMCallResult:
    provider: str
    model: str
    filename: str
    expected_decision: str
    predicted_decision: str
    confidence: float
    reasoning: str
    latency_ms: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    error: str = ""

    @property
    def correct(self) -> bool:
        return not self.error and self.predicted_decision == self.expected_decision


@dataclass(frozen=True)
class ModelSummary:
    provider: str
    model: str
    rows: int
    completed: int
    correct: int
    errors: int
    accuracy: float
    completed_accuracy: float
    total_cost_usd: float
    avg_cost_per_1000: float
    median_latency_ms: int
    p95_latency_ms: int
    confusion_matrix: dict[str, dict[str, int]]

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.model}"


MODEL_CATALOG: dict[str, ProviderModel] = {
    "deepseek:deepseek-v4-flash": ProviderModel(
        provider="deepseek",
        model="deepseek-v4-flash",
        base_url="https://api.deepseek.com",
        api_key_env="DEEPSEEK_API_KEY",
        input_usd_per_million=0.14,
        output_usd_per_million=0.28,
        pricing_note="DeepSeek official cache-miss/input and output pricing.",
    ),
    "deepseek:deepseek-v4-pro": ProviderModel(
        provider="deepseek",
        model="deepseek-v4-pro",
        base_url="https://api.deepseek.com",
        api_key_env="DEEPSEEK_API_KEY",
        input_usd_per_million=0.435,
        output_usd_per_million=0.87,
        pricing_note="DeepSeek official 75% promo pricing through 2026-05-31 15:59 UTC.",
    ),
    "moonshot:kimi-k2.6": ProviderModel(
        provider="moonshot",
        model="kimi-k2.6",
        base_url="https://api.moonshot.ai/v1",
        api_key_env="MOONSHOT_API_KEY",
        input_usd_per_million=0.95,
        output_usd_per_million=4.00,
        pricing_note="Kimi official current input and output pricing.",
    ),
    "gemini:gemini-3.1-flash-lite-preview": ProviderModel(
        provider="gemini",
        model="gemini-3.1-flash-lite-preview",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key_env="GEMINI_API_KEY",
        input_usd_per_million=0.25,
        output_usd_per_million=1.50,
        pricing_note="Google official Gemini Developer API paid-tier standard pricing.",
    ),
    "gemini:gemini-3-flash-preview": ProviderModel(
        provider="gemini",
        model="gemini-3-flash-preview",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key_env="GEMINI_API_KEY",
        input_usd_per_million=0.50,
        output_usd_per_million=3.00,
        pricing_note="Google official Gemini Developer API paid-tier standard pricing.",
    ),
    "gemini:gemini-3.1-pro-preview": ProviderModel(
        provider="gemini",
        model="gemini-3.1-pro-preview",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key_env="GEMINI_API_KEY",
        input_usd_per_million=2.00,
        output_usd_per_million=12.00,
        pricing_note="Google official Gemini 3.1 Pro paid-tier pricing for prompts <=200k tokens.",
    ),
    "anthropic:claude-opus-4-7": ProviderModel(
        provider="anthropic",
        model="claude-opus-4-7",
        base_url="",
        api_key_env="ANTHROPIC_API_KEY",
        input_usd_per_million=5.00,
        output_usd_per_million=25.00,
        pricing_note="Anthropic official Opus 4.7 platform pricing.",
        json_mode=False,
    ),
    "openai:gpt-5.5": ProviderModel(
        provider="openai",
        model="gpt-5.5",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        input_usd_per_million=5.00,
        output_usd_per_million=30.00,
        pricing_note="OpenAI official GPT-5.5 standard pricing.",
    ),
    "openai:gpt-5.4-mini": ProviderModel(
        provider="openai",
        model="gpt-5.4-mini",
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        input_usd_per_million=0.75,
        output_usd_per_million=4.50,
        pricing_note="OpenAI official GPT-5.4 mini standard pricing.",
    ),
}


def parse_model_spec(spec: str) -> ProviderModel:
    """Return a provider/model configuration from a CLI spec."""
    normalized = spec.strip().lower()
    if normalized in MODEL_CATALOG:
        return MODEL_CATALOG[normalized]
    if ":" not in normalized:
        raise ValueError("model spec must look like provider:model")
    provider, model = normalized.split(":", 1)
    if provider == "deepseek":
        base_url = "https://api.deepseek.com"
        key_env = "DEEPSEEK_API_KEY"
    elif provider in {"moonshot", "kimi"}:
        provider = "moonshot"
        base_url = "https://api.moonshot.ai/v1"
        key_env = "MOONSHOT_API_KEY"
    elif provider == "gemini":
        base_url = "https://generativelanguage.googleapis.com/v1beta/openai"
        key_env = "GEMINI_API_KEY"
    elif provider == "anthropic":
        base_url = ""
        key_env = "ANTHROPIC_API_KEY"
    elif provider in {"openai", "openai_compatible"}:
        provider = "openai"
        base_url = os.getenv("LLM_API_BASE", "https://api.openai.com/v1")
        key_env = "OPENAI_API_KEY"
    else:
        raise ValueError(f"unsupported provider: {provider}")
    return ProviderModel(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key_env=key_env,
        input_usd_per_million=0.0,
        output_usd_per_million=0.0,
        pricing_note="No built-in pricing. Add it to MODEL_CATALOG for cost ranking.",
        json_mode=provider != "anthropic",
    )


def available_default_models() -> list[ProviderModel]:
    """Choose default models based on keys available in the local environment."""
    models: list[ProviderModel] = []
    deepseek_key = os.getenv("DEEPSEEK_API_KEY") or (
        os.getenv("LLM_API_KEY") if os.getenv("LLM_PROVIDER", "").lower() == "deepseek" else ""
    )
    if deepseek_key:
        models.append(MODEL_CATALOG["deepseek:deepseek-v4-flash"])
        models.append(MODEL_CATALOG["deepseek:deepseek-v4-pro"])
    if os.getenv("MOONSHOT_API_KEY") or (
        os.getenv("LLM_API_KEY") if os.getenv("LLM_PROVIDER", "").lower() in {"moonshot", "kimi"} else ""
    ):
        models.append(MODEL_CATALOG["moonshot:kimi-k2.6"])
    if os.getenv("GEMINI_API_KEY") or (
        os.getenv("LLM_API_KEY") if os.getenv("LLM_PROVIDER", "").lower() == "gemini" else ""
    ):
        models.append(MODEL_CATALOG["gemini:gemini-3.1-pro-preview"])
        models.append(MODEL_CATALOG["gemini:gemini-3.1-flash-lite-preview"])
        models.append(MODEL_CATALOG["gemini:gemini-3-flash-preview"])
    if os.getenv("ANTHROPIC_API_KEY"):
        models.append(MODEL_CATALOG["anthropic:claude-opus-4-7"])
    if os.getenv("OPENAI_API_KEY") or (
        os.getenv("LLM_API_KEY") if os.getenv("LLM_PROVIDER", "").lower() in {"openai", "openai_compatible"} else ""
    ):
        models.append(MODEL_CATALOG["openai:gpt-5.5"])
        models.append(MODEL_CATALOG["openai:gpt-5.4-mini"])
    return models


def read_payment_samples(
    dataset_dir: Path,
    *,
    splits: tuple[str, ...] = DEFAULT_SPLITS,
    source_types: tuple[str, ...] = DEFAULT_SOURCE_TYPES,
    allow_pii: bool = False,
    max_samples_per_decision: int = 5,
    seed: int = 1337,
    body_chars: int = 2400,
) -> list[PaymentSample]:
    """Read, filter, and balance payment-decision samples."""
    labels_path = dataset_dir / LABELS_CSV
    if not labels_path.exists():
        raise FileNotFoundError(f"labels.csv not found: {labels_path}")

    with labels_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    selected_rows: list[dict[str, str]] = []
    split_filter = {value.lower() for value in splits if value.lower() != "all"}
    source_filter = {value.lower() for value in source_types if value.lower() != "all"}

    for row in rows:
        decision = row.get("payment_decision", "").strip().upper()
        if decision not in DECISIONS:
            continue
        if split_filter and row.get("split", "").strip().lower() not in split_filter:
            continue
        if source_filter and row.get("source_type", "").strip().lower() not in source_filter:
            continue
        contains_pii = row.get("contains_real_pii", "unknown").strip().lower()
        if not allow_pii and contains_pii != "no":
            continue
        selected_rows.append(row)

    by_decision: dict[str, list[dict[str, str]]] = {decision: [] for decision in DECISIONS}
    for row in selected_rows:
        by_decision[row["payment_decision"].strip().upper()].append(row)

    rng = random.Random(seed)
    balanced_rows: list[dict[str, str]] = []
    for decision in DECISIONS:
        decision_rows = sorted(by_decision[decision], key=lambda row: row.get("filename", ""))
        rng.shuffle(decision_rows)
        if max_samples_per_decision > 0:
            decision_rows = decision_rows[:max_samples_per_decision]
        balanced_rows.extend(sorted(decision_rows, key=lambda row: row.get("filename", "")))

    return [
        _row_to_sample(dataset_dir, row, body_chars=body_chars)
        for row in balanced_rows
    ]


def _row_to_sample(dataset_dir: Path, row: dict[str, str], *, body_chars: int) -> PaymentSample:
    filename = row.get("filename", "").strip()
    sample_path = dataset_dir / SAMPLES_DIR / filename
    if not sample_path.exists():
        raise FileNotFoundError(f"sample not found for labels.csv row: {sample_path}")

    data = sample_path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(data)
    body = _message_body(message)
    return PaymentSample(
        filename=filename,
        expected_decision=row.get("payment_decision", "").strip().upper(),
        source_type=row.get("source_type", "").strip(),
        split=row.get("split", "").strip(),
        contains_real_pii=row.get("contains_real_pii", "").strip().lower(),
        subject=str(message.get("Subject", "")),
        from_header=str(message.get("From", "")),
        reply_to=str(message.get("Reply-To", "")),
        body=_compact_text(body)[:body_chars],
        path=sample_path,
    )


def _message_body(message: Any) -> str:
    if message.is_multipart():
        part = message.get_body(preferencelist=("plain", "html"))
        if part is not None:
            payload = part.get_content()
            return str(payload)
        chunks = []
        for part in message.walk():
            if part.get_content_maintype() == "text":
                chunks.append(str(part.get_content()))
        return "\n".join(chunks)
    return str(message.get_content())


def _compact_text(text: str) -> str:
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def build_prompt(sample: PaymentSample) -> str:
    return f"""You classify payment-risk emails for an accounts-payable firewall.

Return JSON only. Use exactly one decision:
- SAFE: normal or non-payment email; no payment hold is needed.
- VERIFY: payment, invoice, supplier, portal, or account activity that needs out-of-band verification before money moves.
- DO_NOT_PAY: block payment release because the email shows bank-detail changes, payment redirection, urgent executive transfer pressure, approval bypass language, or a likely malicious payment portal.

Bias rules:
- If payment risk is ambiguous, choose VERIFY.
- If the email asks for new bank details, a changed account, a wire transfer, or an urgent executive payment, choose DO_NOT_PAY.
- If it is a normal invoice/remittance with no risky change, pressure, or suspicious portal, choose SAFE.

Email:
Subject: {sample.subject}
From: {sample.from_header}
Reply-To: {sample.reply_to}
Body:
{sample.body}

Return this exact shape:
{{"decision":"SAFE|VERIFY|DO_NOT_PAY","confidence":0.0,"reasoning":"short reason"}}
"""


def parse_llm_json(text: str) -> tuple[str, float, str]:
    """Parse and validate a provider JSON response."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    if not cleaned.startswith("{"):
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            cleaned = match.group(0)
    payload = json.loads(cleaned)
    decision = str(payload.get("decision", "")).strip().upper()
    if decision not in DECISIONS:
        raise ValueError(f"invalid decision: {decision or '<empty>'}")
    confidence_raw = payload.get("confidence", 0.0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(confidence, 1.0))
    reasoning = str(payload.get("reasoning", "")).strip()[:240]
    return decision, confidence, reasoning


async def evaluate_model(
    model: ProviderModel,
    samples: list[PaymentSample],
    *,
    run_live: bool,
    timeout_seconds: float,
) -> list[LLMCallResult]:
    if not run_live:
        return [
            LLMCallResult(
                provider=model.provider,
                model=model.model,
                filename=sample.filename,
                expected_decision=sample.expected_decision,
                predicted_decision="",
                confidence=0.0,
                reasoning="dry run only",
                latency_ms=0,
                prompt_tokens=estimate_tokens(build_prompt(sample)),
                completion_tokens=0,
                cost_usd=0.0,
                error="dry_run",
            )
            for sample in samples
        ]

    api_key = _api_key_for(model)
    if not api_key:
        return [
            LLMCallResult(
                provider=model.provider,
                model=model.model,
                filename=sample.filename,
                expected_decision=sample.expected_decision,
                predicted_decision="",
                confidence=0.0,
                reasoning="missing API key",
                latency_ms=0,
                prompt_tokens=estimate_tokens(build_prompt(sample)),
                completion_tokens=0,
                cost_usd=0.0,
                error=f"missing {model.api_key_env}",
            )
            for sample in samples
        ]

    if model.provider == "anthropic":
        return await _evaluate_anthropic(model, api_key, samples, timeout_seconds=timeout_seconds)
    return await _evaluate_openai_compatible(model, api_key, samples, timeout_seconds=timeout_seconds)


def _api_key_for(model: ProviderModel) -> str:
    key = os.getenv(model.api_key_env, "")
    if key:
        return key
    if model.provider == os.getenv("LLM_PROVIDER", "").lower():
        return os.getenv("LLM_API_KEY", "")
    if model.provider == "moonshot" and os.getenv("LLM_PROVIDER", "").lower() == "kimi":
        return os.getenv("LLM_API_KEY", "")
    return ""


async def _evaluate_openai_compatible(
    model: ProviderModel,
    api_key: str,
    samples: list[PaymentSample],
    *,
    timeout_seconds: float,
) -> list[LLMCallResult]:
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    results: list[LLMCallResult] = []
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for sample in samples:
            prompt = build_prompt(sample)
            body = openai_compatible_body(model, prompt)
            started = time.perf_counter()
            prompt_tokens = estimate_tokens(prompt)
            completion_tokens = 0
            try:
                async with session.post(
                    f"{model.base_url.rstrip('/')}/chat/completions",
                    json=body,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                ) as response:
                    payload = await _read_json_response(response)
                    if response.status >= 400:
                        raise RuntimeError(_provider_error(payload, response.status))
                text = _openai_compatible_text(payload)
                usage = payload.get("usage") if isinstance(payload, dict) else None
                if isinstance(usage, dict):
                    prompt_tokens = int(usage.get("prompt_tokens") or prompt_tokens)
                    completion_tokens = int(usage.get("completion_tokens") or estimate_tokens(text))
                else:
                    completion_tokens = estimate_tokens(text)
                predicted, confidence, reasoning = parse_llm_json(text)
                latency_ms = int((time.perf_counter() - started) * 1000)
                results.append(
                    LLMCallResult(
                        provider=model.provider,
                        model=model.model,
                        filename=sample.filename,
                        expected_decision=sample.expected_decision,
                        predicted_decision=predicted,
                        confidence=confidence,
                        reasoning=reasoning,
                        latency_ms=latency_ms,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        cost_usd=estimate_cost_usd(model, prompt_tokens, completion_tokens),
                    )
                )
            except Exception as exc:
                latency_ms = int((time.perf_counter() - started) * 1000)
                results.append(
                    LLMCallResult(
                        provider=model.provider,
                        model=model.model,
                        filename=sample.filename,
                        expected_decision=sample.expected_decision,
                        predicted_decision="",
                        confidence=0.0,
                        reasoning="",
                        latency_ms=latency_ms,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        cost_usd=estimate_cost_usd(model, prompt_tokens, completion_tokens),
                        error=str(exc)[:240],
                    )
                )
    return results


def openai_compatible_body(model: ProviderModel, prompt: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 256,
    }
    if model.json_mode:
        body["response_format"] = {"type": "json_object"}
    if model.provider == "deepseek":
        body["thinking"] = {"type": "disabled"}
        body["temperature"] = 0
    elif model.provider == "moonshot" and model.model.startswith(("kimi-k2.6", "kimi-k2.5")):
        body["thinking"] = {"type": "disabled"}
    elif model.provider == "gemini":
        body["temperature"] = 0
        if model.model.startswith("gemini-3.1-pro"):
            body["reasoning_effort"] = "low"
            body["max_tokens"] = 1024
        elif model.model.startswith("gemini-2.5"):
            body["reasoning_effort"] = "none"
        elif model.model.startswith("gemini-3"):
            body["reasoning_effort"] = "minimal"
    elif model.provider == "openai" and model.model.startswith("gpt-5"):
        body.pop("max_tokens", None)
        body["max_completion_tokens"] = 512
        body["reasoning_effort"] = "none"
    else:
        body["temperature"] = 0
    return body


async def _read_json_response(response: aiohttp.ClientResponse) -> dict[str, Any]:
    try:
        payload = await response.json()
    except Exception:
        text = await response.text()
        raise RuntimeError(f"HTTP {response.status}: non-JSON response: {text[:120]}")
    if not isinstance(payload, dict):
        raise RuntimeError("provider returned a non-object JSON response")
    return payload


def _provider_error(payload: dict[str, Any], status: int) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or f"HTTP {status}")
    if isinstance(error, str):
        return error
    return f"HTTP {status}"


def _openai_compatible_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("provider response did not include choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise RuntimeError("provider choice was not an object")
    message = first.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                str(part.get("text", ""))
                for part in content
                if isinstance(part, dict)
            )
    text = first.get("text")
    if isinstance(text, str):
        return text
    raise RuntimeError("provider response did not include text content")


async def _evaluate_anthropic(
    model: ProviderModel,
    api_key: str,
    samples: list[PaymentSample],
    *,
    timeout_seconds: float,
) -> list[LLMCallResult]:
    try:
        import anthropic
    except Exception as exc:
        return [
            LLMCallResult(
                provider=model.provider,
                model=model.model,
                filename=sample.filename,
                expected_decision=sample.expected_decision,
                predicted_decision="",
                confidence=0.0,
                reasoning="anthropic package missing",
                latency_ms=0,
                prompt_tokens=estimate_tokens(build_prompt(sample)),
                completion_tokens=0,
                cost_usd=0.0,
                error=str(exc)[:240],
            )
            for sample in samples
        ]

    client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout_seconds)
    results: list[LLMCallResult] = []
    for sample in samples:
        prompt = build_prompt(sample)
        started = time.perf_counter()
        prompt_tokens = estimate_tokens(prompt)
        completion_tokens = 0
        try:
            body = {
                "model": model.model,
                "max_tokens": 256,
                "messages": [{"role": "user", "content": prompt}],
            }
            if not model.model.startswith("claude-opus-4-7"):
                body["temperature"] = 0
            message = await client.messages.create(**body)
            text = str(message.content[0].text)
            usage = getattr(message, "usage", None)
            if usage is not None:
                prompt_tokens = int(getattr(usage, "input_tokens", prompt_tokens))
                completion_tokens = int(getattr(usage, "output_tokens", estimate_tokens(text)))
            else:
                completion_tokens = estimate_tokens(text)
            predicted, confidence, reasoning = parse_llm_json(text)
            latency_ms = int((time.perf_counter() - started) * 1000)
            results.append(
                LLMCallResult(
                    provider=model.provider,
                    model=model.model,
                    filename=sample.filename,
                    expected_decision=sample.expected_decision,
                    predicted_decision=predicted,
                    confidence=confidence,
                    reasoning=reasoning,
                    latency_ms=latency_ms,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    cost_usd=estimate_cost_usd(model, prompt_tokens, completion_tokens),
                )
            )
        except Exception as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            results.append(
                LLMCallResult(
                    provider=model.provider,
                    model=model.model,
                    filename=sample.filename,
                    expected_decision=sample.expected_decision,
                    predicted_decision="",
                    confidence=0.0,
                    reasoning="",
                    latency_ms=latency_ms,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    cost_usd=estimate_cost_usd(model, prompt_tokens, completion_tokens),
                    error=str(exc)[:240],
                )
            )
    await client.close()
    return results


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


def estimate_cost_usd(model: ProviderModel, prompt_tokens: int, completion_tokens: int) -> float:
    return (
        prompt_tokens * model.input_usd_per_million +
        completion_tokens * model.output_usd_per_million
    ) / 1_000_000


def summarize_results(results: list[LLMCallResult]) -> list[ModelSummary]:
    grouped: dict[tuple[str, str], list[LLMCallResult]] = defaultdict(list)
    for result in results:
        grouped[(result.provider, result.model)].append(result)

    summaries: list[ModelSummary] = []
    for (provider, model), rows in sorted(grouped.items()):
        scored = [row for row in rows if not row.error]
        correct = sum(1 for row in rows if row.correct)
        errors = sum(1 for row in rows if row.error)
        accuracy = correct / len(rows) if rows else 0.0
        completed_accuracy = correct / len(scored) if scored else 0.0
        latencies = [row.latency_ms for row in scored if row.latency_ms]
        matrix: dict[str, dict[str, int]] = {decision: {} for decision in DECISIONS}
        for row in rows:
            predicted = row.predicted_decision or ("ERROR" if row.error else "")
            matrix.setdefault(row.expected_decision, {})
            matrix[row.expected_decision][predicted] = (
                matrix[row.expected_decision].get(predicted, 0) + 1
            )
        total_cost = sum(row.cost_usd for row in rows)
        summaries.append(
            ModelSummary(
                provider=provider,
                model=model,
                rows=len(rows),
                completed=len(scored),
                correct=correct,
                errors=errors,
                accuracy=accuracy,
                completed_accuracy=completed_accuracy,
                total_cost_usd=total_cost,
                avg_cost_per_1000=(total_cost / len(rows) * 1000) if rows else 0.0,
                median_latency_ms=int(statistics.median(latencies)) if latencies else 0,
                p95_latency_ms=_p95(latencies),
                confusion_matrix=matrix,
            )
        )
    return summaries


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return values[0]
    values = sorted(values)
    index = math.ceil(len(values) * 0.95) - 1
    return values[max(0, min(index, len(values) - 1))]


def recommend_tiers(
    summaries: list[ModelSummary],
    *,
    min_accuracy: float = 0.90,
    quality_delta: float = 0.02,
) -> dict[str, str]:
    """Pick cost-aware models for starter/pro/business tiers."""
    usable = [summary for summary in summaries if summary.errors == 0 and summary.rows > 0]
    if not usable:
        return {
            "starter": "rules-only",
            "pro": "rules-only",
            "business": "rules-only",
            "note": "No live model completed every sample.",
        }

    eligible = [summary for summary in usable if summary.accuracy >= min_accuracy]
    if not eligible:
        best = max(usable, key=lambda item: (item.accuracy, -item.total_cost_usd))
        return {
            "starter": "rules-only",
            "pro": best.key,
            "business": best.key,
            "note": f"No model met {min_accuracy:.0%}; keep LLM behind paid or review mode.",
        }

    best_accuracy = max(summary.accuracy for summary in eligible)
    near_best = [
        summary for summary in eligible
        if best_accuracy - summary.accuracy <= quality_delta
    ]
    cheapest_near_best = min(near_best, key=lambda item: item.total_cost_usd)
    cheapest_eligible = min(eligible, key=lambda item: item.total_cost_usd)
    best_model = max(eligible, key=lambda item: (item.accuracy, -item.total_cost_usd))
    business = (
        best_model
        if best_model.accuracy - cheapest_near_best.accuracy > quality_delta
        else cheapest_near_best
    )
    return {
        "starter": cheapest_eligible.key,
        "pro": cheapest_near_best.key,
        "business": business.key,
        "note": (
            "Use the cheapest model within the quality band; reserve expensive "
            "models only when they beat cheaper models by a real margin."
        ),
    }


def write_reports(
    output_prefix: Path,
    *,
    samples: list[PaymentSample],
    results: list[LLMCallResult],
    summaries: list[ModelSummary],
    recommendations: dict[str, str],
    models: list[ProviderModel],
    filters: dict[str, Any],
) -> tuple[Path, Path]:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    md_path = output_prefix.with_suffix(".md")
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters": filters,
        "sample_count": len(samples),
        "samples": [
            {
                "filename": sample.filename,
                "expected_decision": sample.expected_decision,
                "source_type": sample.source_type,
                "split": sample.split,
                "contains_real_pii": sample.contains_real_pii,
            }
            for sample in samples
        ],
        "models": [
            {
                "provider": model.provider,
                "model": model.model,
                "input_usd_per_million": model.input_usd_per_million,
                "output_usd_per_million": model.output_usd_per_million,
                "pricing_note": model.pricing_note,
            }
            for model in models
        ],
        "summaries": [summary.__dict__ for summary in summaries],
        "recommendations": recommendations,
        "results": [result.__dict__ for result in results],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(summaries, recommendations, models, filters), encoding="utf-8")
    return json_path, md_path


def render_markdown(
    summaries: list[ModelSummary],
    recommendations: dict[str, str],
    models: list[ProviderModel],
    filters: dict[str, Any],
) -> str:
    lines = [
        "# LLM Provider Eval",
        "",
        "## Filters",
        "",
        f"- Dataset: `{filters['dataset']}`",
        f"- Splits: `{', '.join(filters['splits'])}`",
        f"- Source types: `{', '.join(filters['source_types'])}`",
        f"- PII allowed: `{filters['allow_pii']}`",
        "",
        "## Results",
        "",
        "| Model | Accuracy | Errors | Cost | Cost / 1k scans | Median latency | P95 latency |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            "| "
            f"{summary.key} | "
            f"{summary.correct}/{summary.rows} ({summary.accuracy:.3f}); completed {summary.completed}/{summary.rows} | "
            f"{summary.errors} | "
            f"${summary.total_cost_usd:.6f} | "
            f"${summary.avg_cost_per_1000:.4f} | "
            f"{summary.median_latency_ms} ms | "
            f"{summary.p95_latency_ms} ms |"
        )
    lines.extend(
        [
            "",
            "## Tier Recommendation",
            "",
            f"- Starter: `{recommendations['starter']}`",
            f"- Pro: `{recommendations['pro']}`",
            f"- Business: `{recommendations['business']}`",
            f"- Note: {recommendations['note']}",
            "",
            "## Pricing Notes",
            "",
        ]
    )
    for model in models:
        lines.append(
            f"- `{model.key}`: input ${model.input_usd_per_million:g}/1M, "
            f"output ${model.output_usd_per_million:g}/1M. {model.pricing_note}"
        )
    lines.extend(["", "## Confusion Matrices", ""])
    for summary in summaries:
        lines.append(f"### {summary.key}")
        lines.append("")
        for expected, predictions in summary.confusion_matrix.items():
            cells = ", ".join(f"{predicted}: {count}" for predicted, count in sorted(predictions.items()))
            lines.append(f"- {expected}: {cells or '0'}")
        lines.append("")
    return "\n".join(lines)


def print_summary(summaries: list[ModelSummary], recommendations: dict[str, str]) -> None:
    print("LLM provider eval")
    for summary in summaries:
        print(
            f"  {summary.key}: {summary.correct}/{summary.rows} "
            f"accuracy={summary.accuracy:.3f} completed={summary.completed}/{summary.rows} "
            f"completed_accuracy={summary.completed_accuracy:.3f} errors={summary.errors} "
            f"cost=${summary.total_cost_usd:.6f} "
            f"latency_med={summary.median_latency_ms}ms"
        )
    print("Recommendations:")
    print(f"  Starter:  {recommendations['starter']}")
    print(f"  Pro:      {recommendations['pro']}")
    print(f"  Business: {recommendations['business']}")
    print(f"  Note:     {recommendations['note']}")


async def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate LLM provider performance and cost on payment-decision labels.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--split", action="append", default=None, help="Dataset split. Repeatable. Use all for every split.")
    parser.add_argument("--source-type", action="append", default=None, help="Source type. Repeatable. Use all for every type.")
    parser.add_argument("--max-samples-per-decision", type=int, default=5, help="0 means all matching samples.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--body-chars", type=int, default=2400)
    parser.add_argument("--allow-pii", action="store_true", help="Allow rows marked as containing real PII.")
    parser.add_argument("--model", action="append", default=None, help="Provider model, e.g. deepseek:deepseek-v4-flash.")
    parser.add_argument("--run-live", action="store_true", help="Actually call external LLM APIs.")
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--min-accuracy", type=float, default=0.90)
    parser.add_argument("--quality-delta", type=float, default=0.02)
    parser.add_argument("--output-prefix", type=Path, default=None)
    args = parser.parse_args()

    if load_dotenv:
        load_dotenv(PROJECT_ROOT / ".env")

    splits = tuple(args.split or DEFAULT_SPLITS)
    source_types = tuple(args.source_type or DEFAULT_SOURCE_TYPES)
    samples = read_payment_samples(
        args.dataset,
        splits=splits,
        source_types=source_types,
        allow_pii=args.allow_pii,
        max_samples_per_decision=args.max_samples_per_decision,
        seed=args.seed,
        body_chars=args.body_chars,
    )
    if not samples:
        print("No samples matched the selected filters.", file=sys.stderr)
        return 2

    if args.model:
        models = [parse_model_spec(spec) for spec in args.model]
    else:
        models = available_default_models()
    if not models:
        print(
            "No model API keys were found. Pass --model and set the provider key, "
            "or run without --run-live for a dry-run selection check.",
            file=sys.stderr,
        )
        return 2

    results: list[LLMCallResult] = []
    for model in models:
        results.extend(
            await evaluate_model(
                model,
                samples,
                run_live=args.run_live,
                timeout_seconds=args.timeout_seconds,
            )
        )
    summaries = summarize_results(results)
    recommendations = recommend_tiers(
        summaries,
        min_accuracy=args.min_accuracy,
        quality_delta=args.quality_delta,
    )
    output_prefix = args.output_prefix
    if output_prefix is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_prefix = args.dataset / "reports" / f"llm_provider_eval_{stamp}"
    json_path, md_path = write_reports(
        output_prefix,
        samples=samples,
        results=results,
        summaries=summaries,
        recommendations=recommendations,
        models=models,
        filters={
            "dataset": str(args.dataset),
            "splits": splits,
            "source_types": source_types,
            "allow_pii": args.allow_pii,
            "max_samples_per_decision": args.max_samples_per_decision,
            "run_live": args.run_live,
        },
    )
    print_summary(summaries, recommendations)
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    if not args.run_live:
        return 0
    return 0 if all(summary.errors == 0 for summary in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

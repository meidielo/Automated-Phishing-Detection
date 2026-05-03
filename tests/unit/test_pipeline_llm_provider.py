from __future__ import annotations

import pytest

from src.analyzers.clients.openai_compatible_client import OpenAICompatibleLLMClient
from src.config import APIConfig, PipelineConfig
from src.orchestrator.pipeline import PhishingPipeline


@pytest.mark.asyncio
async def test_pipeline_builds_deepseek_llm_client_from_provider_config():
    pipeline = PhishingPipeline(
        PipelineConfig(
            api=APIConfig(
                llm_provider="deepseek",
                deepseek_key="deepseek_test_key",
            )
        )
    )

    analyzer = await pipeline._load_analyzer("nlp_intent")
    try:
        assert isinstance(analyzer.llm_client, OpenAICompatibleLLMClient)
        assert analyzer.llm_client.base_url == "https://api.deepseek.com"
        assert analyzer.llm_client.model == "deepseek-v4-flash"
    finally:
        await pipeline.close()


@pytest.mark.asyncio
async def test_pipeline_builds_kimi_llm_client_from_provider_config():
    pipeline = PhishingPipeline(
        PipelineConfig(
            api=APIConfig(
                llm_provider="moonshot",
                moonshot_key="moonshot_test_key",
                llm_model="kimi-k2.6",
            )
        )
    )

    analyzer = await pipeline._load_analyzer("nlp_intent")
    try:
        assert isinstance(analyzer.llm_client, OpenAICompatibleLLMClient)
        assert analyzer.llm_client.base_url == "https://api.moonshot.ai/v1"
        assert analyzer.llm_client.model == "kimi-k2.6"
    finally:
        await pipeline.close()

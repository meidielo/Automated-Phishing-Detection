"""
Tests for src/analyzers/clients/anthropic_client.py.

Locks the LLM determinism contract:
- temperature=0
- top_p NOT set (the Anthropic API rejects requests that set both
  temperature and top_p; temperature=0 alone is sufficient for greedy
  decoding on Claude models)
- model_id is captured per-call (drift detection)
- LLMResponse is the structured return type

These properties are referenced from docs/EVALUATION.md §3.2 — if any of
them change without an explicit decision, the eval harness's
reproducibility guarantee silently breaks.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analyzers.clients.anthropic_client import AnthropicLLMClient, LLMResponse


def _build_mock_message(text: str = '{"intent":"legitimate"}', model: str = "claude-haiku-4-5-20251001"):
    """Construct an object that quacks like an Anthropic Message response."""
    msg = MagicMock()
    msg.content = [MagicMock(text=text)]
    msg.model = model
    return msg


@pytest.fixture
def client_with_mocked_api():
    """AnthropicLLMClient with the underlying SDK call patched."""
    client = AnthropicLLMClient(api_key="test-key")
    client._client = MagicMock()
    client._client.messages = MagicMock()
    client._client.messages.create = AsyncMock(return_value=_build_mock_message())
    return client


class TestDeterminismContract:
    @pytest.mark.asyncio
    async def test_temperature_is_zero(self, client_with_mocked_api):
        await client_with_mocked_api.analyze("hello")
        kwargs = client_with_mocked_api._client.messages.create.call_args.kwargs
        assert kwargs["temperature"] == 0

    @pytest.mark.asyncio
    async def test_opus_47_omits_deprecated_temperature_parameter(self):
        client = AnthropicLLMClient(api_key="test-key", model="claude-opus-4-7")
        client._client = MagicMock()
        client._client.messages = MagicMock()
        client._client.messages.create = AsyncMock(
            return_value=_build_mock_message(model="claude-opus-4-7")
        )

        await client.analyze("hello")

        kwargs = client._client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-opus-4-7"
        assert "temperature" not in kwargs

    @pytest.mark.asyncio
    async def test_top_p_not_set(self, client_with_mocked_api):
        """top_p must NOT be passed: the Anthropic API rejects requests
        that set both temperature and top_p. temperature=0 alone is
        sufficient for greedy decoding. See anthropic_client.py
        determinism contract docstring."""
        await client_with_mocked_api.analyze("hello")
        kwargs = client_with_mocked_api._client.messages.create.call_args.kwargs
        assert "top_p" not in kwargs

    @pytest.mark.asyncio
    async def test_model_passed_to_api(self, client_with_mocked_api):
        await client_with_mocked_api.analyze("hello")
        kwargs = client_with_mocked_api._client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-haiku-4-5-20251001"

    @pytest.mark.asyncio
    async def test_max_tokens_pinned(self, client_with_mocked_api):
        await client_with_mocked_api.analyze("hello")
        kwargs = client_with_mocked_api._client.messages.create.call_args.kwargs
        assert kwargs["max_tokens"] == 512


class TestModelIdCapture:
    @pytest.mark.asyncio
    async def test_returns_llm_response_namedtuple(self, client_with_mocked_api):
        result = await client_with_mocked_api.analyze("hello")
        assert isinstance(result, LLMResponse)
        assert hasattr(result, "text")
        assert hasattr(result, "model_id")

    @pytest.mark.asyncio
    async def test_captures_actual_model_from_api(self, client_with_mocked_api):
        # Simulate the API returning a different point release than requested
        client_with_mocked_api._client.messages.create.return_value = _build_mock_message(
            text='{"intent":"bec_wire_fraud"}',
            model="claude-haiku-4-5-20260101",  # newer point release
        )
        result = await client_with_mocked_api.analyze("hello")
        assert result.model_id == "claude-haiku-4-5-20260101"
        # Configured model is unchanged
        assert client_with_mocked_api.model == "claude-haiku-4-5-20251001"

    @pytest.mark.asyncio
    async def test_falls_back_to_configured_model_if_field_missing(self, client_with_mocked_api):
        msg = MagicMock()
        msg.content = [MagicMock(text='{"intent":"legitimate"}')]
        # Simulate a response object that doesn't expose .model
        del msg.model
        msg.model = None
        client_with_mocked_api._client.messages.create.return_value = msg

        result = await client_with_mocked_api.analyze("hello")
        assert result.model_id == "claude-haiku-4-5-20251001"

    @pytest.mark.asyncio
    async def test_text_extracted_correctly(self, client_with_mocked_api):
        client_with_mocked_api._client.messages.create.return_value = _build_mock_message(
            text="hello world"
        )
        result = await client_with_mocked_api.analyze("prompt")
        assert result.text == "hello world"


class TestBackwardCompatibleUnpacking:
    """LLMResponse must unpack as a 2-tuple for callers that destructure."""

    @pytest.mark.asyncio
    async def test_tuple_unpacking_works(self, client_with_mocked_api):
        result = await client_with_mocked_api.analyze("hello")
        text, model_id = result  # NamedTuple unpacking
        assert text == '{"intent":"legitimate"}'
        assert model_id == "claude-haiku-4-5-20251001"

    @pytest.mark.asyncio
    async def test_index_access_works(self, client_with_mocked_api):
        result = await client_with_mocked_api.analyze("hello")
        assert result[0] == result.text
        assert result[1] == result.model_id

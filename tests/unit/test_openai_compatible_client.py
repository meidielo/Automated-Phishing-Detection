from __future__ import annotations

import pytest

from src.analyzers.clients.anthropic_client import LLMResponse
from src.analyzers.clients.openai_compatible_client import OpenAICompatibleLLMClient


class _FakeResponse:
    def __init__(self, *, status: int = 200, payload: dict | None = None, text: str = ""):
        self.status = status
        self._payload = payload if payload is not None else {}
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def json(self):
        return self._payload

    async def text(self):
        return self._text


class _FakeSession:
    closed = False

    def __init__(self, response: _FakeResponse):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_openai_compatible_client_sends_deterministic_json_request():
    session = _FakeSession(
        _FakeResponse(
            payload={
                "model": "deepseek-v4-flash",
                "choices": [{"message": {"content": '{"intent":"legitimate"}'}}],
            }
        )
    )
    client = OpenAICompatibleLLMClient(
        "test-key",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
    )
    client._session = session

    result = await client.analyze("classify this")

    assert isinstance(result, LLMResponse)
    assert result.text == '{"intent":"legitimate"}'
    assert result.model_id == "deepseek-v4-flash"
    url, kwargs = session.calls[0]
    assert url == "https://api.deepseek.com/chat/completions"
    assert kwargs["headers"]["Authorization"] == "Bearer test-key"
    assert kwargs["json"]["temperature"] == 0
    assert kwargs["json"]["thinking"] == {"type": "disabled"}
    assert kwargs["json"]["max_tokens"] == 512
    assert kwargs["json"]["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_openai_compatible_client_uses_kimi_supported_parameters():
    session = _FakeSession(
        _FakeResponse(
            payload={
                "model": "kimi-k2.6",
                "choices": [{"message": {"content": '{"intent":"legitimate"}'}}],
            }
        )
    )
    client = OpenAICompatibleLLMClient(
        "test-key",
        base_url="https://api.moonshot.ai/v1",
        model="kimi-k2.6",
    )
    client._session = session

    await client.analyze("classify this")

    _, kwargs = session.calls[0]
    assert "temperature" not in kwargs["json"]
    assert kwargs["json"]["thinking"] == {"type": "disabled"}
    assert kwargs["json"]["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_openai_compatible_client_raises_clean_provider_error():
    session = _FakeSession(
        _FakeResponse(
            status=401,
            payload={"error": {"message": "invalid api key"}},
        )
    )
    client = OpenAICompatibleLLMClient(
        "test-key",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-flash",
    )
    client._session = session

    with pytest.raises(RuntimeError, match="invalid api key"):
        await client.analyze("classify this")

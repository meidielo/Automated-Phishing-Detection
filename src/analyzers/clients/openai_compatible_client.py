"""OpenAI-compatible LLM client for NLP intent analysis.

DeepSeek, Kimi/Moonshot, Gemini, OpenAI, and several routing providers expose a
Chat Completions-compatible endpoint. The NLP intent analyzer only needs a
small deterministic JSON classification call, so this wrapper keeps the
provider surface narrow and easy to evaluate.
"""

from __future__ import annotations

from typing import Any

import aiohttp

from src.analyzers.clients.anthropic_client import LLMResponse


class OpenAICompatibleLLMClient:
    """Thin async wrapper for OpenAI-compatible chat completion APIs."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str,
        model: str,
        timeout_seconds: float = 30.0,
        json_response: bool = True,
    ) -> None:
        if not api_key:
            raise ValueError("LLM API key is not configured")
        if not base_url:
            raise ValueError("LLM API base URL is not configured")
        if not model:
            raise ValueError("LLM model is not configured")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.json_response = json_response
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def analyze(self, prompt: str) -> LLMResponse:
        """Send prompt to an OpenAI-compatible API and return text + model."""
        body = self._request_body(prompt)

        session = await self._get_session()
        async with session.post(
            f"{self.base_url}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
        ) as response:
            payload = await self._read_payload(response)
            if response.status >= 400:
                message = (
                    self._error_message(payload) or
                    f"HTTP {response.status}"
                )
                raise RuntimeError(f"LLM API request failed: {message}")

        text = self._extract_text(payload)
        model_id = str(payload.get("model") or self.model)
        return LLMResponse(text=text, model_id=model_id)

    def _request_body(self, prompt: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 512,
        }
        if self.json_response:
            body["response_format"] = {"type": "json_object"}

        # DeepSeek V4 and Kimi K2.6 default to thinking mode. Disabling it keeps
        # classification calls short and reduces JSON formatting failures.
        if self.base_url.lower().startswith("https://api.deepseek.com"):
            body["thinking"] = {"type": "disabled"}
            body["temperature"] = 0
        elif (
            self.base_url.lower().startswith("https://api.moonshot.ai") and
            self.model.startswith(("kimi-k2.6", "kimi-k2.5"))
        ):
            body["thinking"] = {"type": "disabled"}
        elif "generativelanguage.googleapis.com" in self.base_url.lower():
            body["temperature"] = 0
            if self.model.startswith("gemini-3.1-pro"):
                body["reasoning_effort"] = "low"
                body["max_tokens"] = max(int(body["max_tokens"]), 1024)
            elif self.model.startswith("gemini-2.5"):
                body["reasoning_effort"] = "none"
            elif self.model.startswith("gemini-3"):
                body["reasoning_effort"] = "minimal"
        elif (
            self.base_url.lower().startswith("https://api.openai.com") and
            self.model.startswith("gpt-5")
        ):
            body.pop("max_tokens", None)
            body["max_completion_tokens"] = 1024
            body["reasoning_effort"] = "none"
        else:
            body["temperature"] = 0
        return body

    async def _read_payload(
        self,
        response: aiohttp.ClientResponse,
    ) -> dict[str, Any]:
        try:
            payload = await response.json()
        except Exception:
            text = await response.text()
            raise RuntimeError(
                "LLM API returned invalid JSON with "
                f"HTTP {response.status}: {text[:160]}"
            )
        if not isinstance(payload, dict):
            raise RuntimeError("LLM API returned a non-object response")
        return payload

    def _error_message(self, payload: dict[str, Any]) -> str:
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "")
        if isinstance(error, str):
            return error
        return ""

    def _extract_text(self, payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("LLM API response did not include choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise RuntimeError("LLM API choice was not an object")
        message = first.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts = [
                    str(part.get("text", ""))
                    for part in content
                    if isinstance(part, dict)
                ]
                return "".join(parts)
        text = first.get("text")
        if isinstance(text, str):
            return text
        raise RuntimeError("LLM API response did not include text content")

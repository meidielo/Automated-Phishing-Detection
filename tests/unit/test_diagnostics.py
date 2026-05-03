"""
Tests for src/diagnostics/api_checks.py.

Network calls are not exercised in unit tests — those would be flaky and
slow. Tests here cover:

  - SKIP path when no API key is configured
  - CheckResult dataclass shape and to_dict() serialization
  - Registry contents (all expected services present)
  - run_all_checks dispatches to every registered check
  - summarize() counts and headline
"""
from __future__ import annotations

import pytest

from src.diagnostics import api_checks as api_checks_module
from src.diagnostics import CheckResult, CheckStatus, run_all_checks
from src.diagnostics.api_checks import (
    _CHECK_REGISTRY,
    check_abuseipdb,
    check_anthropic,
    check_deepseek,
    check_gemini,
    check_google_safebrowsing,
    check_moonshot,
    check_openai,
    check_urlscan,
    check_virustotal,
    summarize,
)


# ─── Skip-path tests (no API key, no network call) ──────────────────────────


class TestSkipPathNoApiKey:
    """Every check returns SKIP cleanly when its key is empty."""

    @pytest.mark.asyncio
    async def test_virustotal_skip(self):
        result = await check_virustotal("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "virustotal"
        assert "no API key" in result.message

    @pytest.mark.asyncio
    async def test_google_safebrowsing_skip(self):
        result = await check_google_safebrowsing("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "google_safebrowsing"

    @pytest.mark.asyncio
    async def test_urlscan_skip(self):
        result = await check_urlscan("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "urlscan"

    @pytest.mark.asyncio
    async def test_abuseipdb_skip(self):
        result = await check_abuseipdb("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "abuseipdb"

    @pytest.mark.asyncio
    async def test_anthropic_skip(self):
        result = await check_anthropic("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "anthropic_llm"

    @pytest.mark.asyncio
    async def test_deepseek_skip(self):
        result = await check_deepseek("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "deepseek_llm"

    @pytest.mark.asyncio
    async def test_moonshot_skip(self):
        result = await check_moonshot("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "moonshot_llm"

    @pytest.mark.asyncio
    async def test_gemini_skip(self):
        result = await check_gemini("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "gemini_llm"

    @pytest.mark.asyncio
    async def test_openai_skip(self):
        result = await check_openai("")
        assert result.status == CheckStatus.SKIP
        assert result.service == "openai_llm"


class TestCheckResultDataclass:
    def test_to_dict_uses_string_status(self):
        result = CheckResult("svc", CheckStatus.PASS, "ok", http_status=200)
        d = result.to_dict()
        assert d["status"] == "pass"  # string, not enum
        assert d["service"] == "svc"
        assert d["http_status"] == 200
        assert d["message"] == "ok"
        assert d["extra"] == {}

    def test_extra_dict_is_carried(self):
        result = CheckResult("svc", CheckStatus.PASS, "ok", extra={"score": 42})
        d = result.to_dict()
        assert d["extra"] == {"score": 42}

    def test_default_message_empty(self):
        result = CheckResult("svc", CheckStatus.SKIP)
        assert result.message == ""
        assert result.http_status is None


# ─── Registry shape ─────────────────────────────────────────────────────────


class TestRegistry:
    def test_expected_services_registered(self):
        env_names = [env_name for env_name, _ in _CHECK_REGISTRY]
        assert "VIRUSTOTAL_API_KEY" in env_names
        assert "GOOGLE_SAFE_BROWSING_API_KEY" in env_names
        assert "URLSCAN_API_KEY" in env_names
        assert "ABUSEIPDB_API_KEY" in env_names
        assert "ANTHROPIC_API_KEY" in env_names
        assert "DEEPSEEK_API_KEY" in env_names
        assert "MOONSHOT_API_KEY" in env_names
        assert "GEMINI_API_KEY" in env_names
        assert "OPENAI_API_KEY" in env_names

    def test_every_check_is_callable(self):
        for env_name, check_fn in _CHECK_REGISTRY:
            assert callable(check_fn), f"{env_name} check is not callable"

    def test_no_duplicate_env_names(self):
        env_names = [env_name for env_name, _ in _CHECK_REGISTRY]
        assert len(env_names) == len(set(env_names))


# ─── run_all_checks dispatch ────────────────────────────────────────────────


class TestRunAllChecksDispatch:
    @pytest.mark.asyncio
    async def test_all_skip_when_no_keys_in_env(self, monkeypatch):
        # Wipe every diagnostic env var
        for env_name, _ in _CHECK_REGISTRY:
            monkeypatch.delenv(env_name, raising=False)

        results = await run_all_checks()
        assert len(results) == len(_CHECK_REGISTRY)
        assert all(r.status == CheckStatus.SKIP for r in results)

    @pytest.mark.asyncio
    async def test_results_in_registry_order(self, monkeypatch):
        for env_name, _ in _CHECK_REGISTRY:
            monkeypatch.delenv(env_name, raising=False)

        results = await run_all_checks()
        services = [r.service for r in results]
        # virustotal is first in the registry, should be first in results
        assert services[0] == "virustotal"

    @pytest.mark.asyncio
    async def test_config_api_path_used_when_supplied(self):
        """When config_api is supplied, env vars are bypassed."""

        class FakeApiConfig:
            virustotal_key = ""
            google_safebrowsing_key = ""
            urlscan_key = ""
            abuseipdb_key = ""
            anthropic_key = ""
            deepseek_key = ""
            moonshot_key = ""
            gemini_key = ""
            openai_key = ""

        results = await run_all_checks(config_api=FakeApiConfig())
        # All empty -> all SKIP
        assert all(r.status == CheckStatus.SKIP for r in results)

    @pytest.mark.asyncio
    async def test_config_api_uses_generic_llm_key_for_provider(
        self,
        monkeypatch,
    ):
        async def fake_check(api_key, timeout):
            return CheckResult(api_key, CheckStatus.PASS, str(timeout))

        class FakeApiConfig:
            llm_provider = "deepseek"
            llm_api_key = "generic-llm-key"
            deepseek_key = ""

        monkeypatch.setattr(
            api_checks_module,
            "_CHECK_REGISTRY",
            [("DEEPSEEK_API_KEY", fake_check)],
        )

        results = await run_all_checks(config_api=FakeApiConfig(), timeout=3)

        assert results == [
            CheckResult("generic-llm-key", CheckStatus.PASS, "3"),
        ]

    @pytest.mark.asyncio
    async def test_config_api_uses_generic_llm_key_for_gemini_provider(
        self,
        monkeypatch,
    ):
        async def fake_check(api_key, timeout):
            return CheckResult(api_key, CheckStatus.PASS, str(timeout))

        class FakeApiConfig:
            llm_provider = "gemini"
            llm_api_key = "generic-gemini-key"
            gemini_key = ""

        monkeypatch.setattr(
            api_checks_module,
            "_CHECK_REGISTRY",
            [("GEMINI_API_KEY", fake_check)],
        )

        results = await run_all_checks(config_api=FakeApiConfig(), timeout=3)

        assert results == [
            CheckResult("generic-gemini-key", CheckStatus.PASS, "3"),
        ]

    @pytest.mark.asyncio
    async def test_config_api_uses_generic_llm_key_for_openai_provider(
        self,
        monkeypatch,
    ):
        async def fake_check(api_key, timeout):
            return CheckResult(api_key, CheckStatus.PASS, str(timeout))

        class FakeApiConfig:
            llm_provider = "openai"
            llm_api_key = "generic-openai-key"
            openai_key = ""

        monkeypatch.setattr(
            api_checks_module,
            "_CHECK_REGISTRY",
            [("OPENAI_API_KEY", fake_check)],
        )

        results = await run_all_checks(config_api=FakeApiConfig(), timeout=3)

        assert results == [
            CheckResult("generic-openai-key", CheckStatus.PASS, "3"),
        ]

    @pytest.mark.asyncio
    async def test_openai_gpt5_diagnostic_uses_supported_parameters(
        self,
        monkeypatch,
    ):
        captured = {}

        class FakeResponse:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

        class FakeSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return None

            def post(self, url, **kwargs):
                captured["url"] = url
                captured["json"] = kwargs["json"]
                return FakeResponse()

        monkeypatch.setattr(api_checks_module.aiohttp, "ClientSession", FakeSession)

        result = await api_checks_module._check_openai_compatible_llm(
            service="openai_llm",
            api_key="test-key",
            base_url="https://api.openai.com/v1",
            model="gpt-5.5",
            timeout=3,
        )

        assert result.status == CheckStatus.PASS
        assert captured["url"] == "https://api.openai.com/v1/chat/completions"
        assert "temperature" not in captured["json"]
        assert "max_tokens" not in captured["json"]
        assert captured["json"]["max_completion_tokens"] == 16
        assert captured["json"]["reasoning_effort"] == "none"


# ─── summarize() ────────────────────────────────────────────────────────────


class TestSummarize:
    def test_counts_pass_fail_skip_warn(self):
        results = [
            CheckResult("a", CheckStatus.PASS),
            CheckResult("b", CheckStatus.PASS),
            CheckResult("c", CheckStatus.FAIL),
            CheckResult("d", CheckStatus.SKIP),
            CheckResult("e", CheckStatus.WARN),
        ]
        summary = summarize(results)
        assert summary["counts"]["pass"] == 2
        assert summary["counts"]["fail"] == 1
        assert summary["counts"]["skip"] == 1
        assert summary["counts"]["warn"] == 1
        assert summary["total"] == 5

    def test_headline_excludes_skipped_from_denominator(self):
        """A skipped service shouldn't count against 'configured' total."""
        results = [
            CheckResult("a", CheckStatus.PASS),
            CheckResult("b", CheckStatus.SKIP),
            CheckResult("c", CheckStatus.SKIP),
        ]
        summary = summarize(results)
        # 1 pass out of 1 configured (the 2 skips are not counted)
        assert "1/1" in summary["headline"]

    def test_warn_counts_as_operational(self):
        """A rate-limited service is operational, just degraded."""
        results = [
            CheckResult("a", CheckStatus.WARN),
            CheckResult("b", CheckStatus.PASS),
        ]
        summary = summarize(results)
        # 2 operational out of 2 configured
        assert "2/2" in summary["headline"]

    def test_empty_results(self):
        summary = summarize([])
        assert summary["total"] == 0
        assert summary["counts"]["pass"] == 0

"""
Sandbox client with strategy pattern for multiple sandbox services.
Supports: Hybrid Analysis, AnyRun, JoeSandbox
"""
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Optional, Literal
from enum import Enum

import aiohttp

from .base_client import BaseAPIClient
from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class SandboxProvider(str, Enum):
    """Supported sandbox providers."""
    HYBRID_ANALYSIS = "hybrid_analysis"
    ANYRUN = "anyrun"
    JOESANDBOX = "joesandbox"


class SandboxStrategy(ABC):
    """Abstract base class for sandbox strategies."""

    @abstractmethod
    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str,
        is_private: bool = True,
    ) -> dict:
        """Submit a file for analysis."""
        pass

    @abstractmethod
    async def get_results(self, submission_id: str) -> dict:
        """Get analysis results for a submission."""
        pass

    @abstractmethod
    async def verify_api_key(self) -> bool:
        """Verify API credentials."""
        pass


class HybridAnalysisStrategy(SandboxStrategy, BaseAPIClient):
    """Hybrid Analysis (Payload Security) sandbox strategy."""

    def __init__(self, api_key: str, api_secret: str):
        """
        Initialize Hybrid Analysis client.

        Args:
            api_key: API key
            api_secret: API secret
        """
        BaseAPIClient.__init__(
            self,
            api_key=api_key,
            base_url="https://api.hybrid-analysis.com/api/v2",
            rate_limit=(10, 60),
        )
        self.api_secret = api_secret

    async def verify_api_key(self) -> bool:
        """Verify Hybrid Analysis credentials."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/user/api-key-info",
                headers=self._get_headers(),
                timeout=10,
            )
            return "result" in response
        except Exception as e:
            logger.error(f"Hybrid Analysis verification failed: {e}")
            return False

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str,
        is_private: bool = True,
    ) -> dict:
        """Submit file to Hybrid Analysis."""
        try:
            data = aiohttp.FormData()
            data.add_field(
                "file",
                file_bytes,
                filename=filename,
            )
            data.add_field("private", "on" if is_private else "off")
            data.add_field("environment_id", "100")  # Windows 10 64-bit

            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/submit/file",
                headers=self._get_headers(),
                data=data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                json_response = await response.json()
                return {
                    "job_id": json_response.get("job_id"),
                    "submission_id": json_response.get("submission_id"),
                    "sha256": json_response.get("sha256"),
                    "status": json_response.get("status"),
                }

        except Exception as e:
            logger.error(f"Hybrid Analysis file submission failed: {e}")
            return {"error": str(e)}

    async def get_results(self, submission_id: str, max_wait: int = 300) -> dict:
        """Get analysis results with polling."""
        elapsed = 0
        poll_interval = 5

        while elapsed < max_wait:
            try:
                response = await self._request(
                    method="GET",
                    endpoint=f"/report/{submission_id}/summary",
                    headers=self._get_headers(),
                    timeout=15,
                )

                status = response.get("status", "")
                if status in ["error", "complete"]:
                    return self._normalize_response(response)

                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

            except Exception as e:
                logger.warning(f"Error polling Hybrid Analysis: {e}")
                if elapsed >= max_wait:
                    raise

        raise TimeoutError(f"Hybrid Analysis analysis timed out after {max_wait}s")

    def _get_headers(self) -> dict[str, str]:
        """Get Hybrid Analysis headers."""
        return {
            "api-key": self.api_key,
            "api-secret": self.api_secret,
            "user-agent": "Phishing-Detection-Pipeline/1.0",
        }

    @staticmethod
    def _normalize_response(response: dict) -> dict:
        """Normalize Hybrid Analysis response."""
        return {
            "provider": "hybrid_analysis",
            "verdict": response.get("verdict", "unknown"),
            "threat_score": response.get("threat_score", 0),
            "tags": response.get("tags", []),
            "report_url": f"https://www.hybrid-analysis.com/sample/{response.get('sha256')}",
        }


class AnyRunStrategy(SandboxStrategy, BaseAPIClient):
    """AnyRun sandbox strategy."""

    def __init__(self, api_key: str):
        """
        Initialize AnyRun client.

        Args:
            api_key: API key
        """
        BaseAPIClient.__init__(
            self,
            api_key=api_key,
            base_url="https://api.any.run/v1",
            rate_limit=(5, 60),
        )

    async def verify_api_key(self) -> bool:
        """Verify AnyRun credentials."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/user",
                headers=self._get_headers(),
                timeout=10,
            )
            return "name" in response
        except Exception as e:
            logger.error(f"AnyRun verification failed: {e}")
            return False

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str,
        is_private: bool = True,
    ) -> dict:
        """Submit file to AnyRun."""
        try:
            data = aiohttp.FormData()
            data.add_field("file", file_bytes, filename=filename)

            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/tasks",
                headers=self._get_headers(),
                data=data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                json_response = await response.json()
                return {
                    "task_id": json_response.get("data", {}).get("taskid"),
                    "status": json_response.get("data", {}).get("status", "submitting"),
                }

        except Exception as e:
            logger.error(f"AnyRun file submission failed: {e}")
            return {"error": str(e)}

    async def get_results(self, task_id: str, max_wait: int = 300) -> dict:
        """Get analysis results with polling."""
        elapsed = 0
        poll_interval = 5

        while elapsed < max_wait:
            try:
                response = await self._request(
                    method="GET",
                    endpoint=f"/tasks/{task_id}",
                    headers=self._get_headers(),
                    timeout=15,
                )

                data = response.get("data", {})
                status = data.get("status", "")

                if status in ["complete", "error"]:
                    return self._normalize_response(data)

                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

            except Exception as e:
                logger.warning(f"Error polling AnyRun: {e}")
                if elapsed >= max_wait:
                    raise

        raise TimeoutError(f"AnyRun analysis timed out after {max_wait}s")

    def _get_headers(self) -> dict[str, str]:
        """Get AnyRun headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "Phishing-Detection-Pipeline/1.0",
        }

    @staticmethod
    def _normalize_response(data: dict) -> dict:
        """Normalize AnyRun response."""
        verdict = data.get("verdict", "unknown").lower()
        threat_score_map = {
            "malicious": 1.0,
            "suspicious": 0.7,
            "no_threats": 0.0,
        }

        return {
            "provider": "anyrun",
            "verdict": verdict,
            "threat_score": threat_score_map.get(verdict, 0.5),
            "tags": data.get("tags", []),
            "report_url": f"https://any.run/report/{data.get('taskid')}",
        }


class JoeSandboxStrategy(SandboxStrategy, BaseAPIClient):
    """JoeSandbox sandbox strategy."""

    def __init__(self, api_key: str):
        """
        Initialize JoeSandbox client.

        Args:
            api_key: API key
        """
        BaseAPIClient.__init__(
            self,
            api_key=api_key,
            base_url="https://joeapi.joesandbox.com/v2",
            rate_limit=(5, 60),
        )

    async def verify_api_key(self) -> bool:
        """Verify JoeSandbox credentials."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/account/info",
                params={"apikey": self.api_key},
                timeout=10,
            )
            return response.get("error") is None
        except Exception as e:
            logger.error(f"JoeSandbox verification failed: {e}")
            return False

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str,
        is_private: bool = True,
    ) -> dict:
        """Submit file to JoeSandbox."""
        try:
            data = aiohttp.FormData()
            data.add_field("apikey", self.api_key)
            data.add_field("file", file_bytes, filename=filename)

            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/submission/new",
                data=data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                json_response = await response.json()
                return {
                    "submission_id": json_response.get("submission_id"),
                    "status": json_response.get("status", "submitted"),
                }

        except Exception as e:
            logger.error(f"JoeSandbox file submission failed: {e}")
            return {"error": str(e)}

    async def get_results(self, submission_id: str, max_wait: int = 600) -> dict:
        """Get analysis results with polling."""
        elapsed = 0
        poll_interval = 10

        while elapsed < max_wait:
            try:
                response = await self._request(
                    method="GET",
                    endpoint="/submission/status",
                    params={
                        "apikey": self.api_key,
                        "submission_id": submission_id,
                    },
                    timeout=15,
                )

                status = response.get("status", "")

                if status in ["finished", "error"]:
                    return await self._get_full_report(submission_id)

                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

            except Exception as e:
                logger.warning(f"Error polling JoeSandbox: {e}")
                if elapsed >= max_wait:
                    raise

        raise TimeoutError(f"JoeSandbox analysis timed out after {max_wait}s")

    async def _get_full_report(self, submission_id: str) -> dict:
        """Get full analysis report."""
        try:
            response = await self._request(
                method="GET",
                endpoint="/submission/report",
                params={
                    "apikey": self.api_key,
                    "submission_id": submission_id,
                    "format": "json",
                },
                timeout=15,
            )

            return self._normalize_response(response)

        except Exception as e:
            logger.error(f"Failed to get JoeSandbox report: {e}")
            return {"error": str(e)}

    @staticmethod
    def _normalize_response(data: dict) -> dict:
        """Normalize JoeSandbox response."""
        verdict = data.get("verdict", "unknown").lower()
        threat_score_map = {
            "malicious": 1.0,
            "suspicious": 0.7,
            "clean": 0.0,
        }

        return {
            "provider": "joesandbox",
            "verdict": verdict,
            "threat_score": threat_score_map.get(verdict, 0.5),
            "tags": data.get("tags", []),
            "report_url": f"https://www.joesandbox.com/submission/{data.get('submission_id')}",
        }


class SandboxClient:
    """
    Unified sandbox client using strategy pattern.
    Supports multiple sandbox providers with fallback.
    """

    def __init__(self, providers: dict[str, dict]):
        """
        Initialize sandbox client with multiple providers.

        Args:
            providers: Dictionary of provider name to credentials
                      {
                          "hybrid_analysis": {"api_key": "...", "api_secret": "..."},
                          "anyrun": {"api_key": "..."},
                          "joesandbox": {"api_key": "..."},
                      }
        """
        self.strategies: dict[SandboxProvider, SandboxStrategy] = {}

        if "hybrid_analysis" in providers:
            creds = providers["hybrid_analysis"]
            self.strategies[SandboxProvider.HYBRID_ANALYSIS] = HybridAnalysisStrategy(
                api_key=creds["api_key"],
                api_secret=creds.get("api_secret", ""),
            )

        if "anyrun" in providers:
            creds = providers["anyrun"]
            self.strategies[SandboxProvider.ANYRUN] = AnyRunStrategy(
                api_key=creds["api_key"]
            )

        if "joesandbox" in providers:
            creds = providers["joesandbox"]
            self.strategies[SandboxProvider.JOESANDBOX] = JoeSandboxStrategy(
                api_key=creds["api_key"]
            )

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str,
        preferred_provider: Optional[SandboxProvider] = None,
    ) -> AnalyzerResult:
        """
        Submit file to sandbox (tries preferred provider first).

        Args:
            file_bytes: File content
            filename: Filename
            preferred_provider: Preferred sandbox provider

        Returns:
            AnalyzerResult with submission info
        """
        if not self.strategies:
            return AnalyzerResult(
                analyzer_name="sandbox",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=["No sandbox providers configured"],
            )

        # Try preferred provider first
        providers = list(self.strategies.keys())
        if preferred_provider and preferred_provider in self.strategies:
            providers.remove(preferred_provider)
            providers.insert(0, preferred_provider)

        errors = []
        for provider in providers:
            try:
                strategy = self.strategies[provider]
                result = await strategy.submit_file(file_bytes, filename)

                if "error" not in result:
                    return AnalyzerResult(
                        analyzer_name="sandbox",
                        risk_score=0.0,
                        confidence=0.0,
                        details={
                            "filename": filename,
                            "file_size": len(file_bytes),
                            "provider": provider.value,
                            "submission_id": result.get("submission_id") or result.get("job_id") or result.get("task_id"),
                            "status": result.get("status", "submitted"),
                        },
                    )
                else:
                    errors.append(f"{provider.value}: {result['error']}")

            except Exception as e:
                errors.append(f"{provider.value}: {str(e)}")
                logger.error(f"Sandbox submission to {provider.value} failed: {e}")

        return AnalyzerResult(
            analyzer_name="sandbox",
            risk_score=0.0,
            confidence=0.0,
            details={"filename": filename, "file_size": len(file_bytes)},
            errors=errors,
        )

    async def get_results(
        self,
        submission_id: str,
        provider: SandboxProvider,
    ) -> AnalyzerResult:
        """
        Get analysis results from sandbox.

        Args:
            submission_id: Submission ID
            provider: Sandbox provider

        Returns:
            AnalyzerResult with analysis findings
        """
        if provider not in self.strategies:
            return AnalyzerResult(
                analyzer_name="sandbox",
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[f"Provider {provider.value} not configured"],
            )

        try:
            strategy = self.strategies[provider]
            result = await strategy.get_results(submission_id)

            if "error" in result:
                return AnalyzerResult(
                    analyzer_name="sandbox",
                    risk_score=0.0,
                    confidence=0.0,
                    details={"submission_id": submission_id, "provider": provider.value},
                    errors=[result["error"]],
                )

            # Normalize results
            threat_score = result.get("threat_score", 0.0)
            return AnalyzerResult(
                analyzer_name="sandbox",
                risk_score=min(threat_score, 1.0),
                confidence=0.9,
                details={
                    "submission_id": submission_id,
                    "provider": provider.value,
                    "verdict": result.get("verdict", "unknown"),
                    "tags": result.get("tags", []),
                    "report_url": result.get("report_url"),
                },
            )

        except Exception as e:
            logger.error(f"Failed to get sandbox results from {provider.value}: {e}")
            return AnalyzerResult(
                analyzer_name="sandbox",
                risk_score=0.0,
                confidence=0.0,
                details={"submission_id": submission_id, "provider": provider.value},
                errors=[str(e)],
            )

    async def close(self) -> None:
        """Close all strategies."""
        for strategy in self.strategies.values():
            if hasattr(strategy, "close"):
                await strategy.close()

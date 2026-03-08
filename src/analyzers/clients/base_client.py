"""
Abstract base class for all external API clients.
Provides rate limiting, caching, retry logic, and circuit breaker functionality.
"""
import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple
from datetime import datetime, timedelta

import aiohttp
from asyncio_throttle import AsyncThrottle

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Simple circuit breaker implementation for API failures."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 300):
        """
        Args:
            failure_threshold: Number of consecutive failures before opening circuit
            recovery_timeout: Seconds before attempting recovery (half-open state)
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half-open

    def record_success(self) -> None:
        """Record a successful request."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self) -> None:
        """Record a failed request."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning(
                f"Circuit breaker opened after {self.failure_count} failures"
            )

    def can_attempt(self) -> bool:
        """Check if we can attempt a request."""
        if self.state == "closed":
            return True
        if self.state == "open":
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time >= self.recovery_timeout
            ):
                self.state = "half-open"
                logger.info("Circuit breaker entering half-open state")
                return True
            return False
        # half-open state
        return True


class TTLCache:
    """Simple in-memory cache with TTL (time-to-live) support."""

    def __init__(self):
        self._cache: dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if it exists and hasn't expired."""
        if key not in self._cache:
            return None
        value, expiry = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Set value in cache with TTL."""
        expiry = time.time() + ttl_seconds
        self._cache[key] = (value, expiry)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    def cleanup_expired(self) -> None:
        """Remove expired entries."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (_, expiry) in self._cache.items()
            if current_time > expiry
        ]
        for key in expired_keys:
            del self._cache[key]


class BaseAPIClient(ABC):
    """
    Abstract base class for external API clients.

    Provides:
    - Rate limiting via asyncio-throttle
    - TTL-based in-memory caching
    - Retry logic with exponential backoff
    - Circuit breaker pattern
    - Proper async/await patterns with aiohttp
    """

    def __init__(
        self,
        api_key: str,
        base_url: str,
        rate_limit: Tuple[int, int] = (10, 60),
        cache_ttl: int = 3600,
    ):
        """
        Initialize the API client.

        Args:
            api_key: API key for authentication
            base_url: Base URL for the API
            rate_limit: Tuple of (requests, seconds) for rate limiting. Default: 10 req/60s
            cache_ttl: Default cache TTL in seconds. Default: 3600 (1 hour)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.cache_ttl = cache_ttl
        self.cache = TTLCache()

        # Rate limiter: (max_requests, time_period_seconds)
        self.throttler = AsyncThrottle(max_rate=rate_limit[0], time_period=rate_limit[1])

        # Circuit breaker
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=300)

        # Session management
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _request(
        self,
        method: str,
        endpoint: str,
        max_retries: int = 3,
        timeout: int = 30,
        **kwargs
    ) -> dict[str, Any]:
        """
        Make HTTP request with retry logic and exponential backoff.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base_url)
            max_retries: Maximum number of retry attempts
            timeout: Request timeout in seconds
            **kwargs: Additional arguments to pass to aiohttp request

        Returns:
            Response JSON as dictionary

        Raises:
            Exception: If all retries fail
        """
        # Check circuit breaker
        if not self.circuit_breaker.can_attempt():
            raise Exception(
                "Circuit breaker is open - API is unavailable. "
                "Will retry in a few minutes."
            )

        url = f"{self.base_url}{endpoint}"

        # Rate limiting
        async with self.throttler:
            for attempt in range(max_retries):
                try:
                    session = await self._get_session()

                    async with session.request(
                        method,
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        **kwargs
                    ) as response:
                        # Handle rate limiting responses (429)
                        if response.status == 429:
                            retry_after = int(response.headers.get("Retry-After", 60))
                            logger.warning(
                                f"Rate limited. Waiting {retry_after}s before retry"
                            )
                            await asyncio.sleep(retry_after)
                            continue

                        # Handle client errors
                        if response.status >= 400 and response.status < 500:
                            text = await response.text()
                            error_msg = f"Client error {response.status}: {text}"
                            logger.error(error_msg)
                            self.circuit_breaker.record_failure()
                            raise Exception(error_msg)

                        # Handle server errors with retry
                        if response.status >= 500:
                            if attempt < max_retries - 1:
                                wait_time = 2 ** attempt  # Exponential backoff
                                logger.warning(
                                    f"Server error {response.status}. "
                                    f"Retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})"
                                )
                                await asyncio.sleep(wait_time)
                                continue
                            else:
                                text = await response.text()
                                error_msg = f"Server error {response.status}: {text}"
                                logger.error(error_msg)
                                self.circuit_breaker.record_failure()
                                raise Exception(error_msg)

                        # Success
                        self.circuit_breaker.record_success()
                        try:
                            data = await response.json()
                            return data
                        except Exception as e:
                            text = await response.text()
                            logger.error(f"Failed to parse JSON response: {e}")
                            return {"raw_response": text, "status": response.status}

                except asyncio.TimeoutError:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.warning(
                            f"Request timeout. Retrying in {wait_time}s "
                            f"(attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Request timeout after {max_retries} attempts")
                        self.circuit_breaker.record_failure()
                        raise

                except aiohttp.ClientError as e:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.warning(
                            f"Network error: {e}. Retrying in {wait_time}s "
                            f"(attempt {attempt + 1}/{max_retries})"
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Network error after {max_retries} attempts: {e}")
                        self.circuit_breaker.record_failure()
                        raise

        raise Exception(f"Request failed after {max_retries} attempts")

    def _get_cache_key(self, *args: str) -> str:
        """Generate cache key from arguments."""
        return ":".join([self.__class__.__name__] + list(args))

    def _cache_get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        return self.cache.get(key)

    def _cache_set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        cache_ttl = ttl if ttl is not None else self.cache_ttl
        self.cache.set(key, value, cache_ttl)

    def _cache_clear(self) -> None:
        """Clear cache."""
        self.cache.clear()

    @abstractmethod
    async def verify_api_key(self) -> bool:
        """Verify that the API key is valid. Implement in subclasses."""
        pass

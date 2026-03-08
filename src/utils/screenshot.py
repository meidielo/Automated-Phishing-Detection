"""
Screenshot utility for URL detonation captures.

Captures browser screenshots during URL analysis using headless
Chromium. Supports full-page captures, viewport-specific shots,
and visual hashing for brand impersonation comparison.
"""
import asyncio
import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ScreenshotResult:
    """Result of a screenshot capture."""
    url: str
    filepath: str
    timestamp: datetime
    width: int
    height: int
    file_size_bytes: int
    sha256: str
    phash: Optional[str] = None
    error: Optional[str] = None
    success: bool = True


@dataclass
class ScreenshotConfig:
    """Configuration for screenshot captures."""
    output_dir: str = "detonation_captures"
    viewport_width: int = 1280
    viewport_height: int = 800
    full_page: bool = True
    timeout_seconds: int = 30
    wait_after_load_ms: int = 2000
    format: str = "png"  # png or jpeg
    quality: int = 85  # jpeg quality (ignored for png)
    max_file_size_mb: int = 10


class ScreenshotCapture:
    """
    Captures screenshots of URLs using headless browser.

    Designed for use in the URL detonation pipeline to capture
    visual evidence of phishing pages.
    """

    def __init__(self, config: Optional[ScreenshotConfig] = None):
        self.config = config or ScreenshotConfig()
        os.makedirs(self.config.output_dir, exist_ok=True)

    async def capture(self, url: str, filename: Optional[str] = None) -> ScreenshotResult:
        """
        Capture a screenshot of a URL.

        Args:
            url: URL to screenshot
            filename: Custom filename (auto-generated if not provided)

        Returns:
            ScreenshotResult with capture details
        """
        timestamp = datetime.utcnow()

        if not filename:
            url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            ts_str = timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{ts_str}_{url_hash}.{self.config.format}"

        filepath = os.path.join(self.config.output_dir, filename)

        try:
            # Try playwright first, fall back to selenium
            result = await self._capture_with_playwright(url, filepath, timestamp)
            return result
        except ImportError:
            logger.debug("Playwright not available, trying selenium")
        except Exception as e:
            logger.warning(f"Playwright capture failed: {e}")

        try:
            result = await self._capture_with_selenium(url, filepath, timestamp)
            return result
        except ImportError:
            logger.debug("Selenium not available either")
        except Exception as e:
            logger.warning(f"Selenium capture failed: {e}")

        return ScreenshotResult(
            url=url,
            filepath=filepath,
            timestamp=timestamp,
            width=0,
            height=0,
            file_size_bytes=0,
            sha256="",
            success=False,
            error="No browser engine available (install playwright or selenium)",
        )

    async def _capture_with_playwright(
        self, url: str, filepath: str, timestamp: datetime
    ) -> ScreenshotResult:
        """Capture using Playwright."""
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={
                    "width": self.config.viewport_width,
                    "height": self.config.viewport_height,
                },
                ignore_https_errors=True,
            )
            page = await context.new_page()

            try:
                await page.goto(
                    url,
                    timeout=self.config.timeout_seconds * 1000,
                    wait_until="networkidle",
                )
            except Exception:
                # Try with less strict wait
                await page.goto(
                    url,
                    timeout=self.config.timeout_seconds * 1000,
                    wait_until="domcontentloaded",
                )

            # Wait for page to stabilise
            await asyncio.sleep(self.config.wait_after_load_ms / 1000)

            await page.screenshot(
                path=filepath,
                full_page=self.config.full_page,
                type=self.config.format,
            )

            await browser.close()

        return self._build_result(url, filepath, timestamp)

    async def _capture_with_selenium(
        self, url: str, filepath: str, timestamp: datetime
    ) -> ScreenshotResult:
        """Capture using Selenium (sync, wrapped in executor)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._selenium_sync_capture, url, filepath, timestamp
        )

    def _selenium_sync_capture(
        self, url: str, filepath: str, timestamp: datetime
    ) -> ScreenshotResult:
        """Synchronous Selenium capture."""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(
            f"--window-size={self.config.viewport_width},{self.config.viewport_height}"
        )

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(self.config.timeout_seconds)

        try:
            driver.get(url)
            import time
            time.sleep(self.config.wait_after_load_ms / 1000)
            driver.save_screenshot(filepath)
        finally:
            driver.quit()

        return self._build_result(url, filepath, timestamp)

    def _build_result(
        self, url: str, filepath: str, timestamp: datetime
    ) -> ScreenshotResult:
        """Build ScreenshotResult from a captured file."""
        file_size = os.path.getsize(filepath)
        sha256 = self._compute_sha256(filepath)

        # Try to get image dimensions
        width, height = self._get_image_dimensions(filepath)

        phash = self._compute_phash(filepath)

        return ScreenshotResult(
            url=url,
            filepath=filepath,
            timestamp=timestamp,
            width=width,
            height=height,
            file_size_bytes=file_size,
            sha256=sha256,
            phash=phash,
        )

    @staticmethod
    def _compute_sha256(filepath: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _get_image_dimensions(filepath: str) -> tuple[int, int]:
        """Get image width and height."""
        try:
            from PIL import Image
            with Image.open(filepath) as img:
                return img.size
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Could not read image dimensions: {e}")
        return (0, 0)

    @staticmethod
    def _compute_phash(filepath: str) -> Optional[str]:
        """Compute perceptual hash for brand comparison."""
        try:
            import imagehash
            from PIL import Image
            with Image.open(filepath) as img:
                return str(imagehash.phash(img))
        except ImportError:
            return None
        except Exception as e:
            logger.debug(f"Could not compute phash: {e}")
            return None

    async def capture_batch(
        self, urls: list[str], concurrency: int = 3
    ) -> list[ScreenshotResult]:
        """
        Capture screenshots for multiple URLs concurrently.

        Args:
            urls: List of URLs to capture
            concurrency: Max concurrent captures

        Returns:
            List of ScreenshotResult instances
        """
        semaphore = asyncio.Semaphore(concurrency)
        results = []

        async def _bounded_capture(url: str):
            async with semaphore:
                return await self.capture(url)

        tasks = [_bounded_capture(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final.append(ScreenshotResult(
                    url=urls[i],
                    filepath="",
                    timestamp=datetime.utcnow(),
                    width=0,
                    height=0,
                    file_size_bytes=0,
                    sha256="",
                    success=False,
                    error=str(result),
                ))
            else:
                final.append(result)

        return final

    def cleanup_old_captures(self, max_age_hours: int = 24) -> int:
        """
        Remove screenshot files older than max_age_hours.

        Returns:
            Number of files removed
        """
        removed = 0
        cutoff = datetime.utcnow().timestamp() - (max_age_hours * 3600)

        for entry in os.scandir(self.config.output_dir):
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                try:
                    os.unlink(entry.path)
                    removed += 1
                except OSError as e:
                    logger.warning(f"Failed to remove {entry.path}: {e}")

        logger.info(f"Cleaned up {removed} old screenshots")
        return removed

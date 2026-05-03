"""
URL extraction: Extract, decode, and resolve URLs from email bodies.

Extracts URLs from plaintext body, HTML href/src attributes, handles obfuscation,
resolves URL shorteners, and provides defanged URLs for logging.
"""
import asyncio
import html
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from src.models import ExtractedURL, URLSource
from src.security.web_security import SSRFBlockedError, default_ssrf_guard

logger = logging.getLogger(__name__)

# Try to import aiohttp for async URL resolution
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    logger.warning("aiohttp not available; URL resolution will be limited")


@dataclass
class URLExtractionConfig:
    """Configuration for URL extraction."""
    max_redirects: int = 5
    timeout_seconds: float = 5.0
    resolve_shorteners: bool = True
    common_shorteners: set = None

    def __post_init__(self):
        if self.common_shorteners is None:
            self.common_shorteners = {
                "bit.ly", "tinyurl.com", "ow.ly", "buff.ly", "adf.ly",
                "goo.gl", "is.gd", "short.link", "rebrand.ly", "shorte.st",
                "t.co", "shortened.me", "q.gs", "x.co", "clck.ru",
            }


class URLExtractor:
    """
    Extract, parse, and analyze URLs from email content.

    Supports:
    - Plaintext URL extraction
    - HTML href/src attribute extraction
    - Encoded URL decoding
    - Obfuscated URL detection
    - URL shortener resolution (async)
    - URL defanging for safe logging
    """

    # Regex for URL detection in plaintext
    URL_REGEX = re.compile(
        r"https?://[^\s\"\'<>\)\]]+",
        re.IGNORECASE
    )

    # Additional patterns for obfuscated URLs
    OBFUSCATED_PATTERNS = [
        re.compile(r"hxxp[s]?://", re.IGNORECASE),  # Common obfuscation
        re.compile(r"h\[t\]tp[s]?://", re.IGNORECASE),  # Bracket obfuscation
        re.compile(r"ht\+tp[s]?://", re.IGNORECASE),  # Plus obfuscation
    ]

    def __init__(self, config: Optional[URLExtractionConfig] = None):
        """
        Initialize URL extractor.

        Args:
            config: URLExtractionConfig instance
        """
        self.config = config or URLExtractionConfig()
        self.logger = logger

    def extract_from_plaintext(self, text: str, source_detail: str = "") -> list[ExtractedURL]:
        """
        Extract URLs from plaintext body.

        Args:
            text: Plaintext email body
            source_detail: Additional source detail (e.g., "body paragraph 2")

        Returns:
            List of ExtractedURL objects
        """
        urls = []

        # Standard URLs
        for match in self.URL_REGEX.finditer(text):
            url = match.group(0).rstrip(".,;:!?)")  # Remove trailing punctuation
            if self._is_valid_url(url):
                urls.append(ExtractedURL(
                    url=url,
                    source=URLSource.BODY_PLAINTEXT,
                    source_detail=source_detail,
                ))

        # Obfuscated URLs
        for pattern in self.OBFUSCATED_PATTERNS:
            for match in pattern.finditer(text):
                # Get context around match
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 100)
                context = text[start:end]

                # Extract what looks like a URL
                url_match = re.search(r"(hxxps?|h\[t\]tps?|ht\+tps?)://\S+", context, re.IGNORECASE)
                if url_match:
                    obfuscated_url = url_match.group(0)
                    # Defang it for now, we'll note it as obfuscated
                    urls.append(ExtractedURL(
                        url=obfuscated_url,
                        source=URLSource.BODY_PLAINTEXT,
                        source_detail=f"{source_detail} (obfuscated)",
                    ))

        return urls

    def extract_from_html(self, html_content: str, source_detail: str = "") -> list[ExtractedURL]:
        """
        Extract URLs from HTML href and src attributes.

        Args:
            html_content: HTML email body
            source_detail: Additional source detail

        Returns:
            List of ExtractedURL objects
        """
        urls = []

        # Extract href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html_content):
            url = match.group(1).strip()
            url = self._decode_url(url)
            if self._is_valid_url(url):
                urls.append(ExtractedURL(
                    url=url,
                    source=URLSource.BODY_HTML,
                    source_detail=source_detail or "href attribute",
                ))

        # Extract src attributes (images, scripts, etc.)
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in src_pattern.finditer(html_content):
            url = match.group(1).strip()
            url = self._decode_url(url)
            if self._is_valid_url(url):
                urls.append(ExtractedURL(
                    url=url,
                    source=URLSource.BODY_HTML,
                    source_detail=source_detail or "src attribute",
                ))

        # Extract from data URIs (embedded images) - only if they look like URLs
        data_pattern = re.compile(r'(?:href|src)=["\']data:[^"\']*["\']', re.IGNORECASE)
        # We skip data URIs as they're not actionable

        return urls

    def _decode_url(self, url: str) -> str:
        """
        Decode encoded/escaped URLs.

        Args:
            url: Potentially encoded URL

        Returns:
            Decoded URL
        """
        # Unescape HTML entities
        url = html.unescape(url)

        # URL decode
        try:
            url = urllib.parse.unquote(url)
        except Exception:
            pass

        return url

    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format.

        Args:
            url: URL string

        Returns:
            True if valid URL
        """
        if not url:
            return False

        # Minimum URL length
        if len(url) < 10:
            return False

        # Must start with http/https or be decodable
        url_lower = url.lower()
        if not (url_lower.startswith("http://") or url_lower.startswith("https://") or
                "hxxp" in url_lower or "h[t]tp" in url_lower or "ht+tp" in url_lower):
            return False

        # Try to parse
        try:
            # Replace obfuscation patterns for parsing validation
            test_url = url.lower()
            test_url = test_url.replace("hxxp", "http").replace("h[t]tp", "http").replace("ht+tp", "http")
            result = urlparse(test_url)
            return result.scheme and result.netloc
        except Exception:
            return False

    def defang_url(self, url: str) -> str:
        """
        Defang URL for safe logging/display.

        Converts "http://evil.com" to "hxxp://evil[.]com"

        Args:
            url: URL to defang

        Returns:
            Defanged URL
        """
        url = url.replace("http://", "hxxp://")
        url = url.replace("https://", "hxxps://")
        url = url.replace(".", "[.]")
        return url

    def refang_url(self, defanged_url: str) -> str:
        """
        Refang a defanged URL.

        Converts "hxxp://evil[.]com" back to "http://evil.com"

        Args:
            defanged_url: Defanged URL

        Returns:
            Original URL
        """
        url = defanged_url.replace("hxxps://", "https://")
        url = url.replace("hxxp://", "http://")
        url = url.replace("[.]", ".")
        return url

    async def resolve_url(self, url: str, allow_redirects: bool = True) -> tuple[str, list[str]]:
        """
        Resolve URL and follow redirects asynchronously.

        Args:
            url: URL to resolve
            allow_redirects: Whether to follow redirects

        Returns:
            Tuple of (final_url, redirect_chain)
        """
        if not HAS_AIOHTTP:
            self.logger.warning("aiohttp not available; cannot resolve URLs")
            return url, []

        redirect_chain = []
        current_url = url

        if not allow_redirects:
            return current_url, []

        try:
            async with aiohttp.ClientSession() as session:
                for attempt in range(self.config.max_redirects):
                    try:
                        current_url = default_ssrf_guard.assert_safe(current_url)
                    except SSRFBlockedError as exc:
                        self.logger.warning("Blocked unsafe URL during redirect resolution: %s", exc)
                        break
                    try:
                        async with session.head(
                            current_url,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                            allow_redirects=False,
                            ssl=False,
                        ) as resp:
                            redirect_chain.append(current_url)

                            # Check for redirect
                            if resp.status in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location")
                                if location:
                                    next_url = urllib.parse.urljoin(current_url, location)
                                    try:
                                        current_url = default_ssrf_guard.assert_safe(next_url)
                                    except SSRFBlockedError as exc:
                                        self.logger.warning(
                                            "Blocked unsafe redirect target during URL resolution: %s",
                                            exc,
                                        )
                                        break
                                    continue
                            break
                    except Exception as e:
                        self.logger.debug(f"Error resolving {current_url}: {e}")
                        break

            return current_url, redirect_chain
        except Exception as e:
            self.logger.warning(f"Failed to resolve URL {url}: {e}")
            return url, []

    async def resolve_urls_batch(self, urls: list[str]) -> dict[str, tuple[str, list[str]]]:
        """
        Resolve multiple URLs concurrently.

        Args:
            urls: List of URLs to resolve

        Returns:
            Dictionary mapping original_url -> (final_url, redirect_chain)
        """
        tasks = [self.resolve_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        resolved = {}
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                resolved[url] = (url, [])
            else:
                resolved[url] = result

        return resolved

    def extract_all(
        self,
        plaintext: str = "",
        html: str = "",
        resolve_shorteners: bool = True,
    ) -> list[ExtractedURL]:
        """
        Extract URLs from both plaintext and HTML.

        Args:
            plaintext: Plaintext email body
            html: HTML email body
            resolve_shorteners: Whether to attempt shortener resolution

        Returns:
            List of deduplicated ExtractedURL objects
        """
        urls = []

        # Extract from plaintext
        if plaintext:
            urls.extend(self.extract_from_plaintext(plaintext, "plaintext body"))

        # Extract from HTML
        if html:
            urls.extend(self.extract_from_html(html, "html body"))

        # Deduplicate by URL
        seen = set()
        unique_urls = []
        for url_obj in urls:
            url_lower = url_obj.url.lower()
            if url_lower not in seen:
                seen.add(url_lower)
                unique_urls.append(url_obj)

        return unique_urls


def extract_urls(
    plaintext: str = "",
    html: str = "",
    config: Optional[URLExtractionConfig] = None,
) -> list[ExtractedURL]:
    """
    Convenience function to extract URLs.

    Args:
        plaintext: Plaintext email body
        html: HTML email body
        config: URLExtractionConfig instance

    Returns:
        List of ExtractedURL objects
    """
    extractor = URLExtractor(config)
    return extractor.extract_all(plaintext, html)


def defang_url(url: str) -> str:
    """
    Convenience function to defang a URL.

    Args:
        url: URL to defang

    Returns:
        Defanged URL
    """
    extractor = URLExtractor()
    return extractor.defang_url(url)


def refang_url(defanged_url: str) -> str:
    """
    Convenience function to refang a URL.

    Args:
        defanged_url: Defanged URL

    Returns:
        Original URL
    """
    extractor = URLExtractor()
    return extractor.refang_url(defanged_url)

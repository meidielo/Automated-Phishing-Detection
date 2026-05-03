"""
URLDetonationAnalyzer: Visit URLs in a sandboxed browser and capture screenshots.

Uses Playwright (Chromium headless) to:
1. Navigate to each URL extracted from the email
2. Follow redirect chains
3. Capture full-page screenshots
4. Record final landing URLs
5. Detect credential harvesting forms (login inputs)
6. Measure page load behavior

The screenshots are fed to BrandImpersonationAnalyzer for visual comparison,
and displayed in the monitor UI for analyst review.

Requirements:
    pip install playwright
    python -m playwright install chromium
"""
import asyncio
import base64
import logging
import os
import tempfile
from typing import Optional
from urllib.parse import urlparse

from src.models import AnalyzerResult, ExtractedURL
from src.security.web_security import SSRFBlockedError, default_ssrf_guard

logger = logging.getLogger(__name__)

# Maximum URLs to detonate per email (browser is expensive)
MAX_URLS_TO_DETONATE = 5
# Navigation timeout per URL
PAGE_TIMEOUT_MS = 15000
# Viewport size for screenshots
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 900


class URLDetonationAnalyzer:
    """
    Detonate (visit) extracted URLs in a sandboxed headless browser.

    Captures screenshots, redirect chains, and page content analysis.
    Results are stored as base64-encoded PNG screenshots keyed by URL.
    """

    def __init__(
        self,
        timeout_ms: int = PAGE_TIMEOUT_MS,
        max_urls: int = MAX_URLS_TO_DETONATE,
        user_agent: Optional[str] = None,
        browser_ws_endpoint: Optional[str] = None,
        browser_cdp_endpoint: Optional[str] = None,
    ):
        self.timeout_ms = timeout_ms
        self.max_urls = max_urls
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.browser_ws_endpoint = browser_ws_endpoint or os.getenv("PLAYWRIGHT_WS_ENDPOINT", "").strip()
        self.browser_cdp_endpoint = browser_cdp_endpoint or os.getenv("BROWSER_CDP_ENDPOINT", "").strip()
        self._browser = None
        self._playwright = None

    async def _ensure_browser(self):
        """Launch browser if not already running."""
        if self._browser and self._browser.is_connected():
            return

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            if self.browser_ws_endpoint:
                self._browser = await self._playwright.chromium.connect(
                    self.browser_ws_endpoint,
                    timeout=self.timeout_ms,
                )
                logger.info("URL detonation connected to remote Playwright browser sandbox")
            elif self.browser_cdp_endpoint:
                self._browser = await self._playwright.chromium.connect_over_cdp(
                    self.browser_cdp_endpoint,
                    timeout=self.timeout_ms,
                )
                logger.info("URL detonation connected to remote CDP browser sandbox")
            else:
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                        "--disable-background-networking",
                        "--disable-default-apps",
                        "--disable-sync",
                    ],
                )
                logger.info("URL detonation browser launched locally (Chromium headless)")
        except Exception as e:
            logger.error(f"Failed to launch browser: {e}")
            raise

    async def _close_browser(self):
        """Close the browser."""
        try:
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
        except Exception:
            pass

    @staticmethod
    def _should_reconnect_browser(error: Exception) -> bool:
        message = str(error).lower()
        return any(
            marker in message
            for marker in (
                "targetclosederror",
                "has been closed",
                "browser has been closed",
                "browser closed",
                "connection closed",
            )
        )

    async def detonate_url(self, url: str) -> dict:
        """
        Visit a single URL and capture results.

        Returns:
            Dict with screenshot (base64), redirect_chain, final_url,
            page_title, has_login_form, risk indicators.
        """
        result = {
            "url": url,
            "final_url": url,
            "redirect_chain": [],
            "page_title": "",
            "screenshot_b64": None,
            "screenshot_bytes": None,
            "has_login_form": False,
            "has_password_field": False,
            "form_action_external": False,
            "page_loaded": False,
            "error": None,
            "risk_indicators": [],
            "ssrf_blocked_requests": [],
        }

        try:
            try:
                default_ssrf_guard.assert_safe(url)
            except SSRFBlockedError as exc:
                reason = str(exc)[:200]
                result["error"] = f"SSRF blocked: {reason}"
                result["risk_indicators"] = ["ssrf_blocked_initial_url"]
                result["ssrf_blocked_requests"] = [
                    {"url": url, "reason": reason}
                ]
                return result

            await self._ensure_browser()

            context = await self._browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                user_agent=self.user_agent,
                java_script_enabled=True,
                ignore_https_errors=True,
            )

            # Track redirects
            redirects = []

            page = await context.new_page()
            ssrf_blocked_requests: list[dict[str, str]] = []

            async def _guard_request(route, request):
                request_url = getattr(request, "url", "")
                try:
                    default_ssrf_guard.assert_safe(request_url)
                except SSRFBlockedError as exc:
                    reason = str(exc)[:200]
                    if len(ssrf_blocked_requests) < 10:
                        ssrf_blocked_requests.append(
                            {"url": request_url, "reason": reason}
                        )
                    await route.abort()
                    return
                await route.continue_()

            await page.route("**/*", _guard_request)

            # Capture redirect chain
            page.on("response", lambda response: (
                redirects.append(response.url)
                if response.status in range(300, 400)
                else None
            ))

            try:
                response = await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=self.timeout_ms,
                )

                result["page_loaded"] = True
                result["final_url"] = page.url
                result["redirect_chain"] = redirects
                result["page_title"] = await page.title()

                # Detect login forms
                login_analysis = await self._analyze_page_content(page)
                result.update(login_analysis)

                # Take screenshot
                screenshot_bytes = await page.screenshot(
                    full_page=False,
                    type="png",
                )
                result["screenshot_bytes"] = screenshot_bytes
                result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode()

                # Build risk indicators
                risk_indicators = []

                # Check if redirected to different domain
                original_domain = urlparse(url).netloc
                final_domain = urlparse(page.url).netloc
                if original_domain != final_domain:
                    risk_indicators.append(f"redirect_domain_change:{original_domain}->{final_domain}")

                if result["has_login_form"]:
                    risk_indicators.append("login_form_detected")
                if result["has_password_field"]:
                    risk_indicators.append("password_field_detected")
                if result["form_action_external"]:
                    risk_indicators.append("form_submits_externally")
                if len(redirects) > 3:
                    risk_indicators.append(f"excessive_redirects:{len(redirects)}")

                if ssrf_blocked_requests:
                    result["ssrf_blocked_requests"] = ssrf_blocked_requests
                    risk_indicators.append(
                        f"ssrf_blocked_requests:{len(ssrf_blocked_requests)}"
                    )

                result["risk_indicators"] = risk_indicators

            except Exception as nav_error:
                if ssrf_blocked_requests:
                    result["error"] = "Navigation blocked by SSRF guard"
                    result["ssrf_blocked_requests"] = ssrf_blocked_requests
                    if "ssrf_blocked_request" not in result["risk_indicators"]:
                        result["risk_indicators"].append("ssrf_blocked_request")
                else:
                    result["error"] = f"Navigation failed: {str(nav_error)[:200]}"
                if self._should_reconnect_browser(nav_error):
                    await self._close_browser()
                # Still try to capture whatever loaded
                try:
                    screenshot_bytes = await page.screenshot(
                        full_page=False, type="png",
                    )
                    result["screenshot_bytes"] = screenshot_bytes
                    result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode()
                except Exception:
                    pass

            finally:
                await context.close()

        except Exception as e:
            result["error"] = str(e)[:300]
            if self._should_reconnect_browser(e):
                await self._close_browser()
            logger.error(f"URL detonation failed for {url}: {e}")

        return result

    async def _analyze_page_content(self, page) -> dict:
        """Analyze page DOM for credential harvesting indicators."""
        try:
            analysis = await page.evaluate("""() => {
                const forms = document.querySelectorAll('form');
                const passwordFields = document.querySelectorAll('input[type="password"]');
                const emailFields = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"], input[name*="login"]');
                const submitButtons = document.querySelectorAll('input[type="submit"], button[type="submit"], button');

                let hasLoginForm = false;
                let hasPasswordField = passwordFields.length > 0;
                let formActionExternal = false;

                // Check if any form has a password field (= login form)
                forms.forEach(form => {
                    const pw = form.querySelector('input[type="password"]');
                    const em = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');
                    if (pw || em) hasLoginForm = true;

                    // Check if form action points to external domain
                    const action = form.getAttribute('action') || '';
                    if (action.startsWith('http') && !action.includes(window.location.hostname)) {
                        formActionExternal = true;
                    }
                });

                // Also check for standalone password fields outside forms
                if (!hasLoginForm && (hasPasswordField || emailFields.length > 0)) {
                    hasLoginForm = true;
                }

                return {
                    has_login_form: hasLoginForm,
                    has_password_field: hasPasswordField,
                    form_action_external: formActionExternal,
                    form_count: forms.length,
                    password_field_count: passwordFields.length,
                    email_field_count: emailFields.length,
                };
            }""")
            return analysis
        except Exception as e:
            logger.warning(f"Page content analysis failed: {e}")
            return {
                "has_login_form": False,
                "has_password_field": False,
                "form_action_external": False,
            }

    async def analyze(self, urls: list[ExtractedURL]) -> AnalyzerResult:
        """
        Detonate URLs and return analysis result.

        Args:
            urls: List of extracted URLs to detonate.

        Returns:
            AnalyzerResult with screenshots and risk analysis.
        """
        analyzer_name = "url_detonation"

        if not urls:
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={"message": "no_urls_to_detonate"},
            )

        # Check if Playwright is available
        try:
            import playwright  # noqa: F401
        except ImportError:
            logger.warning("Playwright not installed — URL detonation disabled")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={"message": "playwright_not_installed"},
            )

        urls_to_check = urls[:self.max_urls]
        all_results = {}
        all_errors = []
        screenshots = {}  # url -> bytes (for brand impersonation)

        try:
            for extracted_url in urls_to_check:
                try:
                    det_result = await self.detonate_url(extracted_url.url)
                    all_results[extracted_url.url] = det_result

                    if det_result.get("screenshot_bytes"):
                        screenshots[extracted_url.url] = det_result["screenshot_bytes"]

                    if det_result.get("error"):
                        all_errors.append(f"{extracted_url.url}: {det_result['error']}")

                except Exception as e:
                    all_errors.append(f"{extracted_url.url}: {str(e)}")

        finally:
            await self._close_browser()

        # Calculate risk score from detonation results
        risk_score = 0.0
        risk_signals = []

        for url, det in all_results.items():
            indicators = det.get("risk_indicators", [])
            if any("ssrf_blocked" in i for i in indicators):
                risk_score = max(risk_score, 0.8)
                risk_signals.append(f"{url}: blocked by SSRF guard")
                continue

            if not det.get("page_loaded"):
                continue

            url_risk = 0.0

            if det.get("has_password_field"):
                url_risk = max(url_risk, 0.6)
                risk_signals.append(f"{url}: password field detected")

            if det.get("has_login_form"):
                url_risk = max(url_risk, 0.5)
                risk_signals.append(f"{url}: login form detected")

            if det.get("form_action_external"):
                url_risk = max(url_risk, 0.7)
                risk_signals.append(f"{url}: form submits to external domain")

            if any("redirect_domain_change" in i for i in indicators):
                url_risk = max(url_risk, 0.4)
            if any("excessive_redirects" in i for i in indicators):
                url_risk = max(url_risk, 0.3)

            risk_score = max(risk_score, url_risk)

        # Confidence based on how many URLs we successfully detonated.
        #
        # Cycle 14 fix: when risk_score is 0.0 and coverage is incomplete
        # (some URLs didn't load), confidence must be 0.0 (abstain).
        # Asserting "clean with partial confidence" on incomplete evidence
        # dilutes the weighted average the same way cycle 13's
        # attachment_analysis bug did: zero numerator, non-zero denominator.
        # A phishing email with one malicious URL among several decoys will
        # produce risk=0.0 if the detonator tested the wrong half.
        #
        # When risk_score > 0 (we found something), partial coverage still
        # warrants reporting because the finding is real even if we didn't
        # check everything. When risk_score == 0.0, partial coverage means
        # "I don't know" not "it's clean."
        loaded_count = sum(1 for r in all_results.values() if r.get("page_loaded"))
        total = max(len(urls_to_check), 1)
        coverage = loaded_count / total

        if risk_score > 0.0:
            # Found something: confidence scales with coverage
            confidence = min(coverage, 1.0) * 0.8
        elif loaded_count == len(urls_to_check) and loaded_count > 0:
            # Full coverage, found nothing: legitimate clean signal
            confidence = 0.8
        else:
            # Partial or zero coverage, found nothing: abstain
            confidence = 0.0

        # Sanitize results for JSON serialization (remove raw bytes)
        json_results = {}
        for url, det in all_results.items():
            sanitized = dict(det)
            sanitized.pop("screenshot_bytes", None)
            json_results[url] = sanitized

        logger.info(
            f"URL detonation complete: {loaded_count}/{len(urls_to_check)} loaded, "
            f"risk={risk_score:.2f}, signals={len(risk_signals)}"
        )

        return AnalyzerResult(
            analyzer_name=analyzer_name,
            risk_score=risk_score,
            confidence=confidence,
            details={
                "urls_detonated": len(urls_to_check),
                "urls_loaded": loaded_count,
                "detonation_results": json_results,
                "risk_signals": risk_signals,
                "screenshots": {
                    url: base64.b64encode(data).decode()
                    for url, data in screenshots.items()
                },
            },
            errors=all_errors if all_errors else [],
        )


async def detonate_single_url(url: str, timeout_ms: int = PAGE_TIMEOUT_MS) -> dict:
    """
    Convenience function to detonate a single URL.

    Used by the API endpoint for on-demand link simulation.
    Returns the full detonation result dict.
    """
    analyzer = URLDetonationAnalyzer(timeout_ms=timeout_ms, max_urls=1)
    try:
        return await analyzer.detonate_url(url)
    finally:
        await analyzer._close_browser()

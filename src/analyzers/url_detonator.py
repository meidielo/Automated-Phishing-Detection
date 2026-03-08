"""
URLDetonationAnalyzer: Visit URLs in a controlled browser environment.
Captures screenshots, follows redirects, and detects suspicious features like login forms.
"""
import asyncio
import logging
from typing import Optional

from src.models import AnalyzerResult, ExtractedURL

logger = logging.getLogger(__name__)


class URLDetonationAnalyzer:
    """
    Analyze URLs by visiting them in a controlled browser environment.

    Capabilities:
    - Follow redirect chains
    - Capture screenshots at each redirect
    - Detect login forms
    - Identify suspicious JavaScript
    - Check for certificate issues
    """

    def __init__(self, browser_client: Optional[object] = None):
        """
        Initialize URL detonation analyzer with dependency injection.

        Args:
            browser_client: Playwright-based browser client for visiting URLs
        """
        self.browser_client = browser_client

    async def _visit_url(self, url: str, timeout: int = 30) -> tuple[float, float, dict]:
        """
        Visit a URL and capture detonation results.

        Args:
            url: URL to visit
            timeout: Timeout in seconds

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.browser_client:
            return 0.0, 0.0, {}

        try:
            detonation_result = await asyncio.wait_for(
                self.browser_client.visit_url(url),
                timeout=timeout
            )

            risk_score = 0.0
            confidence = 0.5
            details: dict = {
                "detonation": {
                    "url": url,
                    "accessible": True,
                }
            }

            # Check redirect chain
            redirect_chain = detonation_result.get("redirect_chain", [])
            if redirect_chain:
                details["detonation"]["redirect_chain"] = redirect_chain
                details["detonation"]["redirect_count"] = len(redirect_chain)

                # Multiple redirects can be suspicious
                if len(redirect_chain) > 3:
                    risk_score = max(risk_score, 0.4)

                # Check for domain switching in redirects
                original_domain = self._extract_domain(url)
                final_domain = self._extract_domain(redirect_chain[-1])
                if original_domain and final_domain and original_domain != final_domain:
                    risk_score = max(risk_score, 0.5)
                    details["detonation"]["domain_switch"] = True

            # Check for login forms
            login_forms = detonation_result.get("login_forms", [])
            if login_forms:
                details["detonation"]["login_forms_detected"] = len(login_forms)
                risk_score = max(risk_score, 0.6)
                details["detonation"]["form_details"] = login_forms

            # Check for suspicious scripts
            suspicious_scripts = detonation_result.get("suspicious_scripts", [])
            if suspicious_scripts:
                details["detonation"]["suspicious_scripts"] = suspicious_scripts
                risk_score = max(risk_score, 0.5)

            # Check certificate validity
            cert_valid = detonation_result.get("cert_valid", True)
            if not cert_valid:
                risk_score = max(risk_score, 0.7)
                details["detonation"]["certificate_issue"] = True

            # Capture screenshot
            screenshot = detonation_result.get("screenshot")
            if screenshot:
                details["detonation"]["screenshot"] = screenshot
                confidence = 0.8

            # Check page title and content
            page_title = detonation_result.get("page_title", "")
            if page_title:
                details["detonation"]["page_title"] = page_title

            # Check for authentication bypass attempts
            auth_bypass_indicators = detonation_result.get("auth_bypass_indicators", [])
            if auth_bypass_indicators:
                risk_score = max(risk_score, 0.7)
                details["detonation"]["auth_bypass_indicators"] = auth_bypass_indicators

            return risk_score, confidence, details

        except asyncio.TimeoutError:
            logger.warning(f"URL detonation timeout for {url}")
            return 0.0, 0.0, {
                "detonation_error": "timeout",
                "url": url,
            }
        except Exception as e:
            logger.warning(f"URL detonation failed for {url}: {e}")
            return 0.0, 0.0, {
                "detonation_error": str(e),
                "url": url,
            }

    def _extract_domain(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.

        Args:
            url: URL string

        Returns:
            Domain name or None
        """
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                domain = url.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return None

    async def analyze(self, urls: list[ExtractedURL]) -> AnalyzerResult:
        """
        Analyze URLs by visiting them in a browser environment.

        Args:
            urls: List of extracted URLs to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "url_detonation"

        try:
            if not urls:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=1.0,
                    details={"message": "no_urls_to_analyze"},
                )

            detonation_results: dict[str, dict] = {}

            for extracted_url in urls:
                try:
                    det_score, det_conf, det_details = await self._visit_url(
                        extracted_url.url
                    )

                    detonation_results[extracted_url.url] = {
                        "risk_score": det_score,
                        "confidence": det_conf,
                        "details": det_details,
                        "source": extracted_url.source.value,
                        "source_detail": extracted_url.source_detail,
                    }

                except Exception as e:
                    logger.error(f"Error detonating URL {extracted_url.url}: {e}")
                    detonation_results[extracted_url.url] = {
                        "error": str(e),
                        "source": extracted_url.source.value,
                    }

            # Overall: max across all URLs
            url_scores = [
                result.get("risk_score", 0.0)
                for result in detonation_results.values()
                if "error" not in result
            ]
            url_confidences = [
                result.get("confidence", 0.0)
                for result in detonation_results.values()
                if "error" not in result
            ]

            overall_risk_score = max(url_scores) if url_scores else 0.0
            overall_confidence = max(url_confidences) if url_confidences else 0.0

            logger.info(
                f"URL detonation analysis complete: "
                f"risk={overall_risk_score:.2f}, confidence={overall_confidence:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=overall_risk_score,
                confidence=overall_confidence,
                details={
                    "url_count": len(urls),
                    "urls_analyzed": detonation_results,
                },
            )

        except Exception as e:
            logger.error(f"URL detonation analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

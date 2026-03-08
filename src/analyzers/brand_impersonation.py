"""
BrandImpersonationAnalyzer: Detect brand impersonation using image similarity.
Uses pHash and SSIM comparison against reference brand templates.
"""
import logging
from typing import Optional

from src.models import AnalyzerResult

logger = logging.getLogger(__name__)


class BrandImpersonationAnalyzer:
    """
    Detect brand impersonation through visual similarity analysis.

    Analyzes screenshots using:
    - Perceptual hashing (pHash) for robust image comparison
    - SSIM (Structural Similarity Index) for pixel-level similarity
    - Domain-brand mismatch detection

    Supported brands:
    - Microsoft 365
    - Google
    - Apple
    - PayPal
    - DocuSign
    - DHL
    - FedEx
    """

    BRANDS = {
        "microsoft_365": {
            "domains": ["microsoft.com", "office.com", "outlook.com"],
            "alternate_domains": ["onedrive.com", "sharepoint.com"],
        },
        "google": {
            "domains": ["google.com", "accounts.google.com"],
            "alternate_domains": ["gmail.com", "drive.google.com"],
        },
        "apple": {
            "domains": ["apple.com", "icloud.com", "appleid.apple.com"],
            "alternate_domains": [],
        },
        "paypal": {
            "domains": ["paypal.com", "www.paypal.com"],
            "alternate_domains": ["checkout.paypal.com"],
        },
        "docusign": {
            "domains": ["docusign.com", "docusign.net"],
            "alternate_domains": ["signnow.com"],
        },
        "dhl": {
            "domains": ["dhl.com", "dhl.de"],
            "alternate_domains": ["dhlparcel.com"],
        },
        "fedex": {
            "domains": ["fedex.com", "fedexexpress.com"],
            "alternate_domains": ["groundnewsletter.fedex.com"],
        },
    }

    def __init__(
        self,
        image_comparison_client: Optional[object] = None,
        brand_templates_path: Optional[str] = None,
    ):
        """
        Initialize brand impersonation analyzer with dependency injection.

        Args:
            image_comparison_client: Client for image similarity comparison
            brand_templates_path: Path to stored brand reference templates
        """
        self.image_comparison_client = image_comparison_client
        self.brand_templates_path = brand_templates_path or "data/brand_templates"

    def _extract_domain(self, url: Optional[str]) -> Optional[str]:
        """
        Extract domain from URL.

        Args:
            url: URL string

        Returns:
            Domain name or None
        """
        if not url:
            return None

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

    def _check_domain_brand_mismatch(self, domain: Optional[str]) -> tuple[float, bool, str]:
        """
        Check if domain mismatches claimed brand.

        Args:
            domain: Domain to check

        Returns:
            Tuple of (risk_score, mismatch_detected, mismatched_brand)
        """
        if not domain:
            return 0.0, False, ""

        for brand_name, brand_info in self.BRANDS.items():
            all_domains = brand_info["domains"] + brand_info["alternate_domains"]

            # Check if domain matches brand
            if any(bd in domain for bd in all_domains):
                return 0.0, False, ""

            # Check for slight misspellings of brand domain
            for brand_domain in all_domains:
                base_domain = brand_domain.split(".")[0]
                if base_domain in domain and domain != brand_domain:
                    # Domain contains brand name but isn't exact match
                    return 0.7, True, brand_name

        return 0.0, False, ""

    async def _compare_with_brand_template(self, screenshot: bytes, brand: str) -> tuple[float, float]:
        """
        Compare screenshot with brand reference template.

        Args:
            screenshot: Screenshot bytes to analyze
            brand: Brand name to compare against

        Returns:
            Tuple of (similarity_score, confidence)
        """
        if not self.image_comparison_client or not screenshot:
            return 0.0, 0.0

        try:
            # Load reference template
            template_path = f"{self.brand_templates_path}/{brand}_template.png"

            result = await self.image_comparison_client.compare_images(
                screenshot,
                template_path,
            )

            phash_similarity = result.get("phash_similarity", 0.0)
            ssim_similarity = result.get("ssim_similarity", 0.0)

            # Combined similarity with weighted average
            combined_similarity = (phash_similarity * 0.4) + (ssim_similarity * 0.6)

            # Confidence increases with high SSIM (pixel-level similarity)
            confidence = ssim_similarity

            return combined_similarity, confidence

        except Exception as e:
            logger.warning(f"Brand template comparison failed for {brand}: {e}")
            return 0.0, 0.0

    async def analyze(
        self, detonation_screenshots: dict[str, bytes], extracted_urls: Optional[list] = None
    ) -> AnalyzerResult:
        """
        Analyze screenshots for brand impersonation.

        Args:
            detonation_screenshots: Dict mapping URLs to screenshot bytes
            extracted_urls: Optional list of ExtractedURL objects for domain context

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "brand_impersonation"

        try:
            if not detonation_screenshots:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=1.0,
                    details={"message": "no_screenshots_to_analyze"},
                )

            analysis_results: dict[str, dict] = {}
            max_risk_score = 0.0
            max_confidence = 0.0

            for url, screenshot in detonation_screenshots.items():
                try:
                    url_result: dict = {
                        "url": url,
                        "screenshot_present": screenshot is not None,
                        "brand_checks": {},
                    }

                    domain = self._extract_domain(url)

                    # Check for domain-brand mismatch
                    mismatch_risk, mismatch_detected, mismatched_brand = (
                        self._check_domain_brand_mismatch(domain)
                    )

                    if mismatch_detected:
                        url_result["domain_mismatch"] = {
                            "detected": True,
                            "brand": mismatched_brand,
                            "risk_score": mismatch_risk,
                        }
                        max_risk_score = max(max_risk_score, mismatch_risk)

                    # Compare screenshot against all brand templates
                    if screenshot:
                        for brand_name in self.BRANDS.keys():
                            similarity, confidence = await self._compare_with_brand_template(
                                screenshot, brand_name
                            )

                            url_result["brand_checks"][brand_name] = {
                                "similarity": similarity,
                                "confidence": confidence,
                            }

                            # Impersonation detected if high similarity but domain mismatch
                            if similarity > 0.7 and mismatch_detected:
                                max_risk_score = max(max_risk_score, 0.85)
                                max_confidence = max(max_confidence, confidence)
                                url_result["impersonation_detected"] = True
                                url_result["impersonated_brand"] = brand_name
                            elif similarity > 0.7:
                                max_risk_score = max(max_risk_score, 0.6)
                                max_confidence = max(max_confidence, confidence)

                    analysis_results[url] = url_result

                except Exception as e:
                    logger.error(f"Error analyzing screenshot for {url}: {e}")
                    analysis_results[url] = {
                        "error": str(e),
                    }

            # Determine overall confidence
            overall_confidence = max_confidence if max_risk_score > 0.5 else 0.3

            logger.info(
                f"Brand impersonation analysis complete: "
                f"risk={max_risk_score:.2f}, confidence={overall_confidence:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=max_risk_score,
                confidence=overall_confidence,
                details={
                    "screenshot_count": len(detonation_screenshots),
                    "screenshots_analyzed": analysis_results,
                    "brands_checked": list(self.BRANDS.keys()),
                },
            )

        except Exception as e:
            logger.error(f"Brand impersonation analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

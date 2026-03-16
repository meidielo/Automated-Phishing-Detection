"""
BrandImpersonationAnalyzer: Detect brand impersonation in emails.

Uses multiple signals:
1. Domain-brand mismatch (sender domain vs claimed brand)
2. Display name spoofing (display name contains brand but domain doesn't match)
3. Email body content analysis (brand keywords, logos, templates)
4. Reply-To domain mismatch
5. Look-alike domain detection (typosquatting, homoglyphs)
6. Optional: Screenshot comparison via pHash/SSIM (when detonation is available)
"""
import logging
import re
from typing import Optional

from src.models import AnalyzerResult, EmailObject

logger = logging.getLogger(__name__)


class BrandImpersonationAnalyzer:
    """
    Detect brand impersonation through content and domain analysis.

    Works WITHOUT screenshots by analyzing:
    - Sender email domain vs known brand domains
    - Display name vs sender domain
    - Email body for brand keywords and patterns
    - Reply-To header mismatches
    - Look-alike domain patterns

    When screenshots are available (via URL detonation), also compares
    visual similarity using pHash and SSIM.
    """

    # Comprehensive brand database: domains that legitimately send email for each brand
    BRANDS = {
        "microsoft": {
            "display_names": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "teams"],
            "legit_domains": [
                "microsoft.com", "office.com", "outlook.com", "live.com",
                "onedrive.com", "sharepoint.com", "microsoftonline.com",
                "office365.com", "microsoft365.com",
            ],
            "body_keywords": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "teams", "azure"],
        },
        "google": {
            "display_names": ["google", "gmail", "google drive", "google docs"],
            "legit_domains": [
                "google.com", "gmail.com", "googlemail.com",
                "accounts.google.com", "drive.google.com",
            ],
            "body_keywords": ["google", "gmail", "google drive", "google docs", "google workspace"],
        },
        "apple": {
            "display_names": ["apple", "icloud", "apple id", "app store", "itunes"],
            "legit_domains": [
                "apple.com", "icloud.com", "me.com", "mac.com",
                "itunes.com", "email.apple.com",
            ],
            "body_keywords": ["apple id", "icloud", "app store", "itunes", "macbook", "iphone"],
        },
        "paypal": {
            "display_names": ["paypal", "pay pal"],
            "legit_domains": ["paypal.com", "paypal.me", "e.paypal.com"],
            "body_keywords": ["paypal", "payment received", "send money", "paypal.com"],
        },
        "amazon": {
            "display_names": ["amazon", "amazon prime", "aws"],
            "legit_domains": [
                "amazon.com", "amazon.co.uk", "amazon.com.au", "amazon.de",
                "amazonaws.com", "amazonses.com", "amazon.in",
            ],
            "body_keywords": ["amazon", "prime", "aws", "your order", "delivery"],
        },
        "indeed": {
            "display_names": ["indeed", "interview invitation", "job invitation"],
            "legit_domains": [
                "indeed.com", "indeed.co.uk", "indeed.com.au",
                "indeed.co.in", "indeed.hk",
                "indeedemail.com", "indeed.force.com",
                "engage.indeed.com", "notifications.indeed.com",
                "bounces.indeed.com",
            ],
            "body_keywords": ["indeed", "job application", "interview invitation", "hiring process", "apply now"],
        },
        "linkedin": {
            "display_names": ["linkedin", "linked in"],
            "legit_domains": ["linkedin.com", "e.linkedin.com", "linkedin.email"],
            "body_keywords": ["linkedin", "connection request", "new job", "endorsement"],
        },
        "netflix": {
            "display_names": ["netflix"],
            "legit_domains": ["netflix.com", "mailer.netflix.com"],
            "body_keywords": ["netflix", "subscription", "streaming", "watch now"],
        },
        "docusign": {
            "display_names": ["docusign", "docu sign"],
            "legit_domains": ["docusign.com", "docusign.net"],
            "body_keywords": ["docusign", "please sign", "review document", "signature"],
        },
        "dhl": {
            "display_names": ["dhl", "dhl express"],
            "legit_domains": ["dhl.com", "dhl.de", "dhlparcel.com"],
            "body_keywords": ["dhl", "shipment", "tracking", "delivery", "parcel"],
        },
        "fedex": {
            "display_names": ["fedex", "fed ex"],
            "legit_domains": ["fedex.com"],
            "body_keywords": ["fedex", "tracking", "delivery", "shipment"],
        },
        "usps": {
            "display_names": ["usps", "us postal"],
            "legit_domains": ["usps.com", "informeddelivery.usps.com"],
            "body_keywords": ["usps", "postal service", "tracking", "delivery"],
        },
        "auspost": {
            "display_names": ["australia post", "auspost"],
            "legit_domains": [
                "auspost.com.au", "notifications.auspost.com.au",
                "bounces.auspost.com.au",
            ],
            "body_keywords": ["australia post", "auspost", "parcel", "delivery", "tracking"],
        },
        "bank_generic": {
            "display_names": ["bank", "security alert", "fraud alert", "account verification"],
            "legit_domains": [],  # No legit domains — any email claiming to be a bank is checked
            "body_keywords": [
                "verify your account", "confirm your identity", "suspended",
                "unusual activity", "security alert", "update your payment",
                "click here to verify", "account locked", "confirm your details",
            ],
        },
        "dropbox": {
            "display_names": ["dropbox"],
            "legit_domains": ["dropbox.com", "dropboxmail.com"],
            "body_keywords": ["dropbox", "shared folder", "shared file"],
        },
        "facebook": {
            "display_names": ["facebook", "meta", "instagram"],
            "legit_domains": [
                "facebook.com", "facebookmail.com", "fb.com",
                "instagram.com", "meta.com",
            ],
            "body_keywords": ["facebook", "instagram", "meta", "login alert"],
        },
    }

    def __init__(
        self,
        image_comparison_client: Optional[object] = None,
        brand_templates_path: Optional[str] = None,
    ):
        self.image_comparison_client = image_comparison_client
        self.brand_templates_path = brand_templates_path or "data/brand_templates"

    def _extract_domain(self, address: Optional[str]) -> Optional[str]:
        """Extract domain from an email address or URL."""
        if not address:
            return None
        try:
            if "@" in address:
                return address.split("@")[-1].lower().strip()
            from urllib.parse import urlparse
            parsed = urlparse(address)
            domain = parsed.netloc.lower()
            if not domain:
                domain = address.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return None

    def _is_legit_domain_for_brand(self, domain: str, brand_info: dict) -> bool:
        """Check if a domain is a legitimate sender for a brand."""
        for legit in brand_info["legit_domains"]:
            if domain == legit or domain.endswith("." + legit):
                return True
        return False

    def _detect_brand_in_text(self, text: str) -> list[tuple[str, float]]:
        """
        Detect brand references in text content.
        Returns list of (brand_name, match_strength) tuples.
        """
        if not text:
            return []

        text_lower = text.lower()
        matches = []

        for brand_name, brand_info in self.BRANDS.items():
            keyword_hits = 0
            total_keywords = len(brand_info["body_keywords"])

            for keyword in brand_info["body_keywords"]:
                if keyword.lower() in text_lower:
                    keyword_hits += 1

            if keyword_hits > 0:
                strength = min(keyword_hits / max(total_keywords, 1), 1.0)
                matches.append((brand_name, strength))

        return sorted(matches, key=lambda x: x[1], reverse=True)

    def _detect_brand_in_display_name(self, display_name: str) -> list[str]:
        """Detect brand names in the email display name."""
        if not display_name:
            return []

        name_lower = display_name.lower()
        matched_brands = []

        for brand_name, brand_info in self.BRANDS.items():
            for dn in brand_info["display_names"]:
                if dn.lower() in name_lower:
                    matched_brands.append(brand_name)
                    break

        return matched_brands

    def _check_lookalike_domain(self, domain: str) -> list[tuple[str, float]]:
        """
        Check if a domain is a look-alike of a known brand domain.
        Detects: indeed-verify.com, indeedhr.com, lndeed.com, indeed.evil.com
        """
        if not domain:
            return []

        matches = []
        domain_parts = domain.split(".")

        for brand_name, brand_info in self.BRANDS.items():
            for legit_domain in brand_info["legit_domains"]:
                legit_base = legit_domain.split(".")[0]

                if len(legit_base) < 3:
                    continue

                # Brand name in domain but not a legit domain
                if legit_base in domain and not self._is_legit_domain_for_brand(domain, brand_info):
                    matches.append((brand_name, 0.7))
                    break

                # Subdomain abuse: brand.evil.com
                if legit_base in domain_parts[0] and len(domain_parts) > 2:
                    if not self._is_legit_domain_for_brand(domain, brand_info):
                        matches.append((brand_name, 0.6))
                        break

        return matches

    def _detect_random_sender(self, local_part: str) -> float:
        """
        Detect random/generated email local parts like 'as628967uuwwj_3eg'.
        Returns suspicion score 0.0-1.0.
        """
        if not local_part:
            return 0.0

        # Long random strings with mixed alphanumeric
        if len(local_part) > 12 and re.search(r'\d.*[a-z].*\d|[a-z].*\d.*[a-z]', local_part):
            digit_ratio = sum(c.isdigit() for c in local_part) / len(local_part)
            if digit_ratio > 0.25:
                return 0.8

        # Pattern like as628967uuwwj_3eg (letters+digits+underscore)
        if re.match(r'^[a-z]+\d+[a-z_]+\d*[a-z]*$', local_part, re.IGNORECASE):
            return 0.6

        # Pure numeric
        if re.match(r'^\d+$', local_part):
            return 0.7

        return 0.0

    async def analyze(
        self,
        email: Optional[EmailObject] = None,
        detonation_screenshots: Optional[dict[str, bytes]] = None,
        extracted_urls: Optional[list] = None,
    ) -> AnalyzerResult:
        """
        Analyze email for brand impersonation.

        Works with or without screenshots. When no screenshots are available,
        uses email headers, display name, body content, and domain analysis.
        """
        analyzer_name = "brand_impersonation"

        try:
            # If no email object, fall back to screenshot-only mode
            if not email:
                if not detonation_screenshots:
                    return AnalyzerResult(
                        analyzer_name=analyzer_name,
                        risk_score=0.0,
                        confidence=0.0,  # No data = no confidence
                        details={"message": "no_email_data"},
                    )
                return await self._analyze_screenshots_only(detonation_screenshots)

            signals = []
            max_risk = 0.0

            from_addr = email.from_address or ""
            from_domain = self._extract_domain(from_addr)
            from_local = from_addr.split("@")[0] if "@" in from_addr else ""
            display_name = getattr(email, "display_name", "") or ""
            reply_to = getattr(email, "reply_to", "") or ""
            reply_domain = self._extract_domain(reply_to)
            body = email.body_plain or email.body_html or ""
            subject = email.subject or ""
            combined_text = f"{subject} {body}"

            # ── Signal 1: Brand in display name but sender domain doesn't match ──
            display_brands = self._detect_brand_in_display_name(display_name)
            if not display_brands:
                display_brands = self._detect_brand_in_display_name(subject)

            for brand in display_brands:
                brand_info = self.BRANDS[brand]
                if from_domain and not self._is_legit_domain_for_brand(from_domain, brand_info):
                    risk = 0.75
                    signals.append({
                        "signal": "display_name_brand_mismatch",
                        "brand": brand,
                        "display_name": display_name or subject,
                        "from_domain": from_domain,
                        "risk": risk,
                    })
                    max_risk = max(max_risk, risk)

            # ── Signal 2: Brand in body content but sender domain doesn't match ──
            body_brands = self._detect_brand_in_text(combined_text)
            for brand, strength in body_brands:
                brand_info = self.BRANDS[brand]
                if from_domain and not self._is_legit_domain_for_brand(from_domain, brand_info):
                    if strength >= 0.3:
                        risk = min(0.5 + strength * 0.4, 0.85)
                        signals.append({
                            "signal": "body_brand_mismatch",
                            "brand": brand,
                            "keyword_strength": round(strength, 2),
                            "from_domain": from_domain,
                            "risk": risk,
                        })
                        max_risk = max(max_risk, risk)

            # ── Signal 3: Look-alike domain ──
            if from_domain:
                lookalikes = self._check_lookalike_domain(from_domain)
                for brand, risk in lookalikes:
                    signals.append({
                        "signal": "lookalike_domain",
                        "brand": brand,
                        "domain": from_domain,
                        "risk": risk,
                    })
                    max_risk = max(max_risk, risk)

            # ── Signal 4: Reply-To domain mismatch ──
            if reply_domain and from_domain and reply_domain != from_domain:
                reply_risk = 0.6
                if signals:  # Combined with brand signals = very suspicious
                    reply_risk = 0.85
                signals.append({
                    "signal": "reply_to_domain_mismatch",
                    "from_domain": from_domain,
                    "reply_domain": reply_domain,
                    "risk": reply_risk,
                })
                max_risk = max(max_risk, reply_risk)

            # ── Signal 5: Random/generated sender address ──
            random_score = self._detect_random_sender(from_local)
            if random_score > 0.5:
                if signals:  # Random sender + brand signals = phishing
                    random_score = min(random_score + 0.15, 0.9)
                signals.append({
                    "signal": "random_sender_address",
                    "local_part": from_local,
                    "suspicion": round(random_score, 2),
                    "risk": random_score,
                })
                max_risk = max(max_risk, random_score)

            # ── Signal 6: Screenshot comparison (if available) ──
            screenshot_results = {}
            if detonation_screenshots:
                screenshot_results = await self._analyze_screenshots(detonation_screenshots)
                for url, result in screenshot_results.items():
                    if result.get("risk", 0) > 0:
                        signals.append({
                            "signal": "screenshot_brand_match",
                            "url": url,
                            **result,
                        })
                        max_risk = max(max_risk, result.get("risk", 0))

            # ── Compute overall confidence ──
            if not signals:
                confidence = 0.8  # Moderately confident it's clean
            else:
                confidence = min(0.6 + len(signals) * 0.1, 1.0)

            logger.info(
                f"Brand impersonation analysis: risk={max_risk:.2f}, "
                f"confidence={confidence:.2f}, signals={len(signals)}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=max_risk,
                confidence=confidence,
                details={
                    "signals_found": len(signals),
                    "signals": signals,
                    "brands_checked": len(self.BRANDS),
                    "screenshot_analysis": screenshot_results if screenshot_results else None,
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

    async def _analyze_screenshots_only(self, screenshots: dict[str, bytes]) -> AnalyzerResult:
        """Fallback: screenshot-only analysis when no email object is available."""
        results = await self._analyze_screenshots(screenshots)
        max_risk = max((r.get("risk", 0) for r in results.values()), default=0.0)
        confidence = 0.5 if max_risk > 0 else 0.0

        return AnalyzerResult(
            analyzer_name="brand_impersonation",
            risk_score=max_risk,
            confidence=confidence,
            details={"screenshots_analyzed": results},
        )

    async def _analyze_screenshots(self, screenshots: dict[str, bytes]) -> dict:
        """Analyze screenshots against brand templates."""
        results = {}
        if not self.image_comparison_client:
            return results

        for url, screenshot in screenshots.items():
            if not screenshot:
                continue
            try:
                domain = self._extract_domain(url)
                for brand_name, brand_info in self.BRANDS.items():
                    template_path = f"{self.brand_templates_path}/{brand_name}_template.png"
                    try:
                        result = await self.image_comparison_client.compare_images(
                            screenshot, template_path,
                        )
                        similarity = (
                            result.get("phash_similarity", 0.0) * 0.4
                            + result.get("ssim_similarity", 0.0) * 0.6
                        )
                        if similarity > 0.7:
                            is_legit = domain and self._is_legit_domain_for_brand(domain, brand_info)
                            risk = 0.3 if is_legit else 0.85
                            results[url] = {
                                "brand": brand_name,
                                "similarity": round(similarity, 3),
                                "domain_is_legit": is_legit,
                                "risk": risk,
                            }
                    except Exception:
                        pass
            except Exception as e:
                logger.warning(f"Screenshot analysis failed for {url}: {e}")

        return results

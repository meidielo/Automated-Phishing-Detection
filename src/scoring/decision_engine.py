"""
Decision engine for phishing detection pipeline.

Implements weighted multi-signal scoring with override rules, confidence-based
verdict capping, and comprehensive reasoning generation. Combines risk scores
from multiple analyzers into a final verdict.
"""

import logging
from dataclasses import asdict
from datetime import datetime
from typing import Optional

from src.config import ScoringConfig
from src.models import AnalyzerResult, Verdict, PipelineResult, IntentCategory
from src.scoring.confidence import ConfidenceCalculator
from src.scoring.thresholds import ThresholdManager

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    Phishing detection decision engine that combines analyzer results
    into a final verdict using weighted scoring and override rules.

    The engine implements:
    1. Weighted confidence scoring with automatic downweighting of failed analyzers
    2. Overall confidence calculation with verdict capping
    3. Override rules for known threats and safe emails
    4. Threshold-based verdict mapping
    5. Comprehensive reasoning generation
    """

    def __init__(self, config: ScoringConfig):
        """
        Initialize decision engine with scoring configuration.

        Args:
            config: ScoringConfig with weights and thresholds
        """
        self.config = config
        self.threshold_manager = ThresholdManager(config.thresholds)
        self._validate_config()
        logger.info(
            f"DecisionEngine initialized with weights: {config.weights} "
            f"and thresholds: {config.thresholds}"
        )

    def _validate_config(self):
        """Validate that configuration is well-formed."""
        weights = self.config.weights
        if not weights:
            raise ValueError("No analyzer weights configured")

        total_weight = sum(weights.values())
        if total_weight <= 0:
            raise ValueError("Total weight must be positive")

        # Warn if weights don't sum to 1.0
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(
                f"Analyzer weights sum to {total_weight:.2f}, not 1.0. "
                f"This is valid but unusual."
            )

    def score(
        self,
        results: dict[str, AnalyzerResult],
        email_id: str = "",
        email_data: Optional[dict] = None,
    ) -> PipelineResult:
        """
        Score email based on multiple analyzer results.

        Implements a 5-step process:
        1. Calculate weighted confidence score
        2. Calculate overall confidence
        3. Apply override rules
        4. Map score to verdict using thresholds
        5. Generate reasoning

        Args:
            results: Dict of analyzer_name -> AnalyzerResult
            email_id: Email identifier for logging and tracing
            email_data: Optional dict with email metadata for override rules

        Returns:
            PipelineResult with verdict, scores, and reasoning
        """
        if not results:
            logger.warning(f"No analyzer results for email {email_id}")
            return PipelineResult(
                email_id=email_id,
                verdict=Verdict.SUSPICIOUS,
                overall_score=0.5,
                overall_confidence=0.0,
                analyzer_results={},
                extracted_urls=[],
                iocs={},
                reasoning="No analyzer results available",
            )

        logger.debug(f"Scoring email {email_id} with {len(results)} analyzer results")

        # Step 1 & 2: Calculate weighted score and overall confidence
        weighted_score, overall_confidence = self._calculate_weighted_scores(results)

        # Step 3: Check override rules
        override_verdict, override_reasoning = self._check_override_rules(
            results=results,
            weighted_score=weighted_score,
            email_data=email_data,
        )

        # If override rule applies, use it
        if override_verdict is not None:
            logger.info(
                f"Override rule applied for email {email_id}: {override_verdict} - {override_reasoning}"
            )
            reasoning = override_reasoning
            final_verdict = override_verdict
            final_score = weighted_score
        else:
            # Step 4: Apply threshold mapping with confidence capping
            final_verdict = self._apply_confidence_capping(weighted_score, overall_confidence)

            # Step 5: Generate reasoning
            reasoning = self._generate_reasoning(
                results=results,
                weighted_score=weighted_score,
                overall_confidence=overall_confidence,
                final_verdict=final_verdict,
            )
            final_score = weighted_score

        logger.info(
            f"Email {email_id} scored: verdict={final_verdict}, "
            f"score={final_score:.3f}, confidence={overall_confidence:.3f}"
        )

        # Extract IOCs and URLs for reporting
        iocs = self._extract_iocs(results)
        extracted_urls = results.get("url_reputation", AnalyzerResult(
            analyzer_name="url_reputation",
            risk_score=0.0,
            confidence=0.0,
            details={}
        )).details.get("urls_analyzed", {})

        return PipelineResult(
            email_id=email_id,
            verdict=final_verdict,
            overall_score=final_score,
            overall_confidence=overall_confidence,
            analyzer_results=results,
            extracted_urls=[],  # URLs are in iocs/details
            iocs=iocs,
            reasoning=reasoning,
            timestamp=datetime.utcnow(),
        )

    def _calculate_weighted_scores(
        self,
        results: dict[str, AnalyzerResult],
    ) -> tuple[float, float]:
        """
        Calculate weighted confidence score and overall confidence.

        Weighted score formula:
            score = sum(weight_i * risk_i * confidence_i) / sum(weight_i * confidence_i)

        This naturally downweights failed analyzers (confidence=0.0).

        Overall confidence formula:
            overall_conf = sum(weight_i * confidence_i) / sum(weight_i)

        Args:
            results: Dict of analyzer results

        Returns:
            Tuple of (weighted_score, overall_confidence)
        """
        weighted_score_sum = 0.0
        weighted_confidence_sum = 0.0
        total_weight = 0.0
        confidence_weighted_sum = 0.0

        for analyzer_name, result in results.items():
            # Get weight for this analyzer, default to 0 if not configured
            weight = self.config.weights.get(analyzer_name, 0.0)
            if weight == 0.0:
                logger.debug(f"No weight configured for analyzer: {analyzer_name}")
                continue

            # Skip analyzers with zero confidence (no data)
            if result.confidence == 0.0:
                logger.debug(
                    f"Skipping {analyzer_name} due to zero confidence (no data)"
                )
                continue

            # Accumulate weighted values
            weighted_score_sum += weight * result.risk_score * result.confidence
            weighted_confidence_sum += weight * result.confidence
            confidence_weighted_sum += weight * result.confidence
            total_weight += weight

            logger.debug(
                f"{analyzer_name}: risk={result.risk_score:.3f}, "
                f"conf={result.confidence:.3f}, weight={weight:.3f}"
            )

        # Calculate overall confidence (sum of weighted confidences / total weight)
        if total_weight > 0:
            overall_confidence = confidence_weighted_sum / total_weight
        else:
            overall_confidence = 0.0

        # Calculate weighted score (normalized by total weighted confidence)
        if weighted_confidence_sum > 0:
            weighted_score = weighted_score_sum / weighted_confidence_sum
        else:
            # No analyzers provided data - neutral score
            weighted_score = 0.5
            overall_confidence = 0.0

        # Clamp to valid range
        weighted_score = max(0.0, min(1.0, weighted_score))
        overall_confidence = max(0.0, min(1.0, overall_confidence))

        logger.debug(
            f"Calculated weighted_score={weighted_score:.3f}, "
            f"overall_confidence={overall_confidence:.3f}"
        )

        return weighted_score, overall_confidence

    def _check_override_rules(
        self,
        results: dict[str, AnalyzerResult],
        weighted_score: float,
        email_data: Optional[dict] = None,
    ) -> tuple[Optional[Verdict], str]:
        """
        Check override rules that can force a verdict regardless of score.

        Override rules (first match wins):
        1. Known malware hash → CONFIRMED_PHISHING
        2. URL on phishing feed (VT detection > 30%) → min LIKELY_PHISHING
        3. All SPF+DKIM+DMARC pass + known sender + no URLs + no attachments → max CLEAN
        4. NLP intent = bec_wire_fraud with confidence > 0.8 → min LIKELY_PHISHING

        Args:
            results: Analyzer results dict
            weighted_score: Calculated weighted score
            email_data: Optional email metadata

        Returns:
            Tuple of (override_verdict or None, reason_string)
        """
        email_data = email_data or {}

        # Rule 1: Known malware hash
        attachment_result = results.get("attachment_analysis")
        if attachment_result and self._has_known_malware(attachment_result):
            return Verdict.CONFIRMED_PHISHING, "Known malware hash detected in attachment"

        # Rule 2: URL on phishing feed (VirusTotal detection > 30%)
        url_result = results.get("url_reputation")
        if url_result and self._has_malicious_urls(url_result):
            return Verdict.LIKELY_PHISHING, "URL detected as malicious by multiple vendors"

        # Rule 3: All auth passes + known sender + no URLs/attachments
        if self._is_clean_email(results, email_data):
            return Verdict.CLEAN, "All authentication checks passed, no suspicious indicators"

        # Rule 4: NLP intent = BEC with high confidence
        nlp_result = results.get("nlp_intent")
        if nlp_result and self._is_bec_threat(nlp_result):
            return (
                Verdict.LIKELY_PHISHING,
                "High-confidence Business Email Compromise intent detected",
            )

        # No override rule matched
        return None, ""

    def _has_known_malware(self, attachment_result: AnalyzerResult) -> bool:
        """
        Check if attachment contains known malware hash.

        Args:
            attachment_result: Attachment analysis result

        Returns:
            True if known malware detected
        """
        details = attachment_result.details or {}
        attachments = details.get("attachments", [])

        for attachment in attachments:
            if isinstance(attachment, dict):
                # Check for known hash
                if attachment.get("risk_category") == "malicious":
                    if attachment.get("hash_match_count", 0) > 0:
                        logger.info(f"Known malware hash detected: {attachment.get('filename')}")
                        return True

        return False

    def _has_malicious_urls(self, url_result: AnalyzerResult) -> bool:
        """
        Check if URLs were flagged as malicious by threat intelligence.

        Detection threshold: > 30% of vendors flagged as malicious.

        Args:
            url_result: URL reputation analysis result

        Returns:
            True if malicious URLs detected
        """
        details = url_result.details or {}
        urls_analyzed = details.get("urls_analyzed", {})

        for url, url_data in urls_analyzed.items():
            if isinstance(url_data, dict) and "error" not in url_data:
                risk_score = url_data.get("risk_score", 0.0)
                if risk_score > 0.3:
                    logger.info(f"Malicious URL detected: {url} (risk={risk_score:.2f})")
                    return True

        return False

    def _is_clean_email(
        self,
        results: dict[str, AnalyzerResult],
        email_data: dict,
    ) -> bool:
        """
        Check if email passes all security checks and has no suspicious content.

        Criteria:
        - SPF, DKIM, DMARC all pass
        - Sender is known/trusted
        - No URLs found
        - No attachments

        Args:
            results: Analyzer results
            email_data: Email metadata

        Returns:
            True if email is definitely clean
        """
        # Check authentication
        header_result = results.get("header_analysis")
        if header_result:
            details = header_result.details or {}
            header_detail = details.get("header_analysis_detail", {})

            spf_pass = header_detail.get("spf_pass")
            dkim_pass = header_detail.get("dkim_pass")
            dmarc_pass = header_detail.get("dmarc_pass")

            # All must pass
            if not (spf_pass and dkim_pass and dmarc_pass):
                return False
        else:
            return False  # Can't verify auth

        # Check for URLs
        url_result = results.get("url_reputation")
        if url_result:
            details = url_result.details or {}
            url_count = details.get("url_count", 0)
            if url_count > 0:
                return False

        # Check for attachments
        attachment_result = results.get("attachment_analysis")
        if attachment_result:
            details = attachment_result.details or {}
            attachment_count = details.get("attachment_count", 0)
            if attachment_count > 0:
                return False

        # Check sender reputation
        sender_result = results.get("sender_profiling")
        if sender_result and sender_result.risk_score > 0.2:
            return False

        return True

    def _is_bec_threat(self, nlp_result: AnalyzerResult) -> bool:
        """
        Check if NLP detected Business Email Compromise intent with high confidence.

        Args:
            nlp_result: NLP intent analysis result

        Returns:
            True if high-confidence BEC detected
        """
        details = nlp_result.details or {}
        intent_classification = details.get("intent_classification", {})

        if isinstance(intent_classification, dict):
            category = intent_classification.get("category")
            confidence = intent_classification.get("confidence", 0.0)

            # Check for BEC intent and high confidence
            if (
                category == IntentCategory.BEC_WIRE_FRAUD.value
                and confidence > 0.8
            ):
                logger.info("High-confidence BEC threat detected")
                return True

        return False

    def _apply_confidence_capping(
        self,
        weighted_score: float,
        overall_confidence: float,
    ) -> Verdict:
        """
        Apply verdict with confidence-based capping.

        If overall_confidence < 0.4, verdict is capped at SUSPICIOUS.
        This prevents overconfident verdicts when data is incomplete.

        Args:
            weighted_score: Calculated weighted score
            overall_confidence: Overall confidence level

        Returns:
            Final verdict after confidence capping
        """
        verdict = self.threshold_manager.get_verdict(weighted_score)

        # If confidence is too low, cap verdict to SUSPICIOUS
        if overall_confidence < 0.4:
            logger.debug(
                f"Confidence {overall_confidence:.3f} below threshold 0.4, "
                f"capping verdict to SUSPICIOUS"
            )
            return self.threshold_manager.map_to_safe_verdict(
                weighted_score,
                enforce_upper_cap=True,
                cap_verdict=Verdict.SUSPICIOUS,
            )

        return verdict

    def _generate_reasoning(
        self,
        results: dict[str, AnalyzerResult],
        weighted_score: float,
        overall_confidence: float,
        final_verdict: Verdict,
    ) -> str:
        """
        Generate human-readable reasoning for the decision.

        Args:
            results: Analyzer results
            weighted_score: Calculated score
            overall_confidence: Overall confidence
            final_verdict: Final verdict reached

        Returns:
            Reasoning string explaining the verdict
        """
        lines = [
            f"Phishing Detection Analysis",
            f"─" * 40,
            f"Final Verdict: {final_verdict.value}",
            f"Risk Score: {weighted_score:.1%}",
            f"Confidence: {overall_confidence:.1%}",
            "",
            "Analyzer Contributions:",
        ]

        # Sort by contribution (weight * confidence)
        contributions = []
        for analyzer_name, result in results.items():
            weight = self.config.weights.get(analyzer_name, 0.0)
            if weight == 0.0 or result.confidence == 0.0:
                continue

            contribution = weight * result.confidence
            contributions.append((analyzer_name, result, contribution))

        contributions.sort(key=lambda x: x[2], reverse=True)

        for analyzer_name, result, contribution in contributions:
            risk_label = self._risk_label(result.risk_score)
            lines.append(
                f"  • {analyzer_name}: {risk_label} "
                f"(score={result.risk_score:.2f}, conf={result.confidence:.2f})"
            )

            # Add key details
            if result.details:
                details_summary = self._summarize_details(analyzer_name, result.details)
                if details_summary:
                    lines.append(f"    → {details_summary}")

        lines.append("")
        lines.append("Summary:")

        # Add verdict-specific summary
        if final_verdict == Verdict.CONFIRMED_PHISHING:
            lines.append("  This email shows strong phishing indicators and should be blocked.")
        elif final_verdict == Verdict.LIKELY_PHISHING:
            lines.append("  This email has multiple phishing characteristics and requires caution.")
        elif final_verdict == Verdict.SUSPICIOUS:
            lines.append("  This email has some suspicious characteristics that warrant review.")
        else:  # CLEAN
            lines.append("  This email appears legitimate based on available analysis.")

        if overall_confidence < 0.5:
            lines.append("  ⚠ Low confidence - analysis may be incomplete.")

        return "\n".join(lines)

    @staticmethod
    def _risk_label(risk_score: float) -> str:
        """Get human-readable risk label for a score."""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _summarize_details(analyzer_name: str, details: dict) -> str:
        """
        Summarize analyzer details into a brief human-readable string.

        Args:
            analyzer_name: Name of the analyzer
            details: Details dict from the analyzer

        Returns:
            Summary string
        """
        if analyzer_name == "url_reputation":
            url_count = details.get("url_count", 0)
            if url_count == 0:
                return "No URLs found"
            return f"{url_count} URLs analyzed"

        elif analyzer_name == "attachment_analysis":
            att_count = details.get("attachment_count", 0)
            if att_count == 0:
                return "No attachments"
            return f"{att_count} attachments scanned"

        elif analyzer_name == "header_analysis":
            header_detail = details.get("header_analysis_detail", {})
            auth_status = []
            if header_detail.get("spf_pass"):
                auth_status.append("SPF✓")
            if header_detail.get("dkim_pass"):
                auth_status.append("DKIM✓")
            if header_detail.get("dmarc_pass"):
                auth_status.append("DMARC✓")
            if auth_status:
                return f"Auth: {' '.join(auth_status)}"
            return "Authentication failed"

        elif analyzer_name == "nlp_intent":
            intent_class = details.get("intent_classification", {})
            if isinstance(intent_class, dict):
                category = intent_class.get("category", "unknown")
                return f"Intent: {category}"

        elif analyzer_name == "sender_profiling":
            return details.get("reputation", "Unknown reputation")

        return ""

    @staticmethod
    def _extract_iocs(results: dict[str, AnalyzerResult]) -> dict:
        """
        Extract Indicators of Compromise from analyzer results.

        Args:
            results: Analyzer results

        Returns:
            Dict with IOCs organized by type
        """
        iocs = {
            "urls": [],
            "attachments": [],
            "headers": {},
        }

        # URLs from URL reputation
        url_result = results.get("url_reputation")
        if url_result and url_result.details:
            urls_analyzed = url_result.details.get("urls_analyzed", {})
            for url, data in urls_analyzed.items():
                if isinstance(data, dict) and "error" not in data:
                    iocs["urls"].append({
                        "url": url,
                        "risk_score": data.get("risk_score", 0.0),
                        "source": data.get("source", "unknown"),
                    })

        # Attachments from attachment analysis
        att_result = results.get("attachment_analysis")
        if att_result and att_result.details:
            attachments = att_result.details.get("attachments", [])
            for att in attachments:
                if isinstance(att, dict):
                    iocs["attachments"].append({
                        "filename": att.get("filename", "unknown"),
                        "risk_category": att.get("risk_category", "unknown"),
                    })

        return iocs

    def update_weights(self, new_weights: dict[str, float]):
        """
        Update analyzer weights at runtime.

        Called by retraining pipeline to adjust weights based on feedback.

        Args:
            new_weights: Dict mapping analyzer names to new weights

        Raises:
            ValueError: If weights are invalid
        """
        # Validate new weights
        if not new_weights:
            raise ValueError("New weights cannot be empty")

        total_weight = sum(new_weights.values())
        if total_weight <= 0:
            raise ValueError("Total weight must be positive")

        # Update config
        self.config.weights = new_weights
        self._validate_config()

        logger.info(f"Analyzer weights updated: {new_weights}")

    def update_thresholds(self, new_thresholds: dict[str, tuple[float, float]]):
        """
        Update verdict thresholds at runtime.

        Args:
            new_thresholds: Dict mapping verdict names to (min, max) tuples

        Raises:
            ValueError: If thresholds are invalid
        """
        self.threshold_manager.update_thresholds(new_thresholds)
        self.config.thresholds = new_thresholds
        logger.info(f"Verdict thresholds updated")

    def get_config_snapshot(self) -> dict:
        """
        Export current configuration as dict for logging/auditing.

        Returns:
            Dict with weights and thresholds
        """
        return {
            "weights": self.config.weights.copy(),
            "thresholds": self.threshold_manager.get_config_dict(),
        }

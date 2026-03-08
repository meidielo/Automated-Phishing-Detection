"""
NLPIntentAnalyzer: Classify email intent using NLP.
Supports both LLM-based and local sklearn fallback approaches.
"""
import asyncio
import json
import logging
from typing import Optional

from src.models import AnalyzerResult, EmailObject, IntentCategory

logger = logging.getLogger(__name__)


class NLPIntentAnalyzer:
    """
    Classify email intent using natural language processing.

    Supports two approaches:
    1. LLM-based: Call API with structured prompt, parse JSON response
    2. Local sklearn fallback: TF-IDF + pretrained classifier

    Intent categories and risk score mapping:
    - CREDENTIAL_HARVESTING: 0.95 (very high risk)
    - MALWARE_DELIVERY: 0.90 (very high risk)
    - BEC_WIRE_FRAUD: 0.85 (high risk)
    - GIFT_CARD_SCAM: 0.80 (high risk)
    - EXTORTION: 0.75 (high risk)
    - LEGITIMATE: 0.05 (very low risk)
    - UNKNOWN: 0.30 (medium risk)

    Additional urgency score modifier (0.0 to 1.0) boosts risk for urgent language.
    """

    INTENT_RISK_MAPPING = {
        IntentCategory.CREDENTIAL_HARVESTING: 0.95,
        IntentCategory.MALWARE_DELIVERY: 0.90,
        IntentCategory.BEC_WIRE_FRAUD: 0.85,
        IntentCategory.GIFT_CARD_SCAM: 0.80,
        IntentCategory.EXTORTION: 0.75,
        IntentCategory.LEGITIMATE: 0.05,
        IntentCategory.UNKNOWN: 0.30,
    }

    URGENCY_KEYWORDS = [
        "urgent",
        "immediate",
        "asap",
        "right now",
        "immediately",
        "quickly",
        "time-sensitive",
        "within 24 hours",
        "within 48 hours",
        "act now",
        "do not delay",
        "critical",
        "emergency",
        "alert",
    ]

    def __init__(
        self,
        llm_client: Optional[object] = None,
        sklearn_classifier: Optional[object] = None,
        use_llm: bool = True,
    ):
        """
        Initialize NLP intent analyzer with dependency injection.

        Args:
            llm_client: LLM API client for intent classification
            sklearn_classifier: sklearn classifier for fallback analysis
            use_llm: Whether to prefer LLM-based approach
        """
        self.llm_client = llm_client
        self.sklearn_classifier = sklearn_classifier
        self.use_llm = use_llm

    def _calculate_urgency_score(self, text: str) -> float:
        """
        Calculate urgency score based on keywords in text.

        Args:
            text: Email text to analyze

        Returns:
            Urgency score from 0.0 to 1.0
        """
        text_lower = text.lower()
        matched_keywords = sum(
            1 for keyword in self.URGENCY_KEYWORDS
            if keyword in text_lower
        )

        # Normalize to 0-1 range
        urgency_score = min(matched_keywords / 5.0, 1.0)
        return urgency_score

    async def _analyze_with_llm(self, email: EmailObject) -> tuple[IntentCategory, float, str, float]:
        """
        Classify email intent using LLM.

        Args:
            email: Email object to analyze

        Returns:
            Tuple of (intent_category, confidence, reasoning, urgency_score)
        """
        if not self.llm_client:
            return IntentCategory.UNKNOWN, 0.0, "No LLM client available", 0.0

        try:
            # Prepare email text for analysis
            email_text = f"""
Subject: {email.subject}
From: {email.from_address} ({email.from_display_name})
Body: {email.body_plain[:2000]}
"""

            # Create structured prompt
            prompt = f"""Analyze this email and classify its intent.

Email:
{email_text}

Classify the email into one of these categories:
- credential_harvesting: Attempting to steal login credentials
- malware_delivery: Delivering malware or malicious attachments
- bec_wire_fraud: Business Email Compromise / wire fraud attempt
- gift_card_scam: Requesting gift card purchases
- extortion: Threatening or extortion content
- legitimate: Legitimate business email
- unknown: Cannot determine intent

Respond in JSON format:
{{
    "intent": "category_name",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation",
    "urgency_indicators": number of urgent phrases found
}}
"""

            response = await self.llm_client.analyze(prompt)

            # Parse JSON response
            try:
                if isinstance(response, str):
                    # Extract JSON from response if wrapped in markdown
                    if "```json" in response:
                        response = response.split("```json")[1].split("```")[0]
                    response = json.loads(response)
                elif not isinstance(response, dict):
                    response = json.loads(str(response))
            except json.JSONDecodeError:
                logger.warning("Failed to parse LLM response as JSON")
                return IntentCategory.UNKNOWN, 0.0, "JSON parse error", 0.0

            intent_str = response.get("intent", "unknown").lower()
            confidence = response.get("confidence", 0.5)
            reasoning = response.get("reasoning", "")
            urgency_indicators = response.get("urgency_indicators", 0)

            # Map string to IntentCategory enum
            try:
                intent_category = IntentCategory(intent_str)
            except ValueError:
                # Try to match with underscore conversion
                intent_str = intent_str.replace("-", "_").replace(" ", "_")
                try:
                    intent_category = IntentCategory[intent_str.upper()]
                except KeyError:
                    intent_category = IntentCategory.UNKNOWN

            urgency_score = min(urgency_indicators / 5.0, 1.0)

            return intent_category, confidence, reasoning, urgency_score

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return IntentCategory.UNKNOWN, 0.0, f"LLM error: {str(e)}", 0.0

    async def _analyze_with_sklearn(self, email: EmailObject) -> tuple[IntentCategory, float, str, float]:
        """
        Classify email intent using sklearn classifier.

        Args:
            email: Email object to analyze

        Returns:
            Tuple of (intent_category, confidence, reasoning, urgency_score)
        """
        if not self.sklearn_classifier:
            return IntentCategory.UNKNOWN, 0.0, "No sklearn classifier available", 0.0

        try:
            # Prepare text for classification
            email_text = f"{email.subject} {email.body_plain[:1000]}"

            # Use sklearn classifier
            prediction = await self.sklearn_classifier.predict(email_text)

            intent_str = prediction.get("intent", "unknown")
            confidence = prediction.get("probability", 0.0)

            # Map string to IntentCategory
            try:
                intent_category = IntentCategory(intent_str)
            except ValueError:
                intent_category = IntentCategory.UNKNOWN

            reasoning = prediction.get("reasoning", "sklearn classification")
            urgency_score = self._calculate_urgency_score(email_text)

            return intent_category, confidence, reasoning, urgency_score

        except Exception as e:
            logger.error(f"sklearn analysis failed: {e}")
            return IntentCategory.UNKNOWN, 0.0, f"sklearn error: {str(e)}", 0.0

    async def analyze(self, email: EmailObject) -> AnalyzerResult:
        """
        Analyze email intent.

        Args:
            email: Email object to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "nlp_intent"

        try:
            if not email or not email.subject:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=0.0,
                    details={"message": "no_email_content"},
                )

            # Try LLM first, fall back to sklearn if needed
            if self.use_llm:
                intent_category, confidence, reasoning, urgency_score = (
                    await self._analyze_with_llm(email)
                )
                method = "llm"

                if intent_category == IntentCategory.UNKNOWN and self.sklearn_classifier:
                    logger.info("LLM failed or inconclusive, falling back to sklearn")
                    intent_category, confidence, reasoning, urgency_score = (
                        await self._analyze_with_sklearn(email)
                    )
                    method = "sklearn_fallback"
            else:
                intent_category, confidence, reasoning, urgency_score = (
                    await self._analyze_with_sklearn(email)
                )
                method = "sklearn"

            # Map intent to risk score
            base_risk_score = self.INTENT_RISK_MAPPING.get(
                intent_category, 0.3
            )

            # Apply urgency modifier
            # Urgency increases risk, especially for suspicious intents
            urgency_modifier = urgency_score * 0.2 if base_risk_score > 0.5 else urgency_score * 0.1
            final_risk_score = min(base_risk_score + urgency_modifier, 1.0)

            logger.info(
                f"Intent analysis complete: "
                f"intent={intent_category.value}, "
                f"risk={final_risk_score:.2f}, "
                f"confidence={confidence:.2f}, "
                f"urgency={urgency_score:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=final_risk_score,
                confidence=confidence,
                details={
                    "intent_category": intent_category.value,
                    "base_risk_score": base_risk_score,
                    "urgency_score": urgency_score,
                    "urgency_modifier": urgency_modifier,
                    "reasoning": reasoning,
                    "analysis_method": method,
                },
            )

        except Exception as e:
            logger.error(f"NLP intent analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )

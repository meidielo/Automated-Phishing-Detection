"""
Payment fraud analyzer for invoice scams, supplier impersonation, and BEC.

This analyzer turns the phishing pipeline into a business decision guard:
SAFE, VERIFY, or DO_NOT_PAY before money leaves the business.
"""
import logging
import re
from dataclasses import asdict
from email.utils import parseaddr
from html import unescape
from typing import Optional

from src.extractors.header_analyzer import HeaderAnalyzer
from src.models import (
    AnalyzerResult,
    AttachmentObject,
    EmailObject,
    PaymentDecision,
    PaymentFraudAnalysis,
    PaymentFraudSignal,
    PaymentSignalSeverity,
)


logger = logging.getLogger(__name__)


class PaymentFraudAnalyzer:
    """
    Detect payment-specific fraud patterns.

    Focus areas:
    - Invoice fraud and fake supplier payment requests
    - Bank detail change scams
    - Urgent transfer requests and approval bypass language
    - Sender and reply-to mismatch around payment instructions
    - Risky invoice-themed attachments
    """

    PAYMENT_TERMS = [
        "invoice",
        "payment",
        "payable",
        "remittance",
        "remit",
        "bank transfer",
        "wire transfer",
        "eft",
        "ach",
        "bsb",
        "account number",
        "account no",
        "iban",
        "swift",
        "payid",
        "overdue",
        "outstanding balance",
        "statement attached",
        "settlement",
    ]

    BANK_CHANGE_PATTERNS = [
        r"new\s+(?:bank|account|payment)\s+details",
        r"updated\s+(?:bank|account|payment)\s+details",
        r"change(?:d)?\s+(?:our\s+)?(?:bank|account|payment)\s+details",
        r"use\s+the\s+(?:new|updated)\s+(?:bank|account|payment)\s+details",
        r"do\s+not\s+use\s+(?:the\s+)?old\s+(?:bank|account|payment)\s+details",
        r"bank\s+account\s+(?:has\s+)?changed",
        r"bank\s+details\s+(?:have\s+)?changed",
        r"bank\s+details\s+.*\bchanged\s+in\s+(?:the\s+)?(?:supplier\s+)?portal",
        r"account\s+details\s+(?:have\s+)?changed",
    ]

    URGENCY_PATTERNS = [
        r"\burgent\b",
        r"\basap\b",
        r"\bimmediately\b",
        r"\btoday\b",
        r"\bwithin\s+24\s+hours\b",
        r"\bfinal\s+notice\b",
        r"\boverdue\b",
        r"\bpast\s+due\b",
        r"\bavoid\s+(?:late\s+)?fees\b",
        r"\bpayment\s+hold\b",
    ]

    BYPASS_PATTERNS = [
        r"do\s+not\s+call",
        r"only\s+reply\s+to\s+this\s+email",
        r"keep\s+(?:this\s+)?confidential",
        r"do\s+not\s+discuss",
        r"no\s+need\s+to\s+confirm",
        r"skip\s+(?:the\s+)?approval",
        r"process\s+without\s+delay",
    ]

    EXECUTIVE_REQUEST_PATTERNS = [
        r"\bceo\b",
        r"\bcfo\b",
        r"\bdirector\b",
        r"\bowner\b",
        r"\bmanaging\s+director\b",
        r"\btransfer\s+request\b",
        r"\bwire\s+the\s+funds\b",
        r"\bkindly\s+process\b",
    ]

    POSITIVE_VERIFICATION_PATTERNS = [
        r"confirm\s+(?:through|via)\s+(?:your\s+)?(?:usual|known)\s+contact",
        r"call\s+(?:your\s+)?(?:usual|known)\s+(?:contact|number)",
        r"verify\s+(?:through|via)\s+(?:the\s+)?portal",
        r"purchase\s+order",
    ]

    FREE_EMAIL_DOMAINS = {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
    }

    DANGEROUS_ATTACHMENT_EXTENSIONS = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".vbs",
        ".ps1",
        ".lnk",
        ".iso",
        ".img",
        ".html",
        ".htm",
    )

    INVOICE_ATTACHMENT_TERMS = (
        "invoice",
        "receipt",
        "statement",
        "remittance",
        "payment",
        "quote",
        "purchase-order",
        "po",
    )

    AMOUNT_RE = re.compile(
        r"(?<!\w)(?:AUD|A\$|\$)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b",
        re.IGNORECASE,
    )
    BSB_RE = re.compile(r"\bbsb\s*[:#-]?\s*(\d{3}[-\s]?\d{3})\b", re.IGNORECASE)
    ACCOUNT_RE = re.compile(
        r"\b(?:account(?:\s+(?:number|no\.?))?|acct(?:\s+no\.?)?)"
        r"\s*[:#-]?\s*([0-9][0-9\s-]{5,18}[0-9])\b",
        re.IGNORECASE,
    )
    IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
    SWIFT_RE = re.compile(
        r"\bswift(?:/bic)?\s*[:#-]?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        re.IGNORECASE,
    )
    PAYID_RE = re.compile(
        r"\bpayid\s*[:#-]?\s*([\w.+-]+@[\w.-]+\.\w+|\+?\d[\d\s-]{7,})",
        re.IGNORECASE,
    )
    ABN_RE = re.compile(r"\babn\s*[:#-]?\s*((?:\d\s*){11})\b", re.IGNORECASE)

    async def analyze(
        self,
        email: EmailObject,
        iocs: Optional[dict] = None,
        extracted_urls: Optional[list] = None,
    ) -> AnalyzerResult:
        """
        Analyze an email for payment fraud risk.

        Args:
            email: Email object to analyze.
            iocs: Optional extracted IOC dictionary from the pipeline.
            extracted_urls: Optional extracted URLs.

        Returns:
            AnalyzerResult containing payment decision details.
        """
        analyzer_name = "payment_fraud"

        try:
            text = self._combined_text(email)
            fields = self._extract_payment_fields(text)
            attachments = email.attachments if hasattr(email, "attachments") else []
            invoice_attachments = self._invoice_attachment_names(attachments)
            payment_terms = self._matched_terms(text, self.PAYMENT_TERMS)

            payment_context = bool(payment_terms or fields["has_payment_fields"] or invoice_attachments)
            header_detail = HeaderAnalyzer().analyze(email)
            from_domain = self._domain_from_email(email.from_address)
            reply_domain = self._domain_from_email(email.reply_to or "")

            signals: list[PaymentFraudSignal] = []

            if not payment_context:
                analysis = PaymentFraudAnalysis(
                    decision=PaymentDecision.SAFE,
                    risk_score=0.03,
                    confidence=0.65,
                    summary="No invoice, payment, or bank-detail request detected.",
                    signals=[],
                    extracted_payment_fields=fields,
                    verification_steps=[],
                )
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=analysis.risk_score,
                    confidence=analysis.confidence,
                    details=self._analysis_to_details(analysis),
                )

            self._add_bank_change_signals(text, signals)
            self._add_urgency_signal(text, signals)
            self._add_bypass_signal(text, signals)
            self._add_sender_signals(
                email=email,
                from_domain=from_domain,
                reply_domain=reply_domain,
                header_detail=header_detail,
                signals=signals,
            )
            self._add_payment_field_signals(fields, signals)
            self._add_attachment_signals(attachments, invoice_attachments, signals)
            self._add_executive_request_signal(email, text, signals)

            risk_score = self._combine_signal_risk(signals)
            risk_score = self._apply_positive_verification_discount(text, risk_score)
            confidence = self._calculate_confidence(
                fields=fields,
                signals=signals,
                header_detail=header_detail,
                payment_terms=payment_terms,
                invoice_attachments=invoice_attachments,
            )
            decision = self._decision_from_risk(risk_score, signals)
            verification_steps = self._verification_steps(decision, signals, fields)
            summary = self._summary(decision, signals, fields)

            analysis = PaymentFraudAnalysis(
                decision=decision,
                risk_score=risk_score,
                confidence=confidence,
                summary=summary,
                signals=signals,
                extracted_payment_fields=fields,
                verification_steps=verification_steps,
            )

            logger.info(
                "Payment fraud analysis complete: decision=%s risk=%.2f confidence=%.2f",
                decision.value,
                risk_score,
                confidence,
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=risk_score,
                confidence=confidence,
                details=self._analysis_to_details(analysis),
            )

        except Exception as exc:
            logger.error("Payment fraud analysis failed: %s", exc, exc_info=True)
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.5,
                confidence=0.0,
                details={"error": str(exc)},
                errors=[str(exc)],
            )

    def _combined_text(self, email: EmailObject) -> str:
        html_text = re.sub(r"<[^>]+>", " ", email.body_html or "")
        return unescape(
            " ".join([
                email.subject or "",
                email.from_display_name or "",
                email.from_address or "",
                email.reply_to or "",
                email.body_plain or "",
                html_text,
            ])
        ).lower()

    def _extract_payment_fields(self, text: str) -> dict:
        amounts = self._unique(self.AMOUNT_RE.findall(text))
        bsb_numbers = self._unique(self.BSB_RE.findall(text))
        account_numbers = self._unique(self.ACCOUNT_RE.findall(text))
        ibans = self._unique(self.IBAN_RE.findall(text.upper()))
        swift_codes = self._unique(self.SWIFT_RE.findall(text.upper()))
        payids = self._unique(self.PAYID_RE.findall(text))
        abns = self._unique(self.ABN_RE.findall(text))

        return {
            "amounts": amounts[:5],
            "bsb_numbers": [self._mask_digits(value) for value in bsb_numbers[:5]],
            "account_numbers": [self._mask_digits(value) for value in account_numbers[:5]],
            "iban_numbers": [self._mask_identifier(value) for value in ibans[:5]],
            "swift_codes": swift_codes[:5],
            "payids": [self._mask_payid(value) for value in payids[:5]],
            "abns": [self._mask_digits(value) for value in abns[:5]],
            "payment_field_count": (
                len(bsb_numbers) + len(account_numbers) + len(ibans)
                + len(swift_codes) + len(payids)
            ),
            "has_payment_fields": bool(
                bsb_numbers or account_numbers or ibans or swift_codes or payids
            ),
        }

    def _add_bank_change_signals(self, text: str, signals: list[PaymentFraudSignal]) -> None:
        matches = self._matched_patterns(text, self.BANK_CHANGE_PATTERNS)
        if matches:
            signals.append(self._signal(
                name="bank_detail_change_request",
                severity=PaymentSignalSeverity.CRITICAL,
                evidence=f"Bank or payment detail change language found: {matches[0]}",
                recommendation="Do not pay until the supplier is verified through a saved contact method.",
                risk_weight=0.42,
            ))

    def _add_urgency_signal(self, text: str, signals: list[PaymentFraudSignal]) -> None:
        matches = self._matched_patterns(text, self.URGENCY_PATTERNS)
        if matches:
            signals.append(self._signal(
                name="payment_urgency_pressure",
                severity=PaymentSignalSeverity.HIGH,
                evidence=f"Urgency language found around a payment request: {matches[0]}",
                recommendation="Route the payment through normal approval instead of acting on urgency.",
                risk_weight=0.16,
            ))

    def _add_bypass_signal(self, text: str, signals: list[PaymentFraudSignal]) -> None:
        matches = self._matched_patterns(text, self.BYPASS_PATTERNS)
        if matches:
            signals.append(self._signal(
                name="approval_bypass_language",
                severity=PaymentSignalSeverity.CRITICAL,
                evidence=f"Approval bypass or secrecy language found: {matches[0]}",
                recommendation="Escalate to a second approver before any payment action.",
                risk_weight=0.35,
            ))

    def _add_sender_signals(
        self,
        email: EmailObject,
        from_domain: str,
        reply_domain: str,
        header_detail,
        signals: list[PaymentFraudSignal],
    ) -> None:
        if from_domain and reply_domain and from_domain != reply_domain:
            signals.append(self._signal(
                name="reply_to_domain_mismatch",
                severity=PaymentSignalSeverity.HIGH,
                evidence=f"From domain {from_domain} differs from reply-to domain {reply_domain}.",
                recommendation="Do not continue the payment conversation through the reply-to address.",
                risk_weight=0.18,
            ))

        auth_failures = []
        if header_detail.spf_pass is False:
            auth_failures.append("SPF")
        if header_detail.dkim_pass is False:
            auth_failures.append("DKIM")
        if header_detail.dmarc_pass is False:
            auth_failures.append("DMARC")
        if auth_failures:
            signals.append(self._signal(
                name="sender_authentication_failed",
                severity=PaymentSignalSeverity.HIGH,
                evidence=f"Email authentication failed: {', '.join(auth_failures)}.",
                recommendation="Treat payment instructions as untrusted until independently verified.",
                risk_weight=0.18,
            ))

        if header_detail.envelope_from_mismatch:
            signals.append(self._signal(
                name="envelope_sender_mismatch",
                severity=PaymentSignalSeverity.MEDIUM,
                evidence="Return-Path domain differs from the visible sender domain.",
                recommendation="Compare sender identity against existing supplier records.",
                risk_weight=0.10,
            ))

        if header_detail.display_name_spoofing:
            signals.append(self._signal(
                name="display_name_spoofing",
                severity=PaymentSignalSeverity.HIGH,
                evidence="Display name appears to impersonate a known brand or role.",
                recommendation="Verify the sender through a known supplier contact.",
                risk_weight=0.18,
            ))

        display = (email.from_display_name or "").strip()
        if from_domain in self.FREE_EMAIL_DOMAINS and display:
            signals.append(self._signal(
                name="free_email_supplier_request",
                severity=PaymentSignalSeverity.MEDIUM,
                evidence=f"Payment request came from a free email domain: {from_domain}.",
                recommendation="Check whether this supplier normally uses this email domain.",
                risk_weight=0.08,
            ))

    def _add_payment_field_signals(self, fields: dict, signals: list[PaymentFraudSignal]) -> None:
        if fields.get("payment_field_count", 0) >= 2:
            signals.append(self._signal(
                name="bank_details_in_email_body",
                severity=PaymentSignalSeverity.MEDIUM,
                evidence="Bank or payment details were found directly in the email body.",
                recommendation="Compare these details with the accounting system before payment.",
                risk_weight=0.12,
            ))
        elif fields.get("has_payment_fields"):
            signals.append(self._signal(
                name="payment_identifier_in_email_body",
                severity=PaymentSignalSeverity.LOW,
                evidence="A payment identifier was found in the email body.",
                recommendation="Verify the payment detail against supplier records.",
                risk_weight=0.06,
            ))

    def _add_attachment_signals(
        self,
        attachments: list[AttachmentObject],
        invoice_attachments: list[str],
        signals: list[PaymentFraudSignal],
    ) -> None:
        if not attachments:
            return

        dangerous = []
        macro_docs = []
        for attachment in attachments:
            filename = (attachment.filename or "").lower()
            if filename.endswith(self.DANGEROUS_ATTACHMENT_EXTENSIONS):
                dangerous.append(attachment.filename)
            if attachment.has_macros:
                macro_docs.append(attachment.filename)
            if attachment.magic_type and "executable" in attachment.magic_type.lower():
                dangerous.append(attachment.filename)

        if dangerous:
            signals.append(self._signal(
                name="dangerous_invoice_attachment",
                severity=PaymentSignalSeverity.CRITICAL,
                evidence=f"Payment-themed email includes risky attachment(s): {', '.join(dangerous[:3])}.",
                recommendation="Do not open the attachment or pay from its instructions.",
                risk_weight=0.40,
            ))
        elif macro_docs:
            signals.append(self._signal(
                name="macro_enabled_invoice_attachment",
                severity=PaymentSignalSeverity.HIGH,
                evidence=f"Macro-enabled attachment found: {', '.join(macro_docs[:3])}.",
                recommendation="Treat the invoice attachment as unsafe until sandboxed.",
                risk_weight=0.25,
            ))
        elif invoice_attachments:
            signals.append(self._signal(
                name="invoice_attachment_present",
                severity=PaymentSignalSeverity.INFO,
                evidence=f"Invoice-like attachment found: {', '.join(invoice_attachments[:3])}.",
                recommendation="Review the invoice against purchase order and supplier records.",
                risk_weight=0.03,
            ))

    def _add_executive_request_signal(
        self,
        email: EmailObject,
        text: str,
        signals: list[PaymentFraudSignal],
    ) -> None:
        matches = self._matched_patterns(text, self.EXECUTIVE_REQUEST_PATTERNS)
        subject = (email.subject or "").lower()
        if matches and ("transfer" in text or "wire" in text or "payment" in subject):
            signals.append(self._signal(
                name="executive_payment_request",
                severity=PaymentSignalSeverity.HIGH,
                evidence=f"Executive or authority-based payment language found: {matches[0]}",
                recommendation="Confirm the request with the executive through a separate channel.",
                risk_weight=0.20,
            ))

    def _invoice_attachment_names(self, attachments: list[AttachmentObject]) -> list[str]:
        names = []
        for attachment in attachments:
            filename = (attachment.filename or "").lower()
            if any(term in filename for term in self.INVOICE_ATTACHMENT_TERMS):
                names.append(attachment.filename)
        return names

    def _combine_signal_risk(self, signals: list[PaymentFraudSignal]) -> float:
        if not signals:
            return 0.08

        risk = 0.0
        for signal in signals:
            risk = 1 - ((1 - risk) * (1 - signal.risk_weight))
        return round(max(0.0, min(1.0, risk)), 3)

    def _apply_positive_verification_discount(self, text: str, risk_score: float) -> float:
        if not self._matched_patterns(text, self.POSITIVE_VERIFICATION_PATTERNS):
            return risk_score
        return round(max(0.0, risk_score - 0.12), 3)

    def _calculate_confidence(
        self,
        fields: dict,
        signals: list[PaymentFraudSignal],
        header_detail,
        payment_terms: list[str],
        invoice_attachments: list[str],
    ) -> float:
        confidence = 0.55
        if payment_terms:
            confidence += 0.10
        if fields.get("has_payment_fields"):
            confidence += 0.10
        if invoice_attachments:
            confidence += 0.05
        if any(value is not None for value in [
            header_detail.spf_pass,
            header_detail.dkim_pass,
            header_detail.dmarc_pass,
        ]):
            confidence += 0.08
        confidence += min(len(signals) * 0.035, 0.17)
        return round(max(0.0, min(1.0, confidence)), 3)

    def _decision_from_risk(
        self,
        risk_score: float,
        signals: list[PaymentFraudSignal],
    ) -> PaymentDecision:
        critical_signals = [
            signal for signal in signals
            if signal.severity == PaymentSignalSeverity.CRITICAL
        ]
        high_signals = [
            signal for signal in signals
            if signal.severity == PaymentSignalSeverity.HIGH
        ]

        if risk_score >= 0.78 or (critical_signals and risk_score >= 0.40):
            return PaymentDecision.DO_NOT_PAY
        if risk_score >= 0.22 or high_signals:
            return PaymentDecision.VERIFY
        return PaymentDecision.SAFE

    def _verification_steps(
        self,
        decision: PaymentDecision,
        signals: list[PaymentFraudSignal],
        fields: dict,
    ) -> list[str]:
        if decision == PaymentDecision.SAFE:
            return [
                "Continue normal payment approval checks.",
                "Compare invoice amount and supplier identity against existing records.",
            ]

        steps = [
            "Do not use phone numbers, links, or reply-to addresses from this email for verification.",
            "Call the supplier or executive using a saved contact from the accounting system.",
            "Compare bank details with the last approved supplier payment record.",
            "Record verifier name, date, and approval outcome before releasing funds.",
        ]

        signal_names = {signal.name for signal in signals}
        if "bank_detail_change_request" in signal_names:
            steps.insert(2, "Require second-person approval for the bank-detail change.")
        if "dangerous_invoice_attachment" in signal_names:
            steps.insert(0, "Do not open the attachment on a production machine.")
        if fields.get("payment_field_count", 0) > 0:
            steps.append("Store only verified payment details in the accounting system.")

        return steps

    def _summary(
        self,
        decision: PaymentDecision,
        signals: list[PaymentFraudSignal],
        fields: dict,
    ) -> str:
        if decision == PaymentDecision.DO_NOT_PAY:
            return "Payment should be blocked until independent verification is completed."
        if decision == PaymentDecision.VERIFY:
            return "Payment request has fraud indicators and requires independent verification."
        if fields.get("has_payment_fields"):
            return "Payment details were detected, but no strong fraud indicators were found."
        if signals:
            return "Invoice context detected with low-risk signals only."
        return "No material payment scam indicators found."

    def _analysis_to_details(self, analysis: PaymentFraudAnalysis) -> dict:
        return {
            "decision": analysis.decision.value,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "summary": analysis.summary,
            "signals": [
                {
                    **asdict(signal),
                    "severity": signal.severity.value,
                }
                for signal in analysis.signals
            ],
            "extracted_payment_fields": analysis.extracted_payment_fields,
            "verification_steps": analysis.verification_steps,
        }

    def _signal(
        self,
        name: str,
        severity: PaymentSignalSeverity,
        evidence: str,
        recommendation: str,
        risk_weight: float,
    ) -> PaymentFraudSignal:
        return PaymentFraudSignal(
            name=name,
            severity=severity,
            evidence=evidence,
            recommendation=recommendation,
            risk_weight=risk_weight,
        )

    def _matched_terms(self, text: str, terms: list[str]) -> list[str]:
        return [term for term in terms if term in text]

    def _matched_patterns(self, text: str, patterns: list[str]) -> list[str]:
        matches = []
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                matches.append(match.group(0))
        return matches

    def _domain_from_email(self, address: str) -> str:
        parsed = parseaddr(address or "")[1]
        if "@" not in parsed:
            return ""
        return parsed.rsplit("@", 1)[1].strip().lower()

    def _unique(self, values: list[str]) -> list[str]:
        seen = set()
        ordered = []
        for value in values:
            normalized = re.sub(r"\s+", " ", str(value)).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
        return ordered

    def _mask_digits(self, value: str) -> str:
        digits = re.sub(r"\D", "", value or "")
        if len(digits) <= 3:
            return "***"
        return f"{'*' * max(3, len(digits) - 3)}{digits[-3:]}"

    def _mask_identifier(self, value: str) -> str:
        value = value or ""
        if len(value) <= 6:
            return "***"
        return f"{value[:2]}***{value[-4:]}"

    def _mask_payid(self, value: str) -> str:
        value = value.strip()
        if "@" in value:
            user, domain = value.split("@", 1)
            return f"{user[:2]}***@{domain}"
        return self._mask_digits(value)

"""
Core data models for the phishing detection pipeline.
Every component consumes and produces these types.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_PHISHING = "LIKELY_PHISHING"
    CONFIRMED_PHISHING = "CONFIRMED_PHISHING"


class URLSource(str, Enum):
    BODY_PLAINTEXT = "body_plaintext"
    BODY_HTML = "body_html"
    ATTACHMENT = "attachment"
    QR_CODE = "qr_code"
    QR_CODE_PDF = "qr_code_pdf"
    QR_CODE_DOCX = "qr_code_docx"
    QR_CODE_HTML_RENDERED = "qr_code_html_rendered"


class AttachmentRisk(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class IntentCategory(str, Enum):
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALWARE_DELIVERY = "malware_delivery"
    BEC_WIRE_FRAUD = "bec_wire_fraud"
    GIFT_CARD_SCAM = "gift_card_scam"
    EXTORTION = "extortion"
    LEGITIMATE = "legitimate"
    UNKNOWN = "unknown"


@dataclass
class EmailObject:
    """Standardized email representation produced by the ingestion layer."""
    email_id: str
    raw_headers: dict[str, list[str]]
    from_address: str
    from_display_name: str
    reply_to: Optional[str]
    to_addresses: list[str]
    cc_addresses: list[str]
    subject: str
    body_plain: str
    body_html: str
    date: datetime
    attachments: list["AttachmentObject"]
    inline_images: list[bytes]
    message_id: str
    received_chain: list[str]


@dataclass
class AttachmentObject:
    filename: str
    content_type: str
    magic_type: str
    size_bytes: int
    content: bytes
    is_archive: bool
    has_macros: bool
    nested_files: list["AttachmentObject"] = field(default_factory=list)


@dataclass
class ExtractedURL:
    url: str
    source: URLSource
    source_detail: str
    resolved_url: Optional[str] = None
    redirect_chain: list[str] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    """Every analyzer returns this. Uniform interface for the decision engine."""
    analyzer_name: str
    risk_score: float        # 0.0 (clean) to 1.0 (confirmed malicious)
    confidence: float        # 0.0 (no data) to 1.0 (certain)
    details: dict
    errors: list[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    email_id: str
    verdict: Verdict
    overall_score: float
    overall_confidence: float
    analyzer_results: dict[str, AnalyzerResult]
    extracted_urls: list[ExtractedURL]
    iocs: dict
    reasoning: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FeedbackRecord:
    email_id: str
    original_verdict: Verdict
    correct_label: Verdict
    analyst_notes: str
    feature_vector: dict
    submitted_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class HeaderAnalysisDetail:
    """Detailed header analysis breakdown."""
    spf_pass: Optional[bool] = None
    dkim_pass: Optional[bool] = None
    dmarc_pass: Optional[bool] = None
    from_reply_to_mismatch: bool = False
    display_name_spoofing: bool = False
    suspicious_received_chain: bool = False
    received_chain_details: list[dict] = field(default_factory=list)
    envelope_from_mismatch: bool = False


@dataclass
class IntentClassification:
    category: IntentCategory
    confidence: float
    reasoning: str
    urgency_score: float
    red_flags: list[str] = field(default_factory=list)

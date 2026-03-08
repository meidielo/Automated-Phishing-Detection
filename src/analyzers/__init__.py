"""
Phishing detection analyzer modules.

This package contains all analyzer implementations for the phishing detection pipeline:
- URLReputationAnalyzer: Check URLs against threat intelligence services
- DomainIntelAnalyzer: Analyze domain registration and DNS records
- URLDetonationAnalyzer: Visit URLs in controlled environment
- BrandImpersonationAnalyzer: Detect visual brand impersonation
- NLPIntentAnalyzer: Classify email intent using NLP
- SenderProfileAnalyzer: Track and detect sender behavior anomalies
- AttachmentSandboxAnalyzer: Analyze attachments for malware
"""

from src.analyzers.url_reputation import URLReputationAnalyzer
from src.analyzers.domain_intel import DomainIntelAnalyzer
from src.analyzers.url_detonator import URLDetonationAnalyzer
from src.analyzers.brand_impersonation import BrandImpersonationAnalyzer
from src.analyzers.nlp_intent import NLPIntentAnalyzer
from src.analyzers.sender_profiling import SenderProfileAnalyzer
from src.analyzers.attachment_sandbox import AttachmentSandboxAnalyzer

__all__ = [
    "URLReputationAnalyzer",
    "DomainIntelAnalyzer",
    "URLDetonationAnalyzer",
    "BrandImpersonationAnalyzer",
    "NLPIntentAnalyzer",
    "SenderProfileAnalyzer",
    "AttachmentSandboxAnalyzer",
]

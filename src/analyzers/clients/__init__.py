"""
API client layer for external threat intelligence and analysis services.

Provides unified interfaces for:
- VirusTotal URL/domain/IP/hash scanning
- urlscan.io URL analysis
- AbuseIPDB IP reputation
- Google Safe Browsing threat detection
- WHOIS/DNS domain reconnaissance
- Sandbox file detonation (Hybrid Analysis, AnyRun, JoeSandbox)
"""

from .base_client import BaseAPIClient, CircuitBreaker, TTLCache
from .virustotal import VirusTotalClient
from .urlscan import URLScanClient
from .abuseipdb import AbuseIPDBClient
from .google_safebrowsing import GoogleSafeBrowsingClient
from .whois_client import WhoisClient
from .sandbox_client import (
    SandboxClient,
    SandboxProvider,
    HybridAnalysisStrategy,
    AnyRunStrategy,
    JoeSandboxStrategy,
)

__all__ = [
    "BaseAPIClient",
    "CircuitBreaker",
    "TTLCache",
    "VirusTotalClient",
    "URLScanClient",
    "AbuseIPDBClient",
    "GoogleSafeBrowsingClient",
    "WhoisClient",
    "SandboxClient",
    "SandboxProvider",
    "HybridAnalysisStrategy",
    "AnyRunStrategy",
    "JoeSandboxStrategy",
]

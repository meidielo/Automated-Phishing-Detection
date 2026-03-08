# API Client Layer

Unified client layer for threat intelligence and analysis services. Provides rate limiting, caching, retry logic, and circuit breaker functionality.

## Architecture

### BaseAPIClient
Abstract base class for all API clients providing:
- **Rate Limiting**: Async throttle mechanism with configurable req/sec
- **TTL Cache**: In-memory cache with automatic expiration
- **Retry Logic**: 3 attempts with exponential backoff (2^attempt seconds)
- **Circuit Breaker**: Opens after 5 consecutive failures, recovers after 5 minutes
- **Session Management**: Proper aiohttp lifecycle management

### Supported Clients

| Client | Rate Limit | Cache TTL | Endpoint |
|--------|-----------|-----------|----------|
| VirusTotal | 4 req/min | 1h (URL), 24h (domain/IP) | https://www.virustotal.com/api/v3 |
| urlscan.io | 1 req/15s | 2h | https://urlscan.io/api/v1 |
| AbuseIPDB | 1 req/6s | 6h | https://api.abuseipdb.com/api/v2 |
| Google Safe Browsing | 10 req/min | 30min | https://safebrowsing.googleapis.com/v4 |
| WHOIS/DNS | 10 req/min | 24h | local (no external API) |
| Sandbox (hybrid) | varies | varies | multiple providers |

## Usage

### VirusTotal Client

```python
from src.analyzers.clients import VirusTotalClient

client = VirusTotalClient(api_key="your_api_key")

# URL scanning
result = await client.scan_url("https://suspicious.com")
print(f"Risk Score: {result.risk_score}")
print(f"Malicious Vendors: {result.details['malicious_vendors']}")

# Domain reputation
result = await client.get_domain_report("example.com")

# IP reputation
result = await client.get_ip_report("1.2.3.4")

# File hash lookup
result = await client.check_file_hash("d41d8cd98f00b204e9800998ecf8427e")

await client.close()
```

### urlscan.io Client

```python
from src.analyzers.clients import URLScanClient

client = URLScanClient(api_key="your_api_key")

# Submit and get results (with polling)
result = await client.submit_scan(
    url="https://suspicious.com",
    timeout=60,  # seconds to wait for completion
    visibility="public"
)
print(f"Verdict: {result.details.get('urlscan_verdict')}")

await client.close()
```

### AbuseIPDB Client

```python
from src.analyzers.clients import AbuseIPDBClient

client = AbuseIPDBClient(api_key="your_api_key")

# Single IP check
result = await client.check_ip(
    ip="192.168.1.1",
    max_age_days=90,
    verbose=True
)
print(f"Abuse Score: {result.details['abuse_confidence_score']}")

# Bulk check (respects rate limits)
results = await client.bulk_check_ips(["1.1.1.1", "8.8.8.8"])

await client.close()
```

### Google Safe Browsing Client

```python
from src.analyzers.clients import GoogleSafeBrowsingClient

client = GoogleSafeBrowsingClient(api_key="your_api_key")

# Batch check URLs (up to 500)
result = await client.check_urls([
    "https://malware.com",
    "https://phishing.com",
    "https://clean.com",
])
print(f"Threat Types: {result.details['threat_types']}")

# Single URL
result = await client.check_url("https://example.com")

# Get threat lists
lists = await client.get_threat_lists()

await client.close()
```

### WHOIS/DNS Client

```python
from src.analyzers.clients import WhoisClient

client = WhoisClient(thread_pool_size=5)

# Domain lookup (WHOIS + DNS)
result = await client.lookup_domain("example.com")
print(f"Domain Age: {result.details['creation_date']}")
print(f"Has MX Records: {result.details['has_mx_records']}")
print(f"Has SPF: {result.details['has_spf']}")

# DNS-only lookup
a_records = await client.get_dns_records("example.com", "A")

await client.close()
```

### Sandbox Client (Strategy Pattern)

```python
from src.analyzers.clients import SandboxClient, SandboxProvider

# Configure providers
providers = {
    "hybrid_analysis": {
        "api_key": "your_key",
        "api_secret": "your_secret"
    },
    "anyrun": {
        "api_key": "your_key"
    },
    "joesandbox": {
        "api_key": "your_key"
    }
}

client = SandboxClient(providers)

# Submit file
with open("suspicious.exe", "rb") as f:
    result = await client.submit_file(
        file_bytes=f.read(),
        filename="suspicious.exe",
        preferred_provider=SandboxProvider.HYBRID_ANALYSIS
    )
    submission_id = result.details["submission_id"]

# Get results (with polling)
result = await client.get_results(
    submission_id=submission_id,
    provider=SandboxProvider.HYBRID_ANALYSIS
)
print(f"Verdict: {result.details['verdict']}")

await client.close()
```

## Response Format

All clients return `AnalyzerResult` dataclass:

```python
@dataclass
class AnalyzerResult:
    analyzer_name: str          # e.g., "virustotal_url"
    risk_score: float           # 0.0 (clean) to 1.0 (malicious)
    confidence: float           # 0.0 (no data) to 1.0 (certain)
    details: dict               # Service-specific details
    errors: list[str]           # Any errors encountered
```

### Example VirusTotal URL Result

```python
AnalyzerResult(
    analyzer_name="virustotal_url",
    risk_score=0.75,
    confidence=0.95,
    details={
        "url": "https://suspicious.com",
        "vt_url": "https://virustotal.com/gui/home/search?query=...",
        "last_analysis_date": 1234567890,
        "malicious_vendors": 18,
        "suspicious_vendors": 5,
        "total_vendors": 80,
    },
    errors=[]
)
```

## Configuration

### Rate Limiting

Each client has configurable rate limits:

```python
# Default: 4 requests per 60 seconds
client = VirusTotalClient(api_key="key")

# Custom rate limit via BaseAPIClient
class CustomClient(BaseAPIClient):
    def __init__(self, api_key):
        super().__init__(
            api_key=api_key,
            base_url="https://api.example.com",
            rate_limit=(100, 3600),  # 100 req per hour
            cache_ttl=7200  # 2 hour default cache
        )
```

### Caching

TTL-based in-memory caching is automatic:

```python
# Cache URL scan for 1 hour
result = await virustotal_client.scan_url(url)

# Second request returns cached result
result2 = await virustotal_client.scan_url(url)  # cache hit

# Force refresh
result3 = await virustotal_client.scan_url(url, force_rescan=True)
```

### Circuit Breaker

Automatically opens after 5 consecutive failures:

```
CLOSED -> (success) -> CLOSED
      -> (5 failures) -> OPEN
                     -> (5 min timeout) -> HALF_OPEN
                                       -> (success) -> CLOSED
                                       -> (failure) -> OPEN
```

## Error Handling

All clients gracefully handle errors:

```python
try:
    result = await client.scan_url("https://malicious.com")
    if result.errors:
        print(f"Errors: {result.errors}")
    else:
        print(f"Risk Score: {result.risk_score}")
except Exception as e:
    logger.error(f"Client error: {e}")
```

## Environment Variables

Configure API keys via environment:

```bash
# .env
VIRUSTOTAL_API_KEY=your_key
URLSCAN_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GOOGLE_SAFEBROWSING_API_KEY=your_key
HYBRID_ANALYSIS_API_KEY=your_key
HYBRID_ANALYSIS_API_SECRET=your_secret
ANYRUN_API_KEY=your_key
JOESANDBOX_API_KEY=your_key
```

## Testing

Run unit tests:

```bash
pytest src/analyzers/clients/test_clients.py -v
```

## Implementation Details

### Retry Logic

- Maximum 3 attempts per request
- Exponential backoff: 2^attempt seconds
- Respects HTTP 429 (rate limit) with Retry-After header
- Automatic recovery from transient errors

### Circuit Breaker

- Opens after 5 consecutive failures
- Half-open state after 5 minutes recovery timeout
- Prevents cascading failures
- Logged warnings on state changes

### TTL Cache

- Key format: `ClassName:arg1:arg2:...`
- Automatic expiration checking
- Cleanup of expired entries on get
- Configurable per-client or per-request

### Async Patterns

All clients use proper async/await:
- Non-blocking I/O with aiohttp
- Proper session lifecycle (context managers)
- Executor for blocking WHOIS/DNS operations
- Thread-safe concurrent requests

## Performance

- Rate limiting prevents API throttling
- Caching reduces API calls by 70-80% in typical usage
- Circuit breaker prevents wasted requests
- Thread pool for WHOIS/DNS blocking operations
- Connection pooling via aiohttp session reuse

## Security

- API keys stored in environment variables
- No credentials in logs (filtered)
- HTTPS only for all API endpoints
- Timeout protection against hanging connections
- Input validation on all parameters

## Future Enhancements

- [ ] Persistent caching (Redis/SQLite)
- [ ] Metrics collection (response times, error rates)
- [ ] Request signing for additional APIs
- [ ] Webhook support for async results
- [ ] GraphQL support for VirusTotal v3
- [ ] Database integration for results storage

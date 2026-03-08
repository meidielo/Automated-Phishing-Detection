"""
Input validators for the phishing detection pipeline.

Validates email addresses, URLs, domains, IP addresses, file paths,
and other inputs before they enter the analysis pipeline.
"""
import ipaddress
import re
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Email validation ──────────────────────────────────────────────────

# RFC 5322 simplified pattern
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def is_valid_email(email: str) -> bool:
    """Validate an email address format."""
    if not email or len(email) > 254:
        return False
    return bool(_EMAIL_RE.match(email))


def extract_email_domain(email: str) -> Optional[str]:
    """Extract domain part from an email address."""
    if "@" in email:
        return email.rsplit("@", 1)[-1].lower()
    return None


# ── URL validation ────────────────────────────────────────────────────

_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def is_valid_url(url: str) -> bool:
    """
    Validate a URL for analysis.

    Accepts http:// and https:// URLs with a valid-looking host.
    """
    if not url or len(url) > 2048:
        return False
    if not _URL_SCHEME_RE.match(url):
        return False
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        # Must have at least one dot in hostname (or be localhost/IP)
        host = parsed.hostname or ""
        if not host:
            return False
        if host == "localhost":
            return True
        if is_valid_ipv4(host) or is_valid_ipv6(host):
            return True
        if "." not in host:
            return False
        return True
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent comparison.

    - Lowercases scheme and host
    - Removes default ports (80, 443)
    - Removes trailing slashes from path
    - Sorts query parameters
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port

        # Remove default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        netloc = host
        if port:
            netloc = f"{host}:{port}"
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"

        path = parsed.path.rstrip("/") or "/"

        # Sort query parameters
        query = parsed.query
        if query:
            params = sorted(query.split("&"))
            query = "&".join(params)

        from urllib.parse import urlunparse
        return urlunparse((scheme, netloc, path, parsed.params, query, ""))
    except Exception:
        return url


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract the domain (hostname) from a URL."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None


# ── Domain validation ─────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name format."""
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain))


# ── IP validation ─────────────────────────────────────────────────────

def is_valid_ipv4(ip: str) -> bool:
    """Validate an IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Validate an IPv6 address."""
    try:
        addr = ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Validate an IP address (IPv4 or IPv6)."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


# ── File path validation ──────────────────────────────────────────────

_DANGEROUS_PATH_PATTERNS = [
    r"\.\.",          # Directory traversal
    r"~",             # Home directory expansion
    r"\|",            # Pipe
    r";",             # Command chaining
    r"\$\(",          # Command substitution
    r"`",             # Backtick execution
]


def is_safe_filepath(path: str) -> bool:
    """
    Check if a file path is safe (no traversal or injection).

    Used to validate user-uploaded file paths before processing.
    """
    if not path:
        return False

    for pattern in _DANGEROUS_PATH_PATTERNS:
        if re.search(pattern, path):
            return False

    # Reject null bytes
    if "\x00" in path:
        return False

    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing dangerous characters.

    Preserves the extension but removes path separators,
    null bytes, and other dangerous characters.
    """
    # Remove path components
    filename = filename.replace("/", "_").replace("\\", "_")
    # Remove null bytes
    filename = filename.replace("\x00", "")
    # Remove other dangerous chars
    filename = re.sub(r"[<>:\"|?*]", "_", filename)
    # Collapse multiple underscores
    filename = re.sub(r"_+", "_", filename)
    # Limit length
    if len(filename) > 255:
        name, _, ext = filename.rpartition(".")
        if ext:
            filename = name[:255 - len(ext) - 1] + "." + ext
        else:
            filename = filename[:255]
    return filename.strip("_. ")


# ── Hash validation ───────────────────────────────────────────────────

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def is_valid_md5(h: str) -> bool:
    return bool(_MD5_RE.match(h))


def is_valid_sha1(h: str) -> bool:
    return bool(_SHA1_RE.match(h))


def is_valid_sha256(h: str) -> bool:
    return bool(_SHA256_RE.match(h))


def is_valid_hash(h: str) -> bool:
    """Check if string is a valid MD5, SHA-1, or SHA-256 hash."""
    return is_valid_md5(h) or is_valid_sha1(h) or is_valid_sha256(h)


# ── Content validation ────────────────────────────────────────────────

def is_safe_content_size(
    content: bytes,
    max_size_mb: float = 25.0,
) -> bool:
    """Check if content is within acceptable size limits."""
    max_bytes = int(max_size_mb * 1024 * 1024)
    return len(content) <= max_bytes


def contains_null_bytes(content: bytes) -> bool:
    """Check for null bytes (could indicate binary/malicious content)."""
    return b"\x00" in content

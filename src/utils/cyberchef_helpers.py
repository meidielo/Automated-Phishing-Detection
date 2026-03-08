"""
CyberChef-style encoding/decoding helpers for phishing analysis.

Provides utilities for detecting and decoding common obfuscation
techniques found in phishing emails: Base64, URL encoding, hex encoding,
HTML entities, punycode, and nested/chained encodings.
"""
import base64
import html
import re
import urllib.parse
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Base64 ────────────────────────────────────────────────────────────

_B64_RE = re.compile(r"^[A-Za-z0-9+/\n\r]+={0,2}$")


def is_base64(text: str, min_length: int = 8) -> bool:
    """Check if a string looks like valid Base64."""
    text = text.strip()
    if len(text) < min_length:
        return False
    if len(text) % 4 != 0:
        return False
    return bool(_B64_RE.match(text))


def decode_base64(text: str) -> Optional[str]:
    """Decode a Base64 string, returning None on failure."""
    try:
        text = text.strip()
        decoded = base64.b64decode(text, validate=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base64_url(text: str) -> Optional[str]:
    """Decode a URL-safe Base64 string."""
    try:
        text = text.strip()
        # Add padding if needed
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        decoded = base64.urlsafe_b64decode(text)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


# ── URL encoding ──────────────────────────────────────────────────────

def url_decode(text: str, iterations: int = 3) -> str:
    """
    Iteratively URL-decode a string.

    Phishing emails often double- or triple-encode URLs.
    """
    result = text
    for _ in range(iterations):
        decoded = urllib.parse.unquote(result)
        if decoded == result:
            break
        result = decoded
    return result


def url_encode(text: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(text, safe="")


# ── Hex encoding ──────────────────────────────────────────────────────

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def is_hex_encoded(text: str, min_length: int = 4) -> bool:
    """Check if text looks like hex-encoded data."""
    text = text.strip()
    if len(text) < min_length or len(text) % 2 != 0:
        return False
    return bool(_HEX_RE.match(text))


def decode_hex(text: str) -> Optional[str]:
    """Decode hex string to UTF-8 text."""
    try:
        text = text.strip()
        return bytes.fromhex(text).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def encode_hex(text: str) -> str:
    """Encode text as hex string."""
    return text.encode("utf-8").hex()


# ── HTML entities ─────────────────────────────────────────────────────

def decode_html_entities(text: str) -> str:
    """Decode HTML entities (named and numeric)."""
    return html.unescape(text)


def detect_html_entity_obfuscation(text: str) -> bool:
    """
    Detect if text uses HTML entity obfuscation.

    Returns True if the text contains an unusual density of
    HTML entities (common in phishing HTML payloads).
    """
    entity_count = len(re.findall(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text))
    if len(text) == 0:
        return False
    ratio = entity_count / max(len(text.split()), 1)
    return ratio > 0.3 and entity_count > 3


# ── Punycode / IDN ───────────────────────────────────────────────────

def decode_punycode(domain: str) -> str:
    """
    Decode a punycode domain (xn--...) to Unicode.

    Used to detect IDN homograph attacks.
    """
    try:
        if domain.startswith("xn--") or ".xn--" in domain:
            parts = domain.split(".")
            decoded_parts = []
            for part in parts:
                if part.startswith("xn--"):
                    decoded_parts.append(part.encode("ascii").decode("idna"))
                else:
                    decoded_parts.append(part)
            return ".".join(decoded_parts)
        return domain
    except (UnicodeError, UnicodeDecodeError):
        return domain


def encode_punycode(domain: str) -> str:
    """Encode a Unicode domain to punycode."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def is_homograph_candidate(domain: str) -> bool:
    """
    Check if a domain uses characters from multiple scripts,
    which is a sign of an IDN homograph attack.
    """
    decoded = decode_punycode(domain)
    if decoded == domain and not any(ord(c) > 127 for c in domain):
        return False

    # Check for mixed scripts (Latin + Cyrillic is a classic attack)
    has_latin = bool(re.search(r"[a-zA-Z]", decoded))
    has_cyrillic = bool(re.search(r"[\u0400-\u04FF]", decoded))
    has_greek = bool(re.search(r"[\u0370-\u03FF]", decoded))

    mixed_scripts = sum([has_latin, has_cyrillic, has_greek])
    return mixed_scripts > 1


# ── Chained / nested decoding ────────────────────────────────────────

def auto_decode(text: str, max_depth: int = 5) -> str:
    """
    Attempt to automatically decode obfuscated text by trying
    multiple decoding strategies iteratively.

    Returns the most-decoded version of the text.
    """
    result = text
    for _ in range(max_depth):
        previous = result

        # Try URL decoding
        url_decoded = url_decode(result, iterations=1)
        if url_decoded != result:
            result = url_decoded
            continue

        # Try HTML entity decoding
        html_decoded = decode_html_entities(result)
        if html_decoded != result:
            result = html_decoded
            continue

        # Try Base64
        if is_base64(result):
            b64_decoded = decode_base64(result)
            if b64_decoded and b64_decoded != result:
                result = b64_decoded
                continue

        # Try hex
        if is_hex_encoded(result):
            hex_decoded = decode_hex(result)
            if hex_decoded and hex_decoded != result:
                result = hex_decoded
                continue

        # Nothing changed
        if result == previous:
            break

    return result


# ── Defanging / refanging ────────────────────────────────────────────

def defang_url(url: str) -> str:
    """
    Defang a URL for safe display/logging.

    Example: https://evil.com → hxxps[://]evil[.]com
    """
    result = url
    result = result.replace("http://", "hxxp[://]")
    result = result.replace("https://", "hxxps[://]")
    result = result.replace("ftp://", "fxp[://]")
    result = re.sub(r"\.(?=[a-zA-Z])", "[.]", result)
    return result


def refang_url(url: str) -> str:
    """
    Re-fang a defanged URL back to a live URL.

    Example: hxxps[://]evil[.]com → https://evil.com
    """
    result = url
    result = result.replace("hxxp[://]", "http://")
    result = result.replace("hxxps[://]", "https://")
    result = result.replace("fxp[://]", "ftp://")
    result = result.replace("[://]", "://")
    result = result.replace("[.]", ".")
    return result


def defang_ip(ip: str) -> str:
    """Defang an IP address: 1.2.3.4 → 1[.]2[.]3[.]4"""
    return ip.replace(".", "[.]")


def refang_ip(ip: str) -> str:
    """Re-fang a defanged IP: 1[.]2[.]3[.]4 → 1.2.3.4"""
    return ip.replace("[.]", ".")

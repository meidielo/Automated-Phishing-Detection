"""
Credential encryption for stored account passwords.

Uses AES-256-GCM with Argon2id key derivation (via SecureVault).
The passphrase is auto-generated on first use and stored in .env
as ACCOUNTS_ENCRYPTION_KEY. Without this passphrase, stored passwords
cannot be decrypted.

Security properties:
- AES-256-GCM authenticated encryption (256-bit keys)
- Argon2id KDF with 64 MB memory cost, 3 iterations, 4 lanes
- Unique salt + nonce per encryption (non-deterministic ciphertext)
- AAD binds version, KDF params, salt, and nonce to the auth tag
- Tamper detection via GCM authentication tag
- Backward compatibility: legacy Fernet-encrypted values (enc:v1:)
  are transparently decrypted and re-encrypted on next write

Versioning:
- enc:v1: — Legacy Fernet (AES-128-CBC + HMAC-SHA256). Read-only.
- enc:v2: — AES-256-GCM + Argon2id. Current default.
"""
import base64
import logging
import os
import secrets
import string
from pathlib import Path

logger = logging.getLogger(__name__)

# Prefixes to distinguish encryption versions
_ENC_V1_PREFIX = "enc:v1:"   # Legacy Fernet — read-only support
_ENC_V2_PREFIX = "enc:v2:"   # AES-256-GCM via SecureVault — current

# Minimum passphrase length for auto-generated keys
_PASSPHRASE_LENGTH = 48


def _get_or_create_passphrase() -> str:
    """
    Get the encryption passphrase from the environment.

    If ACCOUNTS_ENCRYPTION_KEY is not set, generates a cryptographically
    strong random passphrase and appends it to .env.

    Returns:
        Passphrase string used by SecureVault for key derivation.
    """
    passphrase = os.getenv("ACCOUNTS_ENCRYPTION_KEY", "").strip()

    if passphrase:
        return passphrase

    # Generate a strong random passphrase (URL-safe chars only: letters, digits, -, _).
    # Avoid shell/env-syntax characters like $ # ! @ % — docker-compose interprets
    # unescaped $ in .env values as variable references, silently truncating keys.
    alphabet = string.ascii_letters + string.digits + "-_"
    passphrase = "".join(secrets.choice(alphabet) for _ in range(_PASSPHRASE_LENGTH))

    # Append to .env file
    env_path = Path(".env")
    try:
        existing = ""
        if env_path.exists():
            existing = env_path.read_text(encoding="utf-8")
            if not existing.endswith("\n"):
                existing += "\n"

        with open(env_path, "a", encoding="utf-8") as f:
            if "ACCOUNTS_ENCRYPTION_KEY" not in existing:
                f.write(f"\n# Auto-generated passphrase for encrypting stored email passwords\n")
                f.write(f"# Used by AES-256-GCM + Argon2id via SecureVault\n")
                f.write(f"ACCOUNTS_ENCRYPTION_KEY={passphrase}\n")

        os.environ["ACCOUNTS_ENCRYPTION_KEY"] = passphrase
        logger.info("Generated new account encryption passphrase and saved to .env")

    except Exception as e:
        logger.error(f"Failed to save encryption passphrase to .env: {e}")
        raise RuntimeError(
            "ACCOUNTS_ENCRYPTION_KEY is not set and .env is not writable. "
            "Set a stable ACCOUNTS_ENCRYPTION_KEY before storing email "
            "account passwords."
        ) from e

    return passphrase


def _get_vault():
    """Get a SecureVault instance."""
    from src.security.secure_vault import SecureVault
    return SecureVault()


def _decrypt_legacy_fernet(stored: str) -> str:
    """
    Decrypt a legacy Fernet-encrypted value (enc:v1:...).

    Uses the same ACCOUNTS_ENCRYPTION_KEY env var. Legacy Fernet keys
    were 44-char base64 strings; if the current passphrase isn't a valid
    Fernet key, this will fail — which is expected for new installations.
    """
    try:
        from cryptography.fernet import Fernet
        key = os.getenv("ACCOUNTS_ENCRYPTION_KEY", "").strip().encode()
        f = Fernet(key)
        token = stored[len(_ENC_V1_PREFIX):].encode("ascii")
        return f.decrypt(token).decode("utf-8")
    except Exception as e:
        logger.error(f"Legacy Fernet decryption failed: {e}")
        raise RuntimeError(
            "Failed to decrypt legacy (v1) password. "
            "The ACCOUNTS_ENCRYPTION_KEY may have changed since this password was stored."
        ) from e


def encrypt_password(plaintext: str) -> str:
    """
    Encrypt a password for storage using AES-256-GCM.

    Args:
        plaintext: The password to encrypt.

    Returns:
        String in format "enc:v2:<json-blob>" that can be stored
        safely in accounts.json.
    """
    if not plaintext:
        return ""

    # Don't double-encrypt
    if plaintext.startswith(_ENC_V2_PREFIX) or plaintext.startswith(_ENC_V1_PREFIX):
        return plaintext

    try:
        vault = _get_vault()
        passphrase = _get_or_create_passphrase()
        blob = vault.encrypt(plaintext, passphrase)
        return _ENC_V2_PREFIX + blob
    except Exception as e:
        logger.error(f"Password encryption failed: {e}")
        raise RuntimeError("Failed to encrypt password") from e


def decrypt_password(stored: str) -> str:
    """
    Decrypt a stored password.

    Handles three cases:
    1. enc:v2: — AES-256-GCM (current)
    2. enc:v1: — Legacy Fernet (backward compat, read-only)
    3. No prefix — Legacy plaintext (backward compat)

    Args:
        stored: Encrypted or plaintext password string.

    Returns:
        Plaintext password.
    """
    if not stored:
        return ""

    # AES-256-GCM (current)
    if stored.startswith(_ENC_V2_PREFIX):
        try:
            vault = _get_vault()
            passphrase = _get_or_create_passphrase()
            blob = stored[len(_ENC_V2_PREFIX):]
            return vault.decrypt(blob, passphrase)
        except Exception as e:
            logger.error(f"Password decryption failed: {e}")
            raise RuntimeError(
                "Failed to decrypt password. Is ACCOUNTS_ENCRYPTION_KEY correct?"
            ) from e

    # Legacy Fernet
    if stored.startswith(_ENC_V1_PREFIX):
        return _decrypt_legacy_fernet(stored)

    # Legacy unencrypted password — return as-is
    return stored


def is_encrypted(value: str) -> bool:
    """Check if a value is already encrypted (any version)."""
    if not value:
        return False
    return value.startswith(_ENC_V2_PREFIX) or value.startswith(_ENC_V1_PREFIX)


def mask_password(stored: str) -> str:
    """
    Return a masked version of the password for display.

    Shows "••••••••" regardless of encryption status.
    Never reveals any part of the actual password.
    """
    if not stored:
        return ""
    return "••••••••"

"""
Unit tests for credential encryption (AES-256-GCM via SecureVault).

Tests cover:
- Encrypt/decrypt roundtrip for passwords
- Non-deterministic encryption (unique ciphertext per call)
- Double-encrypt guard
- Empty and edge-case inputs
- Legacy Fernet (enc:v1:) backward compatibility
- Plaintext passthrough for legacy unencrypted passwords
- is_encrypted detection for all prefix types
- mask_password always fully masks
- Tampered ciphertext detection (integrity check)
- Wrong passphrase rejection
- SecureVault integration (payload structure)
"""
import json
import os
import base64
import builtins

import pytest
from unittest.mock import patch


# All tests use a fixed passphrase to avoid .env side effects
TEST_PASSPHRASE = "test-passphrase-for-unit-tests-only-48chars!!"


@pytest.fixture(autouse=True)
def set_test_passphrase(monkeypatch):
    """Ensure all tests use a fixed passphrase, never touching .env."""
    monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", TEST_PASSPHRASE)


@pytest.fixture
def creds():
    """Import credentials module fresh (after env is set)."""
    from src.security import credentials
    return credentials


# ==========================================
# 1. Core Roundtrip
# ==========================================

class TestEncryptDecryptRoundtrip:
    def test_basic_roundtrip(self, creds):
        encrypted = creds.encrypt_password("my-secret-password")
        assert encrypted.startswith("enc:v2:")
        decrypted = creds.decrypt_password(encrypted)
        assert decrypted == "my-secret-password"

    def test_unicode_roundtrip(self, creds):
        password = "pässwörd-日本語-🔐"
        encrypted = creds.encrypt_password(password)
        assert creds.decrypt_password(encrypted) == password

    def test_special_characters_roundtrip(self, creds):
        password = r"""p@$$w0rd!#%^&*()[]{}|;:'",.<>?/~`"""
        encrypted = creds.encrypt_password(password)
        assert creds.decrypt_password(encrypted) == password

    def test_long_password_roundtrip(self, creds):
        password = "x" * 500
        encrypted = creds.encrypt_password(password)
        assert creds.decrypt_password(encrypted) == password


# ==========================================
# 2. Non-Deterministic Encryption
# ==========================================

class TestNonDeterministic:
    def test_same_password_produces_different_ciphertext(self, creds):
        enc1 = creds.encrypt_password("same-password")
        enc2 = creds.encrypt_password("same-password")
        # Encrypted blobs must differ (unique salt + nonce each time)
        assert enc1 != enc2
        # But both decrypt to the same value
        assert creds.decrypt_password(enc1) == "same-password"
        assert creds.decrypt_password(enc2) == "same-password"


# ==========================================
# 3. Double-Encrypt Guard
# ==========================================

class TestDoubleEncryptGuard:
    def test_v2_not_double_encrypted(self, creds):
        encrypted = creds.encrypt_password("secret")
        double = creds.encrypt_password(encrypted)
        assert double == encrypted

    def test_v1_prefix_not_double_encrypted(self, creds):
        fake_v1 = "enc:v1:some-fernet-token"
        result = creds.encrypt_password(fake_v1)
        assert result == fake_v1


# ==========================================
# 4. Empty & Edge Cases
# ==========================================

class TestEdgeCases:
    def test_empty_string_encrypt(self, creds):
        assert creds.encrypt_password("") == ""

    def test_empty_string_decrypt(self, creds):
        assert creds.decrypt_password("") == ""

    def test_none_like_empty_decrypt(self, creds):
        # None is falsy, should return ""
        assert creds.decrypt_password(None) == ""

    def test_single_char_password(self, creds):
        encrypted = creds.encrypt_password("x")
        assert creds.decrypt_password(encrypted) == "x"


# ==========================================
# 5. Plaintext Passthrough (Legacy Compat)
# ==========================================

class TestPlaintextPassthrough:
    def test_unencrypted_password_returned_as_is(self, creds):
        """Legacy plaintext passwords (no prefix) pass through decrypt."""
        assert creds.decrypt_password("my-old-plaintext-pass") == "my-old-plaintext-pass"

    def test_random_string_not_encrypted(self, creds):
        assert creds.decrypt_password("abc123") == "abc123"


# ==========================================
# 6. is_encrypted Detection
# ==========================================

class TestIsEncrypted:
    def test_v2_detected(self, creds):
        encrypted = creds.encrypt_password("test")
        assert creds.is_encrypted(encrypted) is True

    def test_v1_prefix_detected(self, creds):
        assert creds.is_encrypted("enc:v1:fake-token") is True

    def test_plaintext_not_detected(self, creds):
        assert creds.is_encrypted("plain-password") is False

    def test_empty_not_detected(self, creds):
        assert creds.is_encrypted("") is False

    def test_none_not_detected(self, creds):
        assert creds.is_encrypted(None) is False


# ==========================================
# 7. mask_password
# ==========================================

class TestMaskPassword:
    def test_encrypted_masked(self, creds):
        encrypted = creds.encrypt_password("secret")
        assert creds.mask_password(encrypted) == "••••••••"

    def test_plaintext_masked(self, creds):
        assert creds.mask_password("my-password") == "••••••••"

    def test_empty_returns_empty(self, creds):
        assert creds.mask_password("") == ""

    def test_none_returns_empty(self, creds):
        assert creds.mask_password(None) == ""


# ==========================================
# 8. Tamper Detection (Integrity)
# ==========================================

class TestTamperDetection:
    def test_tampered_ciphertext_rejected(self, creds):
        encrypted = creds.encrypt_password("secret")
        # Extract the JSON blob after prefix, tamper with ciphertext
        blob = encrypted[len("enc:v2:"):]
        payload = json.loads(blob)
        raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
        raw_ct[0] ^= 0xFF
        payload["ciphertext"] = base64.b64encode(raw_ct).decode("ascii")
        tampered = "enc:v2:" + json.dumps(payload)

        with pytest.raises(RuntimeError, match="Failed to decrypt"):
            creds.decrypt_password(tampered)

    def test_tampered_kdf_params_rejected(self, creds):
        encrypted = creds.encrypt_password("secret")
        blob = encrypted[len("enc:v2:"):]
        payload = json.loads(blob)
        payload["header"]["kdf"]["ops"] += 1
        tampered = "enc:v2:" + json.dumps(payload)

        with pytest.raises((RuntimeError, ValueError)):
            creds.decrypt_password(tampered)


# ==========================================
# 9. Wrong Passphrase
# ==========================================

class TestWrongPassphrase:
    def test_wrong_passphrase_fails(self, creds, monkeypatch):
        encrypted = creds.encrypt_password("secret")

        # Switch passphrase
        monkeypatch.setenv("ACCOUNTS_ENCRYPTION_KEY", "completely-different-passphrase-1234567890!!")
        with pytest.raises(RuntimeError, match="Failed to decrypt"):
            creds.decrypt_password(encrypted)


# ==========================================
# 10. SecureVault Payload Structure
# ==========================================

class TestPayloadStructure:
    def test_v2_payload_is_valid_json(self, creds):
        encrypted = creds.encrypt_password("test")
        blob = encrypted[len("enc:v2:"):]
        payload = json.loads(blob)

        assert "header" in payload
        assert "ciphertext" in payload
        assert payload["header"]["v"] == "2.0"
        assert "salt" in payload["header"]
        assert "nonce" in payload["header"]
        kdf = payload["header"]["kdf"]
        assert all(k in kdf for k in ("ops", "mem", "p", "key_len"))
        assert kdf["key_len"] == 32  # AES-256

    def test_ciphertext_is_valid_base64(self, creds):
        encrypted = creds.encrypt_password("test")
        blob = encrypted[len("enc:v2:"):]
        payload = json.loads(blob)
        # Should not raise
        ct_bytes = base64.b64decode(payload["ciphertext"])
        assert len(ct_bytes) > 16  # At least GCM tag + some ciphertext


# ==========================================
# 11. Passphrase Auto-Generation
# ==========================================

class TestPassphraseGeneration:
    def test_generates_passphrase_when_missing(self, creds, monkeypatch, tmp_path):
        monkeypatch.delenv("ACCOUNTS_ENCRYPTION_KEY", raising=False)
        # Point .env to a temp file so we don't pollute the real one
        env_file = tmp_path / ".env"
        monkeypatch.chdir(tmp_path)

        passphrase = creds._get_or_create_passphrase()
        assert len(passphrase) == 48
        assert os.environ["ACCOUNTS_ENCRYPTION_KEY"] == passphrase
        # Should be persisted
        assert "ACCOUNTS_ENCRYPTION_KEY" in env_file.read_text()

    def test_missing_passphrase_fails_when_env_cannot_be_persisted(self, creds, monkeypatch, tmp_path):
        monkeypatch.delenv("ACCOUNTS_ENCRYPTION_KEY", raising=False)
        monkeypatch.chdir(tmp_path)

        real_open = builtins.open

        def deny_env_write(*args, **kwargs):
            if args and str(args[0]) == ".env":
                raise PermissionError("read-only app directory")
            return real_open(*args, **kwargs)

        with patch("builtins.open", side_effect=deny_env_write):
            with pytest.raises(RuntimeError, match="ACCOUNTS_ENCRYPTION_KEY"):
                creds._get_or_create_passphrase()

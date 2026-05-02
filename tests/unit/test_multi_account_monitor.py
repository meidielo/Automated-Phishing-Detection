"""
Tests for the credential migration path in src/automation/multi_account_monitor.py.

The audit (cycle 2 review) flagged "plaintext IMAP passwords stored in
accounts.json" as P0 #4. This was already-mitigated by:
    1. encrypt_password() / decrypt_password() in src/security/credentials.py
       (AES-256-GCM + Argon2id), tested in test_credentials.py
    2. _migrate_plaintext_passwords() in multi_account_monitor.py which runs
       on every load and re-encrypts any plaintext value found in the file

These tests lock the migration behaviour so it can't silently regress.
The migration must:
    - Detect plaintext (non-prefixed) values
    - Re-encrypt them using the current encryption version
    - Write the encrypted values back to disk
    - Leave already-encrypted values untouched (no double-encryption)
    - Be idempotent on subsequent loads
"""
from __future__ import annotations

import json

import pytest

from src.automation.multi_account_monitor import (
    _SENSITIVE_FIELDS,
    _decrypt_sensitive,
    _encrypt_sensitive,
    _migrate_plaintext_passwords,
    add_account_to_file,
    list_accounts,
)
from src.security.credentials import is_encrypted


@pytest.fixture
def isolated_passphrase(monkeypatch, tmp_path):
    """Pin a known passphrase so encryption is deterministic across runs."""
    monkeypatch.setenv(
        "ACCOUNTS_ENCRYPTION_KEY",
        "test-passphrase-for-credentials-tests-do-not-use-in-prod-12345",
    )
    monkeypatch.chdir(tmp_path)


class TestEncryptDecryptSensitive:
    def test_encrypts_password_field(self, isolated_passphrase):
        acct = {"type": "imap", "user": "u", "password": "hunter2"}
        out = _encrypt_sensitive(acct)
        assert is_encrypted(out["password"])
        assert out["password"] != "hunter2"
        # Non-sensitive fields untouched
        assert out["user"] == "u"
        assert out["type"] == "imap"

    def test_encrypts_client_secret_field(self, isolated_passphrase):
        acct = {"type": "outlook", "client_secret": "verySecret"}
        out = _encrypt_sensitive(acct)
        assert is_encrypted(out["client_secret"])

    def test_decrypt_roundtrip(self, isolated_passphrase):
        original = {"type": "imap", "user": "u", "password": "hunter2"}
        encrypted = _encrypt_sensitive(original)
        decrypted = _decrypt_sensitive(encrypted)
        assert decrypted["password"] == "hunter2"
        assert decrypted["user"] == "u"

    def test_no_password_field_no_op(self, isolated_passphrase):
        acct = {"type": "gmail", "credentials_path": "x.json"}
        out = _encrypt_sensitive(acct)
        assert out == acct

    def test_empty_password_not_encrypted(self, isolated_passphrase):
        acct = {"type": "imap", "user": "u", "password": ""}
        out = _encrypt_sensitive(acct)
        assert out["password"] == ""

    def test_does_not_mutate_input(self, isolated_passphrase):
        acct = {"type": "imap", "user": "u", "password": "hunter2"}
        _encrypt_sensitive(acct)
        # Original dict must be unchanged
        assert acct["password"] == "hunter2"


class TestSensitiveFields:
    def test_sensitive_fields_constant(self):
        # Lock the field list — adding new sensitive fields requires
        # explicit code review of every place this constant is read.
        assert _SENSITIVE_FIELDS == ("password", "client_secret")


class TestMigratePlaintextPasswords:
    def test_plaintext_is_migrated_and_written(self, isolated_passphrase, tmp_path):
        path = tmp_path / "accounts.json"
        accounts = [
            {"type": "imap", "user": "a@example.com", "password": "plaintext1"},
            {"type": "outlook", "client_secret": "plaintext2"},
        ]
        path.write_text(json.dumps(accounts))

        _migrate_plaintext_passwords(accounts, str(path))

        # The in-memory accounts dict was mutated to encrypted values
        assert is_encrypted(accounts[0]["password"])
        assert is_encrypted(accounts[1]["client_secret"])

        # And the file on disk was rewritten with the encrypted values
        on_disk = json.loads(path.read_text())
        assert is_encrypted(on_disk[0]["password"])
        assert is_encrypted(on_disk[1]["client_secret"])
        # No plaintext leaks remain
        assert "plaintext1" not in path.read_text()
        assert "plaintext2" not in path.read_text()

    def test_already_encrypted_not_touched(self, isolated_passphrase, tmp_path):
        path = tmp_path / "accounts.json"
        # First write — gets encrypted
        accounts = [{"type": "imap", "user": "u", "password": "secret"}]
        _migrate_plaintext_passwords(accounts, str(path))
        first_ciphertext = accounts[0]["password"]

        # Second pass over the same accounts must be a no-op (idempotent)
        _migrate_plaintext_passwords(accounts, str(path))
        assert accounts[0]["password"] == first_ciphertext

    def test_no_rewrite_when_all_encrypted(self, isolated_passphrase, tmp_path, monkeypatch):
        path = tmp_path / "accounts.json"
        # Simulate a file that's already fully encrypted
        accounts = [{"type": "imap", "user": "u", "password": "secret"}]
        _migrate_plaintext_passwords(accounts, str(path))
        path.write_text(json.dumps(accounts))
        mtime_before = path.stat().st_mtime_ns

        # Capture writes — a clean pass should NOT rewrite the file
        write_count = {"n": 0}
        original_write = type(path).write_text

        def counting_write(self, *a, **kw):
            write_count["n"] += 1
            return original_write(self, *a, **kw)

        monkeypatch.setattr(type(path), "write_text", counting_write)
        _migrate_plaintext_passwords(accounts, str(path))
        assert write_count["n"] == 0

    def test_mixed_encrypted_and_plaintext(self, isolated_passphrase, tmp_path):
        path = tmp_path / "accounts.json"
        # Encrypt one upfront
        encrypted_acct = _encrypt_sensitive({
            "type": "imap", "user": "a", "password": "encMe",
        })
        plaintext_acct = {"type": "imap", "user": "b", "password": "plainMe"}
        accounts = [encrypted_acct, plaintext_acct]
        path.write_text(json.dumps(accounts))

        _migrate_plaintext_passwords(accounts, str(path))

        # Both are now encrypted
        assert is_encrypted(accounts[0]["password"])
        assert is_encrypted(accounts[1]["password"])
        # The plaintext is no longer on disk
        assert "plainMe" not in path.read_text()

    def test_no_plaintext_in_file_after_migration(self, isolated_passphrase, tmp_path):
        """The strongest assertion: after migration, no field's plaintext
        value can be grep'd out of the file. This is the property a
        host-compromise attacker would actually exploit."""
        path = tmp_path / "accounts.json"
        accounts = [
            {"type": "imap", "user": "u", "password": "VerySecretPassword!"},
            {"type": "outlook", "client_secret": "OAuthClientSecretXYZ"},
        ]
        path.write_text(json.dumps(accounts))
        _migrate_plaintext_passwords(accounts, str(path))

        contents = path.read_text()
        assert "VerySecretPassword!" not in contents
        assert "OAuthClientSecretXYZ" not in contents


class TestAddAccount:
    def test_reconnecting_same_mailbox_replaces_stale_record(self, isolated_passphrase, tmp_path):
        path = tmp_path / "accounts.json"

        add_account_to_file(
            {"type": "imap", "user": "meidie@example.com", "password": "old-pass"},
            str(path),
        )
        add_account_to_file(
            {"type": "imap", "user": "meidie@example.com", "password": "new-pass"},
            str(path),
        )

        accounts = json.loads(path.read_text())
        assert len(accounts) == 1
        assert accounts[0]["user"] == "meidie@example.com"
        assert is_encrypted(accounts[0]["password"])
        assert "old-pass" not in path.read_text()
        assert "new-pass" not in path.read_text()

        safe_accounts = list_accounts(str(path))
        assert safe_accounts == [
            {
                "type": "imap",
                "user": "meidie@example.com",
                "password": "••••••••",
            }
        ]

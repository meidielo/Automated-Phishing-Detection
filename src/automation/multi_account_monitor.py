"""
Multi-account email monitoring service.

Manages multiple email accounts simultaneously — Gmail, Outlook, Yahoo,
or any IMAP server. Each account runs as an independent provider, all
feeding into the same phishing detection pipeline.

Usage:
    # Add accounts (one-time each):
    python main.py add-account gmail
    python main.py add-account outlook --client-id YOUR_CLIENT_ID
    python main.py add-account imap --host imap.yahoo.com --user you@yahoo.com

    # Start monitoring all configured accounts:
    python main.py monitor

    # Monitor specific accounts only:
    python main.py monitor --accounts user@gmail.com,work@outlook.com
"""
import asyncio
import json
import logging
import os
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.config import PipelineConfig, IMAPConfig
from src.extractors.eml_parser import EMLParser
from src.ingestion.email_provider import EmailProvider, FetchedEmail
from src.models import EmailObject, PipelineResult, Verdict
from src.orchestrator.pipeline import PhishingPipeline
from src.automation.email_monitor import (
    AlertDispatcher,
    ResultStore,
    ALERT_VERDICTS,
)

logger = logging.getLogger(__name__)

ACCOUNTS_FILE = "data/accounts.json"


class MultiAccountMonitor:
    """
    Monitors multiple email accounts for phishing.

    Architecture:
    - Each account is an EmailProvider (Gmail, Outlook, IMAP)
    - All providers feed into one shared PhishingPipeline
    - Results stored centrally, alerts fired from one dispatcher
    - Accounts configured in data/accounts.json

    The monitor polls all accounts in round-robin fashion within
    each cycle, so a slow account doesn't block the others.
    """

    def __init__(
        self,
        pipeline: PhishingPipeline,
        providers: list[EmailProvider],
        parser: Optional[EMLParser] = None,
        alert_dispatcher: Optional[AlertDispatcher] = None,
        result_store: Optional[ResultStore] = None,
        poll_interval: int = 30,
        quarantine_destination: str = "Quarantine",
    ):
        self.pipeline = pipeline
        self.providers = providers
        self.parser = parser or EMLParser()
        self.alerts = alert_dispatcher or AlertDispatcher()
        self.store = result_store or ResultStore()
        self.poll_interval = poll_interval
        self.quarantine_destination = quarantine_destination
        self._running = False
        self._processed_ids: set[str] = set()  # "account:provider_id"
        self._stats = {
            "started_at": None,
            "accounts": len(providers),
            "emails_processed": 0,
            "phishing_detected": 0,
            "quarantined": 0,
            "errors": 0,
            "last_poll": None,
            "per_account": {},
        }
        self._recent_results: list[dict] = []
        self._MAX_RECENT = 200

    @classmethod
    def from_config(cls, config: PipelineConfig) -> "MultiAccountMonitor":
        """Build from config, loading accounts from data/accounts.json."""
        pipeline = PhishingPipeline(config)

        providers = load_providers_from_file(ACCOUNTS_FILE)
        if not providers:
            # Fallback: try legacy IMAP config
            if config.imap.user and config.imap.password:
                from src.ingestion.imap_provider import IMAPProvider
                providers = [IMAPProvider(config.imap)]
                logger.info("No accounts.json found; using legacy IMAP config")

        alert_dispatcher = AlertDispatcher()
        alert_dispatcher.set_alert_log("data/alerts.jsonl")
        webhook_url = os.getenv("ALERT_WEBHOOK_URL")
        if webhook_url:
            alert_dispatcher.set_webhook(webhook_url)

        result_store = ResultStore(
            db_path=config.feedback_db_path,
            jsonl_path="data/results.jsonl",
        )

        return cls(
            pipeline=pipeline,
            providers=providers,
            alert_dispatcher=alert_dispatcher,
            result_store=result_store,
            poll_interval=int(os.getenv("POLL_INTERVAL", "30")),
            quarantine_destination=os.getenv("QUARANTINE_DESTINATION", "Quarantine"),
        )

    async def run(self, max_iterations: Optional[int] = None):
        """Start the multi-account monitoring loop."""
        if not self.providers:
            logger.error(
                "No email accounts configured. Add one with:\n"
                "  python main.py add-account gmail\n"
                "  python main.py add-account outlook --client-id YOUR_ID\n"
                "  python main.py add-account imap --host HOST --user USER"
            )
            return

        # Authenticate all providers
        active_providers = []
        for provider in self.providers:
            try:
                if provider.authenticate():
                    active_providers.append(provider)
                    self._stats["per_account"][provider.account_id] = {
                        "type": provider.provider_type,
                        "processed": 0,
                        "phishing": 0,
                        "errors": 0,
                    }
                else:
                    logger.error(f"Auth failed for {provider.account_id}, skipping")
            except Exception as e:
                logger.error(f"Auth error for {provider}: {e}")

        if not active_providers:
            logger.error("No accounts authenticated successfully")
            return

        self.providers = active_providers
        self._stats["accounts"] = len(active_providers)
        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()
        iteration = 0

        # Signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                pass

        account_list = ", ".join(p.account_id for p in active_providers)
        logger.info(
            f"Multi-account monitor started: {len(active_providers)} account(s) "
            f"[{account_list}], interval={self.poll_interval}s"
        )

        while self._running:
            if max_iterations is not None and iteration >= max_iterations:
                break

            try:
                await self._poll_all_accounts()
                self._stats["last_poll"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                logger.error(f"Poll cycle error: {e}", exc_info=True)
                self._stats["errors"] += 1

            iteration += 1

            if self._running:
                await asyncio.sleep(self.poll_interval)

        # Cleanup
        for provider in self.providers:
            provider.disconnect()

        logger.info(
            f"Monitor stopped. Totals: "
            f"processed={self._stats['emails_processed']}, "
            f"phishing={self._stats['phishing_detected']}, "
            f"quarantined={self._stats['quarantined']}, "
            f"errors={self._stats['errors']}"
        )

    async def _poll_all_accounts(self):
        """Poll all providers and analyze new emails."""
        for provider in self.providers:
            try:
                fetched = provider.fetch_new_emails(max_results=20)

                new = [
                    f for f in fetched
                    if f"{f.account_id}:{f.provider_id}" not in self._processed_ids
                ]

                if new:
                    logger.info(
                        f"[{provider.account_id}] {len(new)} new email(s)"
                    )

                for email_data in new:
                    await self._process_single(provider, email_data)

            except Exception as e:
                logger.error(f"[{provider.account_id}] fetch error: {e}")
                acct = self._stats["per_account"].get(provider.account_id, {})
                acct["errors"] = acct.get("errors", 0) + 1

    async def _process_single(self, provider: EmailProvider, fetched: FetchedEmail):
        """Analyze a single fetched email."""
        dedup_key = f"{fetched.account_id}:{fetched.provider_id}"
        quarantined = False
        email_obj = None
        result = None

        try:
            # Parse
            email_obj = self.parser.parse_bytes(fetched.raw_bytes)
            if not email_obj:
                logger.error(f"Parse failed for {dedup_key}")
                self._stats["errors"] += 1
                return

            logger.info(
                f"[{fetched.account_id}] Analyzing: "
                f"from={email_obj.from_address}, subject='{email_obj.subject}'"
            )

            # Pipeline
            result = await self.pipeline.analyze(email_obj)
            self._stats["emails_processed"] += 1
            self._processed_ids.add(dedup_key)

            acct_stats = self._stats["per_account"].get(fetched.account_id, {})
            acct_stats["processed"] = acct_stats.get("processed", 0) + 1

            logger.info(
                f"[{fetched.account_id}] Result: "
                f"verdict={result.verdict.value}, score={result.overall_score:.3f}"
            )

            # Store
            await self.store.store(email_obj, result)

            # Mark as read
            provider.mark_as_read(fetched.provider_id)

            # Alert + quarantine
            if result.verdict in ALERT_VERDICTS:
                self._stats["phishing_detected"] += 1
                acct_stats["phishing"] = acct_stats.get("phishing", 0) + 1
                await self.alerts.dispatch(email_obj, result)

                ok = provider.quarantine(
                    fetched.provider_id, self.quarantine_destination
                )
                if ok:
                    quarantined = True
                    self._stats["quarantined"] += 1
                    logger.info(
                        f"[{fetched.account_id}] Quarantined → "
                        f"'{self.quarantine_destination}'"
                    )

        except Exception as e:
            logger.error(f"[{fetched.account_id}] analyze error: {e}", exc_info=True)
            self._stats["errors"] += 1
            acct = self._stats["per_account"].get(fetched.account_id, {})
            acct["errors"] = acct.get("errors", 0) + 1

        # Track recent — include full analysis details for the monitor UI
        analyzer_summary = {}
        extracted_urls_list = []
        reasoning_text = ""
        body_preview = ""
        body_html_preview = ""

        if result:
            for ar_name, ar in (result.analyzer_results or {}).items():
                # Serialize details, skipping raw bytes (screenshots)
                details = ar.details or {}
                safe_details = {}
                for k, v in details.items():
                    if k == "screenshots":
                        safe_details[k] = {url: "(base64 image)" for url in (v or {})}
                    elif isinstance(v, bytes):
                        safe_details[k] = "(binary data)"
                    else:
                        safe_details[k] = v
                analyzer_summary[ar_name] = {
                    "risk_score": ar.risk_score,
                    "confidence": ar.confidence,
                    "details": safe_details,
                    "errors": ar.errors if ar.errors else None,
                }
            extracted_urls_list = [
                {"url": u.url, "source": u.source.value, "source_detail": u.source_detail}
                for u in (result.extracted_urls or [])
            ]
            reasoning_text = result.reasoning if isinstance(result.reasoning, str) else str(result.reasoning)

        if email_obj:
            body_preview = (email_obj.body_plain or "")[:2000]
            body_html_preview = (email_obj.body_html or "")[:5000]

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_id": getattr(email_obj, "email_id", fetched.provider_id) if email_obj else fetched.provider_id,
            "account": fetched.account_id,
            "provider": fetched.provider_type,
            "from": getattr(email_obj, "from_address", "unknown") if email_obj else "unknown",
            "display_name": getattr(email_obj, "from_display_name", "") if email_obj else "",
            "reply_to": getattr(email_obj, "reply_to", "") if email_obj else "",
            "to": getattr(email_obj, "to_addresses", []) if email_obj else [],
            "subject": getattr(email_obj, "subject", "") if email_obj else "",
            "verdict": result.verdict.value if result else "ERROR",
            "score": result.overall_score if result else 0.0,
            "confidence": result.overall_confidence if result else 0.0,
            "quarantined": quarantined,
            "analyzer_results": analyzer_summary,
            "extracted_urls": extracted_urls_list,
            "reasoning": reasoning_text,
            "body_preview": body_preview,
            "body_html": body_html_preview,
        }
        self._recent_results.append(record)
        if len(self._recent_results) > self._MAX_RECENT:
            self._recent_results.pop(0)

    def stop(self):
        logger.info("Multi-account monitor shutdown requested")
        self._running = False

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ── Account Management ──────────────────────────────────────────────

# Sensitive fields that must be encrypted at rest
_SENSITIVE_FIELDS = ("password", "client_secret")


def _encrypt_sensitive(acct: dict) -> dict:
    """Encrypt sensitive fields in an account dict before storing."""
    from src.security.credentials import encrypt_password
    result = dict(acct)
    for field in _SENSITIVE_FIELDS:
        if field in result and result[field]:
            result[field] = encrypt_password(result[field])
    return result


def _decrypt_sensitive(acct: dict) -> dict:
    """Decrypt sensitive fields when loading from storage."""
    from src.security.credentials import decrypt_password
    result = dict(acct)
    for field in _SENSITIVE_FIELDS:
        if field in result and result[field]:
            result[field] = decrypt_password(result[field])
    return result


def load_providers_from_file(path: str = ACCOUNTS_FILE) -> list[EmailProvider]:
    """
    Load email providers from accounts.json.

    Passwords are decrypted in memory only — never written back to disk
    in plaintext. Legacy plaintext passwords are supported for backward
    compatibility but will be re-encrypted on next write.

    Format:
    [
        {"type": "gmail", "credentials_path": "credentials.json", "token_path": "data/gmail_token.json"},
        {"type": "outlook", "client_id": "...", "token_path": "data/outlook_token.json"},
        {"type": "imap", "host": "imap.yahoo.com", "port": 993, "user": "...", "password": "enc:v1:..."}
    ]
    """
    accounts_path = Path(path)
    if not accounts_path.exists():
        return []

    try:
        accounts = json.loads(accounts_path.read_text())
    except Exception as e:
        logger.error(f"Failed to load {path}: {e}")
        return []

    # Migrate: re-encrypt any plaintext passwords found in the file
    _migrate_plaintext_passwords(accounts, path)

    providers = []
    for acct in accounts:
        try:
            decrypted = _decrypt_sensitive(acct)
            provider = _create_provider(decrypted)
            if provider:
                providers.append(provider)
        except Exception as e:
            # Log without exposing sensitive data
            safe_id = acct.get("email") or acct.get("user") or acct.get("type", "unknown")
            logger.error(f"Failed to create provider for {safe_id}: {e}")

    logger.info(f"Loaded {len(providers)} account(s) from {path}")
    return providers


def _migrate_plaintext_passwords(accounts: list[dict], path: str):
    """
    One-time migration: find any plaintext passwords and encrypt them.

    This runs on every load to handle accounts added before encryption
    was implemented, or if someone manually edits accounts.json.
    """
    from src.security.credentials import is_encrypted, encrypt_password
    needs_rewrite = False
    for acct in accounts:
        for field in _SENSITIVE_FIELDS:
            val = acct.get(field, "")
            if val and not is_encrypted(val):
                acct[field] = encrypt_password(val)
                needs_rewrite = True

    if needs_rewrite:
        try:
            Path(path).write_text(json.dumps(accounts, indent=2))
            logger.info("Migrated plaintext passwords to encrypted storage")
        except Exception as e:
            logger.error(f"Failed to migrate passwords: {e}")


def _create_provider(acct: dict) -> Optional[EmailProvider]:
    """Create a provider instance from an account config dict.

    Expects passwords already decrypted (in-memory only).
    """
    acct_type = acct.get("type", "").lower()

    if acct_type == "gmail":
        from src.ingestion.gmail_provider import GmailProvider
        return GmailProvider(
            credentials_path=acct.get("credentials_path", "credentials.json"),
            token_path=acct.get("token_path", "data/gmail_token.json"),
            user_email=acct.get("email", ""),
        )

    elif acct_type == "outlook":
        from src.ingestion.outlook_provider import OutlookProvider
        return OutlookProvider(
            client_id=acct.get("client_id", ""),
            token_path=acct.get("token_path", "data/outlook_token.json"),
            user_email=acct.get("email", ""),
        )

    elif acct_type == "imap":
        from src.ingestion.imap_provider import IMAPProvider
        config = IMAPConfig(
            host=acct.get("host", ""),
            port=acct.get("port", 993),
            user=acct.get("user", ""),
            password=acct.get("password", ""),
            folder=acct.get("folder", "INBOX"),
            quarantine_folder=acct.get("quarantine_folder", "Quarantine"),
        )
        return IMAPProvider(config)

    else:
        logger.error(f"Unknown account type: {acct_type}")
        return None


def add_account_to_file(acct: dict, path: str = ACCOUNTS_FILE):
    """Add an account to accounts.json with sensitive fields encrypted."""
    accounts_path = Path(path)
    accounts_path.parent.mkdir(parents=True, exist_ok=True)

    existing = []
    if accounts_path.exists():
        try:
            existing = json.loads(accounts_path.read_text())
        except Exception:
            pass

    # Encrypt sensitive fields before writing to disk
    encrypted_acct = _encrypt_sensitive(acct)
    existing.append(encrypted_acct)
    accounts_path.write_text(json.dumps(existing, indent=2))

    safe_id = acct.get("email") or acct.get("user") or acct.get("type", "unknown")
    logger.info(f"Added account: {safe_id} ({acct.get('type')})")


def remove_account_from_file(email_or_type: str, path: str = ACCOUNTS_FILE):
    """Remove an account from accounts.json by email or type."""
    accounts_path = Path(path)
    if not accounts_path.exists():
        return

    existing = json.loads(accounts_path.read_text())
    filtered = [
        a for a in existing
        if a.get("email", "") != email_or_type
        and a.get("user", "") != email_or_type
        and a.get("type", "") != email_or_type
    ]
    accounts_path.write_text(json.dumps(filtered, indent=2))
    logger.info(f"Removed {len(existing) - len(filtered)} account(s)")


def list_accounts(path: str = ACCOUNTS_FILE) -> list[dict]:
    """List configured accounts with passwords fully masked.

    Never returns actual passwords or encrypted blobs in API responses.
    """
    from src.security.credentials import mask_password

    accounts_path = Path(path)
    if not accounts_path.exists():
        return []

    accounts = json.loads(accounts_path.read_text())
    safe = []
    for a in accounts:
        masked = dict(a)
        for field in _SENSITIVE_FIELDS:
            if field in masked:
                masked[field] = mask_password(masked[field])
        safe.append(masked)
    return safe

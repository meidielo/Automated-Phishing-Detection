"""SQLite-backed SaaS account, tenant, subscription, and usage store."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from src.billing.entitlements import EntitlementDecision, feature_entitlement
from src.billing.plans import get_plan

ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}


class DuplicateEmailError(ValueError):
    """Raised when a signup tries to reuse an existing email address."""


class InvalidCredentialsError(ValueError):
    """Raised when email/password authentication fails."""


@dataclass(frozen=True)
class AccountContext:
    user_id: str
    email: str
    org_id: str
    org_name: str
    role: str
    plan_slug: str
    plan_name: str
    subscription_status: str
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    monthly_scan_quota: int
    monthly_scan_used: int
    monthly_scan_remaining: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MailAccountRecord:
    id: str
    org_id: str
    user_id: str
    provider: str
    external_account_id: str | None
    encrypted_token_ref: str | None
    status: str
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class SaaSStore:
    """Small production-shaped account store for local SQLite deployments."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute("PRAGMA user_version = 1")
            conn.commit()

    def create_user_with_org(
        self,
        *,
        email: str,
        password: str,
        org_name: str | None = None,
        plan_slug: str = "free",
    ) -> AccountContext:
        normalized_email = normalize_email(email)
        validate_password(password)
        plan = get_plan(plan_slug)
        now = utc_now_iso()
        user_id = new_id("usr")
        org_id = new_id("org")
        organization_name = (org_name or normalized_email.split("@", 1)[0] or "Workspace").strip()
        password_hash = hash_password(password)

        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, normalized_email, password_hash, now),
                )
                conn.execute(
                    """
                    INSERT INTO organizations (id, name, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (org_id, organization_name, now),
                )
                conn.execute(
                    """
                    INSERT INTO memberships (user_id, org_id, role, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, org_id, "owner", now),
                )
                conn.execute(
                    """
                    INSERT INTO subscriptions (org_id, plan_slug, status, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (org_id, plan.slug, "active", now),
                )
                self._write_audit(
                    conn,
                    org_id=org_id,
                    actor_user_id=user_id,
                    action="user.signup",
                    target_type="user",
                    target_id=user_id,
                    metadata={"plan_slug": plan.slug},
                    now=now,
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if "users.email" in str(exc):
                raise DuplicateEmailError("email already exists") from exc
            raise

        context = self.get_account_context(user_id)
        if context is None:
            raise RuntimeError("created account could not be loaded")
        return context

    def authenticate(self, email: str, password: str) -> AccountContext:
        normalized_email = normalize_email(email)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, password_hash, disabled_at FROM users WHERE email = ?",
                (normalized_email,),
            ).fetchone()
            if row is None or row["disabled_at"]:
                raise InvalidCredentialsError("invalid email or password")
            if not verify_password(password, row["password_hash"]):
                raise InvalidCredentialsError("invalid email or password")
            context = self.get_account_context(row["id"])
            if context is None:
                raise InvalidCredentialsError("account has no active organization")
            self._write_audit(
                conn,
                org_id=context.org_id,
                actor_user_id=context.user_id,
                action="user.login",
                target_type="user",
                target_id=context.user_id,
                metadata={},
                now=utc_now_iso(),
            )
            conn.commit()
            return context

    def get_account_context(self, user_id: str) -> AccountContext | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    u.id AS user_id,
                    u.email,
                    o.id AS org_id,
                    o.name AS org_name,
                    o.stripe_customer_id,
                    m.role,
                    COALESCE(s.plan_slug, 'free') AS plan_slug,
                    COALESCE(s.status, 'active') AS subscription_status,
                    s.stripe_subscription_id
                FROM users u
                JOIN memberships m ON m.user_id = u.id
                JOIN organizations o ON o.id = m.org_id
                LEFT JOIN subscriptions s ON s.org_id = o.id
                WHERE u.id = ? AND u.disabled_at IS NULL
                ORDER BY m.created_at ASC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
            if row is None:
                return None

            plan_slug = row["plan_slug"] or "free"
            if row["subscription_status"] not in ACTIVE_SUBSCRIPTION_STATUSES and plan_slug != "free":
                plan_slug = "free"
            plan = get_plan(plan_slug)
            used = self.monthly_usage_count(
                row["org_id"],
                "manual_scan",
                conn=conn,
            )
            return AccountContext(
                user_id=row["user_id"],
                email=row["email"],
                org_id=row["org_id"],
                org_name=row["org_name"],
                role=row["role"],
                plan_slug=plan.slug,
                plan_name=plan.name,
                subscription_status=row["subscription_status"],
                stripe_customer_id=row["stripe_customer_id"],
                stripe_subscription_id=row["stripe_subscription_id"],
                monthly_scan_quota=plan.scan_quota,
                monthly_scan_used=used,
                monthly_scan_remaining=max(plan.scan_quota - used, 0),
            )

    def set_subscription(
        self,
        *,
        org_id: str,
        plan_slug: str,
        status: str = "active",
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        current_period_end: str | None = None,
    ) -> None:
        plan = get_plan(plan_slug)
        now = utc_now_iso()
        with self._connect() as conn:
            if stripe_customer_id:
                conn.execute(
                    "UPDATE organizations SET stripe_customer_id = ? WHERE id = ?",
                    (stripe_customer_id, org_id),
                )
            conn.execute(
                """
                INSERT INTO subscriptions (
                    org_id, stripe_subscription_id, plan_slug, status,
                    current_period_end, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    stripe_subscription_id = excluded.stripe_subscription_id,
                    plan_slug = excluded.plan_slug,
                    status = excluded.status,
                    current_period_end = excluded.current_period_end,
                    updated_at = excluded.updated_at
                """,
                (
                    org_id,
                    stripe_subscription_id,
                    plan.slug,
                    status,
                    current_period_end,
                    now,
                ),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=None,
                action="subscription.updated",
                target_type="subscription",
                target_id=org_id,
                metadata={"plan_slug": plan.slug, "status": status},
                now=now,
            )
            conn.commit()

    def set_org_stripe_customer(self, *, org_id: str, stripe_customer_id: str) -> None:
        """Persist the Stripe customer that owns an organization's billing."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE organizations SET stripe_customer_id = ? WHERE id = ?",
                (stripe_customer_id, org_id),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=None,
                action="stripe.customer.linked",
                target_type="stripe_customer",
                target_id=stripe_customer_id,
                metadata={},
                now=utc_now_iso(),
            )
            conn.commit()

    def get_org_id_for_stripe_customer(self, stripe_customer_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM organizations WHERE stripe_customer_id = ?",
                (stripe_customer_id,),
            ).fetchone()
            return row["id"] if row else None

    def get_org_id_for_stripe_subscription(self, stripe_subscription_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT org_id FROM subscriptions WHERE stripe_subscription_id = ?",
                (stripe_subscription_id,),
            ).fetchone()
            return row["org_id"] if row else None

    def check_entitlement(
        self,
        *,
        org_id: str,
        user_id: str | None,
        feature_slug: str,
        enforce_scan_quota: bool = False,
        audit_lock: bool = True,
    ) -> EntitlementDecision:
        with self._connect() as conn:
            plan_slug = self._org_plan_slug(org_id, conn)
            used = self.monthly_usage_count(org_id, "manual_scan", conn=conn)
            decision = feature_entitlement(
                plan_slug,
                feature_slug,
                monthly_scan_used=used,
                enforce_scan_quota=enforce_scan_quota,
            )
            if audit_lock and not decision.available:
                now = utc_now_iso()
                conn.execute(
                    """
                    INSERT INTO feature_locks (
                        id, org_id, user_id, feature_slug, required_plan, reason, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id("lock"),
                        org_id,
                        user_id,
                        decision.feature_slug,
                        decision.required_plan,
                        decision.reason,
                        now,
                    ),
                )
                self._write_audit(
                    conn,
                    org_id=org_id,
                    actor_user_id=user_id,
                    action="feature.locked",
                    target_type="feature",
                    target_id=decision.feature_slug,
                    metadata=decision.to_dict(),
                    now=now,
                )
                conn.commit()
            return decision

    def record_usage_event(
        self,
        *,
        org_id: str,
        user_id: str | None,
        feature_slug: str,
        quantity: int = 1,
        idempotency_key: str | None = None,
    ) -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO usage_events (
                    id, org_id, user_id, feature_slug, quantity, occurred_at, idempotency_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("use"),
                    org_id,
                    user_id,
                    feature_slug,
                    quantity,
                    now,
                    idempotency_key,
                ),
            )
            conn.commit()

    def create_scan_job(
        self,
        *,
        org_id: str,
        user_id: str,
        source: str,
        mail_account_id: str | None = None,
    ) -> str:
        scan_job_id = new_id("scan")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs (
                    id, org_id, user_id, mail_account_id, status, source, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_job_id, org_id, user_id, mail_account_id, "running", source, utc_now_iso()),
            )
            conn.commit()
        return scan_job_id

    def register_mail_account(
        self,
        *,
        org_id: str,
        user_id: str,
        provider: str,
        external_account_id: str | None,
        encrypted_token_ref: str | None,
        status: str = "pending",
    ) -> MailAccountRecord:
        provider = (provider or "").strip().lower()
        if provider not in {"gmail", "outlook", "imap"}:
            raise ValueError("provider must be gmail, outlook, or imap")
        if status not in {"pending", "active", "error", "disabled"}:
            raise ValueError("status must be pending, active, error, or disabled")

        now = utc_now_iso()
        mail_account_id = new_id("mail")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO mail_accounts (
                    id, org_id, user_id, provider, external_account_id,
                    encrypted_token_ref, status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mail_account_id,
                    org_id,
                    user_id,
                    provider,
                    external_account_id,
                    encrypted_token_ref,
                    status,
                    now,
                ),
            )
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=user_id,
                action="mail_account.registered",
                target_type="mail_account",
                target_id=mail_account_id,
                metadata={"provider": provider, "status": status},
                now=now,
            )
            conn.commit()
        return MailAccountRecord(
            id=mail_account_id,
            org_id=org_id,
            user_id=user_id,
            provider=provider,
            external_account_id=external_account_id,
            encrypted_token_ref=encrypted_token_ref,
            status=status,
            created_at=now,
        )

    def list_mail_accounts(self, org_id: str) -> list[MailAccountRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, org_id, user_id, provider, external_account_id,
                       encrypted_token_ref, status, created_at
                FROM mail_accounts
                WHERE org_id = ?
                ORDER BY created_at DESC
                """,
                (org_id,),
            ).fetchall()
            return [
                MailAccountRecord(
                    id=row["id"],
                    org_id=row["org_id"],
                    user_id=row["user_id"],
                    provider=row["provider"],
                    external_account_id=row["external_account_id"],
                    encrypted_token_ref=row["encrypted_token_ref"],
                    status=row["status"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def set_mail_account_status(
        self,
        *,
        org_id: str,
        mail_account_id: str,
        status: str,
        actor_user_id: str | None = None,
    ) -> None:
        if status not in {"pending", "active", "error", "disabled"}:
            raise ValueError("status must be pending, active, error, or disabled")
        now = utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE mail_accounts
                SET status = ?
                WHERE id = ? AND org_id = ?
                """,
                (status, mail_account_id, org_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("mail account not found for organization")
            self._write_audit(
                conn,
                org_id=org_id,
                actor_user_id=actor_user_id,
                action="mail_account.status_updated",
                target_type="mail_account",
                target_id=mail_account_id,
                metadata={"status": status},
                now=now,
            )
            conn.commit()

    def complete_scan_job(self, scan_job_id: str, status: str = "completed") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status = ?, completed_at = ? WHERE id = ?",
                (status, utc_now_iso(), scan_job_id),
            )
            conn.commit()

    def record_scan_result(
        self,
        *,
        org_id: str,
        user_id: str,
        scan_job_id: str,
        email_id: str,
        verdict: str,
        payment_decision: str | None,
        result: dict,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_results (
                    id, org_id, user_id, scan_job_id, email_id, verdict,
                    payment_decision, result_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("res"),
                    org_id,
                    user_id,
                    scan_job_id,
                    email_id,
                    verdict,
                    payment_decision,
                    json.dumps(result, default=str),
                    utc_now_iso(),
                ),
            )
            conn.commit()

    def list_scan_results(self, org_id: str, *, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, email_id, verdict, payment_decision, result_json, created_at
                FROM scan_results
                WHERE org_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "email_id": row["email_id"],
                    "verdict": row["verdict"],
                    "payment_decision": row["payment_decision"],
                    "created_at": row["created_at"],
                    "result": json.loads(row["result_json"]),
                }
                for row in rows
            ]

    def feature_lock_count(self, org_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM feature_locks WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            return int(row["count"] or 0)

    def monthly_usage_count(
        self,
        org_id: str,
        feature_slug: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        close_conn = conn is None
        if conn is None:
            conn = self._open()
        try:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(quantity), 0) AS used
                FROM usage_events
                WHERE org_id = ? AND feature_slug = ? AND occurred_at >= ?
                """,
                (org_id, feature_slug, month_start_iso()),
            ).fetchone()
            return int(row["used"] or 0)
        finally:
            if close_conn:
                conn.close()

    def _org_plan_slug(self, org_id: str, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT plan_slug, status FROM subscriptions WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if row is None:
            return "free"
        if row["status"] not in ACTIVE_SUBSCRIPTION_STATUSES and row["plan_slug"] != "free":
            return "free"
        return row["plan_slug"] or "free"

    def _write_audit(
        self,
        conn: sqlite3.Connection,
        *,
        org_id: str,
        actor_user_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None,
        metadata: dict,
        now: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_logs (
                id, org_id, actor_user_id, action, target_type, target_id,
                metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("audit"),
                org_id,
                actor_user_id,
                action,
                target_type,
                target_id,
                json.dumps(metadata, default=str),
                now,
            ),
        )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._open()
        try:
            yield conn
        finally:
            conn.close()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_password(password: str) -> None:
    if len(password or "") < 10:
        raise ValueError("password must be at least 10 characters")


def hash_password(password: str, *, iterations: int = 210_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, raw_iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(raw_iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def month_start_iso() -> str:
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stripe_customer_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, org_id)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT,
    plan_slug TEXT NOT NULL,
    status TEXT NOT NULL,
    current_period_end TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mail_accounts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_account_id TEXT,
    encrypted_token_ref TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mail_account_id TEXT REFERENCES mail_accounts(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    email_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    payment_decision TEXT,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_events (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    feature_slug TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    occurred_at TEXT NOT NULL,
    idempotency_key TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS feature_locks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    feature_slug TEXT NOT NULL,
    required_plan TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usage_org_feature_time
    ON usage_events(org_id, feature_slug, occurred_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_org_time
    ON scan_results(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_feature_locks_org_time
    ON feature_locks(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time
    ON audit_logs(org_id, created_at);
"""

"""
Data retention / purge for stored analysis results.

The pipeline writes one JSON line per analyzed email to
`data/results.jsonl`. Each row contains sender, recipient, subject, and
analysis verdict — regulated personal information under the Australian
Privacy Act 1988 and the EU GDPR. Storing it indefinitely is a legal
exposure separate from the security threats in `THREAT_MODEL.md`.

This module provides the purge primitive used by:
- The `purge` CLI subcommand in `main.py`
- A scheduled job (future, tracked in ROADMAP.md) that runs daily
- Per-subject erasure by email address or email_id for JSONL and feedback DB

Design notes:

1. **Atomicity**: writes go to a sibling tempfile and `os.replace` the
   original. If anything fails before the swap, the original is intact.
2. **Conservative on unparseable rows**: by default, rows that don't
   have a valid timestamp are KEPT (we'd rather over-retain than lose
   data we can't classify). Operators who want strict purging can pass
   `keep_unparseable=False`.
3. **Feedback DB handled explicitly**: SQLAlchemy feedback retention and
   per-subject erasure use separate functions so JSONL rewrites and DB
   deletes can be tested independently.
4. **Time-zone safe**: timestamps in the file are ISO-8601 with a TZ
   offset, but legacy rows may be naive. Naive timestamps are treated
   as UTC.

The strongest property the test suite locks: after a successful purge,
no row remains with a timestamp older than the cutoff.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class RetentionStats:
    """
    Summary of one purge run.

    Returned by `purge_results_jsonl` and printed by the CLI subcommand
    so operators can verify what happened without re-reading the file.
    """

    path: str
    cutoff: datetime
    kept: int
    dropped: int
    unparseable: int
    bytes_before: int
    bytes_after: int

    @property
    def total_seen(self) -> int:
        return self.kept + self.dropped + self.unparseable


@dataclass
class FeedbackRetentionStats:
    """Summary of one feedback DB purge run."""

    path: str
    cutoff: datetime
    kept: int
    dropped: int
    keep_recent: int
    dry_run: bool

    @property
    def total_seen(self) -> int:
        return self.kept + self.dropped


@dataclass
class SenderProfileRetentionStats:
    """Summary of one sender profile DB purge run."""

    path: str
    cutoff: datetime
    kept: int
    dropped: int
    dry_run: bool

    @property
    def total_seen(self) -> int:
        return self.kept + self.dropped


@dataclass
class SaaSRetentionStats:
    """Summary of one SaaS account DB purge run."""

    path: str
    cutoff: datetime
    kept: int
    dropped: int
    dry_run: bool

    @property
    def total_seen(self) -> int:
        return self.kept + self.dropped


@dataclass
class ErasureStats:
    """Summary of one per-subject erasure run."""

    path: str
    subject: str
    kept: int
    dropped: int
    dry_run: bool

    @property
    def total_seen(self) -> int:
        return self.kept + self.dropped


def _parse_timestamp(value) -> Optional[datetime]:
    """
    Parse the `timestamp` field from a results.jsonl row.

    Accepts ISO-8601 with or without timezone, with or without
    microseconds. Returns None for anything else (including the wrong
    Python type) so callers can treat "unparseable" as a single case.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Treat naive timestamps as UTC. The pipeline emits TZ-aware
        # timestamps now (datetime.now(timezone.utc)) but legacy rows
        # in the existing data/results.jsonl may be naive.
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _contains_subject(value, subject: str) -> bool:
    needle = subject.casefold()
    if value is None:
        return False
    if isinstance(value, str):
        return needle in value.casefold()
    if isinstance(value, dict):
        return any(_contains_subject(item, subject) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_subject(item, subject) for item in value)
    return needle in str(value).casefold()


def _sql_like_contains(value: str) -> str:
    escaped = (
        value.casefold()
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    return f"%{escaped}%"


def erase_subject_from_results_jsonl(
    path: Union[str, Path],
    subject: str,
    *,
    dry_run: bool = False,
    index=None,
) -> ErasureStats:
    """
    Remove JSONL analysis rows that mention an email address or email_id.

    This is the per-data-subject erasure primitive for `data/results.jsonl`.
    Matching is intentionally broad across nested JSON fields because stored
    rows can contain sender, recipient, reply-to, subject/body previews, and
    analyzer details.
    """
    subject = subject.strip()
    if not subject:
        raise ValueError("subject must not be empty")

    target = Path(path)
    if not target.exists():
        return ErasureStats(path=str(target), subject=subject, kept=0, dropped=0, dry_run=dry_run)

    kept_lines: list[str] = []
    kept = dropped = 0
    with target.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                if _contains_subject(line, subject):
                    dropped += 1
                else:
                    kept += 1
                    kept_lines.append(line)
                continue

            if _contains_subject(row, subject):
                dropped += 1
            else:
                kept += 1
                kept_lines.append(line)

    if not dry_run:
        tmp_path = target.with_suffix(target.suffix + ".erasure.tmp")
        try:
            with tmp_path.open("w", encoding="utf-8", newline="\n") as out:
                for line in kept_lines:
                    out.write(line)
                    out.write("\n")
            os.replace(tmp_path, target)
        except Exception:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            raise
        if index is not None:
            try:
                index.invalidate()
            except Exception:
                logger.exception("Failed to invalidate email lookup index after subject erasure")

    logger.info(
        "Erased subject from %s: subject=%s kept=%d dropped=%d dry_run=%s",
        target, subject, kept, dropped, dry_run,
    )
    return ErasureStats(
        path=str(target),
        subject=subject,
        kept=kept,
        dropped=dropped,
        dry_run=dry_run,
    )


def purge_results_jsonl(
    path: Union[str, Path],
    max_age_days: int,
    *,
    now: Optional[datetime] = None,
    keep_unparseable: bool = True,
    index=None,
) -> RetentionStats:
    """
    Purge rows older than `max_age_days` from a results.jsonl file.

    Args:
        path: Path to the JSONL file. If the file doesn't exist, a
            zero-stats result is returned without raising.
        max_age_days: Maximum age in days. Rows with `timestamp` older
            than `now - max_age_days` are dropped. Must be >= 0; pass 0
            to drop everything.
        now: Reference time for the cutoff. Defaults to `datetime.now(UTC)`.
            Exposed for testability so tests can use a frozen clock.
        keep_unparseable: If True (default), rows without a parseable
            timestamp are preserved. If False, they're dropped along
            with the old rows.
        index: Optional `EmailLookupIndex` to invalidate after the swap.
            See ADR 0002 §FM3 — the atomic swap rewrites the file, so
            every offset in the index points at random byte positions
            in the new file. Passing the index here calls `invalidate()`
            after the swap so the next lookup rebuilds against the
            trimmed file. Standalone usage (no index) is unchanged.

    Returns:
        RetentionStats describing what happened.

    Raises:
        ValueError: if `max_age_days` is negative.
        OSError: if the atomic file swap fails. The original file is
            guaranteed untouched in this case.
    """
    if max_age_days < 0:
        raise ValueError(f"max_age_days must be >= 0, got {max_age_days}")

    target = Path(path)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)

    # Missing file -> nothing to do, return empty stats
    if not target.exists():
        return RetentionStats(
            path=str(target),
            cutoff=cutoff,
            kept=0, dropped=0, unparseable=0,
            bytes_before=0, bytes_after=0,
        )

    bytes_before = target.stat().st_size

    kept_lines: list[str] = []
    kept = dropped = unparseable = 0

    with target.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip():
                # Blank lines are silently dropped — they're not data.
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                unparseable += 1
                if keep_unparseable:
                    kept_lines.append(line)
                continue

            ts = _parse_timestamp(row.get("timestamp"))
            if ts is None:
                unparseable += 1
                if keep_unparseable:
                    kept_lines.append(line)
                continue

            if ts >= cutoff:
                kept += 1
                kept_lines.append(line)
            else:
                dropped += 1

    # Atomic swap: write to a sibling tempfile, then os.replace.
    # `os.replace` is atomic on POSIX and Windows for same-filesystem
    # moves, which a sibling in the same directory always is.
    tmp_path = target.with_suffix(target.suffix + ".purge.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8", newline="\n") as out:
            for line in kept_lines:
                out.write(line)
                out.write("\n")
        os.replace(tmp_path, target)
    except Exception:
        # Make a best-effort cleanup of the tempfile, then re-raise so
        # the caller knows nothing was changed.
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise

    bytes_after = target.stat().st_size

    # ADR 0002 §FM3: invalidate the lookup index after the swap so
    # subsequent lookups rebuild against the new file rather than
    # seeking to stale byte offsets.
    if index is not None:
        try:
            index.invalidate()
        except Exception:
            logger.exception("Failed to invalidate email lookup index after purge")

    logger.info(
        "Purged %s: kept=%d dropped=%d unparseable=%d "
        "(%d bytes -> %d bytes, cutoff=%s)",
        target, kept, dropped, unparseable,
        bytes_before, bytes_after, cutoff.isoformat(),
    )

    return RetentionStats(
        path=str(target),
        cutoff=cutoff,
        kept=kept,
        dropped=dropped,
        unparseable=unparseable,
        bytes_before=bytes_before,
        bytes_after=bytes_after,
    )


def purge_alerts_jsonl(
    path: Union[str, Path],
    max_age_days: int,
    *,
    now: Optional[datetime] = None,
    keep_unparseable: bool = True,
) -> RetentionStats:
    """Purge old alert JSONL rows. Alerts share the `timestamp` schema."""
    return purge_results_jsonl(
        path,
        max_age_days,
        now=now,
        keep_unparseable=keep_unparseable,
    )


def erase_subject_from_alerts_jsonl(
    path: Union[str, Path],
    subject: str,
    *,
    dry_run: bool = False,
) -> ErasureStats:
    """Erase alert JSONL rows that mention an email address or email_id."""
    return erase_subject_from_results_jsonl(path, subject, dry_run=dry_run)


def _sqlite_table_exists(cursor: sqlite3.Cursor, table: str) -> bool:
    return bool(cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone())


def _as_utc_naive(dt: datetime) -> datetime:
    """Normalize a datetime for SQLite DateTime comparisons."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


async def purge_feedback_db(
    db_path: Union[str, Path],
    max_age_days: int,
    *,
    now: Optional[datetime] = None,
    keep_recent: int = 0,
    dry_run: bool = False,
) -> FeedbackRetentionStats:
    """
    Purge old analyst feedback labels from the SQLAlchemy feedback DB.

    Only `feedback_records` are purged. Blocklists, allowlists, and retrain
    history are operational audit state and are intentionally left alone.
    """
    if max_age_days < 0:
        raise ValueError(f"max_age_days must be >= 0, got {max_age_days}")
    if keep_recent < 0:
        raise ValueError(f"keep_recent must be >= 0, got {keep_recent}")

    target = Path(db_path)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
    cutoff_for_db = _as_utc_naive(cutoff)

    if not target.exists():
        return FeedbackRetentionStats(
            path=str(target),
            cutoff=cutoff,
            kept=0,
            dropped=0,
            keep_recent=keep_recent,
            dry_run=dry_run,
        )

    from sqlalchemy import delete, desc, func, select

    from src.feedback.database import (
        DatabaseManager,
        FeedbackRecord,
        create_sqlite_url,
    )

    db = DatabaseManager(create_sqlite_url(str(target)), echo=False)
    await db.initialize()
    try:
        async with db.async_session_maker() as session:
            total = (
                await session.execute(select(func.count(FeedbackRecord.id)))
            ).scalar() or 0

            keep_ids = []
            if keep_recent:
                keep_result = await session.execute(
                    select(FeedbackRecord.id)
                    .order_by(desc(FeedbackRecord.submitted_at), desc(FeedbackRecord.id))
                    .limit(keep_recent)
                )
                keep_ids = list(keep_result.scalars().all())

            old_filter = FeedbackRecord.submitted_at < cutoff_for_db
            if keep_ids:
                old_filter = old_filter & FeedbackRecord.id.not_in(keep_ids)

            drop_count = (
                await session.execute(
                    select(func.count(FeedbackRecord.id)).where(old_filter)
                )
            ).scalar() or 0

            if not dry_run and drop_count:
                await session.execute(delete(FeedbackRecord).where(old_filter))
                await session.commit()
            elif not dry_run:
                await session.commit()

            kept = total - drop_count
    finally:
        await db.close()

    action = "Scanned" if dry_run else "Purged"
    logger.info(
        "%s feedback DB %s: kept=%d dropped=%d keep_recent=%d dry_run=%s cutoff=%s",
        action, target, kept, drop_count, keep_recent, dry_run, cutoff.isoformat(),
    )

    return FeedbackRetentionStats(
        path=str(target),
        cutoff=cutoff,
        kept=kept,
        dropped=drop_count,
        keep_recent=keep_recent,
        dry_run=dry_run,
    )


async def erase_subject_from_feedback_db(
    db_path: Union[str, Path],
    subject: str,
    *,
    dry_run: bool = False,
) -> ErasureStats:
    """Remove feedback rows that mention an email address or email_id."""
    subject = subject.strip()
    if not subject:
        raise ValueError("subject must not be empty")

    target = Path(db_path)
    if not target.exists():
        return ErasureStats(path=str(target), subject=subject, kept=0, dropped=0, dry_run=dry_run)

    from sqlalchemy import delete, func, or_, select

    from src.feedback.database import (
        DatabaseManager,
        FeedbackRecord,
        create_sqlite_url,
    )

    db = DatabaseManager(create_sqlite_url(str(target)), echo=False)
    await db.initialize()
    try:
        async with db.async_session_maker() as session:
            total = (
                await session.execute(select(func.count(FeedbackRecord.id)))
            ).scalar() or 0
            needle = _sql_like_contains(subject)
            match_filter = or_(
                func.lower(FeedbackRecord.email_id).like(needle, escape="\\"),
                func.lower(FeedbackRecord.analyst_notes).like(needle, escape="\\"),
                func.lower(FeedbackRecord.feature_vector).like(needle, escape="\\"),
            )
            drop_count = (
                await session.execute(
                    select(func.count(FeedbackRecord.id)).where(match_filter)
                )
            ).scalar() or 0
            if not dry_run and drop_count:
                await session.execute(delete(FeedbackRecord).where(match_filter))
                await session.commit()
            elif not dry_run:
                await session.commit()
            kept = total - drop_count
    finally:
        await db.close()

    logger.info(
        "Erased subject from feedback DB %s: subject=%s kept=%d dropped=%d dry_run=%s",
        target, subject, kept, drop_count, dry_run,
    )
    return ErasureStats(
        path=str(target),
        subject=subject,
        kept=kept,
        dropped=drop_count,
        dry_run=dry_run,
    )


def purge_saas_db(
    db_path: Union[str, Path],
    max_age_days: int,
    *,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> SaaSRetentionStats:
    """Purge old tenant-scoped SaaS scan, usage, lock, and audit rows."""
    if max_age_days < 0:
        raise ValueError(f"max_age_days must be >= 0, got {max_age_days}")

    target = Path(db_path)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
    if not target.exists():
        return SaaSRetentionStats(
            path=str(target),
            cutoff=cutoff,
            kept=0,
            dropped=0,
            dry_run=dry_run,
        )

    cutoff_text = cutoff.isoformat()
    specs = [
        ("scan_results", "created_at"),
        ("scan_jobs", "created_at"),
        ("usage_events", "occurred_at"),
        ("feature_locks", "created_at"),
        ("audit_logs", "created_at"),
    ]
    total = dropped = 0
    with sqlite3.connect(target) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        for table, column in specs:
            if not _sqlite_table_exists(cursor, table):
                continue
            count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            drop_count = cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {column} < ?",
                (cutoff_text,),
            ).fetchone()[0]
            total += count
            dropped += drop_count
            if drop_count and not dry_run:
                cursor.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff_text,))
        if not dry_run:
            conn.commit()

    kept = total - dropped
    logger.info(
        "Purged SaaS DB %s: kept=%d dropped=%d dry_run=%s cutoff=%s",
        target, kept, dropped, dry_run, cutoff.isoformat(),
    )
    return SaaSRetentionStats(
        path=str(target),
        cutoff=cutoff,
        kept=kept,
        dropped=dropped,
        dry_run=dry_run,
    )


def erase_subject_from_saas_db(
    db_path: Union[str, Path],
    subject: str,
    *,
    dry_run: bool = False,
) -> ErasureStats:
    """Remove SaaS scan/audit rows that mention an email address or email_id."""
    subject = subject.strip()
    if not subject:
        raise ValueError("subject must not be empty")

    target = Path(db_path)
    if not target.exists():
        return ErasureStats(path=str(target), subject=subject, kept=0, dropped=0, dry_run=dry_run)

    needle = _sql_like_contains(subject)
    specs = [
        ("scan_results", "lower(email_id) LIKE ? ESCAPE '\\' OR lower(result_json) LIKE ? ESCAPE '\\'"),
        ("audit_logs", "lower(metadata_json) LIKE ? ESCAPE '\\'"),
    ]
    total = dropped = 0
    with sqlite3.connect(target) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        for table, predicate in specs:
            if not _sqlite_table_exists(cursor, table):
                continue
            count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            params = (needle, needle) if predicate.count("?") == 2 else (needle,)
            drop_count = cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {predicate}",
                params,
            ).fetchone()[0]
            total += count
            dropped += drop_count
            if drop_count and not dry_run:
                cursor.execute(f"DELETE FROM {table} WHERE {predicate}", params)
        if not dry_run:
            conn.commit()

    kept = total - dropped
    logger.info(
        "Erased subject from SaaS DB %s: subject=%s kept=%d dropped=%d dry_run=%s",
        target, subject, kept, dropped, dry_run,
    )
    return ErasureStats(
        path=str(target),
        subject=subject,
        kept=kept,
        dropped=dropped,
        dry_run=dry_run,
    )


def purge_sender_profiles_db(
    db_path: Union[str, Path],
    max_age_days: int,
    *,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> SenderProfileRetentionStats:
    """Purge sender profiling rows older than the retention window."""
    if max_age_days < 0:
        raise ValueError(f"max_age_days must be >= 0, got {max_age_days}")

    target = Path(db_path)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
    if not target.exists():
        return SenderProfileRetentionStats(
            path=str(target),
            cutoff=cutoff,
            kept=0,
            dropped=0,
            dry_run=dry_run,
        )

    cutoff_text = cutoff.isoformat()
    with sqlite3.connect(target) as conn:
        cursor = conn.cursor()
        tables = {
            "sender_emails": "timestamp",
            "sender_recipients": "last_seen",
            "senders": "last_seen",
        }
        total = dropped = 0
        for table, column in tables.items():
            exists = cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            drop_count = cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {column} < ?",
                (cutoff_text,),
            ).fetchone()[0]
            total += count
            dropped += drop_count
            if drop_count and not dry_run:
                cursor.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff_text,))
        if not dry_run:
            conn.commit()

    kept = total - dropped
    logger.info(
        "Purged sender profile DB %s: kept=%d dropped=%d dry_run=%s cutoff=%s",
        target, kept, dropped, dry_run, cutoff.isoformat(),
    )
    return SenderProfileRetentionStats(
        path=str(target),
        cutoff=cutoff,
        kept=kept,
        dropped=dropped,
        dry_run=dry_run,
    )


def erase_subject_from_sender_profiles_db(
    db_path: Union[str, Path],
    subject: str,
    *,
    dry_run: bool = False,
) -> ErasureStats:
    """Remove sender profile rows that mention an email address or email_id."""
    subject = subject.strip()
    if not subject:
        raise ValueError("subject must not be empty")

    target = Path(db_path)
    if not target.exists():
        return ErasureStats(path=str(target), subject=subject, kept=0, dropped=0, dry_run=dry_run)

    needle = _sql_like_contains(subject)
    with sqlite3.connect(target) as conn:
        cursor = conn.cursor()
        specs = [
            ("sender_emails", "lower(email_id) LIKE ? ESCAPE '\\' OR lower(sender_email) LIKE ? ESCAPE '\\'"),
            ("sender_recipients", "lower(sender_email) LIKE ? ESCAPE '\\' OR lower(recipient_email) LIKE ? ESCAPE '\\'"),
            ("senders", "lower(sender_email) LIKE ? ESCAPE '\\'"),
        ]
        total = dropped = 0
        for table, predicate in specs:
            exists = cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if not exists:
                continue
            count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            params = (needle, needle) if predicate.count("?") == 2 else (needle,)
            drop_count = cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {predicate}",
                params,
            ).fetchone()[0]
            total += count
            dropped += drop_count
            if drop_count and not dry_run:
                cursor.execute(f"DELETE FROM {table} WHERE {predicate}", params)
        if not dry_run:
            conn.commit()

    kept = total - dropped
    logger.info(
        "Erased subject from sender profile DB %s: subject=%s kept=%d dropped=%d dry_run=%s",
        target, subject, kept, dropped, dry_run,
    )
    return ErasureStats(
        path=str(target),
        subject=subject,
        kept=kept,
        dropped=dropped,
        dry_run=dry_run,
    )

#!/usr/bin/env python3
"""Create a timestamped backup of runtime data without bundling secrets."""
from __future__ import annotations

import argparse
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_RUNTIME_PATHS = (
    "data/results.jsonl",
    "data/alerts.jsonl",
    "data/feedback.db",
    "data/saas.db",
    "data/sender_profiles.db",
)

SECRET_PATHS = (
    "data/accounts.json",
    "credentials.json",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _existing(paths: list[str]) -> list[Path]:
    return [Path(p) for p in paths if Path(p).exists()]


def _portable(path: Path | str) -> str:
    return str(path).replace(os.sep, "/")


def _prune_old_backups(destination: Path, retention_days: int, now: datetime) -> list[str]:
    if retention_days <= 0 or not destination.exists():
        return []
    cutoff = now - timedelta(days=retention_days)
    removed: list[str] = []
    for backup in destination.glob("runtime-backup-*.zip"):
        modified = datetime.fromtimestamp(backup.stat().st_mtime, timezone.utc)
        if modified < cutoff:
            backup.unlink()
            removed.append(str(backup))
    return removed


def create_backup(
    destination: Path,
    *,
    include_secrets: bool = False,
    extra_paths: list[str] | None = None,
    dry_run: bool = False,
    retention_days: int = 14,
) -> dict:
    now = _utc_now()
    destination.mkdir(parents=True, exist_ok=True)
    paths = list(DEFAULT_RUNTIME_PATHS)
    paths.extend(extra_paths or [])
    if include_secrets:
        paths.extend(SECRET_PATHS)
        paths.extend(str(p) for p in Path("data").glob("*_token.json"))

    files = _existing(paths)
    backup_name = f"runtime-backup-{now.strftime('%Y%m%dT%H%M%SZ')}.zip"
    backup_path = destination / backup_name
    manifest = {
        "created_at": now.isoformat(),
        "include_secrets": include_secrets,
        "files": [_portable(path) for path in files],
        "missing": [path for path in paths if not Path(path).exists()],
    }

    if not dry_run:
        with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
            for path in files:
                archive.write(path, arcname=_portable(path))
        manifest["backup_path"] = str(backup_path)
        manifest["backup_bytes"] = backup_path.stat().st_size
        manifest["pruned"] = _prune_old_backups(destination, retention_days, now)
    else:
        manifest["backup_path"] = str(backup_path)
        manifest["backup_bytes"] = 0
        manifest["pruned"] = []

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Backup runtime phishing detector data.")
    parser.add_argument("--destination", default="backups", help="Directory for backup zip files.")
    parser.add_argument("--include-secrets", action="store_true", help="Also include account/token files. Store this zip encrypted.")
    parser.add_argument("--extra-path", action="append", default=[], help="Additional file or directory to include.")
    parser.add_argument("--retention-days", type=int, default=14, help="Delete backups older than this many days. Set 0 to keep all.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be backed up without writing a zip.")
    args = parser.parse_args()

    manifest = create_backup(
        Path(args.destination),
        include_secrets=args.include_secrets,
        extra_paths=args.extra_path,
        dry_run=args.dry_run,
        retention_days=args.retention_days,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

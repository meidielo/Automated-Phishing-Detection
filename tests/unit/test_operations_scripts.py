from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_backup_runtime_data_excludes_secret_files_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    (data / "results.jsonl").write_text('{"email_id":"one"}\n', encoding="utf-8")
    (data / "alerts.jsonl").write_text('{"email_id":"one"}\n', encoding="utf-8")
    (data / "accounts.json").write_text('{"secret":"token"}\n', encoding="utf-8")

    backup_script = _load_script("backup_runtime_data.py")
    manifest = backup_script.create_backup(tmp_path / "backups", retention_days=14)

    backup_path = Path(manifest["backup_path"])
    assert backup_path.exists()
    assert "data/results.jsonl" in manifest["files"]
    assert "data/accounts.json" not in manifest["files"]

    with zipfile.ZipFile(backup_path) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert "data/results.jsonl" in names
        assert "data/accounts.json" not in names
        archived_manifest = json.loads(archive.read("manifest.json"))
        assert archived_manifest["include_secrets"] is False


def test_backup_runtime_data_can_include_secret_files_explicitly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    (data / "results.jsonl").write_text("{}\n", encoding="utf-8")
    (data / "accounts.json").write_text('{"secret":"token"}\n', encoding="utf-8")

    backup_script = _load_script("backup_runtime_data.py")
    manifest = backup_script.create_backup(
        tmp_path / "backups",
        include_secrets=True,
        retention_days=14,
    )

    assert "data/accounts.json" in manifest["files"]
    with zipfile.ZipFile(manifest["backup_path"]) as archive:
        assert "data/accounts.json" in archive.namelist()


def test_production_health_check_reports_healthy_monitor(monkeypatch):
    health_script = _load_script("production_health_check.py")

    def fake_request(url, *, token="", timeout=5.0):
        if url.endswith("/api/health"):
            return 200, {"status": "healthy"}
        if url.endswith("/api/monitor/stats"):
            return 200, {
                "running": True,
                "stats": {
                    "errors": 0,
                    "last_poll": "2026-04-30T00:00:00+00:00",
                },
            }
        raise AssertionError(url)

    monkeypatch.setattr(health_script, "_request_json", fake_request)
    monkeypatch.setattr(
        health_script,
        "datetime",
        type(
            "FrozenDateTime",
            (),
            {
                "now": staticmethod(lambda tz=None: __import__("datetime").datetime(2026, 4, 30, 0, 1, 0, tzinfo=tz)),
                "fromisoformat": staticmethod(__import__("datetime").datetime.fromisoformat),
            },
        ),
    )

    report = health_script.run_check(
        "https://example.test",
        token="secret",
        require_monitor_running=True,
        max_monitor_age_seconds=300,
    )

    assert report["ok"] is True
    assert report["failures"] == []


def test_production_health_check_fails_when_required_monitor_is_stopped(monkeypatch):
    health_script = _load_script("production_health_check.py")

    def fake_request(url, *, token="", timeout=5.0):
        if url.endswith("/api/health"):
            return 200, {"status": "healthy"}
        if url.endswith("/api/monitor/stats"):
            return 200, {"running": False, "stats": {"errors": 0}}
        raise AssertionError(url)

    monkeypatch.setattr(health_script, "_request_json", fake_request)

    report = health_script.run_check(
        "https://example.test",
        token="secret",
        require_monitor_running=True,
    )

    assert report["ok"] is False
    assert "mailbox monitor is not running" in report["failures"]

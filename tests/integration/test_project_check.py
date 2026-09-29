import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ecomops.cli.app import app
from ecomops.config.schema import SSHConnectionConfig
from ecomops.ssh.client import (
    RemoteFileEntry,
    RemoteFileMissing,
    RemoteFileStat,
    RemoteListing,
    RemoteReadResult,
)
from ecomops.ssh.fetcher import SSHLogSource

MTIME = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


def write_local_project(projects_dir: Path, root: Path) -> None:
    (projects_dir / "example-shop.yaml").write_text(
        f"""
name: example-shop
connection:
  type: local
  root: {root}
log_aliases:
  php:
    path: system.log
    type: php
  transfer:
    path: logs/transfer-*.log
    type: nginx
  gone:
    path: missing.log
    type: cron
""",
        encoding="utf-8",
    )


def local_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    root = tmp_path / "shop"
    (root / "logs").mkdir(parents=True)
    (root / "system.log").write_text(
        "[2026-09-03 10:00:00] ERROR: boom\nloose line\n", encoding="utf-8"
    )
    old = root / "logs/transfer-1.log"
    new = root / "logs/transfer-2.log"
    old.write_text("old\n", encoding="utf-8")
    new.write_text("new\n", encoding="utf-8")
    os.utime(old, (1_000, 1_000))
    os.utime(new, (2_000, 2_000))
    write_local_project(projects_dir, root)
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    return root


def forbid_analyzers(monkeypatch: pytest.MonkeyPatch) -> None:
    from ecomops.analyzers.pipeline import AnalyzerPipeline

    def must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("project check must not run analyzers")

    monkeypatch.setattr(AnalyzerPipeline, "run", must_not_run)


def test_local_project_check_reports_every_alias_without_analyzing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = local_setup(tmp_path, monkeypatch)
    forbid_analyzers(monkeypatch)

    result = CliRunner().invoke(app, ["project", "example-shop", "check"])

    assert result.exit_code == 0, result.output
    output = result.output
    assert "Project: example-shop (LOCAL)" in output
    assert f"[php] php: {root / 'system.log'}" in output
    assert "Parsed: 1 recognized, 1 unrecognized" in output
    assert f"Selected: {root / 'logs/transfer-2.log'}" in output
    assert "Candidates: 2 (newest first)" in output
    assert "[gone] cron:" in output
    assert "Warning: source unavailable: file not found" in output
    assert "Findings" not in output


def test_local_project_check_supports_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = local_setup(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        app, ["project", "example-shop", "check", "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["project"] == "example-shop"
    assert payload["connection_type"] == "local"
    by_alias = {item["alias"]: item for item in payload["aliases"]}
    assert set(by_alias) == {"php", "transfer", "gone"}
    assert by_alias["transfer"]["selected_path"] == str(root / "logs/transfer-2.log")
    assert by_alias["gone"]["source_metadata"]["exists"] is False
    assert by_alias["php"]["parse_stats"]["parsed_lines"] == 1


class FakeRemote:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def read_tail(self, path: str, **kwargs: object) -> RemoteReadResult:
        self.calls.append(f"tail {path}")
        return RemoteReadResult(
            data=b"[2026-09-03 12:00:00] ERROR: remote\n", byte_count=37, truncated=True
        )

    def stat_file(
        self, path: str, **kwargs: object
    ) -> RemoteFileStat | RemoteFileMissing:
        self.calls.append(f"stat {path}")
        if path.endswith("missing.log"):
            return RemoteFileMissing(reason="not_found")
        if not path.endswith(".log"):
            return RemoteFileStat(
                size_bytes=0,
                modified_at=MTIME,
                is_regular_file=False,
                is_directory=True,
            )
        return RemoteFileStat(size_bytes=9_000, modified_at=MTIME, is_regular_file=True)

    def list_files(
        self, directory: str, pattern: str, **kwargs: object
    ) -> RemoteListing:
        self.calls.append(f"list {directory} {pattern}")
        return RemoteListing(
            entries=[
                RemoteFileEntry(name="transfer-a.log", size_bytes=1, modified_at=MTIME)
            ],
            truncated=False,
        )


def test_ssh_project_check_uses_only_fixed_read_only_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.logs import resolver

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (projects_dir / "remote.yaml").write_text(
        """
name: remote
connection:
  type: ssh
  host: logs.example.test
  user: readonly
  root: /srv/example-shop
log_aliases:
  php:
    path: var/log/system.log
    type: php
  transfer:
    path: var/log/transfer-*.log
    type: nginx
  gone:
    path: var/log/missing.log
    type: php
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    remote = FakeRemote()

    def fake_source(
        connection: SSHConnectionConfig,
        password: str | None = None,
        allowed_dirs: list[Path] | None = None,
    ) -> SSHLogSource:
        return SSHLogSource(connection, client=remote, allowed_dirs=allowed_dirs or [])

    monkeypatch.setattr(resolver, "SSHLogSource", fake_source)
    forbid_analyzers(monkeypatch)

    result = CliRunner().invoke(app, ["project", "remote", "check"])

    assert result.exit_code == 0, result.output
    assert "Project: remote (SSH)" in result.output
    assert "Selected: /srv/example-shop/var/log/transfer-a.log" in result.output
    assert "Source: exists, readable, 9000 bytes" in result.output
    assert "Source: missing, unreadable (file not found)" in result.output
    assert remote.calls == [
        "stat /srv/example-shop/var/log/system.log",
        "tail /srv/example-shop/var/log/system.log",
        "stat /srv/example-shop/var/log",
        "list /srv/example-shop/var/log transfer-*.log",
        "stat /srv/example-shop/var/log/transfer-a.log",
        "tail /srv/example-shop/var/log/transfer-a.log",
        "stat /srv/example-shop/var/log/missing.log",
    ]


def test_project_check_for_unknown_project_is_a_readable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_setup(tmp_path, monkeypatch)

    result = CliRunner().invoke(app, ["project", "missing", "check"])

    assert result.exit_code == 1
    assert "Error: Project 'missing' is not configured." in result.output
    assert "Traceback" not in result.output

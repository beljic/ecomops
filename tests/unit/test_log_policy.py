"""Log-only path policy: aliases may only point at log files in log folders."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from ecomops.config.schema import ProjectConfig

SSH = {
    "type": "ssh",
    "host": "logs.example.test",
    "user": "readonly",
    "root": "/srv/example-shop",
}
LOCAL = {"type": "local", "root": "/srv/example-shop"}


def project(
    path: str,
    *,
    connection: dict[str, object] | None = None,
    log_dirs: list[str] | None = None,
    log_type: str = "generic",
) -> ProjectConfig:
    data: dict[str, object] = {
        "name": "example-shop",
        "connection": connection or SSH,
        "log_aliases": {"app": {"path": path, "type": log_type}},
    }
    if log_dirs is not None:
        data["log_dirs"] = log_dirs
    return ProjectConfig.model_validate(data)


@pytest.mark.parametrize(
    "path",
    [
        "var/log/system.log",
        "var/log/exception.log",
        "var/log/debug.log.1",
        "var/log/transfer.log-20260901",
        "var/log/transfer.log.2026-09-01",
        "/var/log/nginx/access.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/cron",
        "var/log/transfer-*.log",
        "/var/log/nginx/access.log.?",
    ],
)
def test_log_files_in_default_log_folders_are_accepted(path: str) -> None:
    assert project(path).log_aliases["app"].path == path


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/etc/passwd",
        "../../etc/passwd",
        "app/etc/env.php",
        ".env",
        "/home/deploy/.ssh/id_rsa",
        "/home/deploy/.ssh/debug.log",
        "/proc/self/environ",
        "/root/install.log",
        "app/etc/*.php",
        "var/log/*",
        "var/log/app.php",
        "pub/errors/local.xml",
        "/var/log/../../etc/shadow",
        "/opt/other-app/debug.log",
    ],
)
def test_system_config_and_secret_files_are_rejected(path: str) -> None:
    with pytest.raises(ValidationError, match="log path policy"):
        project(path)


def test_extensionless_files_are_only_allowed_in_the_system_log_folder() -> None:
    with pytest.raises(ValidationError, match="log path policy"):
        project("var/log/system")


def test_root_slash_does_not_open_system_folders() -> None:
    connection = {**SSH, "root": "/"}

    with pytest.raises(ValidationError, match="log path policy"):
        project("etc/passw?", connection=connection)
    with pytest.raises(ValidationError, match="log path policy"):
        project("etc/shadow", connection=connection)


def test_explicit_log_dirs_allow_logs_outside_the_root() -> None:
    configured = project(
        "../logs/example-shop/access.log",
        connection={**SSH, "root": "/srv/example-shop/current"},
        log_dirs=["../logs/example-shop"],
    )

    assert configured.allowed_log_dirs() == [
        Path("/srv/example-shop/logs/example-shop")
    ]


def test_explicit_log_dirs_replace_the_defaults() -> None:
    with pytest.raises(ValidationError, match="log path policy"):
        project("/var/log/nginx/access.log", log_dirs=["var/log"])


def test_log_dirs_cannot_open_denied_system_folders() -> None:
    with pytest.raises(ValidationError, match="log path policy"):
        project("/etc/app/debug.log", log_dirs=["/etc/app"])


def test_default_log_dirs_are_the_root_and_the_system_log_folder() -> None:
    assert project("var/log/system.log").allowed_log_dirs() == [
        Path("/srv/example-shop"),
        Path("/var/log"),
    ]


def test_local_projects_follow_the_same_policy() -> None:
    with pytest.raises(ValidationError, match="log path policy"):
        project("app/etc/env.php", connection=LOCAL)
    assert project("var/log/system.log", connection=LOCAL)


def test_local_symlink_leaving_the_log_folders_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services
    from ecomops.core.exceptions import LogPathPolicyError

    secret = tmp_path / "secret.log"
    secret.write_text("password=hunter2\n", encoding="utf-8")
    root = tmp_path / "shop"
    (root / "var/log").mkdir(parents=True)
    (root / "var/log/system.log").symlink_to(secret)
    configured = project(
        "var/log/system.log", connection={"type": "local", "root": str(root)}
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({configured.name: configured})),
    )

    with pytest.raises(LogPathPolicyError, match="outside the allowed log folders"):
        services.analyze_project_log("example-shop", "app")
    inspection = services.inspect_project_log("example-shop", "app")
    assert inspection.parse_stats is None
    assert inspection.source_metadata.error is not None
    assert "outside the allowed log folders" in inspection.source_metadata.error


def test_local_symlink_to_another_log_inside_the_folders_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    root = tmp_path / "shop"
    (root / "var/log").mkdir(parents=True)
    target = root / "var/log/system-2026-09-01.log"
    target.write_text("[2026-09-01 10:00:00] ERROR: boom\n", encoding="utf-8")
    (root / "var/log/system.log").symlink_to(target)
    configured = project(
        "var/log/system.log", connection={"type": "local", "root": str(root)}
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({configured.name: configured})),
    )

    report = services.analyze_project_log("example-shop", "app")

    assert report.line_count == 1

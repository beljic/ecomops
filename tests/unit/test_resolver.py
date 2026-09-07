from pathlib import Path

import pytest

from ecomops.config.schema import ProjectConfig
from ecomops.core.exceptions import LogAliasNotFoundError, ProjectNotFoundError


def local_project(log_path: Path) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "name": "local-store",
            "connection": {"type": "local", "root": str(log_path.parent)},
            "log_aliases": {"php": {"path": log_path.name, "type": "php"}},
        }
    )


def ssh_project() -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "name": "production",
            "connection": {
                "type": "ssh",
                "host": "logs.example.test",
                "user": "readonly",
                "port": 2222,
            },
            "log_aliases": {
                "nginx": {"path": "/var/log/nginx/error.log", "type": "nginx"}
            },
        }
    )


def test_resolve_source_uses_local_source_without_constructing_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.logs import resolver
    from ecomops.logs.sources import LocalLogSource

    def fail_if_constructed(*args: object, **kwargs: object) -> None:
        raise AssertionError("local resolution must not construct SSH transport")

    monkeypatch.setattr(resolver, "SSHLogSource", fail_if_constructed)

    source = resolver.resolve_source(local_project(tmp_path / "system.log"), "php")

    assert isinstance(source, LocalLogSource)


def test_resolve_source_uses_configured_ssh_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.logs import resolver

    received: list[object] = []

    class RecordingSSHLogSource:
        def __init__(self, connection: object) -> None:
            received.append(connection)

    monkeypatch.setattr(resolver, "SSHLogSource", RecordingSSHLogSource)
    project = ssh_project()

    source = resolver.resolve_source(project, "nginx")

    assert isinstance(source, RecordingSSHLogSource)
    assert received == [project.connection]


def test_missing_alias_is_rejected_before_ssh_source_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.logs import resolver

    def fail_if_constructed(*args: object, **kwargs: object) -> None:
        raise AssertionError("missing alias must not construct SSH transport")

    monkeypatch.setattr(resolver, "SSHLogSource", fail_if_constructed)

    with pytest.raises(LogAliasNotFoundError, match="missing"):
        resolver.resolve_source(ssh_project(), "missing")


def test_missing_project_is_rejected_before_source_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    def fail_if_resolved(*args: object, **kwargs: object) -> None:
        raise AssertionError("missing project must not resolve a source")

    monkeypatch.setattr(services, "resolve_source", fail_if_resolved)
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({})),
    )

    with pytest.raises(ProjectNotFoundError, match="missing"):
        services.analyze_project_log("missing", "php")


def test_service_rejects_an_explicit_zero_line_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(
            lambda cls: ProjectRegistry({"local-store": local_project(tmp_path / "x")})
        ),
    )
    monkeypatch.setattr(services, "resolve_source", lambda *args: object())

    with pytest.raises(ValueError, match="max_lines"):
        services.analyze_project_log("local-store", "php", max_lines=0)

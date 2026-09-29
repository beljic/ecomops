import os
from pathlib import Path

import pytest

from ecomops.config.schema import ProjectConfig
from ecomops.core.exceptions import (
    ConfigurationError,
    LogAliasNotFoundError,
    LogFileNotFoundError,
    ProjectNotFoundError,
)
from ecomops.core.models import LogEntry, LogReadResult
from ecomops.logs.time_ranges import TimeRange


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
    received_passwords: list[object] = []

    class RecordingSSHLogSource:
        def __init__(self, connection: object, **kwargs: object) -> None:
            received.append(connection)
            received_passwords.append(kwargs.get("password"))

    monkeypatch.setattr(resolver, "SSHLogSource", RecordingSSHLogSource)
    project = ssh_project()

    source = resolver.resolve_source(project, "nginx")

    assert isinstance(source, RecordingSSHLogSource)
    assert received == [project.connection]
    assert received_passwords == [None]


def test_resolve_source_forwards_ephemeral_ssh_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.logs import resolver

    received: list[object] = []

    class RecordingSSHLogSource:
        def __init__(self, connection: object, **kwargs: object) -> None:
            received.append(kwargs["password"])

    monkeypatch.setattr(resolver, "SSHLogSource", RecordingSSHLogSource)

    resolver.resolve_source(ssh_project(), "nginx", ssh_password="one-time-secret")

    assert received == ["one-time-secret"]


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
            lambda cls: ProjectRegistry(
                {"local-store": local_project(tmp_path / "x.log")}
            )
        ),
    )
    monkeypatch.setattr(services, "resolve_source", lambda *args: object())

    with pytest.raises(ValueError, match="max_lines"):
        services.analyze_project_log("local-store", "php", max_lines=0)


def test_service_rejects_missing_alias_before_source_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(
            lambda cls: ProjectRegistry(
                {"local-store": local_project(tmp_path / "x.log")}
            )
        ),
    )

    with pytest.raises(LogAliasNotFoundError, match="missing"):
        services.analyze_project_log("local-store", "missing")


def test_service_includes_ssh_read_metadata_in_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    class StubSource:
        def read(
            self, alias: object, limits: object, time_range: TimeRange
        ) -> LogReadResult:
            return LogReadResult(
                entries=[
                    LogEntry(
                        source="/var/log/nginx/error.log",
                        message="upstream timed out",
                        raw="upstream timed out",
                    )
                ],
                line_count=1,
                byte_count=20,
                truncated=True,
            )

    project = ssh_project()
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )
    monkeypatch.setattr(services, "resolve_source", lambda *args: StubSource())

    report = services.analyze_project_log(project.name, "nginx")

    assert report.connection_type == "ssh"
    assert report.remote_access is True
    assert report.line_count == 1
    assert report.byte_count == 20
    assert report.truncated is True


def test_service_report_explains_a_missing_local_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    project = local_project(tmp_path / "missing.log")
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )

    report = services.analyze_project_log(project.name, "php")

    assert report.findings == []
    assert report.source_metadata is not None
    assert report.source_metadata.error == "file not found"
    assert report.warnings == ["source unavailable: file not found"]


def test_service_report_carries_parse_stats_sampling_and_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.core import services

    log_path = tmp_path / "php.log"
    log_path.write_text("[2026-09-03 10:00:00] ERROR: boom\nloose\n", "utf-8")
    project = local_project(log_path)
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )

    report = services.analyze_project_log(project.name, "php")

    assert report.parse_stats is not None
    assert report.parse_stats.parsed_lines == 1
    assert report.parse_stats.unparsed_lines == 1
    assert report.sampling is not None
    assert report.sampling.direction == "head"
    assert report.actual_range is not None


def glob_project(root: Path) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "name": "local-store",
            "connection": {"type": "local", "root": str(root)},
            "log_aliases": {
                "transfer": {"path": "logs/transfer-*.log", "type": "nginx"}
            },
        }
    )


def use_project(monkeypatch: pytest.MonkeyPatch, project: ProjectConfig) -> None:
    from ecomops.config.projects import ProjectRegistry

    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )


def write_log(path: Path, content: str, mtime: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.utime(path, (mtime, mtime))


def test_glob_alias_analysis_reads_the_newest_matching_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    write_log(tmp_path / "logs/transfer-old.log", "old entry\n", 1_000)
    write_log(tmp_path / "logs/transfer-new.log", "new entry\n", 2_000)
    write_log(tmp_path / "logs/other-newest.log", "not matched\n", 3_000)
    use_project(monkeypatch, glob_project(tmp_path))

    report = services.analyze_project_log("local-store", "transfer")

    assert report.source.path == str(tmp_path / "logs/transfer-new.log")
    assert report.byte_count == len("new entry\n")


def test_glob_alias_analysis_without_matches_raises_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    (tmp_path / "logs").mkdir()
    use_project(monkeypatch, glob_project(tmp_path))

    with pytest.raises(LogFileNotFoundError, match="transfer-\\*.log"):
        services.analyze_project_log("local-store", "transfer")


def test_local_listing_excludes_symlinks_and_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    outside = tmp_path / "outside.log"
    write_log(outside, "outside\n", 5_000)
    write_log(tmp_path / "root/logs/transfer-a.log", "inside\n", 1_000)
    (tmp_path / "root/logs/transfer-link.log").symlink_to(outside)
    (tmp_path / "root/logs/transfer-dir.log").mkdir()
    use_project(monkeypatch, glob_project(tmp_path / "root"))

    listing = services.list_project_log_files("local-store", "transfer")

    assert [candidate.path for candidate in listing.files] == [
        str(tmp_path / "root/logs/transfer-a.log")
    ]
    assert listing.pattern == "transfer-*.log"
    assert listing.files[0].size_bytes == len("inside\n")


def test_listing_an_exact_alias_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    use_project(monkeypatch, local_project(tmp_path / "system.log"))

    with pytest.raises(ConfigurationError, match="not a glob"):
        services.list_project_log_files("local-store", "php")


def test_inspection_reports_metadata_and_parser_recognition_without_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    write_log(
        tmp_path / "logs/transfer-a.log",
        "[2026-09-03 10:00:00] ERROR: boom\nunstructured\n",
        1_000,
    )
    use_project(monkeypatch, glob_project(tmp_path))

    inspection = services.inspect_project_log("local-store", "transfer")

    assert inspection.alias == "transfer"
    assert inspection.log_type == "nginx"
    assert inspection.connection_type == "local"
    assert inspection.selected_path == str(tmp_path / "logs/transfer-a.log")
    assert inspection.listing is not None
    assert len(inspection.listing.files) == 1
    assert inspection.source_metadata.readable is True
    assert inspection.parse_stats is not None
    assert inspection.parse_stats.parsed_lines == 1
    assert inspection.parse_stats.unparsed_lines == 1
    assert not hasattr(inspection, "findings")


def test_inspection_of_a_glob_without_matches_is_a_result_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    (tmp_path / "logs").mkdir()
    use_project(monkeypatch, glob_project(tmp_path))

    inspection = services.inspect_project_log("local-store", "transfer")

    assert inspection.selected_path is None
    assert inspection.source_metadata.exists is False
    assert inspection.source_metadata.error == "no files match transfer-*.log"
    assert inspection.warnings == ["source unavailable: no files match transfer-*.log"]


def test_inspection_of_a_missing_exact_file_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ecomops.core import services

    use_project(monkeypatch, local_project(tmp_path / "missing.log"))

    inspection = services.inspect_project_log("local-store", "php")

    assert inspection.selected_path == str(tmp_path / "missing.log")
    assert inspection.source_metadata.error == "file not found"

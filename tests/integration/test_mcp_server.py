import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ecomops.core.models import (
    AnalysisReport,
    Finding,
    LogSource,
    ParseStats,
    SamplingMetadata,
    Severity,
    SourceMetadata,
)


@pytest.mark.anyio
async def test_analyze_project_log_returns_structured_local_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    received: dict[str, object] = {}

    def fake_analyze_project_log(
        project: str,
        log_alias: str,
        since: str,
        until: str | None,
        max_lines: int | None,
        max_bytes: int | None,
    ) -> AnalysisReport:
        received.update(
            {
                "project": project,
                "log_alias": log_alias,
                "since": since,
                "until": until,
                "max_lines": max_lines,
                "max_bytes": max_bytes,
            }
        )
        return AnalysisReport(
            source=LogSource(type="local", project=project, alias=log_alias),
            findings=[
                Finding(
                    id="php-memory",
                    title="PHP memory exhausted",
                    severity=Severity.high,
                    category="php",
                )
            ],
            generated_at=datetime(2026, 9, 7, tzinfo=UTC),
            connection_type="local",
            remote_access=False,
            line_count=3,
            byte_count=123,
            truncated=False,
        )

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log",
            {
                "project": "local-store",
                "log_alias": "php",
                "since": "1h",
                "until": "2026-09-07T12:00:00+00:00",
                "max_lines": 20,
                "max_bytes": 4096,
            },
        )

    assert result.is_error is False
    assert result.structured_content == {
        "metadata": {
            "connection_type": "local",
            "remote_access": False,
            "line_count": 3,
            "byte_count": 123,
            "truncated": False,
        },
        "findings": [
            {
                "id": "php-memory",
                "title": "PHP memory exhausted",
                "severity": "high",
                "category": "php",
                "root_cause_guess": None,
                "evidence": [],
                "count": 1,
                "first_seen": None,
                "last_seen": None,
                "recommended_steps": [],
            }
        ],
        "rendered_findings": (
            "Connection: LOCAL\nRemote access: no\nRead: 3 lines, 123 bytes\n"
            "Sampling: complete\nFindings: 1\n"
            "[high] PHP memory exhausted (count: 1)"
        ),
    }
    assert received == {
        "project": "local-store",
        "log_alias": "php",
        "since": "1h",
        "until": "2026-09-07T12:00:00+00:00",
        "max_lines": 20,
        "max_bytes": 4096,
    }


@pytest.mark.anyio
async def test_analyze_project_log_returns_structured_ssh_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    def fake_analyze_project_log(*args: object, **kwargs: object) -> AnalysisReport:
        return AnalysisReport(
            source=LogSource(type="ssh", project="remote-store", alias="nginx"),
            findings=[],
            generated_at=datetime(2026, 9, 7, tzinfo=UTC),
            connection_type="ssh",
            remote_access=True,
            line_count=10,
            byte_count=2048,
            truncated=True,
        )

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log",
            {"project": "remote-store", "log_alias": "nginx"},
        )

    assert result.is_error is False
    assert result.structured_content == {
        "metadata": {
            "connection_type": "ssh",
            "remote_access": True,
            "line_count": 10,
            "byte_count": 2048,
            "truncated": True,
        },
        "findings": [],
        "rendered_findings": "Connection: SSH\nRemote access: yes\n"
        "Read: 10 lines, 2048 bytes\nSampling: bounded\nNo findings.",
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"project": "", "log_alias": "php"}, "project"),
        ({"project": "store", "log_alias": ""}, "log_alias"),
        ({"project": "store", "log_alias": "php", "max_lines": 0}, "max_lines"),
        ({"project": "store", "log_alias": "php", "max_bytes": 0}, "max_bytes"),
    ],
)
async def test_analyze_project_log_rejects_invalid_typed_arguments(
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict[str, object],
    message: str,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    def must_not_analyze(*args: object, **kwargs: object) -> AnalysisReport:
        raise AssertionError("invalid arguments must not reach the application service")

    monkeypatch.setattr(server, "analyze_project_log", must_not_analyze)

    async with Client(server.mcp) as client:
        result = await client.call_tool("analyze_project_log", arguments)

    assert result.is_error is True
    assert message in result.content[0].text


@pytest.mark.anyio
async def test_analyze_project_log_returns_config_errors_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.core.exceptions import LogAliasNotFoundError, ProjectNotFoundError
    from ecomops.mcp import server

    errors = iter(
        [
            ProjectNotFoundError("Project 'missing' is not configured."),
            LogAliasNotFoundError("Log alias 'missing' is not configured."),
        ]
    )

    def fake_analyze_project_log(*args: object, **kwargs: object) -> AnalysisReport:
        raise next(errors)

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)

    async with Client(server.mcp) as client:
        missing_project = await client.call_tool(
            "analyze_project_log", {"project": "missing", "log_alias": "php"}
        )
        missing_alias = await client.call_tool(
            "analyze_project_log", {"project": "store", "log_alias": "missing"}
        )

    assert missing_project.is_error is True
    assert missing_project.content[0].text.endswith(
        "Project 'missing' is not configured."
    )
    assert missing_alias.is_error is True
    assert missing_alias.content[0].text.endswith(
        "Log alias 'missing' is not configured."
    )


@pytest.mark.anyio
async def test_analyze_project_log_guides_ssh_access_without_collecting_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.core.exceptions import SSHPermissionDeniedError
    from ecomops.mcp import server

    def fake_analyze_project_log(*args: object, **kwargs: object) -> AnalysisReport:
        raise SSHPermissionDeniedError("SSH permission denied")

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote-store", "log_alias": "nginx"}
        )

    assert result.is_error is True
    assert "Configure the project's SSH agent or key" in result.content[0].text
    assert "password" not in result.content[0].text.lower()


@pytest.mark.anyio
async def test_mcp_server_exposes_only_the_typed_analysis_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    def must_not_analyze(*args: object, **kwargs: object) -> AnalysisReport:
        raise AssertionError("command-shaped input must not reach the service")

    monkeypatch.setattr(server, "analyze_project_log", must_not_analyze)

    async with Client(server.mcp) as client:
        tools = await client.list_tools()
        result = await client.call_tool(
            "analyze_project_log",
            {
                "project": "store",
                "log_alias": "php",
                "command": "tail -f /var/log/php.log",
                "path": "/var/log/php.log",
            },
        )

    assert sorted(tool.name for tool in tools.tools) == [
        "analyze_project_log",
        "check_project",
        "list_log_files",
        "security_scan",
        "traffic_summary",
    ]
    analyze_tool = next(
        tool for tool in tools.tools if tool.name == "analyze_project_log"
    )
    assert set(analyze_tool.input_schema["properties"]) == {
        "project",
        "log_alias",
        "since",
        "until",
        "max_lines",
        "max_bytes",
    }
    assert analyze_tool.input_schema["additionalProperties"] is False
    assert result.is_error is True
    assert "command" in result.content[0].text


@pytest.mark.anyio
async def test_analyze_project_log_returns_read_metadata_and_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    def fake_analyze_project_log(*args: object, **kwargs: object) -> AnalysisReport:
        return AnalysisReport(
            source=LogSource(type="ssh", project="remote-store", alias="nginx"),
            findings=[],
            generated_at=datetime(2026, 9, 7, tzinfo=UTC),
            connection_type="ssh",
            remote_access=True,
            line_count=2,
            byte_count=64,
            truncated=True,
            source_metadata=SourceMetadata(exists=True, readable=True),
            parse_stats=ParseStats(total_lines=2, parsed_lines=0, unparsed_lines=2),
            sampling=SamplingMetadata(
                direction="tail",
                max_bytes=1_000,
                max_lines=50,
                sampled_bytes=64,
                complete_lines=2,
            ),
        )

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log",
            {"project": "remote-store", "log_alias": "nginx"},
        )

    assert result.is_error is False
    content = result.structured_content
    assert content is not None
    metadata = content["metadata"]
    assert metadata["source"] == {
        "exists": True,
        "readable": True,
        "size_bytes": None,
        "modified_at": None,
        "error": None,
    }
    assert metadata["parse_stats"]["unparsed_lines"] == 2
    assert metadata["sampling"]["direction"] == "tail"
    assert metadata["actual_range"] is None
    assert metadata["warnings"] == [
        "parser recognized none of 2 sampled lines; the log format may be unsupported"
    ]
    assert "No findings." not in content["rendered_findings"]


def mcp_local_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file_count: int = 2
) -> Path:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    root = tmp_path / "shop"
    (root / "logs").mkdir(parents=True)
    (root / "system.log").write_text("[2026-09-03 10:00:00] ERROR: boom\n", "utf-8")
    for index in range(file_count):
        path = root / f"logs/transfer-{index:04d}.log"
        path.write_text("line\n", encoding="utf-8")
        os.utime(path, (1_000 + index, 1_000 + index))
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
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))
    return root


@pytest.mark.anyio
async def test_check_project_returns_structured_alias_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import Client

    from ecomops.analyzers.pipeline import AnalyzerPipeline
    from ecomops.mcp import server

    def must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("check_project must not run analyzers")

    monkeypatch.setattr(AnalyzerPipeline, "run", must_not_run)
    root = mcp_local_project(tmp_path, monkeypatch)

    async with Client(server.mcp) as client:
        result = await client.call_tool("check_project", {"project": "example-shop"})

    assert result.is_error is False
    content = result.structured_content
    assert content is not None
    assert content["project"] == "example-shop"
    by_alias = {item["alias"]: item for item in content["aliases"]}
    assert by_alias["php"]["source_metadata"]["readable"] is True
    assert by_alias["php"]["parse_stats"]["parsed_lines"] == 1
    assert by_alias["transfer"]["selected_path"] == str(root / "logs/transfer-0001.log")


@pytest.mark.anyio
async def test_list_log_files_returns_a_bounded_newest_first_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import Client

    from ecomops.mcp import server
    from ecomops.mcp.schemas import MCP_MAX_LISTED_FILES

    root = mcp_local_project(tmp_path, monkeypatch, file_count=MCP_MAX_LISTED_FILES + 3)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "list_log_files", {"project": "example-shop", "log_alias": "transfer"}
        )

    assert result.is_error is False
    content = result.structured_content
    assert content is not None
    assert content["pattern"] == "transfer-*.log"
    assert len(content["files"]) == MCP_MAX_LISTED_FILES
    assert content["total_matches"] == MCP_MAX_LISTED_FILES + 3
    assert content["truncated"] is True
    newest = f"transfer-{MCP_MAX_LISTED_FILES + 2:04d}.log"
    assert content["files"][0]["path"] == str(root / "logs" / newest)


@pytest.mark.anyio
async def test_list_log_files_rejects_exact_and_missing_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    mcp_local_project(tmp_path, monkeypatch)

    async with Client(server.mcp) as client:
        exact = await client.call_tool(
            "list_log_files", {"project": "example-shop", "log_alias": "php"}
        )
        missing = await client.call_tool(
            "list_log_files", {"project": "example-shop", "log_alias": "nope"}
        )

    assert exact.is_error is True
    assert "not a glob" in exact.content[0].text
    assert missing.is_error is True
    assert "Log alias 'nope' is not configured" in missing.content[0].text


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("check_project", {"project": "example-shop", "command": "id"}),
        ("check_project", {"project": "example-shop", "path": "/etc/passwd"}),
        (
            "list_log_files",
            {"project": "example-shop", "log_alias": "transfer", "pattern": "*"},
        ),
        (
            "list_log_files",
            {"project": "example-shop", "log_alias": "transfer", "directory": "/"},
        ),
    ],
)
async def test_discovery_tools_reject_unknown_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    arguments: dict[str, object],
) -> None:
    from mcp import Client

    from ecomops.core import services
    from ecomops.mcp import server

    def must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("unknown arguments must not reach the service")

    monkeypatch.setattr(services, "check_project", must_not_run)
    monkeypatch.setattr(services, "list_project_log_files", must_not_run)
    mcp_local_project(tmp_path, monkeypatch)

    async with Client(server.mcp) as client:
        tools = await client.list_tools()
        result = await client.call_tool(tool, arguments)

    schemas = {item.name: item.input_schema for item in tools.tools}
    assert schemas["check_project"]["additionalProperties"] is False
    assert set(schemas["check_project"]["properties"]) == {"project"}
    assert schemas["list_log_files"]["additionalProperties"] is False
    assert set(schemas["list_log_files"]["properties"]) == {"project", "log_alias"}
    assert result.is_error is True
    assert "Unknown arguments" in result.content[0].text


@pytest.mark.anyio
async def test_traffic_summary_tool_returns_bounded_structured_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    root = mcp_local_project(tmp_path, monkeypatch)
    (root / "access.log").write_text(
        "".join(
            f'192.0.2.{index % 7} - - [03/Sep/2026:12:00:00 +0000] "GET /p{index} '
            f'HTTP/1.1" 200 1 "-" "agent"\n'
            for index in range(40)
        ),
        encoding="utf-8",
    )
    config = tmp_path / "projects/example-shop.yaml"
    config.write_text(
        config.read_text(encoding="utf-8")
        + "  access:\n    path: access.log\n    type: nginx\n",
        encoding="utf-8",
    )

    async with Client(server.mcp) as client:
        tools = await client.list_tools()
        result = await client.call_tool(
            "traffic_summary",
            {"project": "example-shop", "log_alias": "access", "top_n": 3},
        )
        rejected = await client.call_tool(
            "traffic_summary",
            {"project": "example-shop", "log_alias": "access", "command": "id"},
        )

    schema = next(t for t in tools.tools if t.name == "traffic_summary").input_schema
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "project",
        "log_alias",
        "since",
        "until",
        "max_lines",
        "max_bytes",
        "top_n",
    }
    assert result.is_error is False
    content = result.structured_content
    assert content is not None
    assert content["summary"]["total_requests"] == 40
    assert len(content["summary"]["top_client_ips"]) == 3
    assert len(content["summary"]["top_paths"]) == 3
    assert content["read"]["sampling"]["direction"] == "head"
    assert "GET /p" not in str(content)
    assert rejected.is_error is True
    assert "Unknown arguments" in rejected.content[0].text


@pytest.mark.anyio
async def test_security_scan_tool_is_typed_bounded_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import Client

    from ecomops.analyzers.pipeline import AnalyzerPipeline
    from ecomops.mcp import server

    def must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("security_scan must not run the finding analyzers")

    monkeypatch.setattr(AnalyzerPipeline, "run", must_not_run)
    root = mcp_local_project(tmp_path, monkeypatch)
    (root / "access.log").write_text(
        "".join(
            f'192.0.2.9 - - [03/Sep/2026:12:00:00 +0000] "GET /wp-admin/{index} '
            f'HTTP/1.1" 404 1 "-" "agent"\n'
            for index in range(30)
        ),
        encoding="utf-8",
    )
    config = tmp_path / "projects/example-shop.yaml"
    config.write_text(
        config.read_text(encoding="utf-8")
        + "  access:\n    path: access.log\n    type: nginx\n",
        encoding="utf-8",
    )

    async with Client(server.mcp) as client:
        tools = await client.list_tools()
        result = await client.call_tool(
            "security_scan", {"project": "example-shop", "log_alias": "access"}
        )
        rejected = await client.call_tool(
            "security_scan",
            {"project": "example-shop", "log_alias": "access", "tor_list": "x"},
        )

    schema = next(t for t in tools.tools if t.name == "security_scan").input_schema
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "project",
        "log_alias",
        "since",
        "until",
        "max_lines",
        "max_bytes",
    }
    assert result.is_error is False
    content = result.structured_content
    assert content is not None
    wordpress = content["scan"]["indicators"][0]
    assert wordpress["id"] == "scanner.wordpress"
    assert wordpress["count"] == 30
    assert len(wordpress["samples"]) <= 5
    assert content["scan"]["tor"]["status"] == "unavailable"
    assert rejected.is_error is True

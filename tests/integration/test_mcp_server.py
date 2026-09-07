from datetime import UTC, datetime

import pytest

from ecomops.core.models import AnalysisReport, Finding, LogSource, Severity


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

    elicitation_requested = False

    def fake_analyze_project_log(*args: object, **kwargs: object) -> AnalysisReport:
        raise SSHPermissionDeniedError("SSH permission denied")

    async def fake_elicit_ssh_access_check(*args: object, **kwargs: object) -> None:
        nonlocal elicitation_requested
        elicitation_requested = True

    monkeypatch.setattr(server, "analyze_project_log", fake_analyze_project_log)
    monkeypatch.setattr(
        server, "_elicit_ssh_access_check", fake_elicit_ssh_access_check, raising=False
    )

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote-store", "log_alias": "nginx"}
        )

    assert result.is_error is True
    assert elicitation_requested is True
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

    assert [tool.name for tool in tools.tools] == ["analyze_project_log"]
    assert set(tools.tools[0].input_schema["properties"]) == {
        "project",
        "log_alias",
        "since",
        "until",
        "max_lines",
        "max_bytes",
    }
    assert tools.tools[0].input_schema["additionalProperties"] is False
    assert result.is_error is True
    assert "command" in result.content[0].text

"""MCP password elicitation: ask once, retry once, never keep or echo secrets."""

import inspect
import logging
from datetime import UTC, datetime
from typing import Any

import pytest

from ecomops.core.exceptions import SSHPermissionDeniedError
from ecomops.core.models import AnalysisReport, LogSource

SECRET = "s3cret-value-7781"


def test_installed_sdk_exposes_the_elicitation_api_we_use() -> None:
    from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation
    from mcp.server.mcpserver import Context

    parameters = list(inspect.signature(Context.elicit).parameters)
    assert parameters[:3] == ["self", "message", "schema"]
    assert AcceptedElicitation and DeclinedElicitation


class FakeService:
    """Denies SSH until it gets the expected credentials."""

    def __init__(self, *, always_deny: bool = False) -> None:
        self.calls: list[dict[str, object]] = []
        self.always_deny = always_deny

    def __call__(self, project: str, log_alias: str, *args: object, **kwargs: Any):  # type: ignore[no-untyped-def]
        self.calls.append(
            {
                "username": kwargs.get("ssh_username"),
                "password": kwargs.get("ssh_password"),
            }
        )
        if self.always_deny or kwargs.get("ssh_password") != SECRET:
            raise SSHPermissionDeniedError("SSH permission denied")
        return AnalysisReport(
            source=LogSource(type="ssh", project=project, alias=log_alias),
            findings=[],
            generated_at=datetime(2026, 9, 7, tzinfo=UTC),
            connection_type="ssh",
            remote_access=True,
        )


def accepting_callback(requests: list[Any]):  # type: ignore[no-untyped-def]
    import mcp.types as types

    async def callback(context: Any, params: Any) -> Any:
        requests.append(params)
        return types.ElicitResult(
            action="accept", content={"username": "log-reader", "password": SECRET}
        )

    return callback


def result_text(result: Any) -> str:
    return " ".join(getattr(item, "text", "") for item in result.content) + str(
        result.structured_content
    )


@pytest.mark.anyio
async def test_accepted_credentials_are_used_for_exactly_one_retry(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService()
    monkeypatch.setattr(server, "analyze_project_log", service)
    requests: list[Any] = []
    caplog.set_level(logging.DEBUG)

    async with Client(
        server.mcp, elicitation_callback=accepting_callback(requests)
    ) as client:
        tools = await client.list_tools()
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    assert result.is_error is False
    assert service.calls == [
        {"username": None, "password": None},
        {"username": "log-reader", "password": SECRET},
    ]
    assert len(requests) == 1
    assert set(requests[0].requested_schema["properties"]) == {"username", "password"}
    assert SECRET not in result_text(result)
    assert SECRET not in caplog.text
    for tool in tools.tools:
        assert "password" not in tool.input_schema["properties"]
        assert "username" not in tool.input_schema["properties"]
        assert "ctx" not in tool.input_schema["properties"]


@pytest.mark.anyio
async def test_declined_elicitation_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp.types as types
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService()
    monkeypatch.setattr(server, "analyze_project_log", service)

    async def decline(context: Any, params: Any) -> Any:
        return types.ElicitResult(action="decline")

    async with Client(server.mcp, elicitation_callback=decline) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    assert result.is_error is True
    assert "no credentials were provided" in result_text(result)
    assert len(service.calls) == 1


@pytest.mark.anyio
async def test_clients_without_elicitation_get_a_clear_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService()
    monkeypatch.setattr(server, "analyze_project_log", service)

    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    text = result_text(result)
    assert result.is_error is True
    assert "Configure the project's SSH agent or key" in text
    assert "cannot collect credentials" in text
    assert len(service.calls) == 1


@pytest.mark.anyio
async def test_failed_retry_is_reported_once_without_the_secret(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService(always_deny=True)
    monkeypatch.setattr(server, "analyze_project_log", service)
    requests: list[Any] = []
    caplog.set_level(logging.DEBUG)

    async with Client(
        server.mcp, elicitation_callback=accepting_callback(requests)
    ) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    text = result_text(result)
    assert result.is_error is True
    assert "denied for the provided credentials" in text
    assert SECRET not in text
    assert SECRET not in caplog.text
    assert len(service.calls) == 2
    assert len(requests) == 1


@pytest.mark.anyio
async def test_discovery_tools_also_retry_with_elicited_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.core import services
    from ecomops.logs.inspection import ProjectCheck
    from ecomops.mcp import server

    calls: list[object] = []

    def check_project(project: str, **kwargs: Any) -> ProjectCheck:
        calls.append(kwargs.get("ssh_password"))
        if kwargs.get("ssh_password") != SECRET:
            raise SSHPermissionDeniedError("SSH permission denied")
        return ProjectCheck(project=project, connection_type="ssh", aliases=[])

    monkeypatch.setattr(services, "check_project", check_project)

    async with Client(
        server.mcp, elicitation_callback=accepting_callback([])
    ) as client:
        result = await client.call_tool("check_project", {"project": "remote"})

    assert result.is_error is False
    assert calls == [None, SECRET]


def test_services_apply_an_elicited_username_only_to_that_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ecomops.config.projects import ProjectRegistry
    from ecomops.config.schema import ProjectConfig, SSHConnectionConfig
    from ecomops.core import services
    from ecomops.logs import resolver

    project = ProjectConfig.model_validate(
        {
            "name": "remote",
            "connection": {
                "type": "ssh",
                "host": "logs.example.test",
                "user": "configured-user",
            },
            "log_aliases": {"access": {"path": "/var/log/access.log", "type": "nginx"}},
        }
    )
    monkeypatch.setattr(
        ProjectRegistry,
        "load",
        classmethod(lambda cls: ProjectRegistry({project.name: project})),
    )
    seen: list[tuple[str, object]] = []

    class StopAfterConnect(Exception):
        pass

    def fake_source(  # type: ignore[no-untyped-def]
        connection: SSHConnectionConfig,
        password: str | None = None,
        allowed_dirs: object = None,
    ):
        seen.append((connection.user, password))
        raise StopAfterConnect

    monkeypatch.setattr(resolver, "SSHLogSource", fake_source)

    with pytest.raises(StopAfterConnect):
        services.analyze_project_log(
            "remote", "access", ssh_username="log-reader", ssh_password=SECRET
        )

    assert seen == [("log-reader", SECRET)]
    assert project.connection.user == "configured-user"


@pytest.mark.anyio
async def test_legacy_clients_are_asked_in_band_and_retried_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService()
    monkeypatch.setattr(server, "analyze_project_log", service)
    requests: list[Any] = []

    async with Client(
        server.mcp, mode="legacy", elicitation_callback=accepting_callback(requests)
    ) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    assert result.is_error is False
    assert len(requests) == 1
    assert [call["password"] for call in service.calls] == [None, SECRET]
    assert SECRET not in result_text(result)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_invalid_form_answers_never_echo_the_submitted_values(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    import mcp.types as types
    from mcp import Client

    from ecomops.mcp import server

    service = FakeService()
    monkeypatch.setattr(server, "analyze_project_log", service)

    async def wrong_type(context: Any, params: Any) -> Any:
        return types.ElicitResult(
            action="accept",
            content={"username": "log-reader", "password": ["77819931"]},
        )

    async with Client(server.mcp, mode=mode, elicitation_callback=wrong_type) as client:
        result = await client.call_tool(
            "analyze_project_log", {"project": "remote", "log_alias": "access"}
        )

    assert result.is_error is True
    assert "77819931" not in result_text(result)
    assert len(service.calls) == 1

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Annotated, Any

import mcp.types as mcp_types
from mcp.server.elicitation import AcceptedElicitation, render_elicitation_schema
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types.version import is_version_at_least
from pydantic import BaseModel, Field, ValidationError

from ecomops.analyzers.traffic import DEFAULT_TOP_N, MAX_TOP_N
from ecomops.core import services
from ecomops.core.exceptions import EcomOpsError, SSHPermissionDeniedError
from ecomops.core.services import analyze_project_log
from ecomops.reports.terminal import render_terminal

from .schemas import structured_check, structured_listing, structured_report

_SSH_ACCESS_DENIED = "SSH access was denied. Configure the project's SSH agent or key."
_NO_ELICITATION = (
    f"{_SSH_ACCESS_DENIED} This MCP client cannot collect credentials interactively."
)
_NO_CREDENTIALS = "SSH access was denied and no credentials were provided."
_RETRY_DENIED = "SSH access was denied for the provided credentials."

_CREDENTIALS_KEY = "ssh_credentials"
_CREDENTIALS_REQUESTED = "ecomops:ssh-credentials-requested"
_INPUT_REQUIRED_VERSION = "2026-07-28"


class SSHCredentialsForm(BaseModel):
    """Elicitation form; values live only for one tool call and are never stored."""

    username: str = Field(min_length=1, description="SSH username for this request")
    password: str = Field(min_length=1, description="SSH password for this request")


class ReadOnlyMCPServer(MCPServer):
    """MCP server with an explicit closed input surface for read-only tools."""

    _tool_arguments: dict[str, frozenset[str]] = {
        "analyze_project_log": frozenset(
            {"project", "log_alias", "since", "until", "max_lines", "max_bytes"}
        ),
        "check_project": frozenset({"project"}),
        "list_log_files": frozenset({"project", "log_alias"}),
        "security_scan": frozenset(
            {"project", "log_alias", "since", "until", "max_lines", "max_bytes"}
        ),
        "traffic_summary": frozenset(
            {
                "project",
                "log_alias",
                "since",
                "until",
                "max_lines",
                "max_bytes",
                "top_n",
            }
        ),
    }

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Any = None
    ) -> Any:
        allowed = self._tool_arguments.get(name)
        if allowed is not None:
            unknown = sorted(set(arguments) - allowed)
            if unknown:
                raise ToolError(f"Unknown arguments: {', '.join(unknown)}")
        return await super().call_tool(name, arguments, context)


mcp = ReadOnlyMCPServer("ecomops")


async def _with_ssh_retry[T](
    ctx: Context, project: str, call: Callable[[dict[str, str]], T]
) -> T | mcp_types.InputRequiredResult:
    """Run a read-only service call; on SSH denial ask once and retry once.

    Credentials come only from MCP elicitation (never from tool arguments),
    are passed to exactly one retry, and are dropped when this call returns.
    On protocol >= 2026-07-28 the question is returned as an
    ``InputRequiredResult`` and the answer arrives on the client's retried
    call; older clients are asked in-band with ``ctx.elicit``.
    """
    if ctx.request_state == _CREDENTIALS_REQUESTED:
        answer = (ctx.input_responses or {}).get(_CREDENTIALS_KEY)
        return _retry_with_answer(call, answer)

    try:
        return call({})
    except SSHPermissionDeniedError:
        pass
    except EcomOpsError as exc:
        raise ToolError(str(exc)) from None

    supports_elicitation = ctx.request_context.session.check_client_capability(
        mcp_types.ClientCapabilities(elicitation=mcp_types.ElicitationCapability())
    )
    if not supports_elicitation:
        raise ToolError(_NO_ELICITATION)
    message = (
        f"SSH access to project '{project}' was denied. Enter a username and "
        "password for this one read-only request; they are not stored."
    )
    if ctx.protocol_version is not None and is_version_at_least(
        ctx.protocol_version, _INPUT_REQUIRED_VERSION
    ):
        return mcp_types.InputRequiredResult(
            input_requests={
                _CREDENTIALS_KEY: mcp_types.ElicitRequest(
                    params=mcp_types.ElicitRequestFormParams(
                        message=message,
                        requested_schema=render_elicitation_schema(SSHCredentialsForm),
                    )
                )
            },
            request_state=_CREDENTIALS_REQUESTED,
        )
    result = await ctx.elicit(message=message, schema=SSHCredentialsForm)
    if not isinstance(result, AcceptedElicitation):
        raise ToolError(_NO_CREDENTIALS)
    return _retry_with_credentials(
        call,
        {"ssh_username": result.data.username, "ssh_password": result.data.password},
    )


def _retry_with_answer[T](call: Callable[[dict[str, str]], T], answer: object) -> T:
    if (
        not isinstance(answer, mcp_types.ElicitResult)
        or answer.action != "accept"
        or not answer.content
    ):
        raise ToolError(_NO_CREDENTIALS)
    try:
        form = SSHCredentialsForm.model_validate(answer.content)
    except ValidationError:
        # The validation text would echo the submitted values; never return it.
        raise ToolError("The SSH credentials form was incomplete.") from None
    return _retry_with_credentials(
        call, {"ssh_username": form.username, "ssh_password": form.password}
    )


def _retry_with_credentials[T](
    call: Callable[[dict[str, str]], T], credentials: dict[str, str]
) -> T:
    try:
        return call(credentials)
    except SSHPermissionDeniedError:
        raise ToolError(_RETRY_DENIED) from None
    except EcomOpsError as exc:
        raise ToolError(str(exc)) from None
    finally:
        credentials.clear()


async def _analyze_project_log(
    ctx: Context,
    project: Annotated[str, Field(min_length=1)],
    log_alias: Annotated[str, Field(min_length=1)],
    since: str = "all",
    until: str | None = None,
    max_lines: Annotated[int | None, Field(gt=0)] = None,
    max_bytes: Annotated[int | None, Field(gt=0)] = None,
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """Analyze one configured project log using bounded read-only access."""
    report = await _with_ssh_retry(
        ctx,
        project,
        lambda credentials: analyze_project_log(
            project, log_alias, since, until, max_lines, max_bytes, **credentials
        ),
    )
    if isinstance(report, mcp_types.InputRequiredResult):
        return report
    result = structured_report(report)
    result["rendered_findings"] = render_terminal(report)
    return result


async def _check_project(
    ctx: Context,
    project: Annotated[str, Field(min_length=1)],
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """Check every configured log alias of a project without running analyzers."""
    check = await _with_ssh_retry(
        ctx,
        project,
        lambda credentials: services.check_project(project, **credentials),
    )
    if isinstance(check, mcp_types.InputRequiredResult):
        return check
    return structured_check(check)


async def _list_log_files(
    ctx: Context,
    project: Annotated[str, Field(min_length=1)],
    log_alias: Annotated[str, Field(min_length=1)],
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """List files matched by a configured glob log alias, newest first (bounded)."""
    listing = await _with_ssh_retry(
        ctx,
        project,
        lambda credentials: services.list_project_log_files(
            project, log_alias, **credentials
        ),
    )
    if isinstance(listing, mcp_types.InputRequiredResult):
        return listing
    return structured_listing(listing)


async def _traffic_summary(
    ctx: Context,
    project: Annotated[str, Field(min_length=1)],
    log_alias: Annotated[str, Field(min_length=1)],
    since: str = "all",
    until: str | None = None,
    max_lines: Annotated[int | None, Field(gt=0)] = None,
    max_bytes: Annotated[int | None, Field(gt=0)] = None,
    top_n: Annotated[int, Field(ge=1, le=MAX_TOP_N)] = DEFAULT_TOP_N,
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """Summarize web traffic (top IPs, statuses, paths, agents, per-minute load)."""
    report = await _with_ssh_retry(
        ctx,
        project,
        lambda credentials: services.summarize_project_traffic(
            project,
            log_alias,
            since,
            until,
            max_lines,
            max_bytes,
            top_n=top_n,
            **credentials,
        ),
    )
    if isinstance(report, mcp_types.InputRequiredResult):
        return report
    return report.model_dump(mode="json")


async def _security_scan(
    ctx: Context,
    project: Annotated[str, Field(min_length=1)],
    log_alias: Annotated[str, Field(min_length=1)],
    since: str = "all",
    until: str | None = None,
    max_lines: Annotated[int | None, Field(gt=0)] = None,
    max_bytes: Annotated[int | None, Field(gt=0)] = None,
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """Report scanner probes, login guessing, and locally configured Tor matches."""
    report = await _with_ssh_retry(
        ctx,
        project,
        lambda credentials: services.scan_project_security(
            project, log_alias, since, until, max_lines, max_bytes, **credentials
        ),
    )
    if isinstance(report, mcp_types.InputRequiredResult):
        return report
    return report.model_dump(mode="json")


for _function, _name in (
    (_analyze_project_log, "analyze_project_log"),
    (_check_project, "check_project"),
    (_list_log_files, "list_log_files"),
    (_traffic_summary, "traffic_summary"),
    (_security_scan, "security_scan"),
):
    mcp.add_tool(_function, name=_name, structured_output=True)
    mcp._tool_manager._tools[_name].parameters["additionalProperties"] = False


def main() -> None:
    """Run the MCP server over stdio."""
    asyncio.run(mcp.run_stdio_async())

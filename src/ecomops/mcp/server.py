from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from ecomops.core.exceptions import EcomOpsError, SSHPermissionDeniedError
from ecomops.core.services import analyze_project_log
from ecomops.reports.terminal import render_terminal

from .schemas import structured_report


class ReadOnlyMCPServer(MCPServer):
    """MCP server with an explicit closed input surface for read-only tools."""

    _analysis_arguments = frozenset(
        {"project", "log_alias", "since", "until", "max_lines", "max_bytes"}
    )

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Any = None
    ) -> Any:
        if name == "analyze_project_log":
            unknown = sorted(set(arguments) - self._analysis_arguments)
            if unknown:
                raise ToolError(f"Unknown arguments: {', '.join(unknown)}")
        return await super().call_tool(name, arguments, context)


mcp = ReadOnlyMCPServer("ecomops")


async def _elicit_ssh_access_check() -> None:
    """Hook for a future client-side access check; it never collects secrets."""


async def _analyze_project_log(
    project: Annotated[str, Field(min_length=1)],
    log_alias: Annotated[str, Field(min_length=1)],
    since: str = "all",
    until: str | None = None,
    max_lines: Annotated[int | None, Field(gt=0)] = None,
    max_bytes: Annotated[int | None, Field(gt=0)] = None,
) -> dict[str, Any]:
    """Analyze one configured project log using bounded read-only access."""
    try:
        report = analyze_project_log(
            project, log_alias, since, until, max_lines, max_bytes
        )
    except SSHPermissionDeniedError:
        await _elicit_ssh_access_check()
        raise ToolError(
            "SSH access was denied. Configure the project's SSH agent or key."
        ) from None
    except EcomOpsError as exc:
        raise ToolError(str(exc)) from None

    result = structured_report(report)
    result["rendered_findings"] = render_terminal(report)
    return result


mcp.add_tool(_analyze_project_log, name="analyze_project_log", structured_output=True)
mcp._tool_manager._tools["analyze_project_log"].parameters["additionalProperties"] = (
    False
)


def main() -> None:
    """Run the MCP server over stdio."""
    asyncio.run(mcp.run_stdio_async())

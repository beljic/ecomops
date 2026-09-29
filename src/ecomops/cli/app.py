import os
from getpass import getpass
from pathlib import Path
from typing import Literal

import typer
from pydantic import ValidationError

from ecomops import __version__
from ecomops.ai.enrichment import enrich_report
from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.cron import CronAnalyzer
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.nginx import NginxAnalyzer
from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.config.log_policy import LogPathPolicyViolation, check_log_path
from ecomops.config.projects import ProjectRegistry
from ecomops.config.schema import SSHConnectionConfig
from ecomops.core.exceptions import EcomOpsError
from ecomops.core.models import AnalysisContext, LogSource
from ecomops.core.services import analyze_project_log, check_project
from ecomops.logs.readers import read_local_file
from ecomops.reports.check import (
    render_check_json,
    render_check_markdown,
    render_check_terminal,
)
from ecomops.reports.render import render_report

MAX_PASSWORD_STDIN_CHARS = 4_096

app = typer.Typer(
    name="ecomops",
    help="EcomOps Log Analyzer - analyze ecommerce logs from the terminal.",
    no_args_is_help=True,
)


@app.callback()
def callback() -> None:
    """EcomOps Log Analyzer command group."""


@app.command()
def analyze(
    path: Path,
    output_format: Literal["terminal", "json", "markdown"] = typer.Option(
        "terminal", "--format"
    ),
    ai: bool = typer.Option(False, "--ai"),
    ai_provider: str = typer.Option("noop", "--ai-provider"),
) -> None:
    """Analyze a local log file."""
    if not path.is_file():
        raise typer.BadParameter(f"File not found: {path}", param_hint="path")
    real_path = Path(os.path.realpath(path))
    try:
        check_log_path(real_path, [real_path.parent])
    except LogPathPolicyViolation as error:
        raise typer.BadParameter(
            f"Log path policy: {error}", param_hint="path"
        ) from None
    source = LogSource(type="local", path=str(path))
    context = AnalysisContext(source=source)
    entries = list(read_local_file(path))
    report = AnalyzerPipeline(
        [
            PhpAnalyzer(),
            MagentoAnalyzer(),
            NginxAnalyzer(),
            MySQLAnalyzer(),
            CronAnalyzer(),
        ]
    ).run(entries, context)
    if ai:
        try:
            report = enrich_report(report, context, ai_provider)
        except ValueError as error:
            raise typer.BadParameter(str(error), param_hint="--ai-provider") from error
    typer.echo(render_report(report, output_format))


@app.command("project")
def project(
    arguments: list[str],
    since: str = typer.Option("all", "--since"),
    until: str | None = typer.Option(None, "--until"),
    max_lines: int | None = typer.Option(None, "--max-lines", min=1),
    max_bytes: int | None = typer.Option(None, "--max-bytes", min=1),
    output_format: Literal["terminal", "json", "markdown"] = typer.Option(
        "terminal", "--format"
    ),
    ai: bool = typer.Option(False, "--ai"),
    ai_provider: str = typer.Option("noop", "--ai-provider"),
    prompt_password: bool = typer.Option(
        False,
        "--prompt-password",
        help="Ask for an SSH password without echo; kept in memory for this run.",
    ),
    password_stdin: bool = typer.Option(
        False,
        "--password-stdin",
        help="Read an SSH password from stdin (one trailing newline is removed).",
    ),
) -> None:
    """List, show, check, or analyze configured projects."""
    try:
        if arguments == ["list"]:
            for configured_project in ProjectRegistry.load().all():
                typer.echo(
                    f"{configured_project.name} "
                    f"({configured_project.connection.type.upper()})"
                )
            return

        if len(arguments) == 2 and arguments[0] == "show":
            configured_project = ProjectRegistry.load().get(arguments[1])
            typer.echo(f"Project: {configured_project.name}")
            typer.echo(f"Platform: {configured_project.platform}")
            typer.echo(f"Connection: {configured_project.connection.type.upper()}")
            typer.echo("Log aliases:")
            for alias, config in configured_project.log_aliases.items():
                typer.echo(f"  {alias}: {config.type} ({config.path})")
            return

        if len(arguments) == 2 and arguments[1] == "check":
            check = check_project(
                arguments[0],
                ssh_password=_ssh_password(
                    arguments[0], prompt_password, password_stdin
                ),
            )
            if output_format == "json":
                typer.echo(render_check_json(check))
            elif output_format == "markdown":
                typer.echo(render_check_markdown(check))
            else:
                typer.echo(render_check_terminal(check))
            return

        if len(arguments) != 3 or arguments[1] != "analyze":
            raise typer.BadParameter(
                "Expected 'list', 'show <name>', '<name> check', "
                "or '<name> analyze <alias>'."
            )

        ssh_password = _ssh_password(arguments[0], prompt_password, password_stdin)

        report = analyze_project_log(
            arguments[0],
            arguments[2],
            since=since,
            until=until,
            max_lines=max_lines,
            max_bytes=max_bytes,
            ssh_password=ssh_password,
        )
        if ai:
            context = AnalysisContext(
                source=report.source,
                project_name=report.source.project,
                since=since,
            )
            report = enrich_report(report, context, ai_provider)
    except (EcomOpsError, ValidationError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(render_report(report, output_format))


def _ssh_password(
    project_name: str, prompt_password: bool, password_stdin: bool
) -> str | None:
    """Collect an ephemeral SSH password; it is never stored or echoed."""
    if prompt_password and password_stdin:
        raise typer.BadParameter(
            "Use either --password-stdin or --prompt-password, not both."
        )
    if not prompt_password and not password_stdin:
        return None
    option = "--password-stdin" if password_stdin else "--prompt-password"
    configured_project = ProjectRegistry.load().get(project_name)
    if not isinstance(configured_project.connection, SSHConnectionConfig):
        raise typer.BadParameter(f"{option} is only valid for SSH projects.")
    if password_stdin:
        return _read_password_stdin()
    return getpass(
        f"SSH password for {configured_project.connection.user}@"
        f"{configured_project.connection.host}: "
    )


def _read_password_stdin() -> str:
    data = typer.get_text_stream("stdin").read(MAX_PASSWORD_STDIN_CHARS + 1)
    if len(data) > MAX_PASSWORD_STDIN_CHARS:
        raise typer.BadParameter("Password from --password-stdin is too long.")
    if data.endswith("\r\n"):
        data = data[:-2]
    elif data.endswith("\n"):
        data = data[:-1]
    if not data:
        raise typer.BadParameter("Password from --password-stdin is empty.")
    return data


@app.command()
def version() -> None:
    """Print the installed EcomOps Log Analyzer version."""
    typer.echo(f"ecomops {__version__}")


def main() -> None:
    app()

import os
from getpass import getpass
from pathlib import Path
from typing import Any, Literal

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
from ecomops.analyzers.traffic import DEFAULT_TOP_N, MAX_TOP_N
from ecomops.config.log_policy import LogPathPolicyViolation, check_log_path
from ecomops.config.projects import ProjectRegistry
from ecomops.config.schema import SSHConnectionConfig
from ecomops.core.exceptions import EcomOpsError
from ecomops.core.models import (
    AnalysisContext,
    LogSource,
    SecurityReport,
    TrafficReport,
)
from ecomops.core.services import (
    analyze_project_log,
    check_project,
    scan_project_security,
    summarize_project_traffic,
)
from ecomops.logs.inspection import ProjectCheck
from ecomops.logs.readers import read_local_file
from ecomops.reports.check import (
    render_check_json,
    render_check_markdown,
    render_check_terminal,
)
from ecomops.reports.render import ReportFormat, render_report
from ecomops.reports.structured import render_text, security_lines, traffic_lines

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
    top: int = typer.Option(
        DEFAULT_TOP_N,
        "--top",
        min=1,
        max=MAX_TOP_N,
        help="Top-N size for traffic or unclassified error groups.",
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
    """List, show, check, analyze, traffic, or security for configured projects."""
    try:
        if arguments == ["list"]:
            _list_projects()
            return
        if len(arguments) == 2 and arguments[0] == "show":
            _show_project(arguments[1])
            return
        if len(arguments) not in (2, 3) or arguments[1] not in _PROJECT_ACTIONS:
            raise typer.BadParameter(
                "Expected 'list', 'show <name>', '<name> check', or "
                "'<name> analyze|traffic|security <alias>'."
            )
        name, action, *rest = arguments
        if (action == "check") != (not rest):
            raise typer.BadParameter(
                f"'{action}' takes {'no' if action == 'check' else 'one'} alias."
            )
        ssh_password = _ssh_password(name, prompt_password, password_stdin)
        read_options: dict[str, Any] = {
            "since": since,
            "until": until,
            "max_lines": max_lines,
            "max_bytes": max_bytes,
            "ssh_password": ssh_password,
        }
        output = _run_project_action(
            name,
            action,
            rest[0] if rest else None,
            read_options,
            output_format,
            top=top,
            ai=ai,
            ai_provider=ai_provider,
        )
    except (EcomOpsError, ValidationError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(output)


_PROJECT_ACTIONS = frozenset({"check", "analyze", "traffic", "security"})


def _run_project_action(
    name: str,
    action: str,
    alias: str | None,
    read_options: dict[str, Any],
    output_format: ReportFormat,
    *,
    top: int,
    ai: bool,
    ai_provider: str,
) -> str:
    if action == "check" or alias is None:
        check = check_project(name, ssh_password=read_options["ssh_password"])
        return _render_check(check, output_format)
    if action == "traffic":
        traffic = summarize_project_traffic(name, alias, top_n=top, **read_options)
        return _render_structured(traffic, traffic_lines(traffic), output_format)
    if action == "security":
        security = scan_project_security(name, alias, **read_options)
        return _render_structured(security, security_lines(security), output_format)
    return _analyze(name, alias, read_options, output_format, ai, ai_provider, top)


def _list_projects() -> None:
    for configured_project in ProjectRegistry.load().all():
        typer.echo(
            f"{configured_project.name} ({configured_project.connection.type.upper()})"
        )


def _show_project(name: str) -> None:
    configured_project = ProjectRegistry.load().get(name)
    typer.echo(f"Project: {configured_project.name}")
    typer.echo(f"Platform: {configured_project.platform}")
    typer.echo(f"Connection: {configured_project.connection.type.upper()}")
    typer.echo("Log aliases:")
    for alias, config in configured_project.log_aliases.items():
        typer.echo(f"  {alias}: {config.type} ({config.path})")


def _render_check(check: ProjectCheck, output_format: str) -> str:
    if output_format == "json":
        return render_check_json(check)
    if output_format == "markdown":
        return render_check_markdown(check)
    return render_check_terminal(check)


def _render_structured(
    report: TrafficReport | SecurityReport, lines: list[str], output_format: str
) -> str:
    if output_format == "json":
        return report.model_dump_json(indent=2)
    return render_text(lines, output_format)


def _analyze(
    name: str,
    alias: str,
    read_options: dict[str, Any],
    output_format: ReportFormat,
    ai: bool,
    ai_provider: str,
    top_n: int,
) -> str:
    report = analyze_project_log(name, alias, top_n=top_n, **read_options)
    if ai:
        context = AnalysisContext(
            source=report.source,
            project_name=report.source.project,
            since=read_options["since"],
        )
        report = enrich_report(report, context, ai_provider)
    return render_report(report, output_format)


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

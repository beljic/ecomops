from pathlib import Path

import typer

from ecomops import __version__
from ecomops.analyzers.pipeline import AnalyzerPipeline
from ecomops.analyzers.rules.cron import CronAnalyzer
from ecomops.analyzers.rules.magento import MagentoAnalyzer
from ecomops.analyzers.rules.mysql import MySQLAnalyzer
from ecomops.analyzers.rules.nginx import NginxAnalyzer
from ecomops.analyzers.rules.php import PhpAnalyzer
from ecomops.core.models import AnalysisContext, LogSource
from ecomops.logs.readers import read_local_file
from ecomops.reports.terminal import render_terminal

app = typer.Typer(
    name="ecomops",
    help="EcomOps Log Analyzer - analyze ecommerce logs from the terminal.",
    no_args_is_help=True,
)


@app.callback()
def callback() -> None:
    """EcomOps Log Analyzer command group."""


@app.command()
def analyze(path: Path) -> None:
    """Analyze a local log file."""
    if not path.is_file():
        raise typer.BadParameter(f"File not found: {path}", param_hint="path")
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
    typer.echo(render_terminal(report))


@app.command()
def version() -> None:
    """Print the installed EcomOps Log Analyzer version."""
    typer.echo(f"ecomops {__version__}")


def main() -> None:
    app()

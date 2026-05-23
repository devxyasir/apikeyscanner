"""
CLI interface for apikeyscanner.
Built with Typer for argument parsing and Rich for beautiful terminal output.
"""

from __future__ import annotations

from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.text import Text

from . import __version__
from .reporter import save_json_report
from .scanner import scan as run_scan

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

app = typer.Typer(
    name="apikeyscanner",
    help="🔍 A local secret leak detection tool for developers and DevOps teams.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True, style="red")

# Severity color map
SEVERITY_COLORS = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}


# ──────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────

@app.command()
def scan(
    path: Annotated[
        str,
        typer.Argument(help="File or directory to scan."),
    ] = ".",
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Recursively scan subdirectories (default: True)."),
    ] = True,
    output: Annotated[
        Optional[str],
        typer.Option("--output", "-o", help="Save results to a JSON report file."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print results as raw JSON (useful for piping)."),
    ] = False,
    severity: Annotated[
        Optional[str],
        typer.Option(
            "--severity",
            "-s",
            help="Filter findings by severity: HIGH, MEDIUM, LOW (comma-separated).",
        ),
    ] = None,
    ignore: Annotated[
        Optional[list[str]],
        typer.Option("--ignore", "-i", help="Extra directory names to ignore (repeatable, or comma/space separated)."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed log output."),
    ] = False,
):
    """
    Scan a file or directory for leaked API keys, tokens, and secrets.

    Examples:

      apikeyscanner scan ./config.py

      apikeyscanner scan ./src

      apikeyscanner scan . --severity HIGH

      apikeyscanner scan . --output reports/report.json

      apikeyscanner scan . --ignore node_modules --ignore venv

      apikeyscanner scan . --json
    """

    # ── Header panel ──────────────────────────
    if not json_output:
        console.print()
        console.print(
            Panel.fit(
                "[bold white]API Key Scanner[/bold white]\n"
                "[dim]Local Secret Leak Detection Tool[/dim]",
                border_style="bright_blue",
                padding=(1, 4),
            )
        )
        console.print()
        console.print(f"  [dim]Target:[/dim]  [cyan]{path}[/cyan]")

    # ── Parse severity filter ─────────────────
    severity_filter: list[str] | None = None
    if severity:
        severity_filter = [s.strip().upper() for s in severity.split(",")]
        if not json_output:
            console.print(f"  [dim]Severity filter:[/dim] {', '.join(severity_filter)}")

    if not json_output:
        console.print()

    # ── Parse ignore filter ───────────────────
    processed_ignore: list[str] = []
    if ignore:
        import re
        for i in ignore:
            parts = [p.strip() for p in re.split(r'[,\s]+', i) if p.strip()]
            processed_ignore.extend(parts)

    # ── Run scan with spinner ─────────────────
    if not json_output:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("  Scanning files...", total=None)
            result = run_scan(
                path=path,
                severity=severity_filter,
                ignore=processed_ignore if processed_ignore else None,
                recursive=recursive,
                verbose=verbose,
            )
    else:
        result = run_scan(
            path=path,
            severity=severity_filter,
            ignore=processed_ignore if processed_ignore else None,
            recursive=recursive,
            verbose=verbose,
        )

    # ── JSON output mode ──────────────────────
    if json_output:
        typer.echo(result.to_json())
        raise typer.Exit(code=1 if result.has_findings else 0)

    # ── Display findings ──────────────────────
    if result.has_findings:
        console.print(
            f"  [bold red]Found {result.total_findings} possible secret(s)[/bold red]\n"
        )
        _print_findings_table(result.findings)
    else:
        console.print(
            "  [bold green]✅ No secrets found.[/bold green]\n"
            "  [dim]Your project looks clean.[/dim]\n"
        )

    # ── Summary panel ─────────────────────────
    _print_summary(result)

    # ── Save JSON report ──────────────────────
    if output:
        save_json_report(result, output, verbose=verbose)
        console.print(f"\n  [dim]📄 Report saved to:[/dim] [cyan]{output}[/cyan]")

    # ── Exit code ─────────────────────────────
    raise typer.Exit(code=1 if result.has_findings else 0)


@app.command()
def version():
    """Show the current version of apikeyscanner."""
    console.print(f"apikeyscanner [bold cyan]v{__version__}[/bold cyan]")


# ──────────────────────────────────────────────
# Display Helpers
# ──────────────────────────────────────────────

def _print_findings_table(findings) -> None:
    """Render findings as a Rich table."""
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold white",
        border_style="dim",
        padding=(0, 1),
    )

    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=28)
    table.add_column("File", width=36)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Match", width=22)

    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            Text(finding.severity, style=color),
            finding.type,
            finding.file,
            str(finding.line),
            f"[dim]{finding.match}[/dim]",
        )

    console.print(table)
    console.print()


def _print_summary(result) -> None:
    """Render a summary panel at the end of the scan."""
    status_color = "red" if result.has_findings else "green"
    status_text = "FAILED ❌" if result.has_findings else "PASSED ✅"

    lines = [
        f"  [dim]Scanned files:[/dim]  {result.scanned_files}",
        f"  [dim]Skipped files:[/dim]  {result.skipped_files}",
        f"  [dim]High findings:[/dim]  [bold red]{result.high_count}[/bold red]",
        f"  [dim]Medium findings:[/dim] [bold yellow]{result.medium_count}[/bold yellow]",
        f"  [dim]Low findings:[/dim]   [bold cyan]{result.low_count}[/bold cyan]",
        "",
        f"  [bold {status_color}]Security Status: {status_text}[/bold {status_color}]",
    ]

    if result.has_findings:
        lines.append(
            "  [dim]Fix the detected secrets before pushing or deploying.[/dim]"
        )

    summary_text = "\n".join(lines)

    console.print(
        Panel(
            summary_text,
            title="[bold white]Summary[/bold white]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )
    console.print()


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    app()


if __name__ == "__main__":
    main()

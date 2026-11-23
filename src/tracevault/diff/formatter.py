"""Human-readable, Rich, and JSON formatters for TraceVault DiffReport."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tracevault.diff.engine import find_earliest_divergence
from tracevault.schema import DiffReport, DivergenceSeverity

_SEVERITY_STYLES: dict[DivergenceSeverity, str] = {
    DivergenceSeverity.BREAKING: "bold red",
    DivergenceSeverity.WARNING: "bold yellow",
    DivergenceSeverity.INFO: "cyan",
}


def _format_value(value: Any) -> str:
    """Format a JSON-safe divergence value deterministically for verbose output."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _summary_counts(report: DiffReport) -> tuple[int, int, int, int]:
    breaking = report.summary.get(
        "breaking",
        sum(1 for d in report.divergences if d.severity == DivergenceSeverity.BREAKING),
    )
    warning = report.summary.get(
        "warning",
        sum(1 for d in report.divergences if d.severity == DivergenceSeverity.WARNING),
    )
    info = report.summary.get(
        "info",
        sum(1 for d in report.divergences if d.severity == DivergenceSeverity.INFO),
    )
    total = report.summary.get("total", len(report.divergences))
    return breaking, warning, info, total


def format_diff_report(report: DiffReport, *, verbose: bool = False) -> str:
    """Render a deterministic plain-text structural diff report."""
    status = "IDENTICAL" if report.identical else "DIVERGENT"
    breaking, warning, info, total = _summary_counts(report)

    lines: list[str] = [
        f"TraceVault Diff Report: {status}",
        f"Baseline : {report.baseline_trace_id}",
        f"Candidate: {report.candidate_trace_id}",
        f"Summary  : breaking={breaking}, warning={warning}, info={info}, total={total}",
    ]

    earliest = find_earliest_divergence(report)
    if earliest is not None:
        lines.append(
            f"Earliest : [{earliest.severity.value.upper()}] "
            f"{earliest.kind.value} at {earliest.path}: {earliest.message}"
        )

    if report.divergences:
        lines.append("")
        lines.append("Divergences:")
        for div in report.divergences:
            lines.append(
                f"  [{div.severity.value.upper()}] {div.kind.value} at {div.path}: {div.message}"
            )
            if verbose:
                lines.append(f"    baseline : {_format_value(div.baseline)}")
                lines.append(f"    candidate: {_format_value(div.candidate)}")

    return "\n".join(lines)


def render_diff_rich(report: DiffReport, *, console: Console | None = None) -> None:
    """Render a color-coded Rich panel and table for a DiffReport."""
    target_console = console if console is not None else Console()
    status = "IDENTICAL" if report.identical else "DIVERGENT"
    status_style = (
        "bold green" if report.identical else ("bold red" if report.has_breaking else "bold yellow")
    )
    breaking, warning, info, total = _summary_counts(report)

    header = Text()
    header.append("Status   : ", style="bold")
    header.append(f"{status}\n", style=status_style)
    header.append("Baseline : ", style="bold")
    header.append(f"{report.baseline_trace_id}\n")
    header.append("Candidate: ", style="bold")
    header.append(f"{report.candidate_trace_id}\n")
    header.append("Summary  : ", style="bold")
    header.append(f"breaking={breaking}", style="red" if breaking else "dim")
    header.append(", ")
    header.append(f"warning={warning}", style="yellow" if warning else "dim")
    header.append(", ")
    header.append(f"info={info}", style="cyan" if info else "dim")
    header.append(f", total={total}")

    earliest = find_earliest_divergence(report)
    if earliest is not None:
        header.append("\nEarliest : ", style="bold")
        header.append(
            f"[{earliest.severity.value.upper()}] ",
            style=_SEVERITY_STYLES[earliest.severity],
        )
        header.append(f"{earliest.kind.value} at {earliest.path}: {earliest.message}")

    border_style = "green" if report.identical else ("red" if report.has_breaking else "yellow")
    target_console.print(Panel(header, title="TraceVault Diff Report", border_style=border_style))

    if not report.divergences:
        return

    table = Table(title="Divergences", show_lines=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Path")
    table.add_column("Message")

    for div in report.divergences:
        sev_text = Text(div.severity.value.upper(), style=_SEVERITY_STYLES[div.severity])
        table.add_row(sev_text, Text(div.kind.value), Text(div.path), Text(div.message))

    target_console.print(table)


def format_diff_json(report: DiffReport, *, indent: int = 2) -> str:
    """Serialize a DiffReport to deterministic indented JSON."""
    return report.model_dump_json(indent=indent)


__all__ = [
    "format_diff_json",
    "format_diff_report",
    "render_diff_rich",
]

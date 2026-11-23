"""Typer CLI application for TraceVault."""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tracevault import __version__
from tracevault.assertions import (
    assert_no_breaking_diffs,
    assert_no_secrets_leaked,
    assert_replay_clean,
    assert_trace_valid,
)
from tracevault.diff import (
    diff_traces,
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)
from tracevault.pytest_plugin import load_regression_trace
from tracevault.schema import (
    SCHEMA_VERSION,
    DiffConfig,
    ExportFormat,
    FixtureNotFoundError,
    InvalidTraceIdError,
    PolicyViolationError,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    RunStatus,
    Trace,
    TraceFrozenError,
    TraceNotFoundError,
    TraceVaultError,
    UnsafeTraceError,
    redact_data,
)
from tracevault.storage import TraceStore, TraceSummary

app = typer.Typer(
    name="tracevault",
    help="Local-first AI execution capture, replay, diff, and regression testing engine.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console(width=120)
err_console = Console(stderr=True, width=120)


def _resolve_store_path(store: Path | None) -> Path:
    """Resolve the active store directory from CLI option or TRACEVAULT_STORE environment var."""
    if store is not None:
        return store
    env_store = os.environ.get("TRACEVAULT_STORE")
    if env_store and env_store.strip():
        return Path(env_store.strip())
    return Path(".tracevault")


@contextlib.contextmanager
def _open_store(store: Path | None) -> Iterator[TraceStore]:
    """Open a TraceStore context guaranteeing SQLite connections close cleanly on exit."""
    store_path = _resolve_store_path(store)
    with TraceStore(store_path) as trace_store:
        yield trace_store


def _is_file_target(target: str) -> bool:
    """Return True if target looks like a JSON file path rather than a store trace_id."""
    return target.lower().endswith(".json") or "/" in target or "\\" in target


def _load_trace_target(store: TraceStore, target: str) -> Trace:
    """Load a Trace either from a .json file path or from the TraceStore by trace_id."""
    if _is_file_target(target):
        return load_regression_trace(target)
    candidate_path = Path(target)
    if candidate_path.is_file() and candidate_path.suffix.lower() == ".json":
        return load_regression_trace(candidate_path)
    return store.load(target)


def _emit_json(payload: Any) -> None:
    """Print deterministic, UTF-8 safe JSON output directly to stdout."""
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False))


def _handle_cli_error(exc: Exception, *, json_output: bool) -> None:
    """Render expected domain and user errors cleanly without raw Python tracebacks."""
    safe_message = str(redact_data(str(exc)))
    error_type = type(exc).__name__
    if json_output:
        _emit_json({"error": safe_message, "error_type": error_type})
    else:
        err_text = Text(f"Error ({error_type}): ", style="bold red")
        err_text.append(safe_message)
        err_console.print(err_text)
    raise typer.Exit(code=1) from exc


_HANDLED_EXCEPTIONS: tuple[type[Exception], ...] = (
    TraceNotFoundError,
    InvalidTraceIdError,
    TraceFrozenError,
    UnsafeTraceError,
    FileExistsError,
    FileNotFoundError,
    FixtureNotFoundError,
    PolicyViolationError,
    ReplayError,
    TraceVaultError,
    AssertionError,
    ValueError,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"tracevault {__version__} (schema {SCHEMA_VERSION})")
        raise typer.Exit(code=0)


@app.callback()
def main_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show TraceVault version and schema version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """TraceVault command-line interface."""


@app.command("version")
def version_cmd(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit version details as JSON."),
    ] = False,
) -> None:
    """Display the TraceVault package version and canonical schema version."""
    if json_output:
        _emit_json({"version": __version__, "schema_version": SCHEMA_VERSION})
    else:
        typer.echo(f"tracevault {__version__} (schema {SCHEMA_VERSION})")


@app.command("init")
def init_cmd(
    store: Annotated[
        Path | None,
        typer.Option(
            "--store",
            "-s",
            help=(
                "Path to the TraceVault store directory "
                "(defaults to TRACEVAULT_STORE or .tracevault)."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit initialization result as JSON."),
    ] = False,
) -> None:
    """Initialize a local TraceVault store directory and SQLite metadata index."""
    try:
        with _open_store(store) as trace_store:
            initialized_path = trace_store.init()
        if json_output:
            _emit_json({"status": "initialized", "store": str(initialized_path)})
        else:
            console.print(
                f"[bold green]Initialized TraceVault store at:[/bold green] {initialized_path}"
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("list")
def list_cmd(
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    status: Annotated[
        str | None,
        typer.Option(
            "--status", help="Filter by run status (running, completed, failed, cancelled)."
        ),
    ] = None,
    tag: Annotated[
        str | None,
        typer.Option("--tag", help="Filter traces containing the specified tag."),
    ] = None,
    frozen: Annotated[
        bool | None,
        typer.Option("--frozen/--unfrozen", help="Filter by frozen or unfrozen trace state."),
    ] = None,
    query: Annotated[
        str | None,
        typer.Option("--query", "-q", help="Substring search over trace_id or run name."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Maximum number of traces to list."),
    ] = 100,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit trace summaries as a JSON array."),
    ] = False,
) -> None:
    """List traces in the store with optional status, tag, frozen, and query filters."""
    try:
        parsed_status: RunStatus | None = None
        if status is not None:
            try:
                parsed_status = RunStatus(status.lower())
            except ValueError as exc:
                valid_statuses = ", ".join(s.value for s in RunStatus)
                raise ValueError(
                    f"Invalid --status {status!r}. Expected one of: {valid_statuses}"
                ) from exc

        with _open_store(store) as trace_store:
            summaries: list[TraceSummary] = trace_store.list_traces(
                status=parsed_status,
                tag=tag,
                frozen=frozen,
                query=query,
                limit=limit,
            )

        if json_output:
            _emit_json([s.model_dump(mode="json") for s in summaries])
            return

        if not summaries:
            console.print("[dim]No traces found.[/dim]")
            return

        table = Table(title=f"Traces ({len(summaries)})", show_lines=False)
        table.add_column("Trace ID", style="bold cyan", no_wrap=True)
        table.add_column("Name")
        table.add_column("Status", no_wrap=True)
        table.add_column("Frozen", no_wrap=True)
        table.add_column("Spans", justify="right")
        table.add_column("Events", justify="right")
        table.add_column("Fixtures", justify="right")
        table.add_column("Created At", no_wrap=True)
        table.add_column("Tags")

        for item in summaries:
            status_style = (
                "green"
                if item.status == RunStatus.COMPLETED
                else ("red" if item.status == RunStatus.FAILED else "yellow")
            )
            table.add_row(
                Text(item.trace_id),
                Text(item.run_name),
                Text(item.status.value, style=status_style),
                "yes" if item.frozen else "no",
                str(item.span_count),
                str(item.event_count),
                str(item.fixture_count),
                item.created_at.isoformat(),
                Text(", ".join(item.tags) if item.tags else "-"),
            )

        console.print(table)
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


def _render_trace_details(
    trace: Trace,
    *,
    show_spans: bool,
    show_events: bool,
    show_fixtures: bool,
    show_metadata: bool,
    json_output: bool,
) -> None:
    """Render a Trace summary and requested detail tables in Rich or JSON."""
    if json_output:
        _emit_json(json.loads(trace.to_json(indent=2)))
        return

    root = trace.root_run
    status_style = (
        "bold green"
        if root.status == RunStatus.COMPLETED
        else ("bold red" if root.status == RunStatus.FAILED else "bold yellow")
    )

    summary = Text()
    summary.append("Trace ID        : ", style="bold")
    summary.append(f"{trace.trace_id}\n", style="cyan")
    summary.append("Parent Trace ID : ", style="bold")
    summary.append(f"{trace.parent_trace_id or '-'}\n")
    summary.append("Schema Version  : ", style="bold")
    summary.append(f"{trace.schema_version}\n")
    summary.append("Created At      : ", style="bold")
    summary.append(f"{trace.created_at.isoformat()}\n")
    summary.append("Frozen          : ", style="bold")
    summary.append(f"{'yes' if trace.frozen else 'no'}\n")
    summary.append("Redacted        : ", style="bold")
    summary.append(f"{'yes' if trace.redaction_applied else 'no'}\n")
    summary.append("Root Run        : ", style="bold")
    summary.append(f"{root.name} ({root.run_id})\n")
    summary.append("Status          : ", style="bold")
    summary.append(f"{root.status.value}\n", style=status_style)
    summary.append("Tags            : ", style="bold")
    summary.append(f"{', '.join(root.tags) if root.tags else '-'}\n")
    summary.append("Counts          : ", style="bold")
    summary.append(
        f"runs={len(trace.runs)}, spans={len(trace.spans)}, "
        f"events={len(trace.events)}, fixtures={len(trace.fixtures.entries)}\n"
    )
    summary.append("Inputs          : ", style="bold")
    summary.append(f"{json.dumps(redact_data(root.inputs), ensure_ascii=False)}\n")
    summary.append("Outputs         : ", style="bold")
    summary.append(f"{json.dumps(redact_data(root.outputs), ensure_ascii=False)}")
    if root.error is not None:
        summary.append("\nError           : ", style="bold red")
        summary.append(
            f"{root.error.error_type}: {redact_data(root.error.message)}",
            style="red",
        )

    console.print(Panel(summary, title=f"Trace {trace.trace_id}", border_style="cyan"))

    if show_spans:
        span_table = Table(title=f"Spans ({len(trace.spans)})", show_lines=False)
        span_table.add_column("Span ID", style="cyan", no_wrap=True)
        span_table.add_column("Name")
        span_table.add_column("Type", no_wrap=True)
        span_table.add_column("Boundary", no_wrap=True)
        span_table.add_column("Status", no_wrap=True)
        span_table.add_column("Parent", no_wrap=True)
        span_table.add_column("Events", justify="right")
        for sp in trace.spans:
            span_table.add_row(
                Text(sp.span_id),
                Text(sp.name),
                sp.span_type.value,
                sp.boundary.value if sp.boundary else "-",
                sp.status.value,
                Text(sp.parent_span_id or "-"),
                str(len(sp.event_ids)),
            )
        console.print(span_table)

    if show_events:
        event_table = Table(title=f"Events ({len(trace.events)})", show_lines=False)
        event_table.add_column("Seq", justify="right", no_wrap=True)
        event_table.add_column("Event ID", style="cyan", no_wrap=True)
        event_table.add_column("Type", no_wrap=True)
        event_table.add_column("Boundary", no_wrap=True)
        event_table.add_column("Span ID", no_wrap=True)
        event_table.add_column("Payload")
        for ev in sorted(trace.events, key=lambda e: e.sequence):
            event_table.add_row(
                str(ev.sequence),
                Text(ev.event_id),
                ev.event_type.value,
                ev.boundary.value if ev.boundary else "-",
                Text(ev.span_id or "-"),
                Text(json.dumps(redact_data(ev.payload), ensure_ascii=False)),
            )
        console.print(event_table)

    if show_fixtures:
        fixture_table = Table(
            title=f"Fixtures ({len(trace.fixtures.entries)})",
            show_lines=False,
        )
        fixture_table.add_column("Fixture ID", style="cyan", no_wrap=True)
        fixture_table.add_column("Boundary", no_wrap=True)
        fixture_table.add_column("Name")
        fixture_table.add_column("Call Index", justify="right")
        fixture_table.add_column("Fingerprint", no_wrap=True)
        fixture_table.add_column("Has Error", no_wrap=True)
        for fx in trace.fixtures.entries:
            fixture_table.add_row(
                Text(fx.fixture_id),
                fx.boundary.value,
                Text(fx.name or "-"),
                str(fx.call_index),
                fx.fingerprint[:16] + "...",
                "yes" if fx.error is not None else "no",
            )
        console.print(fixture_table)

    if show_metadata:
        meta_payload = {
            "trace_metadata": redact_data(trace.metadata),
            "run_metadata": redact_data(root.metadata),
            "environment": redact_data(root.environment),
        }
        console.print(
            Panel(
                Text(json.dumps(meta_payload, indent=2, ensure_ascii=False)),
                title="Metadata & Environment",
                border_style="blue",
            )
        )


@app.command("show")
def show_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a trace .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    spans: Annotated[
        bool,
        typer.Option("--spans", help="Include the spans table."),
    ] = False,
    events: Annotated[
        bool,
        typer.Option("--events", help="Include the ordered events table."),
    ] = False,
    fixtures: Annotated[
        bool,
        typer.Option("--fixtures", help="Include the recorded fixtures table."),
    ] = False,
    metadata: Annotated[
        bool,
        typer.Option("--metadata", help="Include trace and run metadata details."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the full canonical trace JSON."),
    ] = False,
) -> None:
    """Display summary and optional span, event, fixture, or metadata details for a trace."""
    try:
        with _open_store(store) as trace_store:
            trace = _load_trace_target(trace_store, trace_id)
        _render_trace_details(
            trace,
            show_spans=spans,
            show_events=events,
            show_fixtures=fixtures,
            show_metadata=metadata,
            json_output=json_output,
        )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("inspect")
def inspect_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a trace .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    spans: Annotated[
        bool,
        typer.Option("--spans/--no-spans", help="Include or hide the spans table."),
    ] = True,
    events: Annotated[
        bool,
        typer.Option("--events/--no-events", help="Include or hide the ordered events table."),
    ] = True,
    fixtures: Annotated[
        bool,
        typer.Option(
            "--fixtures/--no-fixtures", help="Include or hide the recorded fixtures table."
        ),
    ] = True,
    metadata: Annotated[
        bool,
        typer.Option(
            "--metadata/--no-metadata", help="Include or hide metadata and environment details."
        ),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the full canonical trace JSON."),
    ] = False,
) -> None:
    """Deeply inspect a trace (shows summary, spans, events, fixtures, and metadata by default)."""
    try:
        with _open_store(store) as trace_store:
            trace = _load_trace_target(trace_store, trace_id)
        _render_trace_details(
            trace,
            show_spans=spans,
            show_events=events,
            show_fixtures=fixtures,
            show_metadata=metadata,
            json_output=json_output,
        )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("freeze")
def freeze_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID to mark immutable."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit freeze result as JSON."),
    ] = False,
) -> None:
    """Freeze a trace so it cannot be overwritten or deleted without --force."""
    try:
        with _open_store(store) as trace_store:
            frozen_trace = trace_store.freeze(trace_id)
        if json_output:
            _emit_json({"trace_id": frozen_trace.trace_id, "frozen": frozen_trace.frozen})
        else:
            console.print(f"[bold green]Frozen trace:[/bold green] {frozen_trace.trace_id}")
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("delete")
def delete_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID to delete from the store."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force deletion even if the trace is frozen."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit delete confirmation as JSON."),
    ] = False,
) -> None:
    """Delete a trace from the store (requires --force if the trace is frozen)."""
    try:
        with _open_store(store) as trace_store:
            trace_store.delete(trace_id, force=force)
        if json_output:
            _emit_json({"trace_id": trace_id, "deleted": True, "forced": force})
        else:
            console.print(f"[bold green]Deleted trace:[/bold green] {trace_id}")
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


def _parse_overrides(raw_overrides: list[str] | None) -> dict[str, Any]:
    """Parse KEY=JSON_VALUE pairs into a dictionary of fixture overrides."""
    if not raw_overrides:
        return {}
    parsed: dict[str, Any] = {}
    for item in raw_overrides:
        if "=" not in item:
            raise ValueError(f"Invalid --override {item!r}: expected KEY=JSON_VALUE format")
        key, raw_val = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --override {item!r}: override key must be non-empty")
        try:
            val = json.loads(raw_val)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON value in --override {item!r}: {exc.msg}") from exc
        if not isinstance(val, dict):
            raise ValueError(
                f"Invalid --override {item!r}: override value must be a JSON object (dict)"
            )
        parsed[key] = val
    return parsed


@app.command("replay")
def replay_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a trace .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--lenient",
            help=(
                "Use OFFLINE_STRICT fingerprint matching (default) or "
                "OFFLINE_LENIENT fallback matching."
            ),
        ),
    ] = True,
    fork: Annotated[
        bool,
        typer.Option(
            "--fork", help="Set parent_trace_id on the candidate trace for lineage tracking."
        ),
    ] = False,
    save: Annotated[
        bool,
        typer.Option("--save", help="Persist the replayed candidate trace back into the store."),
    ] = False,
    new_id: Annotated[
        str | None,
        typer.Option("--new-id", help="Explicit trace_id for the replayed candidate trace."),
    ] = None,
    override: Annotated[
        list[str] | None,
        typer.Option(
            "--override",
            help=(
                "Override a fixture response by fixture_id or fingerprint "
                "(format: KEY=JSON_OBJECT)."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit replay result summary as JSON."),
    ] = False,
) -> None:
    """Execute deterministic offline replay for a captured trace without live network calls."""
    from tracevault.replay import ReplayEngine

    try:
        overrides = _parse_overrides(override)
        mode = ReplayMode.OFFLINE_STRICT if strict else ReplayMode.OFFLINE_LENIENT

        with _open_store(store) as trace_store:
            baseline = _load_trace_target(trace_store, trace_id)
            config = ReplayConfig(
                trace_id=baseline.trace_id,
                mode=mode,
                overrides=overrides,
            )
            engine = ReplayEngine(baseline, config=config)
            result = engine.replay_trace(fork=fork, new_trace_id=new_id)

            saved_path: Path | None = None
            if save:
                saved_path = trace_store.save(result.candidate_trace)

        overall_ok = result.success and not result.missing_fixtures

        if json_output:
            _emit_json(
                {
                    "baseline_trace_id": result.baseline_trace_id,
                    "candidate_trace_id": result.candidate_trace.trace_id,
                    "parent_trace_id": result.candidate_trace.parent_trace_id,
                    "mode": result.mode.value,
                    "success": overall_ok,
                    "matched_fixtures": result.matched_fixtures,
                    "overridden_fixtures": result.overridden_fixtures,
                    "missing_fixtures": result.missing_fixtures,
                    "live_calls": result.live_calls,
                    "saved": save,
                    "saved_path": str(saved_path) if saved_path is not None else None,
                    "error": (
                        result.error.model_dump(mode="json") if result.error is not None else None
                    ),
                }
            )
        else:
            status_label = "SUCCESS" if overall_ok else "FAILED"
            status_style = "bold green" if overall_ok else "bold red"
            body = Text()
            body.append("Status             : ", style="bold")
            body.append(f"{status_label}\n", style=status_style)
            body.append("Baseline Trace ID  : ", style="bold")
            body.append(f"{result.baseline_trace_id}\n")
            body.append("Candidate Trace ID : ", style="bold")
            body.append(f"{result.candidate_trace.trace_id}\n")
            body.append("Mode               : ", style="bold")
            body.append(f"{result.mode.value}\n")
            body.append("Matched Fixtures   : ", style="bold")
            body.append(f"{result.matched_fixtures}\n")
            body.append("Overridden         : ", style="bold")
            body.append(f"{result.overridden_fixtures}\n")
            body.append("Missing Fixtures   : ", style="bold")
            body.append(f"{len(result.missing_fixtures)}\n")
            body.append("Live Calls         : ", style="bold")
            body.append(f"{result.live_calls}\n")
            body.append("Saved              : ", style="bold")
            body.append(f"{str(saved_path) if saved_path is not None else 'no'}")
            if result.error is not None:
                body.append("\nError              : ", style="bold red")
                body.append(
                    f"{result.error.error_type}: {redact_data(result.error.message)}",
                    style="red",
                )
            console.print(
                Panel(
                    body,
                    title="TraceVault Offline Replay",
                    border_style="green" if overall_ok else "red",
                )
            )

        if not overall_ok:
            raise typer.Exit(code=1)
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("diff")
def diff_cmd(
    baseline_id: Annotated[
        str,
        typer.Argument(help="Baseline trace ID in the store or path to a baseline .json file."),
    ],
    candidate_id: Annotated[
        str,
        typer.Argument(help="Candidate trace ID in the store or path to a candidate .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    ignore_path: Annotated[
        list[str] | None,
        typer.Option("--ignore-path", help="Dot/bracket path(s) to ignore during diff comparison."),
    ] = None,
    compare_metadata: Annotated[
        bool,
        typer.Option("--compare-metadata", help="Include metadata fields in diff comparison."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Render plain-text verbose diff report with values."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the structured DiffReport as JSON."),
    ] = False,
) -> None:
    """Compare two traces and report structural, semantic, and behavioral divergences."""
    try:
        with _open_store(store) as trace_store:
            baseline = _load_trace_target(trace_store, baseline_id)
            candidate = _load_trace_target(trace_store, candidate_id)

        config = DiffConfig(
            ignore_paths=set(ignore_path or []),
            compare_metadata=compare_metadata,
        )
        report = diff_traces(baseline, candidate, config=config)

        if json_output:
            typer.echo(format_diff_json(report))
        elif verbose:
            typer.echo(format_diff_report(report, verbose=True))
        else:
            render_diff_rich(report, console=console)

        if report.has_breaking:
            raise typer.Exit(code=1)
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("export")
def export_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store to export."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination file path (.json or .jsonl)."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", help="Export file format: 'json' or 'jsonl'."),
    ] = "json",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit export result metadata as JSON."),
    ] = False,
) -> None:
    """Export a stored trace to an atomic JSON or JSONL file."""
    try:
        try:
            export_format = ExportFormat(fmt.lower())
        except ValueError as exc:
            raise ValueError(f"Invalid --format {fmt!r}. Expected 'json' or 'jsonl'.") from exc

        with _open_store(store) as trace_store:
            written_path = trace_store.export_trace(
                trace_id,
                output,
                format=export_format,
            )

        if json_output:
            _emit_json(
                {
                    "trace_id": trace_id,
                    "output": str(written_path),
                    "format": export_format.value,
                }
            )
        else:
            console.print(
                f"[bold green]Exported trace {trace_id} ({export_format.value}) to:[/bold green] "
                f"{written_path}"
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("import")
def import_cmd(
    input_path: Annotated[
        Path,
        typer.Argument(help="Path to the external trace .json file to import."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite", help="Allow replacing an existing unfrozen trace with the same ID."
        ),
    ] = False,
    freeze: Annotated[
        bool,
        typer.Option("--freeze", help="Mark the imported trace as frozen immediately."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit import result metadata as JSON."),
    ] = False,
) -> None:
    """Validate and import an external trace JSON file into the local store."""
    try:
        with _open_store(store) as trace_store:
            imported = trace_store.import_trace(
                input_path,
                overwrite=overwrite,
                freeze=freeze,
            )

        if json_output:
            _emit_json(
                {
                    "trace_id": imported.trace_id,
                    "frozen": imported.frozen,
                    "imported_from": str(input_path),
                }
            )
        else:
            console.print(
                f"[bold green]Imported trace:[/bold green] {imported.trace_id} "
                f"(frozen={'yes' if imported.frozen else 'no'})"
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("export-test")
def export_test_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a trace .json file."),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination path for the generated pytest .py file."),
    ],
    fixture_output: Annotated[
        Path | None,
        typer.Option(
            "--fixture-output",
            help="Optional path to also export a standalone redacted .json trace fixture.",
        ),
    ] = None,
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit generated regression test metadata as JSON."),
    ] = False,
) -> None:
    """Generate a standalone, Ruff-clean pytest regression test from a trace."""
    from tracevault.replay import generate_pytest_regression

    try:
        with _open_store(store) as trace_store:
            trace = _load_trace_target(trace_store, trace_id)

        written_test = generate_pytest_regression(
            trace,
            output,
            trace_path=fixture_output,
        )

        if json_output:
            _emit_json(
                {
                    "trace_id": trace.trace_id,
                    "test_path": str(written_test),
                    "fixture_path": str(fixture_output) if fixture_output is not None else None,
                }
            )
        else:
            console.print(
                f"[bold green]Generated pytest regression test for {trace.trace_id}:[/bold green] "
                f"{written_test}"
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("test")
def test_cmd(
    target: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a regression trace .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    export_test: Annotated[
        Path | None,
        typer.Option(
            "--export-test", help="Optional path to generate a pytest .py regression file."
        ),
    ] = None,
    fixture_output: Annotated[
        Path | None,
        typer.Option(
            "--fixture-output",
            help="Optional companion .json fixture path when --export-test is used.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--lenient", help="Run replay in OFFLINE_STRICT or OFFLINE_LENIENT mode."
        ),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit regression check results as JSON."),
    ] = False,
) -> None:
    """Run offline replay, schema & secret hygiene checks, and diff verification on a trace."""
    from tracevault.replay import ReplayEngine, generate_pytest_regression

    try:
        with _open_store(store) as trace_store:
            trace = _load_trace_target(trace_store, target)

        assert_trace_valid(trace)
        assert_no_secrets_leaked(trace)

        mode = ReplayMode.OFFLINE_STRICT if strict else ReplayMode.OFFLINE_LENIENT
        engine = ReplayEngine(trace, config=ReplayConfig(trace_id=trace.trace_id, mode=mode))
        replay_result = engine.replay_trace()
        assert_replay_clean(replay_result)

        report = diff_traces(trace, replay_result.candidate_trace)
        assert_no_breaking_diffs(report)

        exported_test_path: Path | None = None
        if export_test is not None:
            exported_test_path = generate_pytest_regression(
                trace,
                export_test,
                trace_path=fixture_output,
            )

        if json_output:
            _emit_json(
                {
                    "trace_id": trace.trace_id,
                    "passed": True,
                    "mode": mode.value,
                    "matched_fixtures": replay_result.matched_fixtures,
                    "identical": report.identical,
                    "has_breaking": report.has_breaking,
                    "exported_test": (
                        str(exported_test_path) if exported_test_path is not None else None
                    ),
                }
            )
        else:
            console.print(
                f"[bold green]PASS:[/bold green] Regression test succeeded for trace "
                f"[cyan]{trace.trace_id}[/cyan] "
                f"(matched_fixtures={replay_result.matched_fixtures}, "
                f"breaking_diffs=0)"
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


@app.command("verify")
def verify_cmd(
    trace_id: Annotated[
        str,
        typer.Argument(help="Trace ID in the store or path to a trace .json file."),
    ],
    store: Annotated[
        Path | None,
        typer.Option("--store", "-s", help="Path to the TraceVault store directory."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit verification result as JSON."),
    ] = False,
) -> None:
    """Verify a trace's schema integrity, round-trip serialization, and secret redaction hygiene."""
    try:
        with _open_store(store) as trace_store:
            trace = _load_trace_target(trace_store, trace_id)

        assert_trace_valid(trace)
        assert_no_secrets_leaked(trace)

        if json_output:
            _emit_json(
                {
                    "trace_id": trace.trace_id,
                    "valid": True,
                    "schema_version": trace.schema_version,
                    "redaction_applied": trace.redaction_applied,
                }
            )
        else:
            console.print(
                f"[bold green]VERIFIED:[/bold green] Trace [cyan]{trace.trace_id}[/cyan] is "
                f"schema-valid (v{trace.schema_version}) and passes secret hygiene checks."
            )
    except _HANDLED_EXCEPTIONS as exc:
        _handle_cli_error(exc, json_output=json_output)


__all__ = ["app"]

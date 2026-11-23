# TraceVault Structural Diff & Divergence Analysis

TraceVault's structural diff engine (`tracevault.diff`) compares two canonical `Trace` objects offline and produces a deterministic `DiffReport` explaining **where** execution diverged, **what** changed, and **how severe** each divergence is.

## Design Principles

- **100% Offline & Deterministic**: Never makes network calls, never mutates input traces, and always emits divergences in deterministic order.
- **Structure-Aware Alignment**: Compares runs, spans, events, and fixtures structurally rather than relying on fragile raw text diffs or regenerated UUIDs/timestamps.
- **Noise Filtering**: Ignores volatile timestamps and regenerated IDs by default (`ignore_timestamps=True`, `ignore_ids=True`), and supports exact, prefix, and `[*]` wildcard `ignore_paths`.
- **Actionable Classification**: Maps each difference to a canonical `DivergenceKind` and `DivergenceSeverity` (`INFO`, `WARNING`, `BREAKING`), with `find_earliest_divergence()` to pinpoint the root cause.

## Quick Start

```python
from tracevault import (
    DiffConfig,
    ReplayEngine,
    diff_traces,
    find_earliest_divergence,
    format_diff_report,
)

# Compare a baseline trace against a forked candidate trace
candidate = ReplayEngine(baseline).fork(
    overrides={baseline.fixtures.entries[0].fixture_id: {"status": "ok", "total": 42}}
)

report = diff_traces(baseline, candidate)
print(format_diff_report(report, verbose=True))

earliest = find_earliest_divergence(report)
if earliest is not None:
    print(f"Earliest divergence: [{earliest.severity}] {earliest.kind} at {earliest.path}")
```

## Public API

All diff APIs are available from both `tracevault` and `tracevault.diff`:

- `diff_traces(baseline, candidate, *, config=None, ignore_paths=None) -> DiffReport`
- `DiffEngine(config=None)` with `.compare(baseline, candidate, *, ignore_paths=None) -> DiffReport`
- `find_earliest_divergence(report) -> Divergence | None`
- `format_diff_report(report, *, verbose=False) -> str`
- `render_diff_rich(report, *, console=None) -> None`
- `format_diff_json(report, *, indent=2) -> str`
- `DEFAULT_SEVERITY_MAP: dict[DivergenceKind, DivergenceSeverity]`

## Configuration (`DiffConfig`)

| Option | Default | Description |
| --- | --- | --- |
| `ignore_paths` | `set()` | Exact paths, prefixes (e.g., `"runs[0].metadata"`), or wildcards (e.g., `"events[*].payload.request_id"`). |
| `ignore_timestamps` | `True` | Ignore `created_at`, `started_at`, `ended_at`, and event `timestamp` differences. |
| `ignore_ids` | `True` | Align runs, spans, events, and fixtures structurally without flagging regenerated IDs. |
| `compare_metadata` | `False` | When `True`, compare trace/run/event metadata and span attributes (`INFO` severity by default). |
| `strict_order` | `True` | When `True`, report `SPAN_ORDER_CHANGED` if matched spans appear in a different relative order. |
| `severity_overrides` | `{}` | Override the default `DivergenceSeverity` for specific `DivergenceKind` values. |

## Default Severity Mapping

| Severity | Divergence Kinds |
| --- | --- |
| **BREAKING** | `STATUS_CHANGED`, `OUTPUT_CHANGED`, `ERROR_CHANGED`, `SPAN_REMOVED`, `SPAN_STATUS_CHANGED`, `MODEL_OUTPUT_CHANGED`, `TOOL_ARGS_CHANGED`, `TOOL_RESULT_CHANGED`, `FIXTURE_MISMATCH` |
| **WARNING** | `SPAN_ADDED`, `SPAN_ORDER_CHANGED`, `MODEL_INPUT_CHANGED`, `RETRIEVAL_CHANGED`, `AGENT_TRANSITION_CHANGED`, `STATE_CHANGE_MISMATCH`, `EVENT_ADDED`, `EVENT_REMOVED`, `EVENT_PAYLOAD_CHANGED` |
| **INFO** | Metadata and non-breaking informational path changes (when `compare_metadata=True` or via `severity_overrides`) |

## Output Formats

- **Human-readable text**: `format_diff_report(report, verbose=False|True)`
- **Rich terminal UI**: `render_diff_rich(report, console=None)` renders a summary panel and color-coded divergence table.
- **Machine-readable JSON**: `format_diff_json(report, indent=2)` returns canonical JSON compatible with `DiffReport.model_validate_json(...)`.

## Runnable Examples

Run the offline example script with:

```bash
uv run python examples/diff_examples.py
```

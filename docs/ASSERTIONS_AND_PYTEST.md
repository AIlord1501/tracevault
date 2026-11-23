# TraceVault Assertions & Pytest Regression Testing

TraceVault turns captured AI execution traces into deterministic, offline automated regression tests with **zero mandatory LLM judge** and **zero live API calls**.

## End-to-End Regression Workflow

```
Production Failure → Capture → Freeze → Fork & Fix → Assert → Export Fixture & Pytest Test → CI
```

## 1. Assertion Engine (`tracevault.assertions`)

All assertions are deterministic, validate canonical schema structures, and **automatically redact sensitive values** in failure diagnostics.

### Programmatic Trace Assertions

| Function | Purpose |
| --- | --- |
| `assert_trace_valid(trace)` | Validates canonical schema and JSON round-trip invariants. |
| `assert_run_succeeded(trace, *, run_id=None)` | Asserts `status == RunStatus.COMPLETED` and `error is None`. |
| `assert_run_status(trace, expected_status, *, run_id=None)` | Asserts exact `RunStatus`. |
| `assert_run_output(trace, *, expected=None, subset=None, key=None, value=...)` | Exact, recursive subset, or key/value output matching. |
| `assert_span_exists(trace, name, *, span_type=None)` | Asserts span presence and returns the matching `Span`. |
| `assert_span_status(trace, name, expected_status=SpanStatus.OK, *, span_type=None)` | Asserts span completion status. |
| `assert_span_duration_under(trace, name, max_seconds, *, span_type=None)` | Asserts span timing bound in seconds. |
| `assert_event_exists(trace, event_type, *, boundary=None, payload_subset=None)` | Asserts event presence with optional boundary/payload filter. |
| `assert_event_absent(trace, event_type, *, boundary=None)` | Asserts event absence. |
| `assert_event_order(trace, expected_sequence, *, strict_contiguous=False)` | Asserts ordered subsequence (or contiguous window) of `EventKind`s. |
| `assert_tool_called(trace, tool_name, *, min_calls=1)` | Asserts a tool was called at least `min_calls` times. |
| `assert_tool_not_called(trace, tool_name)` | Asserts a tool was never called. |
| `assert_tool_output(trace, tool_name, *, expected_result=None, result_subset=None, call_index=0)` | Asserts exact or subset match on a tool's result payload. |
| `assert_model_called(trace, *, model=None, provider=None, min_calls=1)` | Asserts model request occurrences. |
| `assert_model_output(trace, *, expected_subset=None, contains_text=None, call_index=-1)` | Asserts model response subset or text content. |
| `assert_retrieval_results(trace, *, min_results=1, expected_subset=None, call_index=0)` | Asserts retrieval document counts and payload subset. |
| `assert_agent_transition(trace, *, to_agent, from_agent=None)` | Asserts multi-agent handoff events. |
| `assert_state_change(trace, state_key, *, expected_after=..., operation=None)` | Asserts state mutation events (`set`, `delete`, `merge`). |
| `assert_no_errors(trace)` | Asserts zero run, span, or event errors. |
| `assert_error_recorded(trace, *, error_type=None, message_contains=None)` | Asserts an `ExecutionError` was recorded. |
| `assert_no_secrets_leaked(trace)` | Verifies `redaction_applied=True` and scans for unredacted secrets. |

### Declarative Fluent Builder (`expect_trace`)

```python
from tracevault import RunStatus, SpanStatus, SpanType, expect_trace

expect_trace(trace) \
    .is_valid() \
    .succeeded() \
    .has_status(RunStatus.COMPLETED) \
    .has_output(subset={"decision": "approved"}) \
    .has_span("lookup_refund", span_type=SpanType.TOOL, status=SpanStatus.OK) \
    .called_tool("lookup_refund", result_subset={"eligible": True}) \
    .did_not_call_tool("delete_customer") \
    .called_model(model="gpt-4o-mini") \
    .has_no_errors() \
    .has_no_secrets_leaked()
```

### Replay & Diff Assertions

- `assert_replay_succeeded(result)`
- `assert_all_fixtures_matched(result)`
- `assert_no_live_calls(result)`
- `assert_replay_clean(result)`
- `assert_traces_equivalent(baseline, candidate, *, config=None)`
- `assert_no_breaking_diffs(report)`
- `assert_diff_matches_expectations(report, *, max_warnings=None, allowed_kinds=None)`

## 2. Portable Regression Fixture & Test Generation (`tracevault.replay`)

Convert any captured or forked trace into a scrubbed JSON fixture and a standalone, Ruff-clean pytest test file:

```python
from tracevault import export_regression_fixture, generate_pytest_regression

fixture_path = export_regression_fixture(fixed_trace, "tests/fixtures/refund_fix.json")
test_path = generate_pytest_regression(
    fixed_trace,
    "tests/test_refund_regression.py",
    trace_path=fixture_path,
)
```

Security guarantees:
- **Mandatory Redaction**: Both `export_regression_fixture` and `generate_pytest_regression` scrub the trace via `redact_data` prior to serialization so credentials never enter generated files.
- **Zero Code Injection**: All identifiers, paths, and expected payloads are emitted exclusively via `json.dumps(...)` without raw string interpolation.

## 3. Pytest Plugin (`tracevault.pytest_plugin`)

TraceVault registers a `pytest11` plugin (`tracevault.pytest_plugin.plugin`) providing zero-side-effect isolated fixtures:

- `tracevault_store`: Per-test isolated `TraceStore` in `tmp_path` (automatically closed on teardown).
- `tracevault_load_trace`: Loads a `Trace` by `trace_id`, JSON file `Path`, or `Trace` instance.
- `tracevault_replay`: Creates an offline `ReplayEngine` from a `trace_id`, JSON file `Path`, or `Trace` (with optional `overrides`).
- `tracevault_expect`: Provides the `expect_trace` fluent assertion builder.
- `verify_regression_trace(trace_path, *, config=None, diff_config=None) -> DiffReport`: Loads a regression trace JSON file, executes offline replay, asserts zero live calls / all fixtures matched / zero breaking diffs, and returns the `DiffReport`.

### Pytest CLI Flags & Marker

- `--tracevault-store PATH`: Optional fallback directory for looking up traces by `trace_id`.
- `--tracevault-lenient-replay`: Default `tracevault_replay` to `OFFLINE_LENIENT` mode.
- `@pytest.mark.tracevault_regression`: Marker for offline TraceVault regression tests.

## Runnable Example

```bash
uv run python examples/regression_examples.py
```

"""Deterministic programmatic and declarative assertions for TraceVault traces."""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from typing import Any

from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    Event,
    EventKind,
    ExecutionError,
    RedactionConfig,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    Trace,
    TraceVaultError,
    canonical_json,
    redact_data,
)

_UNSET = object()


def _safe_format(value: Any) -> str:
    """Format a value for assertion failure diagnostics with automatic secret redaction."""
    try:
        redacted = redact_data(value, config=RedactionConfig())
        return canonical_json(redacted)
    except Exception:
        return repr(REDACTED_VALUE)


def _matches_subset(actual: dict[str, Any], expected_subset: dict[str, Any]) -> bool:
    """Return True if all keys/values in expected_subset recursively match actual."""
    for key, exp_val in expected_subset.items():
        if key not in actual:
            return False
        act_val = actual[key]
        if isinstance(exp_val, dict) and isinstance(act_val, dict):
            if not _matches_subset(act_val, exp_val):
                return False
        elif act_val != exp_val:
            return False
    return True


def _resolve_run(trace: Trace, run_id: str | None) -> Run:
    if run_id is None:
        return trace.root_run
    for run in trace.runs:
        if run.run_id == run_id:
            return run
    available = [r.run_id for r in trace.runs]
    raise AssertionError(
        f"Run {run_id!r} not found in trace {trace.trace_id!r}. Available runs: {available}"
    )


def assert_trace_valid(trace: Trace) -> None:
    """Assert that a Trace object satisfies all canonical schema and round-trip invariants."""
    if not isinstance(trace, Trace):
        raise AssertionError(f"Expected Trace instance, got {type(trace).__name__}")
    try:
        raw_json = trace.to_json()
        reloaded = Trace.from_json(raw_json)
    except (TraceVaultError, ValueError, TypeError) as exc:
        raise AssertionError(f"Trace validation failed: {_safe_format(str(exc))}") from exc

    if reloaded.trace_id != trace.trace_id:
        raise AssertionError(
            f"Trace round-trip trace_id mismatch: expected {trace.trace_id!r}, "
            f"got {reloaded.trace_id!r}"
        )


def assert_run_status(
    trace: Trace,
    expected_status: RunStatus,
    *,
    run_id: str | None = None,
) -> Run:
    """Assert that the specified run (or root_run) has the expected RunStatus."""
    run = _resolve_run(trace, run_id)
    if run.status != expected_status:
        error_info = (
            f", error={_safe_format(run.error.model_dump(mode='json'))}"
            if run.error is not None
            else ""
        )
        raise AssertionError(
            f"Expected run {run.run_id!r} ({run.name!r}) in trace {trace.trace_id!r} "
            f"to have status {expected_status.value!r}, but got {run.status.value!r}{error_info}"
        )
    return run


def assert_run_succeeded(trace: Trace, *, run_id: str | None = None) -> None:
    """Assert that the specified run (or root_run) completed without error."""
    run = assert_run_status(trace, RunStatus.COMPLETED, run_id=run_id)
    if run.error is not None:
        raise AssertionError(
            f"Run {run.run_id!r} has status COMPLETED but contains an error: "
            f"{_safe_format(run.error.model_dump(mode='json'))}"
        )


def assert_run_output(
    trace: Trace,
    *,
    expected: dict[str, Any] | None = None,
    subset: dict[str, Any] | None = None,
    key: str | None = None,
    value: Any = _UNSET,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Assert properties of a run's outputs dictionary (exact match, subset, or key/value)."""
    run = _resolve_run(trace, run_id)
    if run.outputs is None:
        raise AssertionError(
            f"Expected run {run.run_id!r} in trace {trace.trace_id!r} to have outputs, "
            "but outputs is None"
        )
    outputs = run.outputs

    if expected is not None and outputs != expected:
        raise AssertionError(
            f"Run {run.run_id!r} outputs mismatch:\n"
            f"  expected: {_safe_format(expected)}\n"
            f"  actual  : {_safe_format(outputs)}"
        )

    if subset is not None and not _matches_subset(outputs, subset):
        raise AssertionError(
            f"Run {run.run_id!r} outputs do not contain expected subset:\n"
            f"  expected subset: {_safe_format(subset)}\n"
            f"  actual outputs : {_safe_format(outputs)}"
        )

    if key is not None:
        if key not in outputs:
            raise AssertionError(
                f"Expected key {key!r} in run {run.run_id!r} outputs, "
                f"available keys: {sorted(outputs.keys())}"
            )
        if value is not _UNSET and outputs[key] != value:
            raise AssertionError(
                f"Run {run.run_id!r} output[{key!r}] mismatch:\n"
                f"  expected: {_safe_format(value)}\n"
                f"  actual  : {_safe_format(outputs[key])}"
            )

    return outputs


def assert_span_exists(
    trace: Trace,
    name: str,
    *,
    span_type: SpanType | None = None,
) -> Span:
    """Assert that at least one span with the given name (and optional span_type) exists."""
    for span in trace.spans:
        if span.name == name and (span_type is None or span.span_type == span_type):
            return span
    available = [f"{s.name} ({s.span_type.value})" for s in trace.spans]
    type_filter = f" with span_type={span_type.value!r}" if span_type is not None else ""
    raise AssertionError(
        f"Span {name!r}{type_filter} not found in trace {trace.trace_id!r}. "
        f"Available spans: {available}"
    )


def assert_span_status(
    trace: Trace,
    name: str,
    expected_status: SpanStatus = SpanStatus.OK,
    *,
    span_type: SpanType | None = None,
) -> Span:
    """Assert that a span exists and has the expected SpanStatus."""
    span = assert_span_exists(trace, name, span_type=span_type)
    if span.status != expected_status:
        error_info = (
            f", error={_safe_format(span.error.model_dump(mode='json'))}"
            if span.error is not None
            else ""
        )
        raise AssertionError(
            f"Expected span {name!r} ({span.span_id!r}) to have status "
            f"{expected_status.value!r}, but got {span.status.value!r}{error_info}"
        )
    return span


def assert_span_duration_under(
    trace: Trace,
    name: str,
    max_seconds: float,
    *,
    span_type: SpanType | None = None,
) -> float:
    """Assert that a span completed within max_seconds and return its duration in seconds."""
    if max_seconds < 0:
        raise ValueError("max_seconds must be >= 0")
    span = assert_span_exists(trace, name, span_type=span_type)
    if span.ended_at is None:
        raise AssertionError(
            f"Span {name!r} ({span.span_id!r}) has ended_at=None; cannot verify duration"
        )
    duration = (span.ended_at - span.started_at).total_seconds()
    if duration > max_seconds:
        raise AssertionError(
            f"Span {name!r} duration {duration:.6f}s exceeded max_seconds={max_seconds:.6f}s"
        )
    return duration


def assert_event_exists(
    trace: Trace,
    event_type: EventKind,
    *,
    boundary: BoundaryType | None = None,
    payload_subset: dict[str, Any] | None = None,
) -> list[Event]:
    """Assert that at least one event matches event_type (and optional boundary/payload_subset)."""
    matches: list[Event] = []
    for event in trace.events:
        if event.event_type != event_type:
            continue
        if boundary is not None and event.boundary != boundary:
            continue
        if payload_subset is not None and not _matches_subset(event.payload, payload_subset):
            continue
        matches.append(event)

    if not matches:
        boundary_msg = f", boundary={boundary.value!r}" if boundary is not None else ""
        subset_msg = (
            f", payload_subset={_safe_format(payload_subset)}" if payload_subset is not None else ""
        )
        raise AssertionError(
            f"No event matching event_type={event_type.value!r}{boundary_msg}{subset_msg} "
            f"found in trace {trace.trace_id!r}"
        )
    return matches


def assert_event_absent(
    trace: Trace,
    event_type: EventKind,
    *,
    boundary: BoundaryType | None = None,
) -> None:
    """Assert that no event with the given event_type (and optional boundary) exists."""
    matches = [
        ev
        for ev in trace.events
        if ev.event_type == event_type and (boundary is None or ev.boundary == boundary)
    ]
    if matches:
        boundary_msg = f" (boundary={boundary.value!r})" if boundary is not None else ""
        raise AssertionError(
            f"Expected event_type={event_type.value!r}{boundary_msg} to be absent in trace "
            f"{trace.trace_id!r}, but found {len(matches)} occurrence(s)"
        )


def assert_event_order(
    trace: Trace,
    expected_sequence: Sequence[EventKind],
    *,
    strict_contiguous: bool = False,
) -> list[Event]:
    """Assert that events with the given EventKinds appear in the expected order."""
    if not expected_sequence:
        return []

    ordered_events = sorted(trace.events, key=lambda e: e.sequence)
    actual_kinds = [e.event_type for e in ordered_events]

    if strict_contiguous:
        window = len(expected_sequence)
        expected_list = list(expected_sequence)
        for idx in range(len(ordered_events) - window + 1):
            if actual_kinds[idx : idx + window] == expected_list:
                return ordered_events[idx : idx + window]
        raise AssertionError(
            f"Expected contiguous event sequence {[k.value for k in expected_sequence]} "
            f"not found in actual sequence {[k.value for k in actual_kinds]}"
        )

    matched: list[Event] = []
    target_idx = 0
    for event in ordered_events:
        if event.event_type == expected_sequence[target_idx]:
            matched.append(event)
            target_idx += 1
            if target_idx == len(expected_sequence):
                return matched

    raise AssertionError(
        f"Expected ordered event subsequence {[k.value for k in expected_sequence]} "
        f"not satisfied; matched up to index {target_idx} in "
        f"actual sequence {[k.value for k in actual_kinds]}"
    )


def assert_tool_called(
    trace: Trace,
    tool_name: str,
    *,
    min_calls: int = 1,
) -> list[Event]:
    """Assert that the specified tool was called at least min_calls times and return its events."""
    if min_calls < 1:
        raise ValueError("min_calls must be >= 1")

    matches: list[Event] = [
        ev
        for ev in trace.events
        if ev.event_type == EventKind.TOOL_CALL and ev.payload.get("tool_name") == tool_name
    ]
    if len(matches) < min_calls:
        called_tools = sorted(
            {
                str(ev.payload.get("tool_name"))
                for ev in trace.events
                if ev.event_type == EventKind.TOOL_CALL and "tool_name" in ev.payload
            }
        )
        raise AssertionError(
            f"Expected tool {tool_name!r} to be called at least {min_calls} time(s) in trace "
            f"{trace.trace_id!r}, but found {len(matches)} call(s). Called tools: {called_tools}"
        )
    return matches


def assert_tool_not_called(trace: Trace, tool_name: str) -> None:
    """Assert that the specified tool was never called in the trace."""
    matches = [
        ev
        for ev in trace.events
        if ev.event_type == EventKind.TOOL_CALL and ev.payload.get("tool_name") == tool_name
    ]
    if matches:
        raise AssertionError(
            f"Expected tool {tool_name!r} not to be called in trace {trace.trace_id!r}, "
            f"but found {len(matches)} call(s)"
        )


def assert_tool_output(
    trace: Trace,
    tool_name: str,
    *,
    expected_result: dict[str, Any] | None = None,
    result_subset: dict[str, Any] | None = None,
    call_index: int = 0,
) -> dict[str, Any]:
    """Assert the output of a specific tool call by tool_name and call_index."""
    tool_results: list[dict[str, Any]] = []
    for ev in trace.events:
        if (
            ev.event_type == EventKind.TOOL_RESULT
            and ev.payload.get("tool_name") == tool_name
            and isinstance(ev.payload.get("result"), dict)
        ):
            tool_results.append(ev.payload["result"])

    if not tool_results:
        for entry in trace.fixtures.entries:
            if (
                entry.boundary == BoundaryType.TOOL
                and (entry.name == tool_name or entry.request.get("tool_name") == tool_name)
                and entry.response is not None
            ):
                tool_results.append(entry.response)

    if not tool_results:
        raise AssertionError(
            f"No tool result found for tool {tool_name!r} in trace {trace.trace_id!r}"
        )

    try:
        actual = tool_results[call_index]
    except IndexError as exc:
        raise AssertionError(
            f"Tool {tool_name!r} has {len(tool_results)} result(s), "
            f"cannot access call_index={call_index}"
        ) from exc

    if expected_result is not None and actual != expected_result:
        raise AssertionError(
            f"Tool {tool_name!r} (call_index={call_index}) result mismatch:\n"
            f"  expected: {_safe_format(expected_result)}\n"
            f"  actual  : {_safe_format(actual)}"
        )
    if result_subset is not None and not _matches_subset(actual, result_subset):
        raise AssertionError(
            f"Tool {tool_name!r} (call_index={call_index}) result does not match subset:\n"
            f"  expected subset: {_safe_format(result_subset)}\n"
            f"  actual result  : {_safe_format(actual)}"
        )
    return actual


def assert_model_called(
    trace: Trace,
    *,
    model: str | None = None,
    provider: str | None = None,
    min_calls: int = 1,
) -> list[Event]:
    """Assert that a model interaction occurred at least min_calls times."""
    if min_calls < 1:
        raise ValueError("min_calls must be >= 1")
    matches: list[Event] = []
    for ev in trace.events:
        if ev.event_type != EventKind.MODEL_REQUEST:
            continue
        if model is not None and ev.payload.get("model") != model:
            continue
        if provider is not None and ev.payload.get("provider") != provider:
            continue
        matches.append(ev)

    if len(matches) < min_calls:
        raise AssertionError(
            f"Expected at least {min_calls} MODEL_REQUEST event(s) "
            f"(model={model!r}, provider={provider!r}) in trace {trace.trace_id!r}, "
            f"found {len(matches)}"
        )
    return matches


def assert_model_output(
    trace: Trace,
    *,
    expected_subset: dict[str, Any] | None = None,
    contains_text: str | None = None,
    call_index: int = -1,
) -> dict[str, Any]:
    """Assert properties of a model response payload (by default the last model response)."""
    responses = [ev.payload for ev in trace.events if ev.event_type == EventKind.MODEL_RESPONSE]
    if not responses:
        responses = [
            e.response
            for e in trace.fixtures.entries
            if e.boundary == BoundaryType.MODEL and e.response is not None
        ]
    if not responses:
        raise AssertionError(f"No model responses found in trace {trace.trace_id!r}")

    try:
        actual = responses[call_index]
    except IndexError as exc:
        raise AssertionError(
            f"Trace has {len(responses)} model response(s), cannot index {call_index}"
        ) from exc

    if expected_subset is not None and not _matches_subset(actual, expected_subset):
        raise AssertionError(
            f"Model response (call_index={call_index}) does not match expected subset:\n"
            f"  expected subset: {_safe_format(expected_subset)}\n"
            f"  actual response: {_safe_format(actual)}"
        )
    if contains_text is not None:
        serialized = canonical_json(actual)
        if contains_text not in serialized:
            raise AssertionError(
                f"Model response (call_index={call_index}) does not contain text "
                f"{_safe_format(contains_text)} in {_safe_format(actual)}"
            )
    return actual


def assert_retrieval_results(
    trace: Trace,
    *,
    min_results: int = 1,
    expected_subset: dict[str, Any] | None = None,
    call_index: int = 0,
) -> dict[str, Any]:
    """Assert that a retrieval interaction produced expected results."""
    results = [ev.payload for ev in trace.events if ev.event_type == EventKind.RETRIEVAL_RESULT]
    if not results:
        results = [
            e.response
            for e in trace.fixtures.entries
            if e.boundary == BoundaryType.RETRIEVAL and e.response is not None
        ]
    if not results:
        raise AssertionError(f"No retrieval results found in trace {trace.trace_id!r}")

    try:
        actual = results[call_index]
    except IndexError as exc:
        raise AssertionError(
            f"Trace has {len(results)} retrieval result(s), cannot index {call_index}"
        ) from exc

    docs = actual.get("documents", actual.get("results", []))
    if isinstance(docs, list) and len(docs) < min_results:
        raise AssertionError(
            f"Expected at least {min_results} retrieved document(s), got {len(docs)}"
        )
    if expected_subset is not None and not _matches_subset(actual, expected_subset):
        raise AssertionError(
            f"Retrieval result (call_index={call_index}) does not match expected subset:\n"
            f"  expected subset: {_safe_format(expected_subset)}\n"
            f"  actual result  : {_safe_format(actual)}"
        )
    return actual


def assert_agent_transition(
    trace: Trace,
    *,
    to_agent: str,
    from_agent: str | None = None,
) -> Event:
    """Assert that an AGENT_TRANSITION event to to_agent (and optional from_agent) occurred."""
    for ev in trace.events:
        if ev.event_type != EventKind.AGENT_TRANSITION:
            continue
        if ev.payload.get("to_agent") != to_agent:
            continue
        if from_agent is not None and ev.payload.get("from_agent") != from_agent:
            continue
        return ev
    raise AssertionError(
        f"Expected AGENT_TRANSITION (from_agent={from_agent!r} -> to_agent={to_agent!r}) "
        f"not found in trace {trace.trace_id!r}"
    )


def assert_state_change(
    trace: Trace,
    state_key: str,
    *,
    expected_after: Any = _UNSET,
    operation: str | None = None,
) -> Event:
    """Assert that a STATE_CHANGE event occurred for state_key with optional after value."""
    for ev in trace.events:
        if ev.event_type != EventKind.STATE_CHANGE:
            continue
        actual_key = ev.payload.get("key_path") or ev.payload.get("state_key")
        if actual_key != state_key:
            continue
        if operation is not None and ev.payload.get("operation") != operation:
            continue
        if expected_after is not _UNSET and ev.payload.get("after") != expected_after:
            continue
        return ev
    exp_after_str = _safe_format(expected_after) if expected_after is not _UNSET else "*"
    raise AssertionError(
        f"Expected STATE_CHANGE for state_key={state_key!r} "
        f"(operation={operation!r}, expected_after={exp_after_str}) "
        f"not found in trace {trace.trace_id!r}"
    )


def assert_no_errors(trace: Trace) -> None:
    """Assert that no runs, spans, events, or fixtures recorded an error."""
    for run in trace.runs:
        if run.status == RunStatus.FAILED or run.error is not None:
            err_detail = run.error.model_dump(mode="json") if run.error else run.status.value
            raise AssertionError(
                f"Run {run.run_id!r} failed or contains an error: {_safe_format(err_detail)}"
            )
    for span in trace.spans:
        if span.status == SpanStatus.ERROR or span.error is not None:
            span_detail = span.error.model_dump(mode="json") if span.error else span.status.value
            raise AssertionError(
                f"Span {span.name!r} ({span.span_id!r}) has error status: "
                f"{_safe_format(span_detail)}"
            )
    error_kinds = {
        EventKind.RUN_FAILED,
        EventKind.SPAN_FAILED,
        EventKind.MODEL_ERROR,
        EventKind.TOOL_ERROR,
        EventKind.RETRIEVAL_ERROR,
        EventKind.EXCEPTION,
    }
    for ev in trace.events:
        if ev.event_type in error_kinds:
            raise AssertionError(
                f"Trace {trace.trace_id!r} contains error event {ev.event_type.value!r} "
                f"({ev.event_id!r}): {_safe_format(ev.payload)}"
            )


def assert_error_recorded(
    trace: Trace,
    *,
    error_type: str | None = None,
    message_contains: str | None = None,
) -> ExecutionError:
    """Assert that an ExecutionError matching error_type / message_contains was recorded."""
    errors: list[ExecutionError] = []
    for run in trace.runs:
        if run.error is not None:
            errors.append(run.error)
    for span in trace.spans:
        if span.error is not None:
            errors.append(span.error)
    for entry in trace.fixtures.entries:
        if entry.error is not None:
            errors.append(entry.error)
    for ev in trace.events:
        raw_err = ev.payload.get("error")
        if isinstance(raw_err, dict) and "error_type" in raw_err and "message" in raw_err:
            with contextlib.suppress(ValueError, TypeError):
                errors.append(ExecutionError.model_validate(raw_err))

    if not errors:
        raise AssertionError(f"Expected a recorded error in trace {trace.trace_id!r}, found none")

    for err in errors:
        if error_type is not None and err.error_type != error_type:
            continue
        if message_contains is not None and message_contains not in err.message:
            continue
        return err

    raise AssertionError(
        f"No recorded error matched error_type={error_type!r}, "
        f"message_contains={_safe_format(message_contains)} in trace {trace.trace_id!r}. "
        f"Recorded errors: {[_safe_format(e.model_dump(mode='json')) for e in errors]}"
    )


def assert_no_secrets_leaked(trace: Trace) -> None:
    """Assert that no unredacted secret keys or token patterns exist anywhere in the trace."""
    dumped = trace.model_dump(mode="json")
    redacted = redact_data(dumped, config=RedactionConfig())
    if dumped != redacted or not trace.redaction_applied:
        reasons: list[str] = []
        if not trace.redaction_applied:
            reasons.append("trace.redaction_applied is False")
        if dumped != redacted:
            reasons.append("unredacted sensitive values detected during redaction scan")
        raise AssertionError(
            f"Secret hygiene check failed for trace {trace.trace_id!r}: {'; '.join(reasons)}"
        )


class TraceAssertions:
    """Fluent declarative assertion helper for a Trace (`expect_trace(trace)`)."""

    def __init__(self, trace: Trace) -> None:
        self._trace = trace

    @property
    def trace(self) -> Trace:
        return self._trace

    def is_valid(self) -> TraceAssertions:
        assert_trace_valid(self._trace)
        return self

    def succeeded(self, *, run_id: str | None = None) -> TraceAssertions:
        assert_run_succeeded(self._trace, run_id=run_id)
        return self

    def has_status(
        self, expected_status: RunStatus, *, run_id: str | None = None
    ) -> TraceAssertions:
        assert_run_status(self._trace, expected_status, run_id=run_id)
        return self

    def has_output(
        self,
        *,
        expected: dict[str, Any] | None = None,
        subset: dict[str, Any] | None = None,
        key: str | None = None,
        value: Any = _UNSET,
        run_id: str | None = None,
    ) -> TraceAssertions:
        assert_run_output(
            self._trace,
            expected=expected,
            subset=subset,
            key=key,
            value=value,
            run_id=run_id,
        )
        return self

    def has_span(
        self,
        name: str,
        *,
        span_type: SpanType | None = None,
        status: SpanStatus | None = None,
    ) -> TraceAssertions:
        if status is not None:
            assert_span_status(self._trace, name, status, span_type=span_type)
        else:
            assert_span_exists(self._trace, name, span_type=span_type)
        return self

    def called_tool(
        self,
        tool_name: str,
        *,
        min_calls: int = 1,
        result_subset: dict[str, Any] | None = None,
    ) -> TraceAssertions:
        assert_tool_called(self._trace, tool_name, min_calls=min_calls)
        if result_subset is not None:
            assert_tool_output(self._trace, tool_name, result_subset=result_subset)
        return self

    def did_not_call_tool(self, tool_name: str) -> TraceAssertions:
        assert_tool_not_called(self._trace, tool_name)
        return self

    def called_model(
        self,
        *,
        model: str | None = None,
        provider: str | None = None,
        min_calls: int = 1,
    ) -> TraceAssertions:
        assert_model_called(self._trace, model=model, provider=provider, min_calls=min_calls)
        return self

    def has_no_errors(self) -> TraceAssertions:
        assert_no_errors(self._trace)
        return self

    def has_no_secrets_leaked(self) -> TraceAssertions:
        assert_no_secrets_leaked(self._trace)
        return self


def expect_trace(trace: Trace) -> TraceAssertions:
    """Create a fluent TraceAssertions wrapper for declarative chaining."""
    return TraceAssertions(trace)


__all__ = [
    "TraceAssertions",
    "assert_agent_transition",
    "assert_error_recorded",
    "assert_event_absent",
    "assert_event_exists",
    "assert_event_order",
    "assert_model_called",
    "assert_model_output",
    "assert_no_errors",
    "assert_no_secrets_leaked",
    "assert_retrieval_results",
    "assert_run_output",
    "assert_run_status",
    "assert_run_succeeded",
    "assert_span_duration_under",
    "assert_span_exists",
    "assert_span_status",
    "assert_state_change",
    "assert_tool_called",
    "assert_tool_not_called",
    "assert_tool_output",
    "assert_trace_valid",
    "expect_trace",
]

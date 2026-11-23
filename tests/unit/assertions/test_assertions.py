"""Comprehensive unit tests for trace, replay, and diff assertions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tracevault.assertions import (
    assert_agent_transition,
    assert_all_fixtures_matched,
    assert_diff_matches_expectations,
    assert_error_recorded,
    assert_event_absent,
    assert_event_exists,
    assert_event_order,
    assert_model_called,
    assert_model_output,
    assert_no_breaking_diffs,
    assert_no_errors,
    assert_no_live_calls,
    assert_no_secrets_leaked,
    assert_replay_clean,
    assert_replay_succeeded,
    assert_retrieval_results,
    assert_run_output,
    assert_run_status,
    assert_run_succeeded,
    assert_span_duration_under,
    assert_span_exists,
    assert_span_status,
    assert_state_change,
    assert_tool_called,
    assert_tool_not_called,
    assert_tool_output,
    assert_trace_valid,
    assert_traces_equivalent,
    expect_trace,
)
from tracevault.capture import capture
from tracevault.diff import diff_traces
from tracevault.replay import ReplayEngine
from tracevault.schema import (
    BoundaryType,
    DivergenceKind,
    EventKind,
    ExecutionError,
    ReplayMode,
    ReplayResult,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    Trace,
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _build_rich_trace(*, include_error: bool = False) -> Trace:
    with capture("customer_support_flow", inputs={"query": "refund #101"}) as sess:
        with sess.span(
            "retrieve_docs", span_type=SpanType.RETRIEVAL, boundary=BoundaryType.RETRIEVAL
        ):
            sess.record_retrieval(
                {"query": "refund policy", "top_k": 2},
                {"documents": [{"id": "doc_1", "text": "30-day refund window"}]},
                name="kb_search",
            )
        with sess.span("agent_plan", span_type=SpanType.AGENT):
            sess.record_agent_transition(
                "refund_agent",
                from_agent="router_agent",
                reason="refund intent",
            )
            sess.record_model_call(
                {"provider": "openai", "model": "gpt-4o-mini", "prompt": "check refund #101"},
                {"content": "Proceeding with lookup_refund tool", "finish_reason": "tool_calls"},
                name="plan_llm",
            )
        with sess.span("execute_tool", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
            if include_error:
                sess.record_tool_call(
                    "lookup_refund",
                    {"order_id": "101"},
                    result=None,
                    error=ExecutionError(error_type="DatabaseError", message="connection reset"),
                )
            else:
                sess.record_tool_call(
                    "lookup_refund",
                    {"order_id": "101"},
                    result={"eligible": True, "amount_usd": 49.0},
                )
        sess.record_state_change("refund.status", "set", before="pending", after="approved")
        sess.set_outputs({"decision": "approved", "amount_usd": 49.0, "meta": {"tier": "gold"}})
    assert sess.trace is not None
    return sess.trace


def test_trace_validity_and_run_assertions() -> None:
    trace = _build_rich_trace()
    assert_trace_valid(trace)
    assert_run_succeeded(trace)
    run = assert_run_status(trace, RunStatus.COMPLETED)
    assert run.run_id == trace.root_run.run_id

    with pytest.raises(AssertionError, match="Expected Trace instance"):
        assert_trace_valid("not-a-trace")  # type: ignore[arg-type]

    with pytest.raises(AssertionError, match="not found in trace"):
        assert_run_status(trace, RunStatus.COMPLETED, run_id="run_nonexistent")

    with pytest.raises(AssertionError, match="to have status 'failed'"):
        assert_run_status(trace, RunStatus.FAILED)


def test_run_output_exact_subset_and_key_assertions() -> None:
    trace = _build_rich_trace()
    out = assert_run_output(
        trace,
        expected={"decision": "approved", "amount_usd": 49.0, "meta": {"tier": "gold"}},
    )
    assert out["decision"] == "approved"

    assert_run_output(trace, subset={"decision": "approved", "meta": {"tier": "gold"}})
    assert_run_output(trace, key="decision", value="approved")
    assert_run_output(trace, key="amount_usd")

    with pytest.raises(AssertionError, match="outputs mismatch"):
        assert_run_output(trace, expected={"decision": "denied"})

    with pytest.raises(AssertionError, match="do not contain expected subset"):
        assert_run_output(trace, subset={"meta": {"tier": "silver"}})

    with pytest.raises(AssertionError, match="Expected key 'missing_key'"):
        assert_run_output(trace, key="missing_key")

    with pytest.raises(AssertionError, match="output\\['decision'\\] mismatch"):
        assert_run_output(trace, key="decision", value="denied")


def test_span_existence_status_and_timing_assertions() -> None:
    trace = _build_rich_trace()
    span = assert_span_exists(trace, "execute_tool", span_type=SpanType.TOOL)
    assert span.name == "execute_tool"
    assert_span_status(trace, "execute_tool", SpanStatus.OK, span_type=SpanType.TOOL)
    duration = assert_span_duration_under(trace, "execute_tool", 10.0)
    assert duration >= 0.0

    with pytest.raises(AssertionError, match="Span 'missing_span' not found"):
        assert_span_exists(trace, "missing_span")

    with pytest.raises(AssertionError, match="to have status 'error'"):
        assert_span_status(trace, "execute_tool", SpanStatus.ERROR)

    # Create a trace with a 5-second span and check timing bound failure
    slow_run = Run(
        run_id="r1",
        trace_id="tr_slow_001",
        name="slow",
        started_at=T0,
        ended_at=T0 + timedelta(seconds=5),
        status=RunStatus.COMPLETED,
    )
    slow_span = Span(
        span_id="s1",
        run_id="r1",
        span_type=SpanType.MODEL,
        name="slow_llm",
        started_at=T0,
        ended_at=T0 + timedelta(seconds=5),
        status=SpanStatus.OK,
    )
    slow_trace = Trace(trace_id="tr_slow_001", created_at=T0, runs=[slow_run], spans=[slow_span])
    with pytest.raises(AssertionError, match="exceeded max_seconds"):
        assert_span_duration_under(slow_trace, "slow_llm", 1.0)


def test_event_presence_absence_and_ordering_assertions() -> None:
    trace = _build_rich_trace()
    events = assert_event_exists(
        trace,
        EventKind.TOOL_CALL,
        boundary=BoundaryType.TOOL,
        payload_subset={"tool_name": "lookup_refund"},
    )
    assert len(events) == 1

    assert_event_absent(trace, EventKind.TOOL_ERROR)

    with pytest.raises(AssertionError, match="No event matching"):
        assert_event_exists(trace, EventKind.MODEL_ERROR)

    with pytest.raises(AssertionError, match="to be absent"):
        assert_event_absent(trace, EventKind.TOOL_CALL)

    ordered = assert_event_order(
        trace,
        [
            EventKind.RUN_STARTED,
            EventKind.RETRIEVAL_QUERY,
            EventKind.RETRIEVAL_RESULT,
            EventKind.AGENT_TRANSITION,
            EventKind.MODEL_REQUEST,
            EventKind.MODEL_RESPONSE,
            EventKind.TOOL_CALL,
            EventKind.TOOL_RESULT,
            EventKind.STATE_CHANGE,
            EventKind.RUN_COMPLETED,
        ],
    )
    assert len(ordered) == 10

    contiguous = assert_event_order(
        trace,
        [EventKind.MODEL_REQUEST, EventKind.MODEL_RESPONSE],
        strict_contiguous=True,
    )
    assert len(contiguous) == 2

    with pytest.raises(AssertionError, match="Expected ordered event subsequence"):
        assert_event_order(trace, [EventKind.TOOL_RESULT, EventKind.RETRIEVAL_QUERY])

    with pytest.raises(AssertionError, match="Expected contiguous event sequence"):
        assert_event_order(
            trace,
            [EventKind.RETRIEVAL_QUERY, EventKind.TOOL_CALL],
            strict_contiguous=True,
        )


def test_interaction_assertions_model_tool_retrieval_transition_state() -> None:
    trace = _build_rich_trace()

    assert_model_called(trace, model="gpt-4o-mini", provider="openai", min_calls=1)
    model_out = assert_model_output(
        trace,
        expected_subset={"finish_reason": "tool_calls"},
        contains_text="lookup_refund",
    )
    assert "lookup_refund" in model_out["content"]

    assert_tool_called(trace, "lookup_refund", min_calls=1)
    assert_tool_not_called(trace, "delete_account")
    tool_out = assert_tool_output(
        trace,
        "lookup_refund",
        expected_result={"eligible": True, "amount_usd": 49.0},
        result_subset={"eligible": True},
    )
    assert tool_out["amount_usd"] == 49.0

    ret_out = assert_retrieval_results(
        trace,
        min_results=1,
        expected_subset={"documents": [{"id": "doc_1", "text": "30-day refund window"}]},
    )
    assert len(ret_out["documents"]) == 1

    tr_ev = assert_agent_transition(trace, from_agent="router_agent", to_agent="refund_agent")
    assert tr_ev.payload["reason"] == "refund intent"

    st_ev = assert_state_change(
        trace,
        "refund.status",
        expected_after="approved",
        operation="set",
    )
    assert st_ev.payload["before"] == "pending"

    with pytest.raises(AssertionError, match="Expected tool 'missing_tool'"):
        assert_tool_called(trace, "missing_tool")

    with pytest.raises(AssertionError, match="not to be called"):
        assert_tool_not_called(trace, "lookup_refund")


def test_error_and_secret_hygiene_assertions() -> None:
    clean_trace = _build_rich_trace(include_error=False)
    assert_no_errors(clean_trace)
    assert_no_secrets_leaked(clean_trace)

    with pytest.raises(AssertionError, match="Expected a recorded error"):
        assert_error_recorded(clean_trace)

    err_trace = _build_rich_trace(include_error=True)
    with pytest.raises(AssertionError, match="contains error event"):
        assert_no_errors(err_trace)

    err = assert_error_recorded(
        err_trace,
        error_type="DatabaseError",
        message_contains="connection reset",
    )
    assert err.error_type == "DatabaseError"

    # Construct a trace with unredacted secret to verify assert_no_secrets_leaked fails
    leaky_run = Run(
        run_id="r1",
        trace_id="tr_leaky_001",
        name="leaky",
        started_at=T0,
        ended_at=T0,
        status=RunStatus.COMPLETED,
        inputs={"api_key": "sk-live-unredacted-secret-1234567890"},
    )
    leaky_trace = Trace(
        trace_id="tr_leaky_001",
        created_at=T0,
        runs=[leaky_run],
        redaction_applied=False,
    )
    with pytest.raises(AssertionError, match="Secret hygiene check failed"):
        assert_no_secrets_leaked(leaky_trace)


def test_fluent_expect_trace_builder() -> None:
    trace = _build_rich_trace()
    expect_trace(trace).is_valid().succeeded().has_status(RunStatus.COMPLETED).has_output(
        subset={"decision": "approved"}
    ).has_span("execute_tool", span_type=SpanType.TOOL, status=SpanStatus.OK).called_tool(
        "lookup_refund", result_subset={"eligible": True}
    ).did_not_call_tool("drop_database").called_model(
        model="gpt-4o-mini", provider="openai"
    ).has_no_errors().has_no_secrets_leaked()


def test_replay_and_diff_assertions() -> None:
    baseline = _build_rich_trace()
    result = ReplayEngine(baseline).replay_trace()

    assert_replay_succeeded(result)
    assert_all_fixtures_matched(result)
    assert_no_live_calls(result)
    assert_replay_clean(result)

    eq_report = assert_traces_equivalent(baseline, baseline)
    assert eq_report.identical is True

    replay_diff = diff_traces(baseline, result.candidate_trace)
    assert_no_breaking_diffs(replay_diff)
    assert_diff_matches_expectations(
        replay_diff,
        max_warnings=10,
        allowed_kinds={DivergenceKind.EVENT_REMOVED},
    )

    # Fork with breaking change and verify diff assertions fail with diagnostics
    tool_fix = next(e for e in baseline.fixtures.entries if e.boundary == BoundaryType.TOOL)
    forked = ReplayEngine(baseline).fork(
        overrides={tool_fix.fixture_id: {"eligible": False, "amount_usd": 0.0}}
    )
    breaking_report = diff_traces(baseline, forked)

    with pytest.raises(AssertionError, match="Expected 0 breaking divergences"):
        assert_no_breaking_diffs(breaking_report)

    with pytest.raises(AssertionError, match="are not equivalent"):
        assert_traces_equivalent(baseline, forked)

    with pytest.raises(AssertionError, match="disallowed divergence kinds"):
        assert_diff_matches_expectations(
            breaking_report,
            allowed_kinds={DivergenceKind.EVENT_REMOVED},
        )

    # Failing replay result checks
    bad_result = ReplayResult(
        baseline_trace_id=baseline.trace_id,
        candidate_trace=baseline,
        mode=ReplayMode.OFFLINE_STRICT,
        matched_fixtures=0,
        live_calls=1,
        missing_fixtures=["tool:lookup_refund:abc:0"],
        success=False,
        error=ExecutionError(error_type="ReplayError", message="failed"),
    )
    with pytest.raises(AssertionError, match="failed: success=False"):
        assert_replay_succeeded(bad_result)
    with pytest.raises(AssertionError, match="missing fixture"):
        assert_all_fixtures_matched(bad_result)
    with pytest.raises(AssertionError, match="Expected 0 live boundary calls"):
        assert_no_live_calls(bad_result)


def test_failure_diagnostics_redact_sensitive_values() -> None:
    secret_val = "sk-live-supersecret-token-9999999999"
    run = Run(
        run_id="r1",
        trace_id="tr_diag_001",
        name="diag",
        started_at=T0,
        ended_at=T0,
        status=RunStatus.COMPLETED,
        outputs={"api_key": secret_val},
    )
    trace = Trace(trace_id="tr_diag_001", created_at=T0, runs=[run])

    with pytest.raises(AssertionError) as exc_info:
        assert_run_output(trace, expected={"api_key": "other"})

    assert secret_val not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)

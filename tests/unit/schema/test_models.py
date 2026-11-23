"""Tests for core execution, fixture, replay, and diff canonical models."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from tracevault.schema import (
    SCHEMA_VERSION,
    BoundaryMode,
    BoundaryPolicyDecision,
    BoundaryType,
    DiffConfig,
    DiffReport,
    Divergence,
    DivergenceKind,
    DivergenceSeverity,
    Event,
    EventKind,
    ExecutionError,
    FixtureEntry,
    FixtureSet,
    InvalidTraceIdError,
    ReplayConfig,
    ReplayMode,
    ReplayOverride,
    ReplayResult,
    Run,
    RunStatus,
    SafetyPolicy,
    Span,
    SpanStatus,
    SpanType,
    Trace,
    UnsafeTraceError,
)

T0 = datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 11, 24, 0, 0, 1, tzinfo=UTC)
VALID_FP = "a" * 64


def _make_run(
    run_id: str = "run_001",
    trace_id: str = "tr_001",
    parent_run_id: str | None = None,
) -> Run:
    return Run(
        run_id=run_id,
        trace_id=trace_id,
        parent_run_id=parent_run_id,
        name="agent_run",
        started_at=T0,
        ended_at=T1,
        status=RunStatus.COMPLETED,
    )


def _make_span(
    span_id: str = "sp_001",
    run_id: str = "run_001",
    parent_span_id: str | None = None,
    event_ids: list[str] | None = None,
) -> Span:
    return Span(
        span_id=span_id,
        run_id=run_id,
        parent_span_id=parent_span_id,
        span_type=SpanType.MODEL,
        boundary=BoundaryType.MODEL,
        name="openai.chat.completions",
        started_at=T0,
        ended_at=T1,
        status=SpanStatus.OK,
        event_ids=event_ids or [],
    )


def _make_event(
    event_id: str = "ev_001",
    run_id: str = "run_001",
    span_id: str | None = "sp_001",
    sequence: int = 0,
) -> Event:
    return Event(
        event_id=event_id,
        run_id=run_id,
        span_id=span_id,
        event_type=EventKind.MODEL_REQUEST,
        boundary=BoundaryType.MODEL,
        timestamp=T0,
        sequence=sequence,
    )


def test_execution_error_and_frozen_extra_forbid() -> None:
    err = ExecutionError(error_type="ValueError", message="bad input", details={"k": 1})
    assert err.retryable is False
    with pytest.raises(ValidationError):
        err.message = "mutated"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ExecutionError(error_type="ValueError", message="m", extra=1)  # type: ignore[call-arg]
    with pytest.raises(UnsafeTraceError):
        ExecutionError(error_type="ValueError", message="m", details={"x": float("nan")})


def test_datetime_normalization_and_temporal_ordering() -> None:
    tz_minus_4 = timezone(timedelta(hours=-4))
    started = datetime(2026, 11, 24, 0, 0, 0, tzinfo=tz_minus_4)
    ended = datetime(2026, 11, 24, 0, 0, 5, tzinfo=tz_minus_4)

    run = Run(
        run_id="r1",
        trace_id="tr_tz",
        name="tz_test",
        started_at=started,
        ended_at=ended,
    )
    assert run.started_at.tzinfo == UTC
    assert run.ended_at is not None and run.ended_at.tzinfo == UTC

    with pytest.raises(ValidationError):
        Run(
            run_id="r1",
            trace_id="tr_tz",
            name="naive",
            started_at=datetime(2026, 11, 24, 0, 0, 0),
        )

    with pytest.raises(ValidationError, match="ended_at"):
        Run(
            run_id="r1",
            trace_id="tr_tz",
            name="backwards",
            started_at=T1,
            ended_at=T0,
        )

    with pytest.raises(ValidationError, match="ended_at"):
        Span(
            span_id="s1",
            run_id="r1",
            span_type=SpanType.CUSTOM,
            name="backwards",
            started_at=T1,
            ended_at=T0,
        )


def test_fixture_entry_and_set_invariants() -> None:
    ok_entry = FixtureEntry(
        fixture_id="fix_1",
        boundary=BoundaryType.MODEL,
        fingerprint=VALID_FP,
        response={},
    )
    err_entry = FixtureEntry(
        fixture_id="fix_2",
        boundary=BoundaryType.TOOL,
        fingerprint=VALID_FP,
        error=ExecutionError(error_type="ToolError", message="failed"),
    )
    fset = FixtureSet(entries=[ok_entry, err_entry])
    assert fset.version == SCHEMA_VERSION

    with pytest.raises(ValidationError):
        FixtureEntry(fixture_id="fix_bad", boundary=BoundaryType.MODEL, fingerprint=VALID_FP)

    with pytest.raises(ValidationError):
        FixtureSet(entries=[ok_entry, ok_entry])


def test_trace_structural_invariants_and_helpers() -> None:
    root = _make_run("run_root", "tr_001")
    child = _make_run("run_child", "tr_001", parent_run_id="run_root")
    sp_parent = _make_span("sp_1", "run_root", event_ids=["ev_1", "ev_2"])
    sp_child = _make_span("sp_2", "run_child", parent_span_id="sp_1")
    ev2 = _make_event("ev_2", "run_root", "sp_1", sequence=2)
    ev1 = _make_event("ev_1", "run_root", "sp_1", sequence=1)

    trace = Trace(
        trace_id="tr_001",
        created_at=T0,
        runs=[child, root],
        spans=[sp_parent, sp_child],
        events=[ev2, ev1],
    )
    assert trace.root_run == root
    assert trace.get_run("run_child") == child
    assert trace.get_run("missing") is None
    assert [e.event_id for e in trace.get_span_events("sp_1")] == ["ev_1", "ev_2"]

    # Round-trip JSON
    raw = trace.to_json()
    restored = Trace.from_json(raw)
    assert restored == trace
    assert Trace.from_json(raw.encode("utf-8")) == trace


def test_trace_rejects_broken_invariants() -> None:
    # Empty runs
    with pytest.raises(ValidationError):
        Trace(trace_id="tr_001", created_at=T0, runs=[])

    # Mismatched run.trace_id
    with pytest.raises(ValidationError):
        Trace(trace_id="tr_001", created_at=T0, runs=[_make_run("r1", "tr_other")])

    # Duplicate run_id
    with pytest.raises(ValidationError):
        Trace(trace_id="tr_001", created_at=T0, runs=[_make_run("r1"), _make_run("r1")])

    # Cyclic parent_run_id
    r_a = _make_run("r_a", "tr_001", parent_run_id="r_b")
    r_b = _make_run("r_b", "tr_001", parent_run_id="r_a")
    with pytest.raises(ValidationError, match="Cyclic"):
        Trace(trace_id="tr_001", created_at=T0, runs=[r_a, r_b])

    # Missing parent_run_id
    with pytest.raises(ValidationError):
        Trace(
            trace_id="tr_001",
            created_at=T0,
            runs=[_make_run("r_a", "tr_001", parent_run_id="missing")],
        )

    # Span referencing unknown run
    with pytest.raises(ValidationError):
        Trace(
            trace_id="tr_001",
            created_at=T0,
            runs=[_make_run("r1")],
            spans=[_make_span("s1", "r_unknown")],
        )

    # Cyclic parent_span_id
    s_a = _make_span("s_a", "r1", parent_span_id="s_b")
    s_b = _make_span("s_b", "r1", parent_span_id="s_a")
    with pytest.raises(ValidationError, match="Cyclic"):
        Trace(trace_id="tr_001", created_at=T0, runs=[_make_run("r1")], spans=[s_a, s_b])

    # Duplicate event sequence
    with pytest.raises(ValidationError):
        Trace(
            trace_id="tr_001",
            created_at=T0,
            runs=[_make_run("r1")],
            spans=[_make_span("s1", "r1")],
            events=[
                _make_event("e1", "r1", "s1", sequence=0),
                _make_event("e2", "r1", "s1", sequence=0),
            ],
        )

    # Event referencing unknown span
    with pytest.raises(ValidationError):
        Trace(
            trace_id="tr_001",
            created_at=T0,
            runs=[_make_run("r1")],
            events=[_make_event("e1", "r1", "missing_span", sequence=0)],
        )

    # Span.event_ids referencing event from different span
    with pytest.raises(ValidationError):
        Trace(
            trace_id="tr_001",
            created_at=T0,
            runs=[_make_run("r1")],
            spans=[_make_span("s1", "r1", event_ids=["e1"]), _make_span("s2", "r1")],
            events=[_make_event("e1", "r1", "s2", sequence=0)],
        )


def test_trace_from_json_security_guards() -> None:
    valid_trace = Trace(trace_id="tr_sec", created_at=T0, runs=[_make_run("r1", "tr_sec")])
    raw = valid_trace.to_json()

    # Byte limit enforced
    with pytest.raises(UnsafeTraceError, match="max_bytes"):
        Trace.from_json(raw, max_bytes=10)

    # Invalid UTF-8 bytes
    with pytest.raises(UnsafeTraceError, match="UTF-8"):
        Trace.from_json(b"\xff\xfe")

    # Non-finite JSON constants rejected
    for const in ("NaN", "Infinity", "-Infinity"):
        payload = raw.replace('"metadata": {}', f'"metadata": {{"x": {const}}}')
        with pytest.raises(UnsafeTraceError, match="Non-finite"):
            Trace.from_json(payload)

    # Invalid trace_id preserves InvalidTraceIdError
    bad_id_raw = raw.replace('"tr_sec"', '"../escape"')
    with pytest.raises(InvalidTraceIdError):
        Trace.from_json(bad_id_raw)

    # Incompatible schema version rejected with UnsafeTraceError
    bad_ver_raw = raw.replace('"1.0.0"', '"2.0.0"', 1)
    with pytest.raises(UnsafeTraceError, match="schema_version"):
        Trace.from_json(bad_ver_raw)

    # Extra unknown field rejected with UnsafeTraceError
    data = json.loads(raw)
    data["unexpected"] = "nope"
    with pytest.raises(UnsafeTraceError):
        Trace.from_json(json.dumps(data))

    # Excessive nesting depth rejected with UnsafeTraceError
    deep: Any = "leaf"
    for _ in range(70):
        deep = {"a": deep}
    data_deep = json.loads(raw)
    data_deep["metadata"] = deep
    with pytest.raises(UnsafeTraceError, match="depth"):
        Trace.from_json(json.dumps(data_deep))


def test_canonical_example_trace_from_contracts() -> None:
    example_json = {
        "schema_version": "1.0.0",
        "trace_id": "tr_9f8e7d6c5b4a3210",
        "created_at": "2026-11-24T00:00:00Z",
        "frozen": True,
        "parent_trace_id": None,
        "runs": [
            {
                "run_id": "run_001",
                "trace_id": "tr_9f8e7d6c5b4a3210",
                "parent_run_id": None,
                "name": "support_triage_agent",
                "started_at": "2026-11-24T00:00:00Z",
                "ended_at": "2026-11-24T00:00:01Z",
                "status": "completed",
                "inputs": {"ticket": "Billing error on invoice #42"},
                "outputs": {"category": "billing", "action": "refund_review"},
                "error": None,
                "environment": {"python": "3.12.10"},
                "tags": ["triage", "prod-incident-42"],
                "metadata": {},
            }
        ],
        "spans": [
            {
                "span_id": "sp_001",
                "run_id": "run_001",
                "parent_span_id": None,
                "span_type": "model",
                "boundary": "model",
                "name": "openai.chat.completions",
                "started_at": "2026-11-24T00:00:00.100000Z",
                "ended_at": "2026-11-24T00:00:00.900000Z",
                "status": "ok",
                "attributes": {"model": "gpt-4o-mini"},
                "error": None,
                "event_ids": ["ev_001", "ev_002"],
            }
        ],
        "events": [
            {
                "event_id": "ev_001",
                "run_id": "run_001",
                "span_id": "sp_001",
                "event_type": "model_request",
                "boundary": "model",
                "timestamp": "2026-11-24T00:00:00.100000Z",
                "sequence": 0,
                "payload": {
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "Classify invoice #42"}],
                    "parameters": {"temperature": 0.0},
                    "tools": [],
                    "stream": False,
                },
                "metadata": {},
            },
            {
                "event_id": "ev_002",
                "run_id": "run_001",
                "span_id": "sp_001",
                "event_type": "model_response",
                "boundary": "model",
                "timestamp": "2026-11-24T00:00:00.900000Z",
                "sequence": 1,
                "payload": {
                    "model": "gpt-4o-mini",
                    "content": "billing",
                    "tool_calls": [],
                    "finish_reason": "stop",
                    "usage": {
                        "prompt_tokens": 18,
                        "completion_tokens": 2,
                        "total_tokens": 20,
                    },
                    "raw_metadata": {},
                },
                "metadata": {},
            },
        ],
        "fixtures": {
            "version": "1.0.0",
            "entries": [
                {
                    "fixture_id": "fix_001",
                    "boundary": "model",
                    "fingerprint": (
                        "b4d7c1b3d0f9f8b2a1c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8"
                    ),
                    "call_index": 0,
                    "request": {
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "Classify invoice #42"}],
                    },
                    "response": {
                        "model": "gpt-4o-mini",
                        "content": "billing",
                        "finish_reason": "stop",
                    },
                    "error": None,
                    "span_id": "sp_001",
                    "name": "openai.chat.completions",
                }
            ],
        },
        "metadata": {},
        "redaction_applied": True,
    }
    trace = Trace.from_json(json.dumps(example_json))
    assert trace.trace_id == "tr_9f8e7d6c5b4a3210"
    assert trace.frozen is True
    assert len(trace.fixtures.entries) == 1


def test_replay_and_diff_models_and_properties() -> None:
    policy = SafetyPolicy()
    assert policy.allow_live_boundaries == set()
    assert policy.max_live_calls == 0
    assert policy.require_explicit_opt_in is True

    cfg = ReplayConfig()
    assert cfg.strict_matching is True
    assert cfg.boundary_modes == {b: BoundaryMode.RECORDED for b in BoundaryType}

    lenient_cfg = ReplayConfig(mode=ReplayMode.OFFLINE_LENIENT)
    assert lenient_cfg.strict_matching is False

    override = ReplayOverride(
        fixture_id="fix_1",
        boundary=BoundaryType.MODEL,
        call_index=0,
        response={"content": "patched"},
    )
    assert override.error is None

    decision = BoundaryPolicyDecision(
        boundary=BoundaryType.TOOL,
        mode=BoundaryMode.DENY,
        allowed=False,
        reason="Denied by policy",
    )
    assert decision.allowed is False

    candidate = Trace(trace_id="tr_cand", created_at=T0, runs=[_make_run("r1", "tr_cand")])
    result = ReplayResult(
        baseline_trace_id="tr_base",
        candidate_trace=candidate,
        mode=ReplayMode.OFFLINE_STRICT,
        matched_fixtures=1,
        success=True,
    )
    assert result.live_calls == 0

    diff_cfg = DiffConfig()
    assert diff_cfg.ignore_timestamps is True
    assert diff_cfg.ignore_ids is True
    assert diff_cfg.strict_order is True

    warn_div = Divergence(
        kind=DivergenceKind.SPAN_ADDED,
        severity=DivergenceSeverity.WARNING,
        path="spans[1]",
        message="Added span",
    )
    break_div = Divergence(
        kind=DivergenceKind.OUTPUT_CHANGED,
        severity=DivergenceSeverity.BREAKING,
        path="runs[0].outputs",
        message="Output changed",
        baseline={"a": 1},
        candidate={"a": 2},
    )

    report_ok = DiffReport(
        baseline_trace_id="tr_base",
        candidate_trace_id="tr_cand",
        identical=False,
        divergences=[warn_div],
        summary={"info": 0, "warning": 1, "breaking": 0, "total": 1},
    )
    assert report_ok.has_breaking is False

    report_breaking = DiffReport(
        baseline_trace_id="tr_base",
        candidate_trace_id="tr_cand",
        identical=False,
        divergences=[warn_div, break_div],
        summary={"info": 0, "warning": 1, "breaking": 1, "total": 2},
    )
    assert report_breaking.has_breaking is True

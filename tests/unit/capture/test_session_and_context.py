"""Unit tests for CaptureSession, CaptureConfig, and ContextVar propagation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tracevault.capture import (
    CaptureConfig,
    CaptureSession,
    acapture,
    capture,
    get_current_run_id,
    get_current_session,
    get_current_span_id,
)
from tracevault.schema import (
    BoundaryType,
    EventKind,
    InvalidTraceIdError,
    RunStatus,
    SpanStatus,
    SpanType,
    Trace,
)
from tracevault.storage import TraceStore


def test_sync_capture_lifecycle_and_roundtrip() -> None:
    assert get_current_session() is None
    assert get_current_run_id() is None
    assert get_current_span_id() is None

    with capture(
        "support_agent",
        inputs={"ticket": "Invoice #42"},
        tags=["triage", "triage"],
        metadata={"env": "test"},
    ) as session:
        assert get_current_session() is session
        assert get_current_run_id() == session.run_id
        assert get_current_span_id() is None
        assert not session.is_finalized

        session.add_tags("billing", "triage")
        session.set_metadata("priority", "high")
        session.set_outputs({"category": "billing"})

    assert get_current_session() is None
    assert get_current_run_id() is None
    assert get_current_span_id() is None
    assert session.is_finalized
    assert session.trace is not None

    trace = session.trace
    assert trace.trace_id == session.trace_id
    assert trace.root_run.status == RunStatus.COMPLETED
    assert trace.root_run.ended_at is not None
    assert trace.root_run.ended_at >= trace.root_run.started_at
    assert trace.root_run.inputs == {"ticket": "Invoice #42"}
    assert trace.root_run.outputs == {"category": "billing"}
    assert trace.root_run.tags == ["triage", "billing"]
    assert trace.root_run.metadata == {"env": "test", "priority": "high"}
    assert trace.metadata == {"env": "test", "priority": "high"}
    assert trace.redaction_applied is True

    event_kinds = [e.event_type for e in trace.events]
    assert event_kinds[0] == EventKind.RUN_STARTED
    assert event_kinds[-1] == EventKind.RUN_COMPLETED

    # Canonical JSON round-trip
    restored = Trace.from_json(trace.to_json())
    assert restored == trace


async def test_async_capture_lifecycle() -> None:
    async with acapture("async_agent", inputs={"q": "hello"}) as session:
        assert get_current_session() is session
        assert get_current_run_id() == session.run_id
        await asyncio.sleep(0)
        session.set_outputs({"answer": "world"})

    assert get_current_session() is None
    assert session.trace is not None
    assert session.trace.root_run.status == RunStatus.COMPLETED
    assert session.trace.root_run.outputs == {"answer": "world"}


def test_direct_session_finalize_idempotent_and_config_overrides() -> None:
    cfg = CaptureConfig(
        redact=False,
        auto_save=False,
        capture_environment=False,
        default_tags=["default-tag"],
    )
    session = CaptureSession(
        "direct_run",
        tags=["custom-tag"],
        config=cfg,
        parent_trace_id="tr_parent_123",
    )
    with session:
        session.set_outputs({"ok": True})

    assert session.trace is not None
    first = session.trace
    second = session.finalize()
    assert second == first
    assert first.parent_trace_id == "tr_parent_123"
    assert first.redaction_applied is False
    assert first.root_run.environment == {}
    assert first.root_run.tags == ["default-tag", "custom-tag"]

    # Explicit kwarg overrides CaptureConfig
    overridden = CaptureSession("override_run", config=cfg, redact=True)
    built = overridden.build_trace()
    assert built.redaction_applied is True


def test_invalid_trace_id_rejected_immediately() -> None:
    with pytest.raises(InvalidTraceIdError):
        CaptureSession("bad", trace_id="../escape")

    with pytest.raises(InvalidTraceIdError):
        CaptureSession("bad_parent", parent_trace_id="bad/parent")


def test_auto_save_and_manual_persist_with_trace_store(tmp_path: Path) -> None:
    store = TraceStore(tmp_path / ".tracevault")
    store.init()
    try:
        with capture("persisted_run", store=store, auto_save=True) as session:
            session.set_outputs({"saved": True})

        assert store.exists(session.trace_id)
        loaded = store.load(session.trace_id)
        assert loaded.trace_id == session.trace_id
        assert loaded.root_run.outputs == {"saved": True}

        # Manual persist with explicit store and overwrite
        manual_session = CaptureSession("manual_run", trace_id="tr_manual_001")
        with manual_session:
            manual_session.set_outputs({"v": 1})
        saved_path = manual_session.persist(store=store)
        assert saved_path.exists()

        # Persist without store raises ValueError
        with pytest.raises(ValueError, match="No TraceRepository store configured"):
            manual_session.persist()
    finally:
        store.close()


def test_nested_sync_spans_linkage_and_event_ids() -> None:
    with capture("workflow") as session:
        with session.span("outer", span_type=SpanType.WORKFLOW) as outer:
            assert get_current_span_id() == outer.span_id
            assert outer.parent_span_id is None

            session.record_event(EventKind.CUSTOM, {"step": 1})

            with session.span(
                "inner_model",
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
                attributes={"model": "gpt-4o-mini"},
            ) as inner:
                assert get_current_span_id() == inner.span_id
                assert inner.parent_span_id == outer.span_id
                session.record_event(EventKind.CUSTOM, {"step": 2})

            assert get_current_span_id() == outer.span_id

        assert get_current_span_id() is None

    assert session.trace is not None
    trace = session.trace
    assert len(trace.spans) == 2
    sp_outer, sp_inner = trace.spans
    assert sp_outer.parent_span_id is None
    assert sp_outer.status == SpanStatus.OK
    assert sp_outer.ended_at is not None and sp_outer.ended_at >= sp_outer.started_at

    assert sp_inner.parent_span_id == sp_outer.span_id
    assert sp_inner.status == SpanStatus.OK
    assert sp_inner.boundary == BoundaryType.MODEL
    assert sp_inner.attributes == {"model": "gpt-4o-mini"}

    # Verify Span.event_ids matches Trace.get_span_events
    assert sp_outer.event_ids == [e.event_id for e in trace.get_span_events(sp_outer.span_id)]
    assert sp_inner.event_ids == [e.event_id for e in trace.get_span_events(sp_inner.span_id)]


def test_error_capture_and_status_transitions_without_swallowing() -> None:
    with (
        pytest.raises(RuntimeError, match="boom"),
        capture("failing_run") as session,
        session.span("failing_span") as sp,
    ):
        assert get_current_span_id() == sp.span_id
        raise RuntimeError("boom")

    assert get_current_session() is None
    assert get_current_span_id() is None
    assert get_current_run_id() is None
    assert session.trace is not None

    trace = session.trace
    assert trace.root_run.status == RunStatus.FAILED
    assert trace.root_run.error is not None
    assert trace.root_run.error.error_type == "RuntimeError"
    assert "boom" in trace.root_run.error.message

    assert len(trace.spans) == 1
    span = trace.spans[0]
    assert span.status == SpanStatus.ERROR
    assert span.error is not None
    assert span.error.error_type == "RuntimeError"

    event_types = [e.event_type for e in trace.events]
    assert EventKind.SPAN_FAILED in event_types
    assert EventKind.RUN_FAILED in event_types


def test_sync_and_async_child_runs() -> None:
    with capture("parent_run") as session:
        root_run_id = session.run_id
        with session.start_child_run("child_run", inputs={"sub": 1}, tags=["sub"]) as child:
            assert child.parent_run_id == root_run_id
            assert get_current_run_id() == child.run_id
            session.set_outputs({"sub_result": 42})
            with session.span("child_span") as sp:
                assert sp.run_id == child.run_id
        assert get_current_run_id() == root_run_id
        session.set_outputs({"parent_result": "done"})

    assert session.trace is not None
    assert len(session.trace.runs) == 2
    root_run, child_run = session.trace.runs
    assert root_run.status == RunStatus.COMPLETED
    assert root_run.outputs == {"parent_result": "done"}
    assert child_run.parent_run_id == root_run.run_id
    assert child_run.status == RunStatus.COMPLETED
    assert child_run.outputs == {"sub_result": 42}
    assert session.trace.spans[0].run_id == child_run.run_id


async def test_async_child_run_error_handling() -> None:
    async with acapture("async_parent") as session:
        with pytest.raises(ValueError, match="child failed"):
            async with session.astart_child_run("async_child"):
                await asyncio.sleep(0)
                raise ValueError("child failed")
        # Parent catches child error and completes cleanly
        session.set_outputs({"recovered": True})

    assert session.trace is not None
    root_run, child_run = session.trace.runs
    assert root_run.status == RunStatus.COMPLETED
    assert child_run.status == RunStatus.FAILED
    assert child_run.error is not None
    assert child_run.error.error_type == "ValueError"


def test_nested_capture_sessions_are_isolated() -> None:
    with capture("outer_session") as outer, outer.span("outer_span") as outer_sp:
        assert get_current_session() is outer
        assert get_current_span_id() == outer_sp.span_id

        with capture("inner_session") as inner:
            assert get_current_session() is inner
            assert get_current_run_id() == inner.run_id
            assert get_current_span_id() is None
            with inner.span("inner_span") as inner_sp:
                assert inner_sp.parent_span_id is None

        assert get_current_session() is outer
        assert get_current_run_id() == outer.run_id
        assert get_current_span_id() == outer_sp.span_id

    assert outer.trace is not None
    assert inner.trace is not None
    assert len(outer.trace.spans) == 1
    assert len(inner.trace.spans) == 1


async def test_concurrent_asyncio_gather_span_isolation() -> None:
    async with acapture("concurrent_spans") as session:

        async def worker(worker_id: int) -> tuple[str, str]:
            async with session.aspan(f"parent_{worker_id}") as parent_sp:
                await asyncio.sleep(0.01 * (3 - worker_id))
                assert get_current_span_id() == parent_sp.span_id
                async with session.aspan(f"child_{worker_id}") as child_sp:
                    await asyncio.sleep(0.005)
                    assert get_current_span_id() == child_sp.span_id
                    assert child_sp.parent_span_id == parent_sp.span_id
                    session.record_event(EventKind.CUSTOM, {"worker": worker_id})
                assert get_current_span_id() == parent_sp.span_id
                return parent_sp.span_id, child_sp.span_id

        pairs = await asyncio.gather(worker(0), worker(1), worker(2))

    assert session.trace is not None
    spans_by_id = {sp.span_id: sp for sp in session.trace.spans}
    assert len(spans_by_id) == 6
    for parent_id, child_id in pairs:
        assert spans_by_id[parent_id].parent_span_id is None
        assert spans_by_id[child_id].parent_span_id == parent_id

    sequences = [e.sequence for e in session.trace.events]
    assert sequences == list(range(len(sequences)))


async def test_concurrent_asyncio_gather_separate_sessions_isolated() -> None:
    async def run_session(idx: int) -> Trace:
        async with acapture(f"session_{idx}", inputs={"idx": idx}) as sess:
            async with sess.aspan(f"work_{idx}"):
                await asyncio.sleep(0.01 * (2 - idx))
                assert get_current_session() is sess
                sess.record_tool_call("echo", {"idx": idx}, {"echo": idx})
            sess.set_outputs({"idx": idx})
        assert sess.trace is not None
        return sess.trace

    traces = await asyncio.gather(run_session(0), run_session(1), run_session(2))
    assert get_current_session() is None
    assert len({t.trace_id for t in traces}) == 3
    for idx, trace in enumerate(traces):
        assert trace.root_run.name == f"session_{idx}"
        assert trace.root_run.outputs == {"idx": idx}
        assert len(trace.spans) == 1
        assert trace.spans[0].name == f"work_{idx}"
        assert len(trace.fixtures.entries) == 1
        assert trace.fixtures.entries[0].request == {"tool_name": "echo", "arguments": {"idx": idx}}

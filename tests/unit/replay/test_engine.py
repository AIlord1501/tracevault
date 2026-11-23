"""Unit tests for ReplayEngine, forking, context binding, and store integration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tracevault.capture import capture
from tracevault.replay import ReplayEngine, get_current_replay_engine
from tracevault.schema import (
    BoundaryMode,
    BoundaryType,
    ExecutionError,
    FixtureNotFoundError,
    PolicyViolationError,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    ReplayOverride,
    RunStatus,
    SpanStatus,
    SpanType,
    Trace,
)
from tracevault.storage import TraceStore


def _capture_sample_trace(*, include_error: bool = False) -> Trace:
    with capture("triage_workflow", inputs={"ticket": "invoice-42"}, tags=["billing"]) as sess:
        with sess.span("model_step", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
            sess.record_model_call(
                {"model": "gpt-4o-mini", "prompt": "classify"},
                {"content": "billing"},
                name="openai.chat",
            )
        with sess.span("tool_step", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
            if include_error:
                sess.record_tool_call(
                    "lookup_invoice",
                    {"id": 42},
                    result=None,
                    error=ExecutionError(error_type="TimeoutError", message="db timeout"),
                )
            else:
                sess.record_tool_call(
                    "lookup_invoice",
                    {"id": 42},
                    result={"amount": 100},
                )
        sess.set_outputs({"status": "resolved"})
    assert sess.trace is not None
    return sess.trace


def test_replay_trace_offline_strict_preserves_source_immutability() -> None:
    source = _capture_sample_trace()
    before_json = source.to_json()

    engine = ReplayEngine(source)
    result = engine.replay_trace()

    assert result.success is True
    assert result.error is None
    assert result.baseline_trace_id == source.trace_id
    assert result.mode == ReplayMode.OFFLINE_STRICT
    assert result.matched_fixtures == 2
    assert result.overridden_fixtures == 0
    assert result.live_calls == 0
    assert result.missing_fixtures == []

    cand = result.candidate_trace
    assert cand.trace_id != source.trace_id
    assert cand.frozen is False
    assert cand.parent_trace_id is None
    assert len(cand.fixtures.entries) == 2
    assert len(cand.events) == 4
    assert "replay" in cand.metadata
    assert cand.metadata["replay"]["replay_id"] == engine.replay_id
    assert cand.metadata["replay"]["source_trace_id"] == source.trace_id
    assert cand.metadata["replay"]["mode"] == ReplayMode.OFFLINE_STRICT.value

    # Source trace must be 100% unchanged
    assert source.to_json() == before_json


def test_fork_sets_parent_trace_id_and_applies_overrides() -> None:
    source = _capture_sample_trace()
    first_fix_id = source.fixtures.entries[0].fixture_id

    engine = ReplayEngine(source)
    forked = engine.fork(
        overrides={first_fix_id: {"content": "refund_override"}},
        override_rules=[
            ReplayOverride(
                boundary=BoundaryType.TOOL,
                name="lookup_invoice",
                response={"amount": 250},
            )
        ],
        new_trace_id="tr_fork_custom_001",
    )

    assert forked.trace_id == "tr_fork_custom_001"
    assert forked.parent_trace_id == source.trace_id
    assert forked.frozen is False
    assert forked.fixtures.entries[0].response == {"content": "refund_override"}
    assert forked.fixtures.entries[1].response == {"amount": 250}
    # Original untouched
    assert source.fixtures.entries[0].response == {"content": "billing"}
    assert source.fixtures.entries[1].response == {"amount": 100}


def test_error_fixture_behavior_in_interactive_vs_replay_trace() -> None:
    source = _capture_sample_trace(include_error=True)

    # 1. Interactive replay_interaction raises ReplayError on error fixture
    engine = ReplayEngine(source)
    res_model = engine.replay_interaction(
        BoundaryType.MODEL,
        {"model": "gpt-4o-mini", "prompt": "classify"},
        name="openai.chat",
    )
    assert res_model == {"content": "billing"}

    with pytest.raises(ReplayError, match="db timeout"):
        engine.replay_interaction(
            BoundaryType.TOOL,
            {"tool_name": "lookup_invoice", "arguments": {"id": 42}},
            name="lookup_invoice",
        )

    # 2. replay_trace records RunStatus.FAILED and returns success=False with error
    res = ReplayEngine(source).replay_trace()
    assert res.success is False
    assert res.error is not None
    assert res.error.error_type == "TimeoutError"
    assert res.candidate_trace.root_run.status == RunStatus.FAILED
    assert res.candidate_trace.root_run.error == res.error
    tool_span = next(s for s in res.candidate_trace.spans if s.name == "tool_step")
    assert tool_span.status == SpanStatus.ERROR
    assert tool_span.error == res.error


def test_error_fixture_overridden_with_response_succeeds() -> None:
    source = _capture_sample_trace(include_error=True)
    err_fix_id = source.fixtures.entries[1].fixture_id

    cfg = ReplayConfig(overrides={err_fix_id: {"amount": 999}})
    res = ReplayEngine(source, config=cfg).replay_trace()
    assert res.success is True
    assert res.error is None
    assert res.overridden_fixtures == 1
    assert res.candidate_trace.fixtures.entries[1].response == {"amount": 999}


def test_config_trace_id_mismatch_raises_replay_error() -> None:
    source = _capture_sample_trace()
    cfg = ReplayConfig(trace_id="tr_other_trace_999")
    with pytest.raises(ReplayError, match="does not match"):
        ReplayEngine(source, config=cfg)


def test_context_manager_binds_and_resets_current_replay_engine() -> None:
    source = _capture_sample_trace()
    assert get_current_replay_engine() is None

    engine = ReplayEngine(source)
    with engine as active:
        assert active is engine
        assert get_current_replay_engine() is engine

    assert get_current_replay_engine() is None
    assert engine.ended_at is not None

    # Resets cleanly even if exception raised inside block
    with pytest.raises(RuntimeError, match="boom"), ReplayEngine(source) as active2:
        assert get_current_replay_engine() is active2
        raise RuntimeError("boom")
    assert get_current_replay_engine() is None


def test_replay_interaction_enforces_offline_boundary_modes() -> None:
    source = _capture_sample_trace()

    deny_cfg = ReplayConfig(
        boundary_modes={
            BoundaryType.MODEL: BoundaryMode.DENY,
            BoundaryType.TOOL: BoundaryMode.RECORDED,
            BoundaryType.RETRIEVAL: BoundaryMode.RECORDED,
            BoundaryType.CUSTOM: BoundaryMode.RECORDED,
        }
    )
    with pytest.raises(PolicyViolationError, match="denied"):
        ReplayEngine(source, config=deny_cfg).replay_interaction(
            BoundaryType.MODEL, {"model": "gpt-4o-mini", "prompt": "classify"}
        )

    live_cfg = ReplayConfig(
        mode=ReplayMode.BOUNDARY_GOVERNED,
        boundary_modes={
            BoundaryType.MODEL: BoundaryMode.LIVE,
            BoundaryType.TOOL: BoundaryMode.RECORDED,
            BoundaryType.RETRIEVAL: BoundaryMode.RECORDED,
            BoundaryType.CUSTOM: BoundaryMode.RECORDED,
        },
    )
    with pytest.raises(PolicyViolationError, match="BoundaryExecutor"):
        ReplayEngine(source, config=live_cfg).replay_interaction(
            BoundaryType.MODEL, {"model": "gpt-4o-mini", "prompt": "classify"}
        )


def test_interactive_session_and_build_result() -> None:
    source = _capture_sample_trace()
    cfg = ReplayConfig(fail_on_missing_fixture=False)
    engine = ReplayEngine(source, config=cfg)

    r1 = engine.replay_interaction(
        BoundaryType.MODEL,
        {"model": "gpt-4o-mini", "prompt": "classify"},
        name="openai.chat",
    )
    assert r1 == {"content": "billing"}

    # Missing fixture returns {} and records missing key
    r_miss = engine.replay_interaction(
        BoundaryType.RETRIEVAL,
        {"query": "not recorded"},
        name="vec_db",
    )
    assert r_miss == {}

    result = engine.build_result(fork=True, new_trace_id="tr_interactive_001")
    assert result.success is True
    assert result.matched_fixtures == 1
    assert len(result.missing_fixtures) == 1
    assert result.candidate_trace.trace_id == "tr_interactive_001"
    assert result.candidate_trace.parent_trace_id == source.trace_id
    assert len(result.candidate_trace.fixtures.entries) == 2


def test_from_store_integration(tmp_path: Path) -> None:
    store = TraceStore(tmp_path / ".tracevault")
    store.init()
    try:
        source = _capture_sample_trace()
        store.save(source)

        engine = ReplayEngine.from_store(store, source.trace_id)
        res = engine.replay_trace()
        assert res.success is True
        assert res.baseline_trace_id == source.trace_id
        assert res.matched_fixtures == 2
    finally:
        store.close()


def test_replay_engine_has_no_runtime_storage_import() -> None:
    engine_mod = sys.modules["tracevault.replay.engine"]
    assert "TraceRepository" not in vars(engine_mod)


def test_missing_fixture_in_interactive_mode_raises_by_default() -> None:
    source = _capture_sample_trace()
    engine = ReplayEngine(source)
    with pytest.raises(FixtureNotFoundError):
        engine.replay_interaction(BoundaryType.RETRIEVAL, {"query": "unknown"})

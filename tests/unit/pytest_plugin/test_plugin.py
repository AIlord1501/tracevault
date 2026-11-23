"""Unit tests for TraceVault pytest plugin fixtures and regression verification."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from tracevault.assertions import TraceAssertions, assert_no_breaking_diffs
from tracevault.capture import capture
from tracevault.diff import diff_traces
from tracevault.pytest_plugin import load_regression_trace, verify_regression_trace
from tracevault.replay import ReplayEngine
from tracevault.schema import (
    BoundaryType,
    SpanType,
    Trace,
    TraceNotFoundError,
    UnsafeTraceError,
)
from tracevault.storage import TraceStore


def _capture_to_store(store: TraceStore) -> Trace:
    with capture("pytest_plugin_flow", store=store, auto_save=True) as sess:
        with sess.span("model_call", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
            sess.record_model_call(
                {"model": "gpt-4o-mini", "prompt": "check invoice"},
                {"content": "calling tool"},
                name="llm",
            )
        with sess.span("tool_call", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
            sess.record_tool_call(
                "get_invoice",
                {"invoice_id": "INV-10"},
                result={"paid": True, "amount": 100},
            )
        sess.set_outputs({"status": "paid"})
    return store.load(sess.trace_id)


def test_tracevault_store_fixture_isolation(tracevault_store: TraceStore) -> None:
    assert tracevault_store.list_traces() == []
    trace = _capture_to_store(tracevault_store)
    assert tracevault_store.exists(trace.trace_id)
    assert len(tracevault_store.list_traces()) == 1


def test_tracevault_load_trace_and_replay_fixtures(
    tmp_path: Path,
    tracevault_store: TraceStore,
    tracevault_load_trace: Callable[..., Trace],
    tracevault_replay: Callable[..., ReplayEngine],
    tracevault_expect: Callable[[Trace], TraceAssertions],
) -> None:
    trace = _capture_to_store(tracevault_store)

    # 1. Load by trace_id from tracevault_store
    loaded_by_id = tracevault_load_trace(trace.trace_id)
    assert loaded_by_id.trace_id == trace.trace_id

    # 2. Load by Trace instance directly
    loaded_direct = tracevault_load_trace(trace)
    assert loaded_direct.trace_id == trace.trace_id

    # 3. Export to JSON file and load by Path
    json_path = tmp_path / "exported_trace.json"
    json_path.write_text(trace.to_json(indent=2), encoding="utf-8")
    loaded_by_path = tracevault_load_trace(json_path)
    assert loaded_by_path.trace_id == trace.trace_id

    # 4. Replay via tracevault_replay fixture (from trace_id, path, and with overrides)
    engine = tracevault_replay(trace.trace_id)
    res = engine.replay_trace()
    assert res.success is True
    assert res.matched_fixtures == 2

    tool_fix = next(e for e in trace.fixtures.entries if e.boundary == BoundaryType.TOOL)
    override_engine = tracevault_replay(
        json_path,
        overrides={tool_fix.fixture_id: {"paid": False, "amount": 0}},
    )
    override_res = override_engine.replay_trace()
    assert override_res.overridden_fixtures == 1
    report = diff_traces(trace, override_res.candidate_trace)
    with pytest.raises(AssertionError, match="breaking"):
        assert_no_breaking_diffs(report)

    # 5. Fluent assertions via tracevault_expect fixture
    tracevault_expect(trace).is_valid().succeeded().called_tool(
        "get_invoice", result_subset={"paid": True}
    ).has_no_errors().has_no_secrets_leaked()


def test_verify_regression_trace_and_file_validation(
    tmp_path: Path,
    tracevault_store: TraceStore,
) -> None:
    trace = _capture_to_store(tracevault_store)
    json_path = tmp_path / "regression_fixture.json"
    json_path.write_text(trace.to_json(indent=2), encoding="utf-8")

    loaded = load_regression_trace(json_path)
    assert loaded.trace_id == trace.trace_id

    report = verify_regression_trace(json_path)
    assert not report.has_breaking

    # Invalid extension rejected
    txt_path = tmp_path / "bad.txt"
    txt_path.write_text("{}", encoding="utf-8")
    with pytest.raises(UnsafeTraceError, match="\\.json extension"):
        load_regression_trace(txt_path)

    # NUL byte rejected
    with pytest.raises(UnsafeTraceError, match="NUL"):
        load_regression_trace("bad\x00.json")

    # Missing file rejected
    with pytest.raises(TraceNotFoundError):
        load_regression_trace(tmp_path / "does_not_exist.json")

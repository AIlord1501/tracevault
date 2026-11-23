"""Unit tests for BoundaryExecutor, SafetyPolicy enforcement, and boundary adapters."""

from __future__ import annotations

from typing import Any

import pytest

from tracevault.capture import capture
from tracevault.replay import (
    BoundaryExecutor,
    ModelBoundary,
    ReplayEngine,
    RetrievalBoundary,
    ToolBoundary,
)
from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryMode,
    BoundaryType,
    FixtureNotFoundError,
    PolicyViolationError,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    SafetyPolicy,
    SpanType,
    Trace,
)


def _capture_all_boundaries_trace() -> Trace:
    with capture("full_agent") as sess:
        with sess.span("llm", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
            sess.record_model_call(
                {"model": "gpt-4o-mini", "prompt": "hello"},
                {"content": "recorded_model_reply"},
                name="openai.chat",
            )
        with sess.span("tool", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
            sess.record_tool_call(
                "get_weather",
                {"city": "Seattle"},
                {"temp_c": 14},
            )
        with sess.span("rag", span_type=SpanType.RETRIEVAL, boundary=BoundaryType.RETRIEVAL):
            sess.record_retrieval(
                {"query": "return policy", "top_k": 3},
                {"documents": [{"doc_id": "d1", "content": "30 days"}]},
                name="docs_index",
            )
    assert sess.trace is not None
    return sess.trace


def _live_config(
    boundary: BoundaryType,
    *,
    mode: ReplayMode = ReplayMode.BOUNDARY_GOVERNED,
    policy: SafetyPolicy | None = None,
) -> ReplayConfig:
    modes = {b: BoundaryMode.RECORDED for b in BoundaryType}
    modes[boundary] = BoundaryMode.LIVE
    return ReplayConfig(
        mode=mode,
        boundary_modes=modes,
        safety_policy=policy if policy is not None else SafetyPolicy(),
    )


def test_recorded_mode_never_calls_live_fn_and_matches_captured_boundaries() -> None:
    source = _capture_all_boundaries_trace()
    engine = ReplayEngine(source)
    executor = BoundaryExecutor(engine)

    called = False

    def forbidden_live(_req: dict[str, Any]) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"live": True}

    model_res = ModelBoundary(executor).invoke(
        {"model": "gpt-4o-mini", "prompt": "hello"},
        live_fn=forbidden_live,
        name="openai.chat",
    )
    tool_res = ToolBoundary(executor).invoke(
        "get_weather",
        {"city": "Seattle"},
        live_fn=forbidden_live,
    )
    ret_res = RetrievalBoundary(executor).invoke(
        {"query": "return policy", "top_k": 3},
        live_fn=forbidden_live,
        name="docs_index",
    )

    assert called is False
    assert engine.live_calls == 0
    assert model_res == {"content": "recorded_model_reply"}
    assert tool_res == {"temp_c": 14}
    assert ret_res == {"documents": [{"doc_id": "d1", "content": "30 days"}]}


def test_recorded_mode_never_falls_back_to_live_fn_on_missing_fixture() -> None:
    source = _capture_all_boundaries_trace()
    engine = ReplayEngine(source)
    executor = BoundaryExecutor(engine)

    called = False

    def forbidden_live(_req: dict[str, Any]) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"fallback": True}

    with pytest.raises(FixtureNotFoundError):
        ModelBoundary(executor).invoke(
            {"model": "gpt-4o-mini", "prompt": "unseen"},
            live_fn=forbidden_live,
        )
    assert called is False
    assert engine.live_calls == 0


def test_deny_mode_always_raises_policy_violation_without_calling_live_fn() -> None:
    source = _capture_all_boundaries_trace()
    modes = {b: BoundaryMode.RECORDED for b in BoundaryType}
    modes[BoundaryType.TOOL] = BoundaryMode.DENY
    engine = ReplayEngine(source, config=ReplayConfig(boundary_modes=modes))
    executor = BoundaryExecutor(engine)

    decision = executor.evaluate_policy(BoundaryType.TOOL, tool_name="get_weather")
    assert decision.allowed is False
    assert decision.mode == BoundaryMode.DENY

    called = False

    def live_tool(_req: dict[str, Any]) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    with pytest.raises(PolicyViolationError, match="denied"):
        ToolBoundary(executor).invoke("get_weather", {"city": "Seattle"}, live_fn=live_tool)
    assert called is False


def test_live_rejected_when_replay_mode_not_boundary_governed() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.MODEL},
        allowed_hosts={"api.example.test"},
        max_live_calls=5,
    )
    cfg = _live_config(BoundaryType.MODEL, mode=ReplayMode.OFFLINE_STRICT, policy=policy)
    executor = BoundaryExecutor(ReplayEngine(source, config=cfg))

    decision = executor.evaluate_policy(BoundaryType.MODEL, host="api.example.test")
    assert decision.allowed is False
    assert "BOUNDARY_GOVERNED" in decision.reason

    with pytest.raises(PolicyViolationError, match="BOUNDARY_GOVERNED"):
        ModelBoundary(executor).invoke(
            {"prompt": "hi"},
            live_fn=lambda _r: {"ok": True},
            host="api.example.test",
        )


def test_live_rejected_when_boundary_not_in_allow_live_boundaries() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.RETRIEVAL},
        max_live_calls=5,
    )
    cfg = _live_config(BoundaryType.MODEL, policy=policy)
    executor = BoundaryExecutor(ReplayEngine(source, config=cfg))

    with pytest.raises(PolicyViolationError, match="allow_live_boundaries"):
        ModelBoundary(executor).invoke({"prompt": "hi"}, live_fn=lambda _r: {"ok": True})


def test_live_rejected_when_max_live_calls_is_zero() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.MODEL},
        max_live_calls=0,
        require_explicit_opt_in=True,
    )
    cfg = _live_config(BoundaryType.MODEL, policy=policy)
    executor = BoundaryExecutor(ReplayEngine(source, config=cfg))

    with pytest.raises(PolicyViolationError, match="max_live_calls > 0"):
        ModelBoundary(executor).invoke({"prompt": "hi"}, live_fn=lambda _r: {"ok": True})


def test_live_rejected_when_tool_not_in_allowed_tools() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.TOOL},
        allowed_tools={"read_only_lookup"},
        max_live_calls=3,
    )
    cfg = _live_config(BoundaryType.TOOL, policy=policy)
    executor = BoundaryExecutor(ReplayEngine(source, config=cfg))

    called = False

    def dangerous_tool(_req: dict[str, Any]) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"deleted": True}

    with pytest.raises(PolicyViolationError, match="allowed_tools"):
        ToolBoundary(executor).invoke("delete_database", {"confirm": True}, live_fn=dangerous_tool)
    assert called is False


def test_live_rejected_on_unauthorized_or_missing_host() -> None:
    source = _capture_all_boundaries_trace()

    # 1. Empty allowed_hosts rejects any specified host
    policy_empty = SafetyPolicy(
        allow_live_boundaries={BoundaryType.MODEL},
        allowed_hosts=set(),
        max_live_calls=2,
    )
    exec_empty = BoundaryExecutor(
        ReplayEngine(source, config=_live_config(BoundaryType.MODEL, policy=policy_empty))
    )
    with pytest.raises(PolicyViolationError, match="allowed_hosts"):
        ModelBoundary(exec_empty).invoke(
            {"prompt": "hi"},
            live_fn=lambda _r: {"ok": True},
            host="api.openai.com",
        )

    # 2. Non-empty allowed_hosts rejects mismatched host AND missing host
    policy_hosts = SafetyPolicy(
        allow_live_boundaries={BoundaryType.RETRIEVAL},
        allowed_hosts={"search.internal.local"},
        max_live_calls=2,
    )
    exec_hosts = BoundaryExecutor(
        ReplayEngine(source, config=_live_config(BoundaryType.RETRIEVAL, policy=policy_hosts))
    )
    with pytest.raises(PolicyViolationError, match="allowed_hosts"):
        RetrievalBoundary(exec_hosts).invoke(
            {"query": "x"},
            live_fn=lambda _r: {"docs": []},
            host="evil.example.com",
        )
    with pytest.raises(PolicyViolationError, match="Host is required"):
        RetrievalBoundary(exec_hosts).invoke(
            {"query": "x"},
            live_fn=lambda _r: {"docs": []},
            host=None,
        )


def test_live_requires_live_fn() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.MODEL},
        allowed_hosts={"localhost"},
        max_live_calls=1,
    )
    executor = BoundaryExecutor(
        ReplayEngine(source, config=_live_config(BoundaryType.MODEL, policy=policy))
    )
    with pytest.raises(ReplayError, match="live_fn is required"):
        ModelBoundary(executor).invoke({"prompt": "hi"}, live_fn=None, host="localhost")


def test_authorized_live_execution_redacts_records_and_enforces_call_cap() -> None:
    source = _capture_all_boundaries_trace()
    policy = SafetyPolicy(
        allow_live_boundaries={BoundaryType.MODEL, BoundaryType.TOOL, BoundaryType.RETRIEVAL},
        allowed_tools={"get_weather"},
        allowed_hosts={"mock.local"},
        max_live_calls=2,
        require_explicit_opt_in=True,
    )
    cfg = ReplayConfig(
        mode=ReplayMode.BOUNDARY_GOVERNED,
        boundary_modes={
            BoundaryType.MODEL: BoundaryMode.LIVE,
            BoundaryType.TOOL: BoundaryMode.LIVE,
            BoundaryType.RETRIEVAL: BoundaryMode.RECORDED,
            BoundaryType.CUSTOM: BoundaryMode.RECORDED,
        },
        safety_policy=policy,
    )
    engine = ReplayEngine(source, config=cfg)
    executor = BoundaryExecutor(engine)

    # Call 1 (authorized live MODEL) - response contains a secret that must be redacted
    def mock_model(req: dict[str, Any]) -> dict[str, Any]:
        return {
            "content": f"live reply to {req['prompt']}",
            "api_key": "sk-live-secret-should-be-redacted-12345",
        }

    r1 = ModelBoundary(executor).invoke(
        {"prompt": "hello"},
        live_fn=mock_model,
        name="mock_model",
        host="mock.local",
    )
    assert r1["content"] == "live reply to hello"
    assert r1["api_key"] == REDACTED_VALUE
    assert engine.live_calls == 1

    # Call 2 (authorized live TOOL)
    def mock_tool(req: dict[str, Any]) -> dict[str, Any]:
        return {"city": req["arguments"]["city"], "temp_c": 22}

    r2 = ToolBoundary(executor).invoke("get_weather", {"city": "Austin"}, live_fn=mock_tool)
    assert r2 == {"city": "Austin", "temp_c": 22}
    assert engine.live_calls == 2

    # Call 3 exceeds max_live_calls == 2 -> fail closed BEFORE invoking live_fn
    third_called = False

    def should_not_run(_req: dict[str, Any]) -> dict[str, Any]:
        nonlocal third_called
        third_called = True
        return {"ok": True}

    with pytest.raises(PolicyViolationError, match="Live call limit reached"):
        ModelBoundary(executor).invoke(
            {"prompt": "third"},
            live_fn=should_not_run,
            host="mock.local",
        )
    assert third_called is False
    assert engine.live_calls == 2

    # Recorded RETRIEVAL still works offline alongside live boundaries
    r_ret = RetrievalBoundary(executor).invoke(
        {"query": "return policy", "top_k": 3},
        name="docs_index",
    )
    assert r_ret == {"documents": [{"doc_id": "d1", "content": "30 days"}]}

    # Candidate trace captures all recorded + live calls cleanly
    result = engine.build_result(fork=True)
    assert result.success is True
    assert result.live_calls == 2
    assert result.matched_fixtures == 1
    assert len(result.candidate_trace.fixtures.entries) == 3
    assert result.candidate_trace.fixtures.entries[0].response is not None
    assert result.candidate_trace.fixtures.entries[0].response["api_key"] == REDACTED_VALUE

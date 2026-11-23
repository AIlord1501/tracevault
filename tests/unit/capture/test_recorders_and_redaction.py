"""Unit tests for interaction recorders, fixture fingerprinting, and redaction."""

from __future__ import annotations

import pytest

from tracevault.capture import CaptureConfig, capture
from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    EventKind,
    ExecutionError,
    RedactionConfig,
    compute_fingerprint,
)


def test_model_tool_retrieval_recorders_and_call_index() -> None:
    with capture("interactions") as session:
        model_req = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        fix_m0 = session.record_model_call(model_req, {"content": "Hi #1"}, name="chat")
        fix_m1 = session.record_model_call(model_req, {"content": "Hi #2"}, name="chat")
        fix_m_empty = session.record_model_call({"provider": "openai", "model": "gpt-4o-mini"})
        fix_m_err = session.record_model_call(model_req, None, error="rate limited", name="chat")

        fix_t0 = session.record_tool_call("calculator", {"x": 2, "y": 3}, {"sum": 5})
        fix_t1 = session.record_tool_call("calculator", {"x": 2, "y": 3}, {"sum": 5})
        fix_t_err = session.record_tool_call(
            "calculator",
            {"x": 1, "y": 0},
            None,
            error=ZeroDivisionError("division by zero"),
        )

        query = {"retriever": "vector_db", "query": "refund policy", "top_k": 3}
        fix_r0 = session.record_retrieval(
            query,
            {"documents": [{"doc_id": "d1", "content": "30-day refund"}]},
            name="vector_db",
        )
        fix_r_err = session.record_retrieval(
            query,
            None,
            error=ExecutionError(error_type="IndexTimeout", message="timeout"),
            name="vector_db",
        )

    assert session.trace is not None
    trace = session.trace

    # Verify deterministic fingerprints & incrementing call_index
    expected_model_fp = compute_fingerprint(BoundaryType.MODEL, model_req)
    assert fix_m0.fingerprint == expected_model_fp
    assert fix_m0.call_index == 0
    assert fix_m1.fingerprint == expected_model_fp
    assert fix_m1.call_index == 1
    assert fix_m_err.fingerprint == expected_model_fp
    assert fix_m_err.call_index == 2
    assert fix_m_err.error is not None
    assert fix_m_err.error.error_type == "RecordedError"
    assert fix_m_err.error.message == "rate limited"

    # Empty response defaults to {} so FixtureEntry invariant holds
    assert fix_m_empty.response == {}
    assert fix_m_empty.error is None

    expected_tool_fp = compute_fingerprint(
        BoundaryType.TOOL,
        {"tool_name": "calculator", "arguments": {"x": 2, "y": 3}},
    )
    assert fix_t0.fingerprint == expected_tool_fp
    assert fix_t0.call_index == 0
    assert fix_t1.call_index == 1
    assert fix_t_err.error is not None
    assert fix_t_err.error.error_type == "ZeroDivisionError"

    expected_ret_fp = compute_fingerprint(BoundaryType.RETRIEVAL, query)
    assert fix_r0.fingerprint == expected_ret_fp
    assert fix_r0.call_index == 0
    assert fix_r_err.call_index == 1
    assert fix_r_err.error is not None
    assert fix_r_err.error.error_type == "IndexTimeout"

    assert len(trace.fixtures.entries) == 9

    # Monotonic sequence numbers across all events
    sequences = [e.sequence for e in trace.events]
    assert sequences == list(range(len(sequences)))

    event_types = [e.event_type for e in trace.events]
    for expected in (
        EventKind.MODEL_REQUEST,
        EventKind.MODEL_RESPONSE,
        EventKind.MODEL_ERROR,
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
        EventKind.TOOL_ERROR,
        EventKind.RETRIEVAL_QUERY,
        EventKind.RETRIEVAL_RESULT,
        EventKind.RETRIEVAL_ERROR,
    ):
        assert expected in event_types


def test_agent_transition_state_change_stream_chunk_and_error_recorders() -> None:
    with capture("multi_agent") as session:
        ev_trans = session.record_agent_transition(
            "billing_agent",
            from_agent="triage_agent",
            reason="Billing issue",
            handoff_state={"ticket_id": 42},
        )
        ev_state = session.record_state_change(
            "workflow.step",
            "set",
            before="init",
            after="billing",
        )
        ev_chunk_0 = session.record_stream_chunk(
            "stream_1",
            0,
            {"content": "Hello "},
            is_final=False,
        )
        ev_chunk_1 = session.record_stream_chunk(
            "stream_1",
            1,
            {"content": "world"},
            is_final=True,
            finish_reason="stop",
            usage={"total_tokens": 2},
        )
        ev_err = session.record_error(
            ValueError("recoverable parse glitch"),
            boundary=BoundaryType.TOOL,
            recoverable=True,
        )

    assert ev_trans.event_type == EventKind.AGENT_TRANSITION
    assert ev_trans.payload["to_agent"] == "billing_agent"
    assert ev_trans.payload["from_agent"] == "triage_agent"

    assert ev_state.event_type == EventKind.STATE_CHANGE
    assert ev_state.payload["key_path"] == "workflow.step"
    assert ev_state.payload["operation"] == "set"

    assert ev_chunk_0.event_type == EventKind.STREAM_CHUNK
    assert ev_chunk_0.payload["chunk_index"] == 0
    assert ev_chunk_1.payload["is_final"] is True
    assert ev_chunk_1.payload["finish_reason"] == "stop"

    assert ev_err.event_type == EventKind.EXCEPTION
    assert ev_err.boundary == BoundaryType.TOOL
    assert ev_err.payload["recoverable"] is True
    assert ev_err.payload["error"]["error_type"] == "ValueError"


def test_default_redaction_scrubs_secrets_everywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sk = "sk-testsecretvalue1234567890"
    fake_bearer = "Bearer secret_bearer_token_999"
    monkeypatch.setenv("OPENAI_API_KEY", fake_sk)

    with capture(
        "secret_run",
        inputs={"api_key": fake_sk, "prompt": f"Use {fake_bearer}"},
        metadata={"authorization": fake_bearer},
        environment={"custom_secret": "top-secret-val", "region": "us-east"},
    ) as session:
        with session.span("secret_span", attributes={"password": "hunter2"}):
            session.record_model_call(
                {"headers": {"x-api-key": fake_sk}, "prompt": f"key is {fake_sk}"},
                {"content": f"leaked {fake_sk}"},
            )
            session.record_error(RuntimeError(f"Auth failed with {fake_bearer}"))
        session.set_outputs({"access_token": "tok_123", "status": "ok"})

    assert session.trace is not None
    raw_json = session.trace.to_json()

    assert fake_sk not in raw_json
    assert fake_bearer not in raw_json
    assert "hunter2" not in raw_json
    assert "top-secret-val" not in raw_json
    assert "tok_123" not in raw_json
    assert "OPENAI_API_KEY" not in session.trace.root_run.environment

    assert session.trace.root_run.inputs["api_key"] == REDACTED_VALUE
    assert session.trace.root_run.outputs is not None
    assert session.trace.root_run.outputs["access_token"] == REDACTED_VALUE
    assert session.trace.root_run.outputs["status"] == "ok"
    assert session.trace.root_run.environment["custom_secret"] == REDACTED_VALUE
    assert session.trace.root_run.environment["region"] == "us-east"
    assert session.trace.spans[0].attributes["password"] == REDACTED_VALUE


def test_redact_false_and_custom_redaction_config() -> None:
    with capture("no_redact", inputs={"api_key": "sk-visible1234567890"}, redact=False) as s_off:
        s_off.set_outputs({"password": "plain"})

    assert s_off.trace is not None
    assert s_off.trace.redaction_applied is False
    assert s_off.trace.root_run.inputs["api_key"] == "sk-visible1234567890"
    assert s_off.trace.root_run.outputs == {"password": "plain"}

    custom_cfg = CaptureConfig(
        redact=True,
        redaction_config=RedactionConfig(
            sensitive_keys=frozenset({"ssn"}),
            redact_patterns=(),
            replacement="***",
        ),
    )
    with capture("custom_redact", inputs={"ssn": "123-45-6789"}, config=custom_cfg) as s_custom:
        pass

    assert s_custom.trace is not None
    assert s_custom.trace.root_run.inputs["ssn"] == "***"

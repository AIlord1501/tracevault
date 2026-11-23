"""Tests for all 7 canonical interaction payload groups."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tracevault.schema import (
    AgentTransitionPayload,
    BoundaryType,
    ExceptionPayload,
    ExecutionError,
    ModelRequestPayload,
    ModelResponsePayload,
    RetrievalQueryPayload,
    RetrievalResultPayload,
    RetrievedDocument,
    StateChangePayload,
    StreamChunkPayload,
    ToolCallPayload,
    ToolResultPayload,
    UnsafeTraceError,
)


def test_model_request_and_response_payloads() -> None:
    req = ModelRequestPayload(
        provider="openai",
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hello"}],
        parameters={"temperature": 0.0},
    )
    assert req.stream is False
    assert req.tools == []
    assert ModelRequestPayload.model_validate_json(req.model_dump_json()) == req

    resp = ModelResponsePayload(
        model="gpt-4o-mini",
        content="hi there",
        finish_reason="stop",
        usage={"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    )
    assert resp.tool_calls == []
    assert ModelResponsePayload.model_validate_json(resp.model_dump_json()) == resp

    with pytest.raises(ValidationError):
        ModelRequestPayload(provider="", model="gpt-4o-mini")
    with pytest.raises(ValidationError):
        ModelRequestPayload(provider="openai", model="m", extra_key=1)  # type: ignore[call-arg]
    with pytest.raises(UnsafeTraceError):
        ModelRequestPayload(
            provider="openai",
            model="m",
            parameters={"temp": float("nan")},
        )


def test_tool_call_and_result_payloads() -> None:
    call = ToolCallPayload(tool_name="search_docs", call_id="c1", arguments={"q": "billing"})
    assert ToolCallPayload.model_validate_json(call.model_dump_json()) == call

    res = ToolResultPayload(tool_name="search_docs", call_id="c1", result={"hits": 2})
    assert res.is_error is False
    assert ToolResultPayload.model_validate_json(res.model_dump_json()) == res

    with pytest.raises(UnsafeTraceError):
        ToolResultPayload(tool_name="search_docs", result=object())


def test_retrieval_payloads_and_finite_scores() -> None:
    query = RetrievalQueryPayload(retriever="faiss", query="invoice policy", top_k=3)
    assert query.filters == {}
    with pytest.raises(ValidationError):
        RetrievalQueryPayload(retriever="faiss", query="x", top_k=0)

    doc = RetrievedDocument(doc_id="d1", content="Refunds within 30 days", score=0.92)
    result = RetrievalResultPayload(retriever="faiss", documents=[doc])
    assert RetrievalResultPayload.model_validate_json(result.model_dump_json()) == result

    with pytest.raises(UnsafeTraceError):
        RetrievedDocument(doc_id="d1", content="x", score=float("nan"))
    with pytest.raises(UnsafeTraceError):
        RetrievedDocument(doc_id="d1", content="x", score=float("inf"))


def test_agent_transition_state_change_exception_and_stream_payloads() -> None:
    transition = AgentTransitionPayload(
        from_agent="router",
        to_agent="billing_agent",
        reason="invoice_issue",
        handoff_state={"ticket_id": 42},
    )
    assert AgentTransitionPayload.model_validate_json(transition.model_dump_json()) == transition

    state = StateChangePayload(
        key_path="session.step",
        operation="set",
        before="triage",
        after="refund",
    )
    assert StateChangePayload.model_validate_json(state.model_dump_json()) == state
    with pytest.raises(ValidationError):
        StateChangePayload(key_path="a", operation="invalid")  # type: ignore[arg-type]

    exc_payload = ExceptionPayload(
        error=ExecutionError(error_type="TimeoutError", message="timed out", retryable=True),
        boundary=BoundaryType.MODEL,
        recoverable=True,
    )
    assert ExceptionPayload.model_validate_json(exc_payload.model_dump_json()) == exc_payload

    chunk = StreamChunkPayload(
        stream_id="st_1",
        chunk_index=0,
        delta={"content": "Hel"},
        is_final=False,
    )
    assert StreamChunkPayload.model_validate_json(chunk.model_dump_json()) == chunk
    with pytest.raises(ValidationError):
        StreamChunkPayload(stream_id="st_1", chunk_index=-1)
    with pytest.raises(ValidationError):
        chunk.is_final = True  # type: ignore[misc]

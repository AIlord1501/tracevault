"""Unit tests for sync/async TraceVault instrumentation decorators."""

from __future__ import annotations

import asyncio

import pytest

from tracevault.capture import (
    CaptureSession,
    acapture,
    capture,
    trace_model,
    trace_retrieval,
    trace_span,
    trace_tool,
)
from tracevault.schema import BoundaryType, SpanStatus, SpanType


def test_decorators_noop_passthrough_when_no_session() -> None:
    @trace_span("my_span")
    def step(x: int) -> int:
        """Step docstring."""
        return x + 1

    @trace_model("my_model")
    def call_llm(prompt: str) -> dict[str, str]:
        return {"content": f"reply:{prompt}"}

    @trace_tool("my_tool")
    def add(a: int, b: int) -> int:
        return a + b

    @trace_retrieval("my_retriever")
    def search(query: str) -> list[dict[str, str]]:
        return [{"doc_id": "1", "content": query}]

    assert step.__name__ == "step"
    assert step.__doc__ == "Step docstring."
    assert step(2) == 3
    assert call_llm("hi") == {"content": "reply:hi"}
    assert add(3, 4) == 7
    assert search("refund") == [{"doc_id": "1", "content": "refund"}]


async def test_async_decorators_noop_passthrough_when_no_session() -> None:
    @trace_span()
    async def astep(x: int) -> int:
        await asyncio.sleep(0)
        return x * 2

    @trace_model()
    async def acall_llm(prompt: str) -> dict[str, str]:
        await asyncio.sleep(0)
        return {"content": prompt}

    @trace_tool()
    async def atool(v: int) -> int:
        await asyncio.sleep(0)
        return v + 10

    @trace_retrieval()
    async def aretrieve(q: str) -> list[dict[str, str]]:
        await asyncio.sleep(0)
        return [{"doc_id": "d1", "content": q}]

    assert await astep(3) == 6
    assert await acall_llm("ok") == {"content": "ok"}
    assert await atool(5) == 15
    assert await aretrieve("faq") == [{"doc_id": "d1", "content": "faq"}]


def test_sync_decorators_record_spans_and_fixtures() -> None:
    @trace_model("llm.generate")
    def generate(prompt: str, temperature: float = 0.0) -> dict[str, str]:
        return {"content": f"ans:{prompt}"}

    @trace_tool("math.multiply")
    def multiply(a: int, b: int) -> int:
        return a * b

    @trace_retrieval("kb.search")
    def kb_search(query: str) -> list[dict[str, str]]:
        return [{"doc_id": "kb1", "content": "policy"}]

    @trace_span("pipeline", span_type=SpanType.WORKFLOW)
    def run_pipeline(question: str) -> dict[str, object]:
        docs = kb_search(question)
        product = multiply(6, 7)
        resp = generate(question)
        return {"docs": docs, "product": product, "resp": resp}

    with capture("decorated_sync") as session:
        result = run_pipeline("What is 6*7?")
        session.set_outputs({"product": result["product"]})

    assert result["product"] == 42
    assert session.trace is not None
    trace = session.trace

    assert [s.name for s in trace.spans] == [
        "pipeline",
        "kb.search",
        "math.multiply",
        "llm.generate",
    ]
    pipeline_span = trace.spans[0]
    for child in trace.spans[1:]:
        assert child.parent_span_id == pipeline_span.span_id
        assert child.status == SpanStatus.OK

    assert len(trace.fixtures.entries) == 3
    boundaries = [f.boundary for f in trace.fixtures.entries]
    assert boundaries == [BoundaryType.RETRIEVAL, BoundaryType.TOOL, BoundaryType.MODEL]
    assert trace.fixtures.entries[0].response == {
        "documents": [{"doc_id": "kb1", "content": "policy"}]
    }
    assert trace.fixtures.entries[1].response == {"result": 42}
    assert trace.fixtures.entries[2].response == {"content": "ans:What is 6*7?"}


async def test_async_decorators_record_spans_and_fixtures() -> None:
    @trace_model("async.llm")
    async def acall_llm(prompt: str) -> dict[str, str]:
        await asyncio.sleep(0)
        return {"content": f"async:{prompt}"}

    @trace_tool("async.tool")
    async def arun_tool(x: int) -> dict[str, int]:
        await asyncio.sleep(0)
        return {"doubled": x * 2}

    @trace_retrieval("async.retriever")
    async def asearch(query: str) -> dict[str, list[str]]:
        await asyncio.sleep(0)
        return {"hits": [query]}

    @trace_span("async.workflow", span_type=SpanType.AGENT)
    async def aworkflow(q: str) -> dict[str, object]:
        hits = await asearch(q)
        tool_out = await arun_tool(9)
        model_out = await acall_llm(q)
        return {"hits": hits, "tool": tool_out, "model": model_out}

    async with acapture("decorated_async") as session:
        output = await aworkflow("hello")
        session.set_outputs({"done": True})

    assert output["tool"] == {"doubled": 18}
    assert session.trace is not None
    assert len(session.trace.spans) == 4
    assert len(session.trace.fixtures.entries) == 3
    assert [f.boundary for f in session.trace.fixtures.entries] == [
        BoundaryType.RETRIEVAL,
        BoundaryType.TOOL,
        BoundaryType.MODEL,
    ]


def test_decorators_explicit_session_and_error_recording() -> None:
    explicit_session = CaptureSession("explicit_target")

    @trace_tool("failing_tool", session=explicit_session)
    def explode(x: int) -> int:
        raise ValueError(f"bad input: {x}")

    @trace_model("explicit_model", session=explicit_session)
    def call_model(prompt: str) -> str:
        return f"ok:{prompt}"

    assert call_model("hello") == "ok:hello"
    with pytest.raises(ValueError, match="bad input: 99"):
        explode(99)

    trace = explicit_session.finalize()
    assert len(trace.spans) == 2
    assert trace.spans[0].status == SpanStatus.OK
    assert trace.spans[1].status == SpanStatus.ERROR
    assert trace.spans[1].error is not None
    assert trace.spans[1].error.error_type == "ValueError"

    assert len(trace.fixtures.entries) == 2
    assert trace.fixtures.entries[0].response == {"result": "ok:hello"}
    assert trace.fixtures.entries[1].response is None
    assert trace.fixtures.entries[1].error is not None
    assert trace.fixtures.entries[1].error.error_type == "ValueError"


def test_bound_method_decorator_omits_self_from_fingerprint() -> None:
    class FakeClient:
        @trace_tool("client.fetch")
        def fetch(self, item_id: int) -> dict[str, int]:
            return {"item_id": item_id}

    c1 = FakeClient()
    c2 = FakeClient()
    with capture("method_test") as session:
        c1.fetch(7)
        c2.fetch(7)

    assert session.trace is not None
    f0, f1 = session.trace.fixtures.entries
    assert f0.fingerprint == f1.fingerprint
    assert f0.call_index == 0
    assert f1.call_index == 1
    assert "self" not in f0.request["arguments"]

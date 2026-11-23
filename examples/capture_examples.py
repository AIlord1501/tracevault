"""Runnable TraceVault M3 capture & instrumentation examples (offline, zero network calls)."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from tracevault import (
    BoundaryType,
    EventKind,
    SpanType,
    TraceStore,
    acapture,
    capture,
    trace_model,
    trace_tool,
)


@trace_tool("lookup_order")
def lookup_order(order_id: str) -> dict[str, Any]:
    """Simulated deterministic tool call."""
    return {"order_id": order_id, "status": "shipped", "total_usd": 49.99}


@trace_model("summarize_order")
async def summarize_order_async(order_id: str, prompt: str) -> dict[str, Any]:
    """Simulated async model call."""
    await asyncio.sleep(0)
    return {"content": f"Order {order_id} is shipped.", "prompt_chars": len(prompt)}


def example_basic_sync_capture_and_persistence(store: TraceStore) -> str:
    """Demonstrate basic capture, nested spans, events, model/tool calls, and persistence."""
    with capture(
        "support_triage_workflow",
        inputs={"ticket_id": "T-1042", "api_key": "sk-example-redacted-1234567890"},
        tags=["example", "sync"],
        store=store,
        auto_save=True,
    ) as session:
        session.record_event(EventKind.CUSTOM, {"step": "triage_started"})

        with session.span("plan_and_act", span_type=SpanType.AGENT):
            order = lookup_order("ORD-42")
            session.record_model_call(
                request={
                    "provider": "local-mock",
                    "model": "mock-gpt",
                    "messages": [{"role": "user", "content": f"Summarize {order['order_id']}"}],
                },
                response={"content": "Your order ORD-42 has shipped.", "finish_reason": "stop"},
                name="mock_completion",
            )
            session.record_state_change(
                "ticket.status",
                "set",
                before="open",
                after="answered",
            )

        session.set_outputs({"reply": "Your order ORD-42 has shipped.", "order": order})

    loaded = store.load(session.trace_id)
    assert loaded.root_run.inputs["api_key"] == "[REDACTED]"
    assert len(loaded.fixtures.entries) == 2
    return session.trace_id


def example_error_capture(store: TraceStore) -> str:
    """Demonstrate exception recording and automatic FAILED persistence."""
    captured_id = ""
    try:
        with capture(
            "failing_tool_workflow",
            inputs={"query": "missing-record"},
            tags=["example", "error"],
            store=store,
            auto_save=True,
        ) as session:
            captured_id = session.trace_id
            with session.span(
                "database_lookup", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL
            ):
                raise RuntimeError("Record not found for api_key=sk-secret-token-9876543210")
    except RuntimeError:
        pass

    failed_trace = store.load(captured_id)
    assert failed_trace.root_run.status.value == "failed"
    assert failed_trace.root_run.error is not None
    assert "sk-secret-token-9876543210" not in failed_trace.root_run.error.message
    return captured_id


async def example_async_concurrent_capture(store: TraceStore) -> str:
    """Demonstrate async capture with concurrent isolated spans."""
    async with acapture(
        "async_batch_workflow",
        inputs={"order_ids": ["ORD-1", "ORD-2", "ORD-3"]},
        tags=["example", "async"],
        store=store,
        auto_save=True,
    ) as session:

        async def handle_order(oid: str) -> dict[str, Any]:
            async with session.aspan(f"process_{oid}", span_type=SpanType.WORKFLOW):
                return await summarize_order_async(oid, f"Summarize {oid}")

        results = await asyncio.gather(*(handle_order(oid) for oid in ["ORD-1", "ORD-2", "ORD-3"]))
        session.set_outputs({"summaries": results})

    loaded = store.load(session.trace_id)
    assert len(loaded.spans) == 6  # 3 workflow spans + 3 decorated model spans
    return session.trace_id


def main() -> None:
    """Run all M3 capture examples against a temporary local TraceStore."""
    with tempfile.TemporaryDirectory(prefix="tracevault_m3_examples_") as tmp:
        store = TraceStore(Path(tmp) / ".tracevault")
        store.init()
        try:
            sync_id = example_basic_sync_capture_and_persistence(store)
            err_id = example_error_capture(store)
            async_id = asyncio.run(example_async_concurrent_capture(store))
            summaries = store.list_traces()
            print(f"Captured & persisted {len(summaries)} traces:")
            for item in summaries:
                print(
                    f"  - {item.trace_id} | {item.run_name} | status={item.status.value} "
                    f"| spans={item.span_count} | events={item.event_count} "
                    f"| fixtures={item.fixture_count}"
                )
            assert {sync_id, err_id, async_id} == {s.trace_id for s in summaries}
        finally:
            store.close()


if __name__ == "__main__":
    main()

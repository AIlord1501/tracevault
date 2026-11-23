"""End-to-end integration tests between tracevault.capture and tracevault.storage."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SYNTHETIC_SECRETS
from tracevault.capture import (
    acapture,
    capture,
    get_current_run_id,
    get_current_session,
    get_current_span_id,
    trace_model,
    trace_retrieval,
    trace_span,
    trace_tool,
)
from tracevault.schema import (
    BoundaryType,
    EventKind,
    ExportFormat,
    RunStatus,
    SpanStatus,
    SpanType,
    Trace,
    TraceFrozenError,
)
from tracevault.storage import TraceQuery, TraceStore


@trace_span("sync_workflow_step", span_type=SpanType.WORKFLOW)
def _sync_decorated_workflow(ticket_id: int) -> dict[str, Any]:
    docs = _sync_decorated_retriever(query=f"invoice {ticket_id}")
    tool_res = _sync_decorated_tool(invoice_id=ticket_id)
    model_res = _sync_decorated_model(prompt=f"Summarize {ticket_id} with {len(docs)} docs")
    return {"docs": len(docs), "tool": tool_res, "model": model_res}


@trace_retrieval("kb_retriever")
def _sync_decorated_retriever(query: str) -> list[dict[str, Any]]:
    return [{"doc_id": "d1", "content": f"policy for {query}", "score": 0.95}]


@trace_tool("lookup_invoice")
def _sync_decorated_tool(invoice_id: int) -> dict[str, Any]:
    return {"invoice_id": invoice_id, "amount_cents": 4200, "status": "overcharged"}


@trace_model("local_mock_llm")
def _sync_decorated_model(prompt: str) -> dict[str, Any]:
    return {"content": f"refund_review:{prompt}", "finish_reason": "stop"}


@trace_span("async_workflow_step", span_type=SpanType.WORKFLOW)
async def _async_decorated_workflow(ticket_id: int) -> dict[str, Any]:
    await asyncio.sleep(0)
    docs = await _async_decorated_retriever(query=f"async invoice {ticket_id}")
    tool_res = await _async_decorated_tool(invoice_id=ticket_id)
    model_res = await _async_decorated_model(prompt=f"Async summarize {ticket_id}")
    return {"docs": len(docs), "tool": tool_res, "model": model_res}


@trace_retrieval("async_kb_retriever")
async def _async_decorated_retriever(query: str) -> list[dict[str, Any]]:
    await asyncio.sleep(0)
    return [{"doc_id": "d2", "content": f"async policy for {query}", "score": 0.91}]


@trace_tool("async_lookup_invoice")
async def _async_decorated_tool(invoice_id: int) -> dict[str, Any]:
    await asyncio.sleep(0)
    return {"invoice_id": invoice_id, "status": "verified"}


@trace_model("async_local_mock_llm")
async def _async_decorated_model(prompt: str) -> dict[str, Any]:
    await asyncio.sleep(0)
    return {"content": f"approved:{prompt}", "finish_reason": "stop"}


class TestCaptureStorageSyncIntegration:
    """Full sync capture -> auto_save -> load -> freeze -> query -> export -> import round-trip."""

    def test_sync_capture_auto_save_freeze_query_export_and_import(self, tmp_path: Path) -> None:
        primary_dir = tmp_path / "primary_store"
        secondary_dir = tmp_path / "secondary_store"

        with TraceStore(primary_dir) as store:
            with capture(
                "support_triage_sync",
                trace_id="tr_integ_sync_001",
                inputs={"ticket_id": 42},
                tags=["triage", "billing"],
                metadata={"env": "local-test"},
                store=store,
                auto_save=True,
            ) as session:
                result = _sync_decorated_workflow(42)

                with (
                    session.start_child_run(
                        "refund_subagent",
                        inputs={"invoice": 42},
                        tags=["refund"],
                    ),
                    session.span(
                        "manual_boundary_checks",
                        span_type=SpanType.AGENT,
                        attributes={"stage": "verification"},
                    ),
                ):
                    session.record_model_call(
                        request={
                            "model": "mock-1",
                            "messages": [{"role": "user", "content": "hi"}],
                        },
                        response={"content": "hello", "finish_reason": "stop"},
                        name="manual_llm",
                    )
                    session.record_tool_call(
                        "audit_log",
                        args={"action": "flag_refund"},
                        result={"logged": True},
                    )
                    session.record_retrieval(
                        query={"q": "refund policy"},
                        results={"documents": [{"doc_id": "pol_1", "content": "30 days"}]},
                        name="policy_index",
                    )
                    session.record_agent_transition(
                        to_agent="refund_executor",
                        from_agent="triage_agent",
                        reason="overcharge confirmed",
                        handoff_state={"invoice_id": 42},
                    )
                    session.record_state_change(
                        "ticket.status",
                        "set",
                        before="open",
                        after="refund_pending",
                    )
                    session.record_stream_chunk(
                        "stream_1",
                        0,
                        {"text": "Refund "},
                        is_final=False,
                    )
                    session.record_stream_chunk(
                        "stream_1",
                        1,
                        {"text": "approved."},
                        is_final=True,
                        finish_reason="stop",
                    )
                    session.record_error(
                        "transient warning",
                        boundary=BoundaryType.TOOL,
                        recoverable=True,
                    )

                session.add_tags("verified")
                session.set_metadata("result_docs", result["docs"])
                session.set_outputs({"decision": "refund_approved", "invoice": 42})

            # Context reset cleanly after exit
            assert get_current_session() is None
            assert get_current_span_id() is None
            assert get_current_run_id() is None

            assert session.trace is not None
            loaded = store.load("tr_integ_sync_001")
            assert loaded == session.trace
            assert len(loaded.runs) == 2
            assert loaded.root_run.status == RunStatus.COMPLETED
            assert loaded.root_run.outputs == {"decision": "refund_approved", "invoice": 42}
            assert len(loaded.fixtures.entries) == 6  # 3 decorated + 3 manual

            # Freeze and verify immutability
            frozen = store.freeze("tr_integ_sync_001")
            assert frozen.frozen is True
            with pytest.raises(TraceFrozenError):
                store.save(loaded, overwrite=True)

            # Query & list_traces
            listed = store.list_traces(status=RunStatus.COMPLETED, tag="verified", frozen=True)
            assert len(listed) == 1
            summary = listed[0]
            assert summary.trace_id == "tr_integ_sync_001"
            assert summary.span_count == len(loaded.spans)
            assert summary.event_count == len(loaded.events)
            assert summary.fixture_count == len(loaded.fixtures.entries)
            assert {"triage", "billing", "verified"}.issubset(set(summary.tags))

            queried = store.query(TraceQuery(query="support_triage_sync", frozen=True))
            assert [q.trace_id for q in queried] == ["tr_integ_sync_001"]

            # Export JSONL and verify line structure
            jsonl_path = store.export_jsonl("tr_integ_sync_001", tmp_path / "sync.jsonl")
            jsonl_lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
            assert len(jsonl_lines) == 1 + len(loaded.events)
            header = json.loads(jsonl_lines[0])
            assert header["record_type"] == "trace_header"
            assert header["trace_id"] == "tr_integ_sync_001"
            event_seqs = [json.loads(line)["sequence"] for line in jsonl_lines[1:]]
            assert event_seqs == sorted(event_seqs)

            # Export JSON and import into a second fresh TraceStore
            json_export = store.export_trace(
                "tr_integ_sync_001", tmp_path / "sync.json", format=ExportFormat.JSON
            )

        with TraceStore(secondary_dir) as second_store:
            imported = second_store.import_trace(json_export, freeze=True)
            assert imported.trace_id == "tr_integ_sync_001"
            assert imported.frozen is True
            assert second_store.load("tr_integ_sync_001") == imported


class TestCaptureStorageAsyncIntegration:
    """Async acapture + async decorators + explicit persist() -> TraceStore round-trip."""

    async def test_async_capture_explicit_persist_round_trip(self, tmp_path: Path) -> None:
        with TraceStore(tmp_path / "async_store") as store:
            async with acapture(
                "support_triage_async",
                trace_id="tr_integ_async_001",
                inputs={"ticket_id": 99},
                tags=["async"],
            ) as session:
                res = await _async_decorated_workflow(99)
                async with (
                    session.astart_child_run("async_child_run", inputs={"step": 2}),
                    session.aspan("async_inner", span_type=SpanType.AGENT),
                ):
                    await asyncio.sleep(0)
                    session.record_state_change("async.done", "set", after=True)
                session.set_outputs({"status": "ok", "docs": res["docs"]})

            assert get_current_session() is None
            assert get_current_span_id() is None
            assert get_current_run_id() is None

            saved_path = session.persist(store=store)
            assert saved_path.is_file()

            loaded = store.load("tr_integ_async_001")
            assert loaded == session.trace
            assert Trace.from_json(loaded.to_json()) == loaded
            assert len(loaded.runs) == 2
            assert len(loaded.fixtures.entries) == 3
            assert store.list_traces(tag="async")[0].trace_id == "tr_integ_async_001"


class TestFailureHandlingIntegration:
    """Unhandled exceptions persist FAILED traces with redacted ExecutionError and clean context."""

    def test_sync_unhandled_exception_auto_saves_failed_trace_and_reraises(
        self, tmp_path: Path
    ) -> None:
        with TraceStore(tmp_path / "fail_sync_store") as store:
            with (
                pytest.raises(RuntimeError, match="downstream exploded"),
                capture(
                    "failing_sync_agent",
                    trace_id="tr_fail_sync_001",
                    store=store,
                    auto_save=True,
                ) as session,
                session.span("failing_step", span_type=SpanType.TOOL),
            ):
                raise RuntimeError(f"downstream exploded with {SYNTHETIC_SECRETS['openai_key']}")

            # Context must be completely reset
            assert get_current_session() is None
            assert get_current_span_id() is None
            assert get_current_run_id() is None

            loaded = store.load("tr_fail_sync_001")
            assert loaded.root_run.status == RunStatus.FAILED
            assert loaded.root_run.error is not None
            assert loaded.root_run.error.error_type == "RuntimeError"
            assert SYNTHETIC_SECRETS["openai_key"] not in loaded.root_run.error.message
            assert any(ev.event_type == EventKind.RUN_FAILED for ev in loaded.events)
            assert loaded.spans[0].status == SpanStatus.ERROR
            assert store.list_traces(status=RunStatus.FAILED)[0].trace_id == "tr_fail_sync_001"

    async def test_async_unhandled_exception_auto_saves_failed_trace_and_reraises(
        self, tmp_path: Path
    ) -> None:
        with TraceStore(tmp_path / "fail_async_store") as store:
            with pytest.raises(ValueError, match="async boom"):
                async with (
                    acapture(
                        "failing_async_agent",
                        trace_id="tr_fail_async_001",
                        store=store,
                        auto_save=True,
                    ) as session,
                    session.aspan("failing_async_step", span_type=SpanType.MODEL),
                ):
                    await asyncio.sleep(0)
                    raise ValueError(f"async boom {SYNTHETIC_SECRETS['bearer_token']}")

            assert get_current_session() is None
            assert get_current_span_id() is None
            assert get_current_run_id() is None

            loaded = store.load("tr_fail_async_001")
            assert loaded.root_run.status == RunStatus.FAILED
            assert loaded.root_run.error is not None
            assert loaded.root_run.error.error_type == "ValueError"
            assert SYNTHETIC_SECRETS["bearer_token"] not in loaded.root_run.error.message
            assert store.list_traces(status=RunStatus.FAILED)[0].trace_id == "tr_fail_async_001"


class TestDecoratorsOutsideCaptureAreNoOps:
    """Decorated sync and async functions run transparently when no session is active."""

    def test_sync_decorators_no_op_without_active_session(self) -> None:
        assert get_current_session() is None
        out = _sync_decorated_workflow(7)
        assert out["tool"]["invoice_id"] == 7
        assert get_current_session() is None

    async def test_async_decorators_no_op_without_active_session(self) -> None:
        assert get_current_session() is None
        out = await _async_decorated_workflow(8)
        assert out["tool"]["invoice_id"] == 8
        assert get_current_session() is None

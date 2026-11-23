"""End-to-end offline Capture -> Storage -> Replay integration tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tracevault.capture import acapture, capture
from tracevault.replay import ReplayEngine
from tracevault.schema import (
    BoundaryType,
    SpanType,
    TraceFrozenError,
    UnsafeTraceError,
)
from tracevault.storage import TraceQuery, TraceStore


class TestCaptureStorageReplaySyncWorkflow:
    """Sync capture -> store -> freeze -> ReplayEngine.from_store -> replay/fork -> store."""

    def test_sync_capture_freeze_replay_fork_and_deterministic_repeat(self, tmp_path: Path) -> None:
        store_dir = tmp_path / ".tracevault"
        baseline_id = "tr_sync_base_001"
        fork_id = "tr_sync_fork_001"
        override_fork_id = "tr_sync_override_001"

        with TraceStore(store_dir) as store:
            with capture(
                "triage_pipeline_sync",
                trace_id=baseline_id,
                inputs={"ticket": "Invoice #104 overcharged"},
                tags=["triage", "baseline"],
            ) as session:
                with session.span("triage_agent", span_type=SpanType.AGENT):
                    with session.span(
                        "kb_lookup",
                        span_type=SpanType.RETRIEVAL,
                        boundary=BoundaryType.RETRIEVAL,
                    ):
                        session.record_retrieval(
                            query={"query": "refund policy", "top_k": 2},
                            results={
                                "documents": [{"doc_id": "pol_1", "content": "30-day refund"}]
                            },
                            name="policy_kb",
                        )
                    with session.span(
                        "invoice_tool",
                        span_type=SpanType.TOOL,
                        boundary=BoundaryType.TOOL,
                    ):
                        session.record_tool_call(
                            "fetch_invoice",
                            args={"invoice_id": 104},
                            result={"amount_cents": 9900, "currency": "USD"},
                        )
                    with session.span(
                        "classifier_llm",
                        span_type=SpanType.MODEL,
                        boundary=BoundaryType.MODEL,
                    ):
                        model_fixture = session.record_model_call(
                            request={
                                "provider": "mock",
                                "model": "mock-gpt",
                                "messages": [{"role": "user", "content": "Classify invoice #104"}],
                            },
                            response={"content": "billing_refund", "finish_reason": "stop"},
                            name="classifier",
                        )
                session.set_outputs({"decision": "billing_refund"})

            assert session.trace is not None
            store.save(session.trace)
            frozen_baseline = store.freeze(baseline_id)
            baseline_json_before = frozen_baseline.to_json()

            # Replay via ReplayEngine.from_store()
            engine_a = ReplayEngine.from_store(store, baseline_id)
            result_a = engine_a.replay_trace(fork=True, new_trace_id=fork_id)
            assert result_a.success is True
            assert result_a.baseline_trace_id == baseline_id
            assert result_a.matched_fixtures == 3
            assert result_a.overridden_fixtures == 0
            assert result_a.live_calls == 0
            assert result_a.missing_fixtures == []
            assert result_a.candidate_trace.parent_trace_id == baseline_id
            assert result_a.candidate_trace.frozen is False

            # Save forked candidate trace
            store.save(result_a.candidate_trace)

            # Second independent replay must be deterministic
            engine_b = ReplayEngine.from_store(store, baseline_id)
            result_b = engine_b.replay_trace(fork=True, new_trace_id="tr_sync_fork_002")
            assert [
                (f.boundary, f.fingerprint, f.call_index, f.response)
                for f in result_a.candidate_trace.fixtures.entries
            ] == [
                (f.boundary, f.fingerprint, f.call_index, f.response)
                for f in result_b.candidate_trace.fixtures.entries
            ]
            assert [
                (e.event_type, e.boundary, e.payload) for e in result_a.candidate_trace.events
            ] == [(e.event_type, e.boundary, e.payload) for e in result_b.candidate_trace.events]

            # Fork with override on model fixture
            override_resp = {"content": "escalate_human", "finish_reason": "stop"}
            forked_override = engine_a.fork(
                overrides={model_fixture.fixture_id: override_resp},
                new_trace_id=override_fork_id,
            )
            assert forked_override.parent_trace_id == baseline_id
            assert forked_override.frozen is False
            model_entries = [
                f for f in forked_override.fixtures.entries if f.boundary == BoundaryType.MODEL
            ]
            assert len(model_entries) == 1
            assert model_entries[0].response == override_resp

            store.save(forked_override)

            # Verify frozen baseline is untouched and still immutable
            reloaded_baseline = store.load(baseline_id)
            assert reloaded_baseline.frozen is True
            assert reloaded_baseline.to_json() == baseline_json_before
            with pytest.raises(TraceFrozenError):
                store.save(reloaded_baseline, overwrite=True)

            # Verify lineage query in SQLite index
            children = store.query(TraceQuery(parent_trace_id=baseline_id))
            assert {c.trace_id for c in children} == {fork_id, override_fork_id}


class TestCaptureStorageReplayAsyncWorkflow:
    """Async acapture -> store -> freeze -> ReplayEngine.from_store -> fork -> store."""

    async def test_async_capture_freeze_and_replay_fork(self, tmp_path: Path) -> None:
        store_dir = tmp_path / ".tracevault_async"
        baseline_id = "tr_async_base_001"
        fork_id = "tr_async_fork_001"

        with TraceStore(store_dir) as store:
            async with acapture(
                "triage_pipeline_async",
                trace_id=baseline_id,
                inputs={"ticket": "Async ticket #205"},
                tags=["async", "baseline"],
                store=store,
                auto_save=True,
            ) as session:
                async with session.aspan("async_root", span_type=SpanType.AGENT):
                    await asyncio.sleep(0)
                    async with session.aspan(
                        "async_retrieval",
                        span_type=SpanType.RETRIEVAL,
                        boundary=BoundaryType.RETRIEVAL,
                    ):
                        session.record_retrieval(
                            query={"query": "sla terms"},
                            results={"documents": [{"doc_id": "sla_1", "content": "24h"}]},
                            name="sla_kb",
                        )
                    async with session.aspan(
                        "async_tool",
                        span_type=SpanType.TOOL,
                        boundary=BoundaryType.TOOL,
                    ):
                        session.record_tool_call(
                            "check_sla",
                            args={"ticket_id": 205},
                            result={"within_sla": True},
                        )
                    async with session.aspan(
                        "async_model",
                        span_type=SpanType.MODEL,
                        boundary=BoundaryType.MODEL,
                    ):
                        session.record_model_call(
                            request={
                                "model": "mock-async",
                                "messages": [{"role": "user", "content": "hi"}],
                            },
                            response={"content": "on_track", "finish_reason": "stop"},
                            name="async_llm",
                        )
                session.set_outputs({"status": "on_track"})

            frozen = store.freeze(baseline_id)
            before_json = frozen.to_json()

            engine = ReplayEngine.from_store(store, baseline_id)
            forked = engine.fork(new_trace_id=fork_id)
            assert forked.parent_trace_id == baseline_id
            assert forked.frozen is False
            assert len(forked.fixtures.entries) == 3

            store.save(forked)
            assert store.load(fork_id) == forked
            assert store.load(baseline_id).to_json() == before_json


class TestReplayFromStoreOversizedGuard:
    """Oversized trace files are rejected by ReplayEngine.from_store()."""

    def test_from_store_rejects_oversized_trace(self, tmp_path: Path) -> None:
        store_dir = tmp_path / ".tracevault_size"
        trace_id = "tr_oversized_replay_001"

        with (
            TraceStore(store_dir) as writer_store,
            capture(
                "large_capture",
                trace_id=trace_id,
                metadata={"blob": "x" * 2048},
                store=writer_store,
                auto_save=True,
            ) as session,
        ):
            session.set_outputs({"ok": True})

        with (
            TraceStore(store_dir, max_trace_bytes=256) as restricted_store,
            pytest.raises(UnsafeTraceError, match="exceeds"),
        ):
            ReplayEngine.from_store(restricted_store, trace_id)

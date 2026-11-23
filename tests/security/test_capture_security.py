"""Adversarial security, redaction, and async concurrency tests for tracevault.capture."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from conftest import HOSTILE_TRACE_IDS, SYNTHETIC_SECRETS
from tracevault.capture import (
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
    SpanType,
    UnsafeTraceError,
)
from tracevault.storage import TraceStore

NON_NONE_HOSTILE_TRACE_IDS: list[Any] = [tid for tid in HOSTILE_TRACE_IDS if tid is not None]


class TestHostileCaptureTraceIds:
    """Hostile trace_id and parent_trace_id inputs rejected before entering context."""

    @pytest.mark.parametrize("bad_id", NON_NONE_HOSTILE_TRACE_IDS)
    def test_capture_session_rejects_hostile_trace_id(self, bad_id: Any) -> None:
        with pytest.raises(InvalidTraceIdError):
            CaptureSession("hostile_test", trace_id=bad_id)

    @pytest.mark.parametrize("bad_id", NON_NONE_HOSTILE_TRACE_IDS)
    def test_capture_session_rejects_hostile_parent_trace_id(self, bad_id: Any) -> None:
        with pytest.raises(InvalidTraceIdError):
            CaptureSession("hostile_parent_test", parent_trace_id=bad_id)

    @pytest.mark.parametrize("bad_id", ["../etc/passwd", "..\\win\\sys32", "a\x00b", "a" * 129])
    def test_capture_and_acapture_reject_hostile_ids_without_leaking_context(
        self, bad_id: str
    ) -> None:
        with pytest.raises(InvalidTraceIdError), capture("bad_sync", trace_id=bad_id):
            pass
        assert get_current_session() is None
        assert get_current_span_id() is None
        assert get_current_run_id() is None

        async def _run_async() -> None:
            with pytest.raises(InvalidTraceIdError):
                async with acapture("bad_async", parent_trace_id=bad_id):
                    pass

        asyncio.run(_run_async())
        assert get_current_session() is None
        assert get_current_span_id() is None
        assert get_current_run_id() is None


class TestHostileCapturePayloads:
    """Non-JSON-safe objects, NaN/Infinity, and cyclic containers rejected safely."""

    @pytest.mark.parametrize(
        "bad_payload",
        [
            {"obj": object()},
            {"set_val": {1, 2, 3}},
            {"raw_bytes": b"binary"},
            {"nan_val": float("nan")},
            {"inf_val": float("inf")},
            {"neg_inf": float("-inf")},
            {1: "non-string-key"},
        ],
    )
    def test_non_json_safe_and_non_finite_rejected_in_session_and_recorders(
        self, bad_payload: dict[Any, Any]
    ) -> None:
        with pytest.raises(UnsafeTraceError):
            CaptureSession("bad_inputs", inputs=bad_payload)

        with pytest.raises(UnsafeTraceError):
            CaptureSession("bad_metadata", metadata=bad_payload)

        with capture("recorder_guards") as session:
            with pytest.raises(UnsafeTraceError):
                session.set_outputs(bad_payload)
            with pytest.raises(UnsafeTraceError):
                session.set_metadata("k", bad_payload)
            with pytest.raises(UnsafeTraceError):
                session.record_event(EventKind.CUSTOM, bad_payload)
            with pytest.raises(UnsafeTraceError):
                session.record_model_call(bad_payload, {"ok": True})
            with pytest.raises(UnsafeTraceError):
                session.record_tool_call("calc", bad_payload, {"ok": True})
            with pytest.raises(UnsafeTraceError):
                session.record_retrieval(bad_payload, {"documents": []})
            with pytest.raises(UnsafeTraceError):
                session.record_state_change("state.x", "set", after=bad_payload)

        assert get_current_session() is None

    @pytest.mark.parametrize("redact", [True, False])
    def test_cyclic_containers_rejected_with_unsafe_trace_error(self, redact: bool) -> None:
        cyclic_dict: dict[str, Any] = {}
        cyclic_dict["self"] = cyclic_dict

        cyclic_list: list[Any] = []
        cyclic_list.append(cyclic_list)

        with pytest.raises(UnsafeTraceError, match="Cyclic"):
            CaptureSession("cyclic_inputs", inputs=cyclic_dict, redact=redact)

        with capture("cyclic_recorders", redact=redact) as session:
            with pytest.raises(UnsafeTraceError, match="Cyclic"):
                session.set_outputs(cyclic_dict)
            with pytest.raises(UnsafeTraceError, match="Cyclic"):
                session.record_event(EventKind.CUSTOM, {"items": cyclic_list})
            with pytest.raises(UnsafeTraceError, match="Cyclic"):
                session.record_model_call(cyclic_dict, {"ok": True})


class TestCaptureEndToEndSecretRedaction:
    """Verify zero synthetic secrets survive capture redaction and disk persistence."""

    def test_zero_synthetic_secrets_persisted_on_disk(self, tmp_path: Path) -> None:
        with TraceStore(tmp_path / ".tracevault") as store:
            with capture(
                "secret_redaction_workflow",
                trace_id="tr_secret_audit_001",
                inputs={
                    "api_key": SYNTHETIC_SECRETS["openai_key"],
                    "prompt": f"Use token {SYNTHETIC_SECRETS['bearer_token']}",
                },
                metadata={
                    "service_secret": "synthetic-top-secret-value",
                    "jwt_note": f"jwt={SYNTHETIC_SECRETS['jwt_token']}",
                },
                environment={
                    "OPENAI_API_KEY": SYNTHETIC_SECRETS["openai_proj_key"],
                    "AWS_ACCESS_KEY_ID": SYNTHETIC_SECRETS["aws_access_key"],
                    "SAFE_ENV": "staging",
                },
                store=store,
                auto_save=True,
                redact=True,
            ) as session:
                with session.span(
                    "llm_step",
                    span_type=SpanType.MODEL,
                    boundary=BoundaryType.MODEL,
                    attributes={"authorization": SYNTHETIC_SECRETS["bearer_token"]},
                ):
                    session.record_model_call(
                        request={
                            "provider": "openai",
                            "model": "gpt-4o-mini",
                            "headers": {"X-Api-Key": SYNTHETIC_SECRETS["openai_key"]},
                            "messages": [
                                {
                                    "role": "user",
                                    "content": f"Check {SYNTHETIC_SECRETS['github_pat']}",
                                }
                            ],
                        },
                        response={
                            "content": f"Echo {SYNTHETIC_SECRETS['jwt_token']}",
                            "raw_metadata": {"password": "synthetic-db-password"},
                        },
                        name="openai.chat.completions",
                    )

                with session.span(
                    "tool_step",
                    span_type=SpanType.TOOL,
                    boundary=BoundaryType.TOOL,
                ):
                    session.record_tool_call(
                        "fetch_invoice",
                        args={"credential": SYNTHETIC_SECRETS["aws_access_key"]},
                        result={"body": f"Bearer token: {SYNTHETIC_SECRETS['bearer_token']}"},
                    )

                with session.span(
                    "retrieval_step",
                    span_type=SpanType.RETRIEVAL,
                    boundary=BoundaryType.RETRIEVAL,
                ):
                    session.record_retrieval(
                        query={"q": f"key {SYNTHETIC_SECRETS['openai_proj_key']}"},
                        results={"documents": [{"content": SYNTHETIC_SECRETS["github_pat"]}]},
                        name="vector_store",
                    )

                session.record_agent_transition(
                    to_agent="billing_agent",
                    from_agent="triage_agent",
                    reason=f"Auth via {SYNTHETIC_SECRETS['bearer_token']}",
                    handoff_state={"auth_token": SYNTHETIC_SECRETS["jwt_token"]},
                )
                session.record_state_change(
                    "session.creds",
                    "set",
                    before=SYNTHETIC_SECRETS["openai_key"],
                    after=SYNTHETIC_SECRETS["github_pat"],
                )

                try:
                    raise RuntimeError(
                        f"Upstream error with {SYNTHETIC_SECRETS['openai_proj_key']} "
                        f"and {SYNTHETIC_SECRETS['aws_access_key']}"
                    )
                except RuntimeError as exc:
                    session.record_error(exc, boundary=BoundaryType.MODEL, recoverable=True)

                session.set_outputs(
                    {
                        "summary": f"Done with {SYNTHETIC_SECRETS['jwt_token']}",
                        "refresh_token": "synthetic-refresh-token-value",
                    }
                )

            assert session.trace is not None
            assert session.trace.redaction_applied is True

            persisted_path = store.traces_dir / "tr_secret_audit_001.json"
            assert persisted_path.is_file()
            raw_disk_text = persisted_path.read_text(encoding="utf-8")

            for secret_name, secret_val in SYNTHETIC_SECRETS.items():
                assert secret_val not in raw_disk_text, (
                    f"Synthetic secret '{secret_name}' leaked to disk!"
                )
            assert "synthetic-top-secret-value" not in raw_disk_text
            assert "synthetic-db-password" not in raw_disk_text
            assert "synthetic-refresh-token-value" not in raw_disk_text


class TestAsyncConcurrencyAndContextIsolation:
    """Verify ContextVar isolation, monotonic sequences, and zero leakage under concurrency."""

    async def test_shared_session_24_concurrent_tasks_preserve_span_linkage(self) -> None:
        task_count = 24

        async with acapture("concurrent_shared_session", trace_id="tr_conc_shared_001") as session:

            async def _worker(idx: int) -> tuple[str, str]:
                async with session.aspan(f"parent_{idx}", span_type=SpanType.AGENT) as parent_span:
                    await asyncio.sleep(0)
                    assert get_current_span_id() == parent_span.span_id
                    async with session.aspan(
                        f"child_{idx}",
                        span_type=SpanType.TOOL,
                        boundary=BoundaryType.TOOL,
                    ) as child_span:
                        await asyncio.sleep(0)
                        assert get_current_span_id() == child_span.span_id
                        session.record_tool_call(
                            f"tool_{idx}",
                            args={"idx": idx},
                            result={"ok": True},
                        )
                    await asyncio.sleep(0)
                    assert get_current_span_id() == parent_span.span_id
                    return parent_span.span_id, child_span.span_id

            pairs = await asyncio.gather(*(_worker(i) for i in range(task_count)))

        # Zero context leakage after exit
        assert get_current_session() is None
        assert get_current_span_id() is None
        assert get_current_run_id() is None

        trace = session.trace
        assert trace is not None
        assert trace.root_run.status == RunStatus.COMPLETED
        assert len(trace.spans) == task_count * 2

        spans_by_id = {sp.span_id: sp for sp in trace.spans}
        for parent_id, child_id in pairs:
            assert spans_by_id[parent_id].parent_span_id is None
            assert spans_by_id[child_id].parent_span_id == parent_id

        sequences = [ev.sequence for ev in trace.events]
        assert sequences == list(range(len(sequences)))

    async def test_24_separate_concurrent_acapture_sessions_with_failures(self) -> None:
        session_count = 24
        collected: dict[int, CaptureSession] = {}

        async def _isolated_session(idx: int) -> str:
            trace_id = f"tr_iso_{idx:03d}"
            async with acapture(f"isolated_{idx}", trace_id=trace_id) as sess:
                collected[idx] = sess
                await asyncio.sleep(0)
                active = get_current_session()
                assert active is sess
                assert active.trace_id == trace_id
                async with sess.aspan(f"work_{idx}", span_type=SpanType.WORKFLOW) as sp:
                    await asyncio.sleep(0)
                    assert get_current_span_id() == sp.span_id
                    sess.record_event(EventKind.CUSTOM, {"worker": idx})
                    if idx % 2 == 1:
                        raise ValueError(f"boom_{idx}")
                sess.set_outputs({"worker": idx})
            return trace_id

        results = await asyncio.gather(
            *(_isolated_session(i) for i in range(session_count)),
            return_exceptions=True,
        )

        # Zero context leakage after mixed success/failure exits
        assert get_current_session() is None
        assert get_current_span_id() is None
        assert get_current_run_id() is None

        for idx, res in enumerate(results):
            sess = collected[idx]
            trace = sess.trace
            assert trace is not None
            assert len(trace.spans) == 1
            assert trace.spans[0].name == f"work_{idx}"
            sequences = [ev.sequence for ev in trace.events]
            assert sequences == list(range(len(sequences)))

            if idx % 2 == 1:
                assert isinstance(res, ValueError)
                assert trace.root_run.status == RunStatus.FAILED
                assert trace.root_run.error is not None
                assert f"boom_{idx}" in trace.root_run.error.message
            else:
                assert res == f"tr_iso_{idx:03d}"
                assert trace.root_run.status == RunStatus.COMPLETED
                assert trace.root_run.outputs == {"worker": idx}

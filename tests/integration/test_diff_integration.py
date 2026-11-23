"""End-to-end integration tests for TraceVault's structural diff engine (M5)."""

from __future__ import annotations

import io
import json
from datetime import timedelta
from pathlib import Path

from rich.console import Console

import tracevault
from tracevault import (
    BoundaryType,
    CaptureSession,
    DiffConfig,
    DivergenceKind,
    DivergenceSeverity,
    ExecutionError,
    ReplayConfig,
    ReplayEngine,
    ReplayOverride,
    SpanType,
    TraceStore,
    diff_traces,
    find_earliest_divergence,
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)


def _capture_multi_step_workflow(
    *,
    trace_id: str,
    run_id: str | None = None,
    outputs: dict[str, object] | None = None,
) -> tracevault.Trace:
    """Capture a multi-step AI workflow with nested spans (agent -> retrieval, tool, model)."""
    with CaptureSession(
        "order_support_workflow",
        trace_id=trace_id,
        run_id=run_id,
        inputs={"order_id": "ORD-42", "question": "Where is my refund?"},
        tags=["support", "m5"],
    ) as session:
        with session.span("support_agent", span_type=SpanType.AGENT):
            with session.span(
                "policy_retrieval",
                span_type=SpanType.RETRIEVAL,
                boundary=BoundaryType.RETRIEVAL,
            ):
                session.record_retrieval(
                    query={"retriever": "kb", "query": "refund policy", "top_k": 2},
                    results={
                        "retriever": "kb",
                        "documents": [
                            {"doc_id": "doc_1", "content": "Refunds settle in 5 business days."}
                        ],
                    },
                    name="policy_kb",
                )
            with session.span(
                "order_lookup_tool",
                span_type=SpanType.TOOL,
                boundary=BoundaryType.TOOL,
            ):
                session.record_tool_call(
                    "get_order_status",
                    args={"order_id": "ORD-42"},
                    result={"status": "refunded", "amount_cents": 4900},
                )
            with session.span(
                "response_model",
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
            ):
                session.record_model_call(
                    request={
                        "provider": "mock",
                        "model": "mock-gpt-4o",
                        "messages": [{"role": "user", "content": "Draft refund update"}],
                    },
                    response={
                        "model": "mock-gpt-4o",
                        "content": "Your refund of $49.00 has been processed.",
                        "finish_reason": "stop",
                    },
                    name="response_llm",
                )
        session.set_outputs(
            outputs
            if outputs is not None
            else {"reply": "Your refund of $49.00 has been processed.", "escalated": False}
        )

    assert session.trace is not None
    return session.trace


class TestDiffIntegrationWorkflows:
    """End-to-end Capture -> Store -> Freeze -> Replay -> Diff -> Format integration scenarios."""

    def test_scenario_a_frozen_baseline_identical_to_self_and_regenerated_clone(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault_a"
        baseline_id = "tr_m5_scenario_a_base"
        clone_id = "tr_m5_scenario_a_clone"

        baseline = _capture_multi_step_workflow(trace_id=baseline_id, run_id="run_base_001")

        with TraceStore(store_dir) as store:
            store.save(baseline)
            store.freeze(baseline_id)
            reloaded = store.load(baseline_id)
            assert reloaded.frozen is True

            # 1. Compare frozen baseline against itself
            self_report = diff_traces(reloaded, reloaded)
            assert self_report.identical is True
            assert self_report.has_breaking is False
            assert self_report.divergences == []
            assert find_earliest_divergence(self_report) is None

            # 2. Capture a structurally identical clone with regenerated IDs and shifted timestamps
            clone_raw = _capture_multi_step_workflow(trace_id=clone_id, run_id="run_clone_999")
            shifted_runs = [
                r.model_copy(
                    update={
                        "started_at": r.started_at + timedelta(hours=2),
                        "ended_at": (
                            r.ended_at + timedelta(hours=2) if r.ended_at is not None else None
                        ),
                    }
                )
                for r in clone_raw.runs
            ]
            shifted_spans = [
                s.model_copy(
                    update={
                        "started_at": s.started_at + timedelta(hours=2),
                        "ended_at": (
                            s.ended_at + timedelta(hours=2) if s.ended_at is not None else None
                        ),
                    }
                )
                for s in clone_raw.spans
            ]
            shifted_events = [
                e.model_copy(update={"timestamp": e.timestamp + timedelta(hours=2)})
                for e in clone_raw.events
            ]
            clone = clone_raw.model_copy(
                update={
                    "created_at": clone_raw.created_at + timedelta(hours=2),
                    "runs": shifted_runs,
                    "spans": shifted_spans,
                    "events": shifted_events,
                }
            )
            store.save(clone)
            reloaded_clone = store.load(clone_id)

            clone_report = diff_traces(reloaded, reloaded_clone)
            assert clone_report.identical is True
            assert clone_report.has_breaking is False
            assert clone_report.summary == {"info": 0, "warning": 0, "breaking": 0, "total": 0}

    def test_scenario_b_production_failure_fork_fix_and_earliest_divergence(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault_b"
        baseline_id = "tr_m5_prod_fail_001"
        candidate_id = "tr_m5_fork_fix_001"

        # Capture a failing production trace (tool returns an error)
        with CaptureSession(
            "billing_refund_agent",
            trace_id=baseline_id,
            inputs={"invoice_id": "INV-900"},
            tags=["prod-incident"],
        ) as session:
            with (
                session.span("refund_agent", span_type=SpanType.AGENT),
                session.span(
                    "payment_gateway_tool",
                    span_type=SpanType.TOOL,
                    boundary=BoundaryType.TOOL,
                ),
            ):
                failing_fixture = session.record_tool_call(
                    "issue_refund",
                    args={"invoice_id": "INV-900", "amount_cents": 2500},
                    error=ExecutionError(
                        error_type="GatewayTimeoutError",
                        message="Upstream payment gateway timed out",
                        retryable=True,
                    ),
                )
            session.set_outputs({"refunded": False, "reason": "gateway_timeout"})

        assert session.trace is not None

        with TraceStore(store_dir) as store:
            store.save(session.trace)
            frozen_baseline = store.freeze(baseline_id)
            assert frozen_baseline.frozen is True

            # Replay with fork() override fixing the failing tool response
            override_rule = ReplayOverride(
                fixture_id=failing_fixture.fixture_id,
                response={"refund_id": "ref_ok_900", "status": "succeeded"},
            )
            replay_config = ReplayConfig(override_rules=[override_rule])
            engine = ReplayEngine(frozen_baseline, replay_config)
            candidate_trace = engine.fork(new_trace_id=candidate_id)

            store.save(candidate_trace)
            loaded_baseline = store.load(baseline_id)
            loaded_candidate = store.load(candidate_id)

            report = diff_traces(loaded_baseline, loaded_candidate)
            assert report.identical is False
            assert report.has_breaking is True

            earliest = find_earliest_divergence(report)
            assert earliest is not None
            assert earliest.severity != DivergenceSeverity.INFO
            assert any(
                d.kind == DivergenceKind.FIXTURE_MISMATCH
                and d.severity == DivergenceSeverity.BREAKING
                and d.path.startswith("fixtures[0].")
                for d in report.divergences
            )

            # Verify all three formatters succeed cleanly
            text_brief = format_diff_report(report, verbose=False)
            text_verbose = format_diff_report(report, verbose=True)
            json_report = format_diff_json(report)
            buf = io.StringIO()
            render_diff_rich(report, console=Console(file=buf, force_terminal=False, width=120))

            assert "DIVERGENT" in text_brief
            assert baseline_id in text_brief
            assert candidate_id in text_brief
            assert "baseline :" in text_verbose
            assert "candidate:" in text_verbose

            parsed_json = json.loads(json_report)
            assert parsed_json["baseline_trace_id"] == baseline_id
            assert parsed_json["candidate_trace_id"] == candidate_id
            assert parsed_json["identical"] is False
            assert parsed_json["summary"]["breaking"] >= 1

            rich_output = buf.getvalue()
            assert "TraceVault Diff Report" in rich_output
            assert "DIVERGENT" in rich_output

    def test_scenario_c_ignore_paths_and_severity_overrides_on_stored_traces(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault_c"
        base_id = "tr_m5_cfg_base"
        cand_id = "tr_m5_cfg_cand"

        base_trace = _capture_multi_step_workflow(
            trace_id=base_id,
            outputs={
                "reply": "Your refund of $49.00 has been processed.",
                "volatile_request_uuid": "req-aaa-111",
                "latency_ms": 120,
            },
        )
        cand_trace = _capture_multi_step_workflow(
            trace_id=cand_id,
            outputs={
                "reply": "Your refund of $49.00 has been processed.",
                "volatile_request_uuid": "req-bbb-222",
                "latency_ms": 485,
            },
        )

        with TraceStore(store_dir) as store:
            store.save(base_trace)
            store.save(cand_trace)
            loaded_base = store.load(base_id)
            loaded_cand = store.load(cand_id)

            # Without ignore_paths, volatile output fields trigger BREAKING OUTPUT_CHANGED
            raw_report = diff_traces(loaded_base, loaded_cand)
            assert raw_report.has_breaking is True
            assert all(d.kind == DivergenceKind.OUTPUT_CHANGED for d in raw_report.divergences)

            # 1. ignore_paths suppresses expected volatile noise completely
            suppressed_report = diff_traces(
                loaded_base,
                loaded_cand,
                ignore_paths={
                    "runs[0].outputs.volatile_request_uuid",
                    "runs[0].outputs.latency_ms",
                },
            )
            assert suppressed_report.identical is True
            assert suppressed_report.has_breaking is False

            # 2. severity_overrides downgrades OUTPUT_CHANGED from BREAKING -> INFO
            downgraded_cfg = DiffConfig(
                severity_overrides={DivergenceKind.OUTPUT_CHANGED: DivergenceSeverity.INFO}
            )
            downgraded_report = diff_traces(loaded_base, loaded_cand, config=downgraded_cfg)
            assert downgraded_report.identical is False
            assert downgraded_report.has_breaking is False
            assert downgraded_report.summary["info"] == len(downgraded_report.divergences)
            assert downgraded_report.summary["breaking"] == 0

            # 3. severity_overrides can also upgrade WARNING -> BREAKING
            cand_with_extra_event = loaded_cand.model_copy(
                update={
                    "runs": [
                        loaded_cand.runs[0].model_copy(
                            update={"outputs": loaded_base.runs[0].outputs}
                        )
                    ],
                    "events": [
                        *loaded_cand.events,
                        loaded_cand.events[-1].model_copy(
                            update={
                                "event_id": "ev_extra_custom",
                                "sequence": max(e.sequence for e in loaded_cand.events) + 1,
                                "event_type": tracevault.EventKind.CUSTOM,
                                "boundary": None,
                                "payload": {"note": "extra telemetry"},
                            }
                        ),
                    ],
                }
            )
            default_extra_report = diff_traces(loaded_base, cand_with_extra_event)
            assert default_extra_report.has_breaking is False
            assert default_extra_report.summary["warning"] >= 1

            upgraded_cfg = DiffConfig(
                severity_overrides={DivergenceKind.EVENT_ADDED: DivergenceSeverity.BREAKING}
            )
            upgraded_report = diff_traces(loaded_base, cand_with_extra_event, config=upgraded_cfg)
            assert upgraded_report.has_breaking is True
            assert any(
                d.kind == DivergenceKind.EVENT_ADDED and d.severity == DivergenceSeverity.BREAKING
                for d in upgraded_report.divergences
            )

    def test_scenario_d_top_level_package_exposes_all_m5_diff_symbols(self) -> None:
        expected_symbols = [
            "diff_traces",
            "DiffEngine",
            "DEFAULT_SEVERITY_MAP",
            "find_earliest_divergence",
            "format_diff_report",
            "format_diff_json",
            "render_diff_rich",
            "DiffConfig",
            "DiffReport",
            "Divergence",
            "DivergenceKind",
            "DivergenceSeverity",
        ]
        for sym in expected_symbols:
            assert hasattr(tracevault, sym), f"Missing top-level export: tracevault.{sym}"
            assert sym in tracevault.__all__, f"Missing from tracevault.__all__: {sym}"

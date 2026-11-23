"""End-to-end integration tests for TraceVault M6 Assertions, Pytest Plugin, and Regression."""

from __future__ import annotations

import importlib.util
import socket
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import tracevault
from tracevault import (
    BoundaryType,
    CaptureSession,
    DiffConfig,
    DivergenceKind,
    EventKind,
    ExecutionError,
    ReplayEngine,
    RunStatus,
    SpanStatus,
    SpanType,
    Trace,
    TraceAssertions,
    TraceStore,
    assert_all_fixtures_matched,
    assert_diff_matches_expectations,
    assert_error_recorded,
    assert_event_absent,
    assert_event_exists,
    assert_event_order,
    assert_model_called,
    assert_model_output,
    assert_no_breaking_diffs,
    assert_no_errors,
    assert_no_live_calls,
    assert_no_secrets_leaked,
    assert_replay_clean,
    assert_replay_succeeded,
    assert_retrieval_results,
    assert_run_output,
    assert_run_status,
    assert_run_succeeded,
    assert_span_duration_under,
    assert_span_exists,
    assert_span_status,
    assert_tool_called,
    assert_tool_not_called,
    assert_tool_output,
    assert_trace_valid,
    assert_traces_equivalent,
    diff_traces,
    expect_trace,
    export_regression_fixture,
    generate_pytest_regression,
    load_regression_trace,
    verify_regression_trace,
)


def _execute_generated_regression_module(py_path: Path) -> None:
    """Dynamically import a generated pytest regression test file and invoke its test function."""
    module_name = f"_m6_reg_{py_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, py_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        test_fns = [
            getattr(module, name)
            for name in dir(module)
            if name.startswith("test_") and callable(getattr(module, name))
        ]
        assert len(test_fns) == 1
        test_fns[0]()
    finally:
        sys.modules.pop(module_name, None)


class TestM6EndToEndRegressionWorkflow:
    """Workflow 1: Production failure -> Capture -> Freeze -> Fork fix -> Assert -> Export."""

    def test_workflow_1_prod_failure_to_fork_fix_assertions_and_regression_test(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        tracevault_store: TraceStore,
        tracevault_load_trace: Callable[..., Trace],
        tracevault_replay: Callable[..., ReplayEngine],
        tracevault_expect: Callable[[Trace], TraceAssertions],
    ) -> None:
        # 1. Capture a failing multi-step workflow (retrieval + model + failing tool call)
        failing_trace_id = "tr_m6_prod_failure_001"
        fixed_trace_id = "tr_m6_fork_fixed_001"

        with CaptureSession(
            "invoice_refund_pipeline",
            trace_id=failing_trace_id,
            inputs={"invoice_id": "INV-2026-042", "customer_tier": "enterprise"},
            tags=["production", "incident-42", "m6"],
            store=tracevault_store,
            auto_save=True,
        ) as session:
            with session.span("refund_orchestrator", span_type=SpanType.AGENT):
                with session.span(
                    "policy_retrieval",
                    span_type=SpanType.RETRIEVAL,
                    boundary=BoundaryType.RETRIEVAL,
                ):
                    session.record_retrieval(
                        query={
                            "retriever": "policy_kb",
                            "query": "enterprise refund sla",
                            "top_k": 2,
                        },
                        results={
                            "retriever": "policy_kb",
                            "documents": [
                                {
                                    "doc_id": "pol_01",
                                    "content": "Enterprise refunds are auto-approved under $500.",
                                    "score": 0.98,
                                }
                            ],
                        },
                        name="policy_kb",
                    )

                with session.span(
                    "triage_llm",
                    span_type=SpanType.MODEL,
                    boundary=BoundaryType.MODEL,
                ):
                    session.record_model_call(
                        request={
                            "provider": "openai",
                            "model": "gpt-4o-mini",
                            "messages": [
                                {"role": "user", "content": "Approve refund for INV-2026-042"}
                            ],
                        },
                        response={
                            "model": "gpt-4o-mini",
                            "content": "Calling payment_gateway_refund tool for INV-2026-042.",
                            "finish_reason": "tool_calls",
                        },
                        name="openai.chat.completions",
                    )

                with session.span(
                    "payment_tool_span",
                    span_type=SpanType.TOOL,
                    boundary=BoundaryType.TOOL,
                ):
                    failing_tool_fixture = session.record_tool_call(
                        "payment_gateway_refund",
                        args={"invoice_id": "INV-2026-042", "amount_cents": 12500},
                        error=ExecutionError(
                            error_type="PaymentGatewayTimeout",
                            message="Gateway timed out waiting for settlement ledger",
                            retryable=True,
                        ),
                    )

            session.set_outputs({"refund_status": "failed", "retry_scheduled": True})

        frozen_failing = tracevault_store.freeze(failing_trace_id)
        assert frozen_failing.frozen is True

        # 2. Verify error assertions and event assertions detect the recorded tool error
        loaded_failing = tracevault_load_trace(failing_trace_id)
        assert_trace_valid(loaded_failing)
        assert_run_status(loaded_failing, RunStatus.COMPLETED)
        recorded_err = assert_error_recorded(
            loaded_failing,
            error_type="PaymentGatewayTimeout",
            message_contains="settlement ledger",
        )
        assert recorded_err.retryable is True
        assert_event_exists(
            loaded_failing,
            EventKind.TOOL_ERROR,
            boundary=BoundaryType.TOOL,
        )
        with pytest.raises(AssertionError):
            assert_no_errors(loaded_failing)

        # 3. Fork the trace with ReplayEngine(failing_trace).fork(overrides=...) to supply fix
        fixed_tool_response = {
            "refund_id": "ref_settled_042",
            "status": "succeeded",
            "amount_cents": 12500,
        }
        forked_trace = ReplayEngine(loaded_failing).fork(
            overrides={failing_tool_fixture.fixture_id: fixed_tool_response},
            new_trace_id=fixed_trace_id,
        )
        assert forked_trace.parent_trace_id == failing_trace_id
        assert forked_trace.frozen is False

        # Update root_run outputs on the fixed candidate trace to reflect successful settlement
        updated_root_run = forked_trace.root_run.model_copy(
            update={
                "outputs": {
                    "refund_status": "succeeded",
                    "refund_id": "ref_settled_042",
                    "retry_scheduled": False,
                }
            }
        )
        fixed_candidate = forked_trace.model_copy(update={"runs": [updated_root_run]})
        tracevault_store.save(fixed_candidate)
        frozen_fixed = tracevault_store.freeze(fixed_trace_id)
        assert frozen_fixed.frozen is True

        # 4. Run programmatic and fluent (tracevault_expect) assertions on the fixed trace
        assert_trace_valid(frozen_fixed)
        assert_run_succeeded(frozen_fixed)
        assert_run_output(
            frozen_fixed,
            subset={"refund_status": "succeeded", "refund_id": "ref_settled_042"},
            key="retry_scheduled",
            value=False,
        )
        assert_span_exists(frozen_fixed, "refund_orchestrator", span_type=SpanType.AGENT)
        assert_span_status(
            frozen_fixed,
            "payment_tool_span",
            SpanStatus.OK,
            span_type=SpanType.TOOL,
        )
        assert_span_duration_under(frozen_fixed, "payment_tool_span", 60.0)
        assert_retrieval_results(frozen_fixed, min_results=1)
        assert_model_called(frozen_fixed, model="gpt-4o-mini", provider="openai", min_calls=1)
        assert_model_output(frozen_fixed, contains_text="INV-2026-042")
        assert_tool_called(frozen_fixed, "payment_gateway_refund", min_calls=1)
        assert_tool_not_called(frozen_fixed, "drop_database_tool")
        assert_tool_output(
            frozen_fixed,
            "payment_gateway_refund",
            expected_result=fixed_tool_response,
        )
        assert_event_absent(frozen_fixed, EventKind.TOOL_ERROR)
        assert_event_order(
            frozen_fixed,
            [
                EventKind.RETRIEVAL_QUERY,
                EventKind.RETRIEVAL_RESULT,
                EventKind.MODEL_REQUEST,
                EventKind.MODEL_RESPONSE,
                EventKind.TOOL_CALL,
                EventKind.TOOL_RESULT,
            ],
        )
        assert_no_errors(frozen_fixed)
        assert_no_secrets_leaked(frozen_fixed)

        tracevault_expect(frozen_fixed).is_valid().succeeded().has_status(
            RunStatus.COMPLETED
        ).has_output(
            subset={"refund_status": "succeeded"},
            key="refund_id",
            value="ref_settled_042",
        ).has_span(
            "triage_llm",
            span_type=SpanType.MODEL,
            status=SpanStatus.OK,
        ).called_tool(
            "payment_gateway_refund",
            min_calls=1,
            result_subset={"status": "succeeded"},
        ).did_not_call_tool("unauthorized_tool").called_model(
            model="gpt-4o-mini",
            provider="openai",
        ).has_no_errors().has_no_secrets_leaked()

        # Verify diff between failing baseline and fixed candidate highlights the fix
        fix_diff = diff_traces(loaded_failing, frozen_fixed)
        assert fix_diff.has_breaking is True
        assert_diff_matches_expectations(
            fix_diff,
            allowed_kinds={
                DivergenceKind.OUTPUT_CHANGED,
                DivergenceKind.EVENT_REMOVED,
                DivergenceKind.EVENT_ADDED,
                DivergenceKind.EVENT_PAYLOAD_CHANGED,
                DivergenceKind.TOOL_RESULT_CHANGED,
                DivergenceKind.FIXTURE_MISMATCH,
            },
        )

        # 5. Export portable regression fixture and generate standalone pytest regression test
        fixture_path = tmp_path / "fixtures" / f"{fixed_trace_id}.json"
        test_file_path = tmp_path / "test_refund_regression.py"

        exported_fixture = export_regression_fixture(frozen_fixed, fixture_path)
        generated_test = generate_pytest_regression(
            frozen_fixed,
            test_file_path,
            trace_path=exported_fixture,
        )
        assert exported_fixture.is_file()
        assert generated_test.is_file()

        # 6. Execute verify_regression_trace AND the generated pytest test 100% offline
        def _deny_network(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Offline regression execution must never touch network sockets")

        monkeypatch.setattr(socket, "socket", _deny_network)

        regression_report = verify_regression_trace(
            exported_fixture,
            diff_config=DiffConfig(),
        )
        assert not regression_report.has_breaking
        assert_no_breaking_diffs(regression_report)

        _execute_generated_regression_module(generated_test)


class TestM6FixtureIsolationAndTopLevelExports:
    """Workflow 2: Pytest plugin fixture isolation, replay targets, and top-level exports."""

    def test_workflow_2a_store_isolation_part_1(self, tracevault_store: TraceStore) -> None:
        with CaptureSession(
            "isolated_session_one",
            trace_id="tr_m6_isolated_001",
            store=tracevault_store,
            auto_save=True,
        ) as session:
            session.set_outputs({"step": 1})

        assert tracevault_store.exists("tr_m6_isolated_001")
        assert len(tracevault_store.list_traces()) == 1

    def test_workflow_2b_store_isolation_part_2_and_replay_targets(
        self,
        tmp_path: Path,
        tracevault_store: TraceStore,
        tracevault_load_trace: Callable[..., Trace],
        tracevault_replay: Callable[..., ReplayEngine],
    ) -> None:
        # Must start completely empty despite test_workflow_2a saving a trace
        assert not tracevault_store.exists("tr_m6_isolated_001")
        assert tracevault_store.list_traces() == []

        trace_id = "tr_m6_replay_targets_001"
        with CaptureSession(
            "replay_targets_session",
            trace_id=trace_id,
            store=tracevault_store,
            auto_save=True,
        ) as session:
            with session.span("tool_step", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
                fix = session.record_tool_call(
                    "lookup_weather",
                    args={"city": "Bengaluru"},
                    result={"temp_c": 26, "condition": "sunny"},
                )
            session.set_outputs({"temp_c": 26})

        trace_obj = tracevault_store.freeze(trace_id)
        exported_path = export_regression_fixture(trace_obj, tmp_path / "weather_fixture.json")

        # tracevault_load_trace and tracevault_replay must work from trace_id, Path, and Trace
        for target in (trace_id, exported_path, str(exported_path), trace_obj):
            loaded = tracevault_load_trace(target)
            assert loaded.trace_id == trace_id

            engine = tracevault_replay(target)
            result = engine.replay_trace()
            assert_replay_succeeded(result)
            assert_no_live_calls(result)
            assert_all_fixtures_matched(result)
            assert_replay_clean(result)
            assert_traces_equivalent(loaded, trace_obj)
            rep = diff_traces(loaded, result.candidate_trace)
            assert_no_breaking_diffs(rep)

        # Also verify tracevault_replay with overrides
        overridden_engine = tracevault_replay(
            trace_id,
            overrides={fix.fixture_id: {"temp_c": 19, "condition": "rainy"}},
        )
        overridden_res = overridden_engine.replay_trace()
        assert_replay_clean(overridden_res)
        assert_tool_output(
            overridden_res.candidate_trace,
            "lookup_weather",
            expected_result={"temp_c": 19, "condition": "rainy"},
        )

    def test_workflow_2c_top_level_m6_public_exports(self) -> None:
        expected_m6_exports = [
            "TraceAssertions",
            "expect_trace",
            "assert_trace_valid",
            "assert_run_status",
            "assert_run_succeeded",
            "assert_run_output",
            "assert_span_exists",
            "assert_span_status",
            "assert_span_duration_under",
            "assert_event_exists",
            "assert_event_absent",
            "assert_event_order",
            "assert_tool_called",
            "assert_tool_not_called",
            "assert_tool_output",
            "assert_model_called",
            "assert_model_output",
            "assert_retrieval_results",
            "assert_agent_transition",
            "assert_state_change",
            "assert_no_errors",
            "assert_error_recorded",
            "assert_no_secrets_leaked",
            "assert_replay_succeeded",
            "assert_all_fixtures_matched",
            "assert_no_live_calls",
            "assert_replay_clean",
            "assert_traces_equivalent",
            "assert_no_breaking_diffs",
            "assert_diff_matches_expectations",
            "load_regression_trace",
            "verify_regression_trace",
            "export_regression_fixture",
            "generate_pytest_regression",
        ]
        for symbol in expected_m6_exports:
            assert hasattr(tracevault, symbol), f"Missing top-level export: tracevault.{symbol}"
            assert symbol in tracevault.__all__, f"Missing from tracevault.__all__: {symbol}"
        assert callable(load_regression_trace)
        assert callable(expect_trace)

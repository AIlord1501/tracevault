"""Runnable end-to-end example: convert a captured failure into a pytest regression test."""

from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

from tracevault import (
    BoundaryType,
    ExecutionError,
    ReplayEngine,
    SpanStatus,
    SpanType,
    TraceStore,
    assert_error_recorded,
    assert_no_breaking_diffs,
    assert_replay_clean,
    capture,
    diff_traces,
    expect_trace,
    export_regression_fixture,
    format_diff_report,
    generate_pytest_regression,
    verify_regression_trace,
)


def run_regression_workflow_example() -> None:
    """Demonstrate Capture Failure -> Freeze -> Fork Fix -> Assert -> Generate Pytest Test."""
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        store = TraceStore(workspace / ".tracevault")
        store.init()
        try:
            # 1. Capture a production failure (with an API key in inputs to prove redaction).
            with capture(
                "refund-triage-agent",
                inputs={"order_id": "ORD-500", "api_key": "sk-live-secret-key-1234567890"},
                store=store,
                auto_save=True,
            ) as session:
                with session.span(
                    "plan_action", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL
                ):
                    session.record_model_call(
                        request={
                            "provider": "openai",
                            "model": "gpt-4o-mini",
                            "prompt": "Process refund for ORD-500",
                        },
                        response={"content": "Calling refund_service tool"},
                        name="planner_llm",
                    )
                with session.span(
                    "call_refund_service", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL
                ):
                    session.record_tool_call(
                        "issue_refund",
                        {"order_id": "ORD-500", "amount_cents": 4500},
                        result=None,
                        error=ExecutionError(
                            error_type="GatewayTimeoutError",
                            message="Upstream refund service timed out",
                        ),
                    )
                session.set_outputs({"status": "failed_retryable", "order_id": "ORD-500"})

            failing_trace = store.load(session.trace_id)
            store.freeze(failing_trace.trace_id)

            # Verify the error is recorded and secrets were scrubbed.
            recorded_err = assert_error_recorded(
                failing_trace,
                error_type="GatewayTimeoutError",
                message_contains="timed out",
            )
            print(
                f"1. Captured & froze failing trace {failing_trace.trace_id} "
                f"({recorded_err.error_type})"
            )

            # 2. Fork the trace with a deterministic fixture override simulating the fix.
            tool_fixture = next(
                e for e in failing_trace.fixtures.entries if e.boundary == BoundaryType.TOOL
            )
            fixed_trace = ReplayEngine(failing_trace).fork(
                overrides={
                    tool_fixture.fixture_id: {
                        "refund_id": "ref_9001",
                        "status": "processed",
                        "amount_cents": 4500,
                    }
                },
                new_trace_id="tr_fixed_refund_001",
            )
            store.save(fixed_trace)
            store.freeze(fixed_trace.trace_id)

            # 3. Assert fixed trace properties using fluent expect_trace API.
            expect_trace(fixed_trace).is_valid().succeeded().has_output(
                subset={"order_id": "ORD-500"}
            ).has_span(
                "call_refund_service", span_type=SpanType.TOOL, status=SpanStatus.OK
            ).called_tool(
                "issue_refund", result_subset={"status": "processed", "refund_id": "ref_9001"}
            ).called_model(
                model="gpt-4o-mini", provider="openai"
            ).has_no_errors().has_no_secrets_leaked()
            print(f"2. Verified fixed forked trace {fixed_trace.trace_id} via expect_trace()")

            # 4. Replay the fixed trace offline and assert zero breaking diffs.
            replay_res = ReplayEngine(fixed_trace).replay_trace()
            assert_replay_clean(replay_res)
            diff_rep = diff_traces(fixed_trace, replay_res.candidate_trace)
            assert_no_breaking_diffs(diff_rep)
            print("3. Offline replay of fixed trace succeeded with 0 breaking divergences:")
            print(format_diff_report(diff_rep))

            # 5. Export portable regression fixture and generate standalone pytest file.
            fixture_path = export_regression_fixture(
                fixed_trace,
                workspace / "fixtures" / "tr_fixed_refund_001.json",
            )
            test_file = generate_pytest_regression(
                fixed_trace,
                workspace / "test_refund_regression.py",
                trace_path=fixture_path,
            )
            print(f"4. Exported portable fixture to {fixture_path.name}")
            print(f"5. Generated pytest regression file {test_file.name}:")
            print("-" * 72)
            print(test_file.read_text(encoding="utf-8"))
            print("-" * 72)

            # 6. Execute verify_regression_trace and the generated test function offline.
            verify_report = verify_regression_trace(fixture_path)
            assert not verify_report.has_breaking

            spec = importlib.util.spec_from_file_location("generated_regression_mod", test_file)
            assert spec is not None and spec.loader is not None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            test_fn = next(getattr(mod, attr) for attr in dir(mod) if attr.startswith("test_"))
            test_fn()
            print("6. Executed generated pytest regression test offline: PASSED!")
        finally:
            store.close()


if __name__ == "__main__":
    run_regression_workflow_example()

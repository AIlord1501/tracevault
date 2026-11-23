"""Runnable offline examples for TraceVault structural diff & divergence analysis."""

from __future__ import annotations

import tempfile
from pathlib import Path

from rich.console import Console

from tracevault import (
    BoundaryType,
    DiffConfig,
    DivergenceKind,
    DivergenceSeverity,
    ReplayEngine,
    TraceStore,
    capture,
    diff_traces,
    find_earliest_divergence,
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)


def example_identical_and_divergent_diff() -> None:
    """Capture a failing workflow, fork a fix, and diff baseline vs candidate."""
    with tempfile.TemporaryDirectory() as tmp:
        store = TraceStore(Path(tmp) / ".tracevault")
        store.init()
        try:
            with capture("invoice-support-agent", store=store, auto_save=True) as session:
                with session.span("plan-response"):
                    session.record_model_call(
                        request={
                            "provider": "mock-llm",
                            "model": "gpt-mock-1",
                            "messages": [{"role": "user", "content": "Check invoice INV-404"}],
                        },
                        response={"content": "Calling invoice lookup tool."},
                        name="plan_completion",
                    )
                with session.span("lookup-invoice"):
                    session.record_tool_call(
                        tool_name="fetch_invoice",
                        args={"invoice_id": "INV-404"},
                        result={"status": "error", "reason": "stale cache"},
                    )
                session.set_outputs(
                    {"answer": "Could not load invoice INV-404", "request_id": "req-1"}
                )

            baseline = store.load(session.trace_id)
            store.freeze(baseline.trace_id)

            # 1. Diffing a trace against itself is always identical.
            same_report = diff_traces(baseline, baseline)
            assert same_report.identical is True
            assert same_report.has_breaking is False
            print("=== 1. Identical Trace Diff ===")
            print(format_diff_report(same_report))

            # 2. Fork with a fixture override to simulate a fix and diff the two traces.
            tool_fixture = next(
                e for e in baseline.fixtures.entries if e.boundary == BoundaryType.TOOL
            )
            candidate = ReplayEngine(baseline).fork(
                overrides={
                    tool_fixture.fixture_id: {
                        "status": "ok",
                        "invoice_id": "INV-404",
                        "amount_cents": 19900,
                    }
                }
            )
            store.save(candidate)

            diff_report = diff_traces(baseline, candidate)
            assert diff_report.identical is False
            assert diff_report.has_breaking is True

            earliest = find_earliest_divergence(diff_report)
            assert earliest is not None

            print("\n=== 2. Divergent Fork Diff (Verbose Text) ===")
            print(format_diff_report(diff_report, verbose=True))
            print(f"Earliest meaningful divergence: {earliest.kind.value} at {earliest.path}")

            # 3. Demonstrate ignore_paths & severity_overrides.
            custom_config = DiffConfig(
                ignore_paths={"events[*].payload.request_id"},
                severity_overrides={DivergenceKind.FIXTURE_MISMATCH: DivergenceSeverity.WARNING},
            )
            tuned_report = diff_traces(baseline, candidate, config=custom_config)
            print("\n=== 3. Tuned Severity Diff (JSON summary) ===")
            print(format_diff_json(tuned_report)[:300] + "...")

            # 4. Rich rendering (captured to an off-screen Console for clean script output).
            console = Console(record=True, width=100)
            render_diff_rich(diff_report, console=console)
            print("\n=== 4. Rich Rendered Output ===")
            print(console.export_text())
        finally:
            store.close()


if __name__ == "__main__":
    example_identical_and_divergent_diff()

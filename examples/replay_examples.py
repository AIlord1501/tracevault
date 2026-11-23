"""Runnable TraceVault M4 offline replay & boundary policy examples (zero network calls)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from tracevault import (
    BoundaryExecutor,
    BoundaryMode,
    BoundaryType,
    ModelBoundary,
    PolicyViolationError,
    ReplayConfig,
    ReplayEngine,
    ReplayMode,
    SafetyPolicy,
    ToolBoundary,
    TraceStore,
    capture,
)


def main() -> None:
    """Demonstrate Capture -> Freeze -> Offline Replay -> Fork -> Governed Boundary Replay."""
    with tempfile.TemporaryDirectory(prefix="tracevault_m4_examples_") as tmp:
        store = TraceStore(Path(tmp) / ".tracevault")
        store.init()
        try:
            # 1. Capture and freeze a baseline execution
            with capture(
                "invoice_triage",
                inputs={"invoice_id": "INV-100"},
                tags=["example", "baseline"],
                store=store,
                auto_save=True,
            ) as session:
                tool_fx = session.record_tool_call(
                    "fetch_invoice",
                    {"invoice_id": "INV-100"},
                    result={"amount_usd": 120.0, "status": "overdue"},
                )
                model_fx = session.record_model_call(
                    request={
                        "provider": "mock",
                        "model": "mock-gpt",
                        "messages": [{"role": "user", "content": "Draft reminder for INV-100"}],
                    },
                    response={"content": "Reminder: Invoice INV-100 ($120) is overdue."},
                    name="draft_reminder",
                )
                session.set_outputs({"reply": "Reminder: Invoice INV-100 ($120) is overdue."})

            frozen = store.freeze(session.trace_id)

            # 2. Full offline trace replay loaded from TraceStore
            engine = ReplayEngine.from_store(store, frozen.trace_id)
            result = engine.replay_trace(fork=True)
            assert result.success is True
            assert result.matched_fixtures == 2
            assert result.live_calls == 0
            assert result.candidate_trace.parent_trace_id == frozen.trace_id

            # 3. Fork with a targeted fixture override
            fork_engine = ReplayEngine(frozen)
            forked = fork_engine.fork(
                overrides={
                    model_fx.fixture_id: {
                        "content": "Friendly reminder: Invoice INV-100 ($120) is due."
                    }
                }
            )
            store.save(forked)
            assert forked.parent_trace_id == frozen.trace_id
            assert forked.fixtures.entries[1].response is not None
            assert "Friendly reminder" in forked.fixtures.entries[1].response["content"]

            # 4. Policy-governed boundary replay (Model RECORDED, Tool explicitly LIVE)
            hybrid_cfg = ReplayConfig(
                mode=ReplayMode.BOUNDARY_GOVERNED,
                boundary_modes={
                    BoundaryType.MODEL: BoundaryMode.RECORDED,
                    BoundaryType.TOOL: BoundaryMode.LIVE,
                    BoundaryType.RETRIEVAL: BoundaryMode.RECORDED,
                    BoundaryType.CUSTOM: BoundaryMode.RECORDED,
                },
                safety_policy=SafetyPolicy(
                    allow_live_boundaries={BoundaryType.TOOL},
                    allowed_tools={"fetch_invoice"},
                    max_live_calls=1,
                    require_explicit_opt_in=True,
                ),
            )
            hybrid_engine = ReplayEngine(frozen, config=hybrid_cfg)
            executor = BoundaryExecutor(hybrid_engine)
            model_boundary = ModelBoundary(executor)
            tool_boundary = ToolBoundary(executor)

            def local_mock_live_tool(request: dict[str, Any]) -> dict[str, Any]:
                invoice_id = request["arguments"]["invoice_id"]
                return {"amount_usd": 120.0, "status": "paid", "invoice_id": invoice_id}

            tool_resp = tool_boundary.invoke(
                "fetch_invoice",
                {"invoice_id": "INV-100"},
                live_fn=local_mock_live_tool,
            )
            model_resp = model_boundary.invoke(
                {
                    "provider": "mock",
                    "model": "mock-gpt",
                    "messages": [{"role": "user", "content": "Draft reminder for INV-100"}],
                },
                name="draft_reminder",
            )
            assert tool_resp["status"] == "paid"
            assert "Reminder:" in model_resp["content"]

            # Unauthorized tool call fails closed with PolicyViolationError
            try:
                tool_boundary.invoke("delete_account", {"id": "1"}, live_fn=local_mock_live_tool)
            except PolicyViolationError:
                blocked = True
            else:
                blocked = False
            assert blocked is True

            hybrid_result = hybrid_engine.build_result(fork=True)
            print(
                f"Baseline={frozen.trace_id} (frozen={frozen.frozen}) | "
                f"OfflineReplay matched={result.matched_fixtures} | "
                f"Fork={forked.trace_id} (tool_fixture={tool_fx.fixture_id}) | "
                f"HybridReplay matched={hybrid_result.matched_fixtures}, "
                f"live_calls={hybrid_result.live_calls}"
            )
        finally:
            store.close()


if __name__ == "__main__":
    main()

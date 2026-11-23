"""Runnable M7 end-to-end CLI workflow validation script (zero network calls)."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from tracevault import BoundaryType, SpanType, TraceStore, capture
from tracevault.cli.app import app


def run_cli_end_to_end_workflow() -> None:
    """Execute the 14-step local TraceVault CLI workflow end-to-end offline."""
    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store_a_dir = root / "store_a"
        store_b_dir = root / "store_b"

        # 1. Initialize TraceVault store A via CLI
        res_init = runner.invoke(app, ["init", "--store", str(store_a_dir), "--json"])
        assert res_init.exit_code == 0, res_init.output
        print("1. Initialized store A via `tracevault init`")

        # 2 & 3. Capture a synthetic AI execution and save to store A
        with (
            TraceStore(store_a_dir) as store_a,
            capture(
                "order-lookup-workflow",
                inputs={"order_id": "ORD-777", "api_key": "sk-live-secret-key-9876543210"},
                tags=["cli-e2e", "orders"],
                store=store_a,
                auto_save=True,
            ) as session,
        ):
            with session.span("plan_step", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
                session.record_model_call(
                    {
                        "provider": "mock-llm",
                        "model": "gpt-mock",
                        "messages": [{"role": "user", "content": "Where is ORD-777?"}],
                    },
                    {"content": "Calling get_order_status"},
                    name="planner",
                )
            with session.span("tool_step", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
                session.record_tool_call(
                    "get_order_status",
                    {"order_id": "ORD-777"},
                    result={"status": "delivered", "carrier": "LocalCourier"},
                )
            session.set_outputs({"reply": "Order ORD-777 was delivered.", "status": "delivered"})
            trace_id = session.trace_id
        print(f"2-3. Captured & saved synthetic trace {trace_id}")

        # 4. List and inspect the trace via CLI
        res_list = runner.invoke(
            app, ["list", "--store", str(store_a_dir), "--tag", "orders", "--json"]
        )
        assert res_list.exit_code == 0, res_list.output
        listed = json.loads(res_list.output)
        assert any(item["trace_id"] == trace_id for item in listed)

        res_show = runner.invoke(
            app,
            ["show", trace_id, "--store", str(store_a_dir), "--events", "--fixtures", "--json"],
        )
        assert res_show.exit_code == 0, res_show.output
        shown = json.loads(res_show.output)
        assert shown["trace_id"] == trace_id
        print(f"4. Listed and inspected trace {trace_id} via `tracevault list` & `tracevault show`")

        # 5. Freeze the trace via CLI
        res_freeze = runner.invoke(app, ["freeze", trace_id, "--store", str(store_a_dir), "--json"])
        assert res_freeze.exit_code == 0, res_freeze.output
        print(f"5. Froze trace {trace_id} via `tracevault freeze`")

        # 6. Replay the trace offline and save candidate via CLI
        res_replay = runner.invoke(
            app,
            [
                "replay",
                trace_id,
                "--store",
                str(store_a_dir),
                "--strict",
                "--save",
                "--new-id",
                "tr_cli_replayed_001",
                "--json",
            ],
        )
        assert res_replay.exit_code == 0, res_replay.output
        replay_data = json.loads(res_replay.output)
        candidate_id = replay_data["candidate_trace_id"]
        assert candidate_id == "tr_cli_replayed_001"
        print(f"6. Replayed trace offline -> candidate {candidate_id}")

        # 7. Compare original and replayed execution via CLI
        res_diff = runner.invoke(
            app,
            ["diff", trace_id, candidate_id, "--store", str(store_a_dir), "--json"],
        )
        assert res_diff.exit_code == 0, res_diff.output
        diff_data = json.loads(res_diff.output)
        assert diff_data[" summary" if " summary" in diff_data else "summary"]["breaking"] == 0
        print("7. Compared baseline and replayed candidate via `tracevault diff` (0 breaking)")

        # 8. Generate a regression test via CLI
        test_path = root / "test_order_regression.py"
        fixture_path = root / "order_fixture.json"
        res_export_test = runner.invoke(
            app,
            [
                "export-test",
                trace_id,
                "--store",
                str(store_a_dir),
                "--output",
                str(test_path),
                "--fixture-output",
                str(fixture_path),
                "--json",
            ],
        )
        assert res_export_test.exit_code == 0, res_export_test.output
        assert test_path.exists() and fixture_path.exists()
        print(f"8. Generated pytest regression file {test_path.name}")

        # 9. Run the generated regression test offline
        spec = importlib.util.spec_from_file_location("cli_generated_test", test_path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        test_fn = next(getattr(mod, a) for a in dir(mod) if a.startswith("test_"))
        test_fn()
        print("9. Executed generated pytest regression test offline: PASSED")

        # 10. Export the trace to portable JSON
        exported_path = root / "exported_trace.json"
        res_export = runner.invoke(
            app,
            [
                "export",
                trace_id,
                "--store",
                str(store_a_dir),
                "--output",
                str(exported_path),
                "--json",
            ],
        )
        assert res_export.exit_code == 0, res_export.output
        assert exported_path.exists()
        print(f"10. Exported trace to {exported_path.name}")

        # 11. Import the trace into a separate temporary storage instance (store B)
        res_import = runner.invoke(
            app,
            [
                "import",
                str(exported_path),
                "--store",
                str(store_b_dir),
                "--freeze",
                "--json",
            ],
        )
        assert res_import.exit_code == 0, res_import.output
        print("11. Imported trace into isolated store B via `tracevault import --freeze`")

        # 12. Verify imported trace integrity via CLI
        res_verify = runner.invoke(
            app,
            ["verify", trace_id, "--store", str(store_b_dir), "--json"],
        )
        assert res_verify.exit_code == 0, res_verify.output
        print("12. Verified imported trace schema & secret hygiene via `tracevault verify`")


if __name__ == "__main__":
    run_cli_end_to_end_workflow()

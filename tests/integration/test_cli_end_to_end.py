"""Full 12/14-step end-to-end offline CLI workflow integration test for TraceVault."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from conftest import SYNTHETIC_SECRETS
from tracevault.capture import capture
from tracevault.cli import app
from tracevault.schema import BoundaryType, SpanType
from tracevault.storage import TraceStore

runner = CliRunner()


def _execute_generated_regression_module(py_path: Path) -> None:
    """Dynamically import a generated pytest regression test file and invoke its test function."""
    module_name = f"_cli_e2e_reg_{py_path.stem}"
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


def test_full_end_to_end_cli_offline_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute the complete local-first AI execution lifecycle end-to-end via CLI & TraceStore."""

    # Enforce 100% offline execution across the entire end-to-end workflow
    def _forbid_network(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Offline CLI end-to-end workflow must never open network sockets")

    monkeypatch.setattr(socket, "socket", _forbid_network)

    store_a = tmp_path / "store_a"
    store_b = tmp_path / "store_b"
    baseline_id = "tr_e2e_support_workflow_01"
    replayed_id = "tr_e2e_replayed_strict_01"
    forked_id = "tr_e2e_forked_override_01"
    secret_key = SYNTHETIC_SECRETS["openai_key"]

    # 1. Initialize store_a via `tracevault init --store <store_a>`
    res_init = runner.invoke(app, ["init", "--store", str(store_a), "--json"])
    assert res_init.exit_code == 0
    init_payload = json.loads(res_init.stdout)
    assert init_payload["status"] == "initialized"
    assert (store_a / "traces").is_dir()
    assert (store_a / "index.db").is_file()

    # 2. Capture synthetic AI execution (model, tool, retrieval, state change, secret input)
    with capture(
        "enterprise_billing_triage_agent",
        trace_id=baseline_id,
        inputs={
            "ticket_id": "TCK-9001",
            "api_key": secret_key,
            "query": f"Refund double charge using token {secret_key}",
        },
        tags=["e2e", "billing", "production"],
        metadata={"region": "us-east", "Authorization": SYNTHETIC_SECRETS["bearer_token"]},
    ) as session:
        with session.span("agent_orchestrator", span_type=SpanType.AGENT):
            # Retrieval step
            with session.span(
                "kb_lookup",
                span_type=SpanType.RETRIEVAL,
                boundary=BoundaryType.RETRIEVAL,
            ):
                retrieval_fx = session.record_retrieval(
                    query={"retriever": "billing_kb", "query": "double charge refund policy"},
                    results={
                        "retriever": "billing_kb",
                        "documents": [
                            {
                                "doc_id": "doc_refund_01",
                                "content": "Duplicate charges are eligible for instant refund.",
                                "score": 0.99,
                            }
                        ],
                    },
                    name="billing_kb",
                )

            # State change 1
            session.record_state_change(
                "workflow.policy_verified",
                "set",
                before=False,
                after=True,
            )

            # Model call
            with session.span(
                "triage_llm",
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
            ):
                model_fx = session.record_model_call(
                    request={
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                        "api_key": secret_key,
                        "messages": [
                            {
                                "role": "user",
                                "content": "Process duplicate charge refund for TCK-9001",
                            }
                        ],
                    },
                    response={
                        "model": "gpt-4o-mini",
                        "content": "Issuing refund via issue_billing_refund tool.",
                        "finish_reason": "tool_calls",
                    },
                    name="openai.chat.completions",
                )

            # Tool call
            with session.span(
                "refund_tool",
                span_type=SpanType.TOOL,
                boundary=BoundaryType.TOOL,
            ):
                tool_fx = session.record_tool_call(
                    "issue_billing_refund",
                    args={"ticket_id": "TCK-9001", "amount_usd": 49.0},
                    result={"refund_id": "RF-9001", "status": "approved", "amount_usd": 49.0},
                )

            # State change 2
            session.record_state_change(
                "workflow.refund_status",
                "set",
                before="pending",
                after="approved",
            )

        session.set_outputs(
            {
                "resolution": "approved",
                "refund_id": "RF-9001",
                "amount_usd": 49.0,
            }
        )

    assert session.trace is not None
    captured_trace = session.trace
    assert captured_trace.redaction_applied is True
    assert retrieval_fx.fixture_id
    assert model_fx.fixture_id

    # 3. Save to <store_a>
    with TraceStore(store_a) as store:
        saved_path = store.save(captured_trace)
        assert saved_path.is_file()

    # 4. Inspect via `tracevault list`, `tracevault show`, and `tracevault inspect`
    res_list_rich = runner.invoke(app, ["list", "-s", str(store_a)])
    assert res_list_rich.exit_code == 0
    assert baseline_id in res_list_rich.stdout
    assert "Traces (1)" in res_list_rich.stdout

    res_list_json = runner.invoke(
        app, ["list", "-s", str(store_a), "--tag", "billing", "--status", "completed", "--json"]
    )
    assert res_list_json.exit_code == 0
    list_items = json.loads(res_list_json.stdout)
    assert len(list_items) == 1
    assert list_items[0]["trace_id"] == baseline_id
    assert list_items[0]["run_name"] == "enterprise_billing_triage_agent"
    assert list_items[0]["fixture_count"] == 3

    res_show_rich = runner.invoke(
        app,
        [
            "show",
            baseline_id,
            "-s",
            str(store_a),
            "--spans",
            "--events",
            "--fixtures",
            "--metadata",
        ],
    )
    assert res_show_rich.exit_code == 0
    assert baseline_id in res_show_rich.stdout
    assert "issue_billing_refund" in res_show_rich.stdout
    assert secret_key not in res_show_rich.stdout

    res_show_json = runner.invoke(app, ["show", baseline_id, "-s", str(store_a), "--json"])
    assert res_show_json.exit_code == 0
    shown_data = json.loads(res_show_json.stdout)
    assert shown_data["trace_id"] == baseline_id
    assert secret_key not in res_show_json.stdout

    res_inspect_rich = runner.invoke(app, ["inspect", baseline_id, "-s", str(store_a)])
    assert res_inspect_rich.exit_code == 0
    assert "Spans (4)" in res_inspect_rich.stdout
    assert "Fixtures (3)" in res_inspect_rich.stdout
    assert secret_key not in res_inspect_rich.stdout

    res_inspect_json = runner.invoke(app, ["inspect", baseline_id, "-s", str(store_a), "--json"])
    assert res_inspect_json.exit_code == 0
    assert json.loads(res_inspect_json.stdout)["trace_id"] == baseline_id

    # 5. Freeze via `tracevault freeze` (and verify `tracevault delete` without `--force` exits 1)
    res_freeze = runner.invoke(app, ["freeze", baseline_id, "-s", str(store_a), "--json"])
    assert res_freeze.exit_code == 0
    assert json.loads(res_freeze.stdout) == {"trace_id": baseline_id, "frozen": True}

    res_del_blocked = runner.invoke(app, ["delete", baseline_id, "-s", str(store_a), "--json"])
    assert res_del_blocked.exit_code == 1
    assert json.loads(res_del_blocked.stdout)["error_type"] == "TraceFrozenError"

    # 6. Replay offline via `tracevault replay --strict --save` and fork with `--override`
    res_replay_strict = runner.invoke(
        app,
        [
            "replay",
            baseline_id,
            "-s",
            str(store_a),
            "--strict",
            "--save",
            "--new-id",
            replayed_id,
            "--json",
        ],
    )
    assert res_replay_strict.exit_code == 0
    rp_strict_data = json.loads(res_replay_strict.stdout)
    assert rp_strict_data["success"] is True
    assert rp_strict_data["candidate_trace_id"] == replayed_id
    assert rp_strict_data["matched_fixtures"] == 3
    assert rp_strict_data["overridden_fixtures"] == 0
    assert rp_strict_data["live_calls"] == 0
    assert rp_strict_data["saved"] is True

    override_tool_payload = json.dumps(
        {"refund_id": "RF-DENIED", "status": "manual_review_required", "amount_usd": 0.0}
    )
    res_replay_fork = runner.invoke(
        app,
        [
            "replay",
            baseline_id,
            "-s",
            str(store_a),
            "--strict",
            "--fork",
            "--save",
            "--new-id",
            forked_id,
            "--override",
            f"{tool_fx.fixture_id}={override_tool_payload}",
            "--json",
        ],
    )
    assert res_replay_fork.exit_code == 0
    rp_fork_data = json.loads(res_replay_fork.stdout)
    assert rp_fork_data["success"] is True
    assert rp_fork_data["candidate_trace_id"] == forked_id
    assert rp_fork_data["parent_trace_id"] == baseline_id
    assert rp_fork_data["overridden_fixtures"] == 1
    assert rp_fork_data["live_calls"] == 0

    # 7. Compare baseline vs replayed (exit 0) and baseline vs forked override (exit 1)
    res_diff_clean = runner.invoke(
        app, ["diff", baseline_id, replayed_id, "-s", str(store_a), "--json"]
    )
    assert res_diff_clean.exit_code == 0
    diff_clean_report = json.loads(res_diff_clean.stdout)
    assert diff_clean_report["summary"]["breaking"] == 0

    res_diff_breaking = runner.invoke(
        app, ["diff", baseline_id, forked_id, "-s", str(store_a), "--json"]
    )
    assert res_diff_breaking.exit_code == 1
    diff_break_report = json.loads(res_diff_breaking.stdout)
    assert diff_break_report["identical"] is False
    assert diff_break_report["summary"]["breaking"] >= 1

    # Also test Rich diff output on the breaking divergence
    res_diff_rich = runner.invoke(app, ["diff", baseline_id, forked_id, "-s", str(store_a)])
    assert res_diff_rich.exit_code == 1
    assert "DIVERGENT" in res_diff_rich.stdout

    # 8. Generate a standalone pytest regression test via `tracevault export-test`
    generated_test_path = tmp_path / "test_e2e_generated_regression.py"
    generated_fixture_path = tmp_path / "e2e_regression_fixture.json"
    res_export_test = runner.invoke(
        app,
        [
            "export-test",
            baseline_id,
            "-s",
            str(store_a),
            "-o",
            str(generated_test_path),
            "--fixture-output",
            str(generated_fixture_path),
            "--json",
        ],
    )
    assert res_export_test.exit_code == 0
    assert generated_test_path.is_file()
    assert generated_fixture_path.is_file()

    # 9. Execute generated regression test function AND `tracevault test` offline (exit 0)
    _execute_generated_regression_module(generated_test_path)

    res_cli_test_store = runner.invoke(
        app, ["test", baseline_id, "-s", str(store_a), "--strict", "--json"]
    )
    assert res_cli_test_store.exit_code == 0
    assert json.loads(res_cli_test_store.stdout)["passed"] is True

    res_cli_test_file = runner.invoke(
        app, ["test", str(generated_fixture_path), "--strict", "--json"]
    )
    assert res_cli_test_file.exit_code == 0
    assert json.loads(res_cli_test_file.stdout)["passed"] is True

    # 10. Export the trace via `tracevault export` (both json and jsonl)
    exported_json_path = tmp_path / "exported_baseline.json"
    exported_jsonl_path = tmp_path / "exported_baseline.jsonl"

    res_exp_json = runner.invoke(
        app,
        [
            "export",
            baseline_id,
            "-s",
            str(store_a),
            "-o",
            str(exported_json_path),
            "--format",
            "json",
            "--json",
        ],
    )
    assert res_exp_json.exit_code == 0
    assert exported_json_path.is_file()

    res_exp_jsonl = runner.invoke(
        app,
        [
            "export",
            baseline_id,
            "-s",
            str(store_a),
            "-o",
            str(exported_jsonl_path),
            "--format",
            "jsonl",
            "--json",
        ],
    )
    assert res_exp_jsonl.exit_code == 0
    assert exported_jsonl_path.is_file()
    jsonl_lines = exported_jsonl_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(jsonl_lines) == 1 + len(captured_trace.events)
    assert json.loads(jsonl_lines[0])["record_type"] == "trace_header"

    # 11. Import exported JSON trace into isolated <store_b> via `tracevault import --freeze`
    #     (and verify duplicate import without `--overwrite` exits 1)
    res_import = runner.invoke(
        app,
        ["import", str(exported_json_path), "-s", str(store_b), "--freeze", "--json"],
    )
    assert res_import.exit_code == 0
    imp_payload = json.loads(res_import.stdout)
    assert imp_payload["trace_id"] == baseline_id
    assert imp_payload["frozen"] is True

    res_import_dup = runner.invoke(
        app,
        ["import", str(exported_json_path), "-s", str(store_b), "--json"],
    )
    assert res_import_dup.exit_code == 1
    assert json.loads(res_import_dup.stdout)["error_type"] in {
        "TraceFrozenError",
        "FileExistsError",
    }

    # 12. Verify imported trace integrity via `tracevault verify` (exit_code == 0)
    res_verify_rich = runner.invoke(app, ["verify", baseline_id, "-s", str(store_b)])
    assert res_verify_rich.exit_code == 0
    assert "VERIFIED:" in res_verify_rich.stdout

    res_verify_json = runner.invoke(app, ["verify", baseline_id, "-s", str(store_b), "--json"])
    assert res_verify_json.exit_code == 0
    verify_payload = json.loads(res_verify_json.stdout)
    assert verify_payload["trace_id"] == baseline_id
    assert verify_payload["valid"] is True
    assert verify_payload["redaction_applied"] is True

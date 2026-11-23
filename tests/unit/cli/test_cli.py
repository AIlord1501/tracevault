"""Comprehensive unit tests for the TraceVault Typer CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tracevault import __version__
from tracevault.cli import app
from tracevault.schema import (
    SCHEMA_VERSION,
    BoundaryType,
    Event,
    EventKind,
    ExecutionError,
    FixtureEntry,
    FixtureSet,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    Trace,
    compute_fingerprint,
)
from tracevault.storage import TraceStore

runner = CliRunner()


def _make_sample_trace(
    trace_id: str = "tr_cli_sample_01",
    *,
    name: str = "support_triage_agent",
    status: RunStatus = RunStatus.COMPLETED,
    frozen: bool = False,
    tags: list[str] | None = None,
    outputs: dict[str, Any] | None = None,
    redaction_applied: bool = True,
    extra_metadata: dict[str, Any] | None = None,
    record_error_fixture: bool = False,
) -> Trace:
    ts = datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC)
    req = {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Classify invoice #42"}],
    }
    resp = {"model": "gpt-4o-mini", "content": "billing", "finish_reason": "stop"}
    fp = compute_fingerprint(BoundaryType.MODEL, req)

    fx_error = (
        ExecutionError(error_type="RateLimitError", message="Quota exceeded")
        if record_error_fixture
        else None
    )
    fx_response = None if record_error_fixture else resp

    run_err = fx_error if status == RunStatus.FAILED else None
    resolved_outputs = outputs if outputs is not None else {"category": "billing"}

    run = Run(
        run_id="run_001",
        trace_id=trace_id,
        name=name,
        started_at=ts,
        ended_at=ts,
        status=status,
        inputs={"ticket": "Invoice #42"},
        outputs=resolved_outputs,
        error=run_err,
        environment={"python": "3.12"},
        tags=tags if tags is not None else ["triage", "billing"],
        metadata={"team": "support"},
    )
    span = Span(
        span_id="sp_001",
        run_id="run_001",
        span_type=SpanType.MODEL,
        boundary=BoundaryType.MODEL,
        name="openai.chat.completions",
        started_at=ts,
        ended_at=ts,
        status=SpanStatus.ERROR if record_error_fixture else SpanStatus.OK,
        attributes={"model": "gpt-4o-mini"},
        error=fx_error,
        event_ids=["ev_001", "ev_002"],
    )
    ev1 = Event(
        event_id="ev_001",
        run_id="run_001",
        span_id="sp_001",
        event_type=EventKind.MODEL_REQUEST,
        boundary=BoundaryType.MODEL,
        timestamp=ts,
        sequence=0,
        payload=req,
    )
    ev2 = Event(
        event_id="ev_002",
        run_id="run_001",
        span_id="sp_001",
        event_type=EventKind.MODEL_ERROR if record_error_fixture else EventKind.MODEL_RESPONSE,
        boundary=BoundaryType.MODEL,
        timestamp=ts,
        sequence=1,
        payload=(
            {"error": fx_error.model_dump(mode="json"), "boundary": "model", "recoverable": False}
            if fx_error is not None
            else resp
        ),
    )
    fixture = FixtureEntry(
        fixture_id="fix_001",
        boundary=BoundaryType.MODEL,
        fingerprint=fp,
        call_index=0,
        request=req,
        response=fx_response,
        error=fx_error,
        span_id="sp_001",
        name="openai.chat.completions",
    )
    return Trace(
        trace_id=trace_id,
        created_at=ts,
        frozen=frozen,
        runs=[run],
        spans=[span],
        events=[ev1, ev2],
        fixtures=FixtureSet(entries=[fixture]),
        metadata=extra_metadata or {"env": "test"},
        redaction_applied=redaction_applied,
    )


def _seed_store(store_dir: Path, traces: list[Trace]) -> None:
    with TraceStore(store_dir) as store:
        store.init()
        for tr in traces:
            store.save(tr, overwrite=True)


def test_help_and_version_commands() -> None:
    res_help = runner.invoke(app, ["--help"])
    assert res_help.exit_code == 0
    assert "tracevault" in res_help.stdout.lower()
    assert "replay" in res_help.stdout
    assert "diff" in res_help.stdout

    res_flag = runner.invoke(app, ["--version"])
    assert res_flag.exit_code == 0
    assert f"tracevault {__version__} (schema {SCHEMA_VERSION})" in res_flag.stdout

    res_short = runner.invoke(app, ["-V"])
    assert res_short.exit_code == 0
    assert __version__ in res_short.stdout

    res_cmd = runner.invoke(app, ["version"])
    assert res_cmd.exit_code == 0
    assert f"tracevault {__version__} (schema {SCHEMA_VERSION})" in res_cmd.stdout

    res_json = runner.invoke(app, ["version", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data == {"version": __version__, "schema_version": SCHEMA_VERSION}


def test_init_and_env_var_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store_dir = tmp_path / "custom_store"
    res = runner.invoke(app, ["init", "--store", str(store_dir)])
    assert res.exit_code == 0
    assert (store_dir / "traces").is_dir()
    assert (store_dir / "index.db").is_file()

    env_store_dir = tmp_path / "env_store"
    monkeypatch.setenv("TRACEVAULT_STORE", str(env_store_dir))
    res_json = runner.invoke(app, ["init", "--json"])
    assert res_json.exit_code == 0
    payload = json.loads(res_json.stdout)
    assert payload["status"] == "initialized"
    assert Path(payload["store"]) == env_store_dir
    assert (env_store_dir / "index.db").is_file()


def test_list_filters_and_json(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t1 = _make_sample_trace(
        "tr_alpha",
        name="alpha_agent",
        status=RunStatus.COMPLETED,
        frozen=True,
        tags=["prod", "alpha"],
    )
    t2 = _make_sample_trace(
        "tr_beta",
        name="beta_workflow",
        status=RunStatus.FAILED,
        frozen=False,
        tags=["staging"],
    )
    _seed_store(store_dir, [t1, t2])

    # Rich table output
    res_table = runner.invoke(app, ["list", "-s", str(store_dir)])
    assert res_table.exit_code == 0
    assert "tr_alpha" in res_table.stdout
    assert "tr_beta" in res_table.stdout

    # Filter by status
    res_completed = runner.invoke(
        app, ["list", "-s", str(store_dir), "--status", "completed", "--json"]
    )
    assert res_completed.exit_code == 0
    items = json.loads(res_completed.stdout)
    assert [i["trace_id"] for i in items] == ["tr_alpha"]

    # Invalid status exits 1
    res_bad_status = runner.invoke(
        app, ["list", "-s", str(store_dir), "--status", "not_a_status", "--json"]
    )
    assert res_bad_status.exit_code == 1
    err_data = json.loads(res_bad_status.stdout)
    assert err_data["error_type"] == "ValueError"

    # Filter by tag
    res_tag = runner.invoke(app, ["list", "-s", str(store_dir), "--tag", "staging", "--json"])
    assert res_tag.exit_code == 0
    assert [i["trace_id"] for i in json.loads(res_tag.stdout)] == ["tr_beta"]

    # Filter by frozen / unfrozen
    res_frozen = runner.invoke(app, ["list", "-s", str(store_dir), "--frozen", "--json"])
    assert res_frozen.exit_code == 0
    assert [i["trace_id"] for i in json.loads(res_frozen.stdout)] == ["tr_alpha"]

    res_unfrozen = runner.invoke(app, ["list", "-s", str(store_dir), "--unfrozen", "--json"])
    assert res_unfrozen.exit_code == 0
    assert [i["trace_id"] for i in json.loads(res_unfrozen.stdout)] == ["tr_beta"]

    # Filter by query & limit
    res_query = runner.invoke(app, ["list", "-s", str(store_dir), "-q", "beta", "--json"])
    assert res_query.exit_code == 0
    assert [i["trace_id"] for i in json.loads(res_query.stdout)] == ["tr_beta"]

    res_limit = runner.invoke(app, ["list", "-s", str(store_dir), "--limit", "1", "--json"])
    assert res_limit.exit_code == 0
    assert len(json.loads(res_limit.stdout)) == 1


def test_show_and_inspect_commands(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t1 = _make_sample_trace("tr_show_01")
    _seed_store(store_dir, [t1])

    res_show = runner.invoke(
        app,
        [
            "show",
            "tr_show_01",
            "-s",
            str(store_dir),
            "--spans",
            "--events",
            "--fixtures",
            "--metadata",
        ],
    )
    assert res_show.exit_code == 0
    assert "tr_show_01" in res_show.stdout
    assert "openai.chat.completions" in res_show.stdout
    assert "ev_001" in res_show.stdout
    assert "fix_001" in res_show.stdout
    assert "Metadata & Environment" in res_show.stdout

    res_show_json = runner.invoke(app, ["show", "tr_show_01", "-s", str(store_dir), "--json"])
    assert res_show_json.exit_code == 0
    loaded = json.loads(res_show_json.stdout)
    assert loaded["trace_id"] == "tr_show_01"

    res_inspect = runner.invoke(app, ["inspect", "tr_show_01", "-s", str(store_dir)])
    assert res_inspect.exit_code == 0
    assert "Spans (1)" in res_inspect.stdout
    assert "Events (2)" in res_inspect.stdout
    assert "Fixtures (1)" in res_inspect.stdout

    # Missing trace exits 1
    res_missing = runner.invoke(app, ["show", "tr_does_not_exist", "-s", str(store_dir), "--json"])
    assert res_missing.exit_code == 1
    assert json.loads(res_missing.stdout)["error_type"] == "TraceNotFoundError"

    # Invalid trace ID exits 1
    res_invalid = runner.invoke(app, ["inspect", "../bad_id", "-s", str(store_dir), "--json"])
    assert res_invalid.exit_code == 1
    assert json.loads(res_invalid.stdout)["error_type"] in {
        "InvalidTraceIdError",
        "TraceNotFoundError",
        "UnsafeTraceError",
    }


def test_freeze_and_delete_commands(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t1 = _make_sample_trace("tr_freeze_del", frozen=False)
    _seed_store(store_dir, [t1])

    # Freeze trace
    res_freeze = runner.invoke(app, ["freeze", "tr_freeze_del", "-s", str(store_dir), "--json"])
    assert res_freeze.exit_code == 0
    assert json.loads(res_freeze.stdout) == {"trace_id": "tr_freeze_del", "frozen": True}

    # Delete frozen trace without --force fails with exit 1
    res_del_fail = runner.invoke(app, ["delete", "tr_freeze_del", "-s", str(store_dir), "--json"])
    assert res_del_fail.exit_code == 1
    assert json.loads(res_del_fail.stdout)["error_type"] == "TraceFrozenError"

    # Delete frozen trace with --force succeeds
    res_del_ok = runner.invoke(
        app, ["delete", "tr_freeze_del", "-s", str(store_dir), "--force", "--json"]
    )
    assert res_del_ok.exit_code == 0
    assert json.loads(res_del_ok.stdout)["deleted"] is True

    # Deleting again fails with TraceNotFoundError
    res_del_missing = runner.invoke(app, ["delete", "tr_freeze_del", "-s", str(store_dir)])
    assert res_del_missing.exit_code == 1


def test_replay_command_modes_overrides_and_errors(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t_ok = _make_sample_trace("tr_replay_ok")
    t_err = _make_sample_trace(
        "tr_replay_err",
        status=RunStatus.FAILED,
        record_error_fixture=True,
    )
    _seed_store(store_dir, [t_ok, t_err])

    # Strict replay with --fork, --save, --new-id, and --override
    override_json = json.dumps(
        {"model": "gpt-4o-mini", "content": "overridden_category", "finish_reason": "stop"}
    )
    res_rp = runner.invoke(
        app,
        [
            "replay",
            "tr_replay_ok",
            "-s",
            str(store_dir),
            "--lenient",
            "--fork",
            "--save",
            "--new-id",
            "tr_replayed_fork_01",
            "--override",
            f"fix_001={override_json}",
            "--json",
        ],
    )
    assert res_rp.exit_code == 0
    rp_data = json.loads(res_rp.stdout)
    assert rp_data["success"] is True
    assert rp_data["candidate_trace_id"] == "tr_replayed_fork_01"
    assert rp_data["parent_trace_id"] == "tr_replay_ok"
    assert rp_data["mode"] == "offline_lenient"
    assert rp_data["matched_fixtures"] == 1
    assert rp_data["overridden_fixtures"] == 1
    assert rp_data["live_calls"] == 0
    assert rp_data["saved"] is True

    with TraceStore(store_dir) as store:
        forked = store.load("tr_replayed_fork_01")
        assert forked.parent_trace_id == "tr_replay_ok"
        assert forked.fixtures.entries[0].response is not None
        assert forked.fixtures.entries[0].response["content"] == "overridden_category"

    # Replaying an error trace without override exits 1
    res_err = runner.invoke(
        app,
        ["replay", "tr_replay_err", "-s", str(store_dir), "--strict", "--json"],
    )
    assert res_err.exit_code == 1
    err_data = json.loads(res_err.stdout)
    assert err_data["success"] is False
    assert err_data["error"]["error_type"] == "RateLimitError"


def test_diff_command_identical_breaking_and_options(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t_base = _make_sample_trace("tr_diff_base", outputs={"category": "billing"})
    t_same = _make_sample_trace("tr_diff_same", outputs={"category": "billing"})
    t_break = _make_sample_trace("tr_diff_break", outputs={"category": "technical"})
    _seed_store(store_dir, [t_base, t_same, t_break])

    # Identical diff exits 0
    res_same = runner.invoke(app, ["diff", "tr_diff_base", "tr_diff_same", "-s", str(store_dir)])
    assert res_same.exit_code == 0
    assert "IDENTICAL" in res_same.stdout

    # Breaking diff exits 1
    res_break = runner.invoke(
        app,
        ["diff", "tr_diff_base", "tr_diff_break", "-s", str(store_dir), "--json"],
    )
    assert res_break.exit_code == 1
    report = json.loads(res_break.stdout)
    assert report["identical"] is False
    assert report["summary"]["breaking"] >= 1

    # Verbose diff output
    res_verbose = runner.invoke(
        app,
        ["diff", "tr_diff_base", "tr_diff_break", "-s", str(store_dir), "--verbose"],
    )
    assert res_verbose.exit_code == 1
    assert "TraceVault Diff Report: DIVERGENT" in res_verbose.stdout
    assert "baseline :" in res_verbose.stdout

    # Ignoring the breaking path makes diff exit 0
    res_ignored = runner.invoke(
        app,
        [
            "diff",
            "tr_diff_base",
            "tr_diff_break",
            "-s",
            str(store_dir),
            "--ignore-path",
            "runs[0].outputs",
        ],
    )
    assert res_ignored.exit_code == 0


def test_export_and_import_commands(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    t1 = _make_sample_trace("tr_export_01")
    _seed_store(store_dir, [t1])

    json_out = tmp_path / "exported.json"
    jsonl_out = tmp_path / "exported.jsonl"

    res_exp_json = runner.invoke(
        app,
        ["export", "tr_export_01", "-s", str(store_dir), "-o", str(json_out), "--json"],
    )
    assert res_exp_json.exit_code == 0
    assert json_out.is_file()

    res_exp_jsonl = runner.invoke(
        app,
        [
            "export",
            "tr_export_01",
            "-s",
            str(store_dir),
            "-o",
            str(jsonl_out),
            "--format",
            "jsonl",
        ],
    )
    assert res_exp_jsonl.exit_code == 0
    lines = jsonl_out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3  # 1 header + 2 events

    # Import into a fresh store
    dest_store = tmp_path / "dest_store"
    res_imp = runner.invoke(app, ["import", str(json_out), "-s", str(dest_store), "--json"])
    assert res_imp.exit_code == 0
    imp_data = json.loads(res_imp.stdout)
    assert imp_data["trace_id"] == "tr_export_01"
    assert imp_data["frozen"] is False

    # Importing duplicate without --overwrite exits 1
    res_dup = runner.invoke(app, ["import", str(json_out), "-s", str(dest_store), "--json"])
    assert res_dup.exit_code == 1
    assert json.loads(res_dup.stdout)["error_type"] == "FileExistsError"

    # Importing duplicate with --overwrite and --freeze succeeds
    res_overwrite = runner.invoke(
        app,
        [
            "import",
            str(json_out),
            "-s",
            str(dest_store),
            "--overwrite",
            "--freeze",
            "--json",
        ],
    )
    assert res_overwrite.exit_code == 0
    assert json.loads(res_overwrite.stdout)["frozen"] is True

    # Importing malformed JSON exits 1
    bad_file = tmp_path / "malformed.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    res_bad = runner.invoke(app, ["import", str(bad_file), "-s", str(dest_store), "--json"])
    assert res_bad.exit_code == 1
    assert json.loads(res_bad.stdout)["error_type"] == "UnsafeTraceError"

    # Importing trace with path-traversal trace_id exits 1
    traversal_file = tmp_path / "traversal.json"
    raw_traversal = json.loads(t1.to_json())
    raw_traversal["trace_id"] = "../escape_attempt"
    raw_traversal["runs"][0]["trace_id"] = "../escape_attempt"
    traversal_file.write_text(json.dumps(raw_traversal), encoding="utf-8")
    res_trav = runner.invoke(app, ["import", str(traversal_file), "-s", str(dest_store), "--json"])
    assert res_trav.exit_code == 1
    assert json.loads(res_trav.stdout)["error_type"] in {
        "InvalidTraceIdError",
        "UnsafeTraceError",
    }


def test_export_test_test_and_verify_commands(tmp_path: Path) -> None:
    store_dir = tmp_path / ".tracevault"
    healthy = _make_sample_trace("tr_healthy_01")
    unredacted = _make_sample_trace(
        "tr_unredacted_01",
        redaction_applied=False,
        extra_metadata={"openai_api_key": "sk-live-secret-token-1234567890"},
    )
    broken = _make_sample_trace(
        "tr_broken_01",
        status=RunStatus.FAILED,
        record_error_fixture=True,
    )
    _seed_store(store_dir, [healthy, unredacted, broken])

    # export-test generates valid pytest file and optional fixture file
    test_file = tmp_path / "test_generated_reg.py"
    fixture_file = tmp_path / "tr_healthy_01_fixture.json"
    res_exp_test = runner.invoke(
        app,
        [
            "export-test",
            "tr_healthy_01",
            "-s",
            str(store_dir),
            "-o",
            str(test_file),
            "--fixture-output",
            str(fixture_file),
            "--json",
        ],
    )
    assert res_exp_test.exit_code == 0
    assert test_file.is_file()
    assert fixture_file.is_file()
    assert "def test_tracevault_regression_tr_healthy_01" in test_file.read_text(encoding="utf-8")

    # test command succeeds on healthy trace in store and from .json file
    res_test_ok = runner.invoke(app, ["test", "tr_healthy_01", "-s", str(store_dir), "--json"])
    assert res_test_ok.exit_code == 0
    assert json.loads(res_test_ok.stdout)["passed"] is True

    res_test_file = runner.invoke(app, ["test", str(fixture_file), "--json"])
    assert res_test_file.exit_code == 0
    assert json.loads(res_test_file.stdout)["passed"] is True

    # test command fails with exit 1 on broken trace
    res_test_fail = runner.invoke(app, ["test", "tr_broken_01", "-s", str(store_dir), "--json"])
    assert res_test_fail.exit_code == 1

    # verify passes on healthy trace and fails on unredacted trace
    res_verify_ok = runner.invoke(app, ["verify", "tr_healthy_01", "-s", str(store_dir), "--json"])
    assert res_verify_ok.exit_code == 0
    assert json.loads(res_verify_ok.stdout)["valid"] is True

    res_verify_fail = runner.invoke(
        app, ["verify", "tr_unredacted_01", "-s", str(store_dir), "--json"]
    )
    assert res_verify_fail.exit_code == 1
    err_payload = json.loads(res_verify_fail.stdout)
    assert err_payload["error_type"] == "AssertionError"
    assert "sk-live-secret-token" not in res_verify_fail.stdout

"""Adversarial security, AST, network, traversal, markup, and redaction tests for TraceVault CLI."""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from conftest import (
    SYNTHETIC_SECRETS,
    make_deeply_nested_dict,
    make_valid_event,
    make_valid_fixture_entry,
    make_valid_fixture_set,
    make_valid_run,
    make_valid_span,
    make_valid_trace,
)
from tracevault.capture import CaptureSession
from tracevault.cli import app
from tracevault.schema import (
    DEFAULT_MAX_JSON_DEPTH,
    DEFAULT_MAX_TRACE_BYTES,
    BoundaryType,
    EventKind,
    ExecutionError,
    RunStatus,
    SpanStatus,
    SpanType,
)
from tracevault.storage import TraceStore

runner = CliRunner()

CLI_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "tracevault" / "cli"

FORBIDDEN_CLI_MODULES: frozenset[str] = frozenset(
    {
        "pickle",
        "cPickle",
        "_pickle",
        "marshal",
        "shelve",
        "subprocess",
        "urllib",
        "http",
        "socket",
        "httpx",
        "requests",
    }
)
FORBIDDEN_CLI_BUILTINS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset({"system", "popen"})


def scan_cli_source_for_forbidden_ast(source: str, filename: str = "<memory>") -> list[str]:
    """Audit Python source in src/tracevault/cli/ for forbidden imports and calls."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    os_aliases: set[str] = {"os"}
    builtins_aliases: set[str] = {"builtins"}
    banned_direct_names: set[str] = set(FORBIDDEN_CLI_BUILTINS)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                local_name = alias.asname or root_mod
                if root_mod in FORBIDDEN_CLI_MODULES:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden module import '{alias.name}'"
                    )
                elif alias.name == "os":
                    os_aliases.add(local_name)
                elif alias.name == "builtins":
                    builtins_aliases.add(local_name)

        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root_mod = mod.split(".", 1)[0]
            if root_mod in FORBIDDEN_CLI_MODULES:
                violations.append(f"{filename}:{node.lineno}: forbidden import from '{mod}'")
            for alias in node.names:
                local_name = alias.asname or alias.name
                if mod == "os" and alias.name in FORBIDDEN_OS_FUNCS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import 'from os import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)
                elif mod == "builtins" and alias.name in FORBIDDEN_CLI_BUILTINS:
                    violations.append(
                        f"{filename}:{node.lineno}: "
                        f"forbidden import 'from builtins import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in banned_direct_names:
                violations.append(f"{filename}:{node.lineno}: forbidden call '{func.id}()'")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target = func.value.id
            attr = func.attr
            if (
                target in FORBIDDEN_CLI_MODULES
                or (target in builtins_aliases and attr in FORBIDDEN_CLI_BUILTINS)
                or (target in os_aliases and attr in FORBIDDEN_OS_FUNCS)
            ):
                violations.append(f"{filename}:{node.lineno}: forbidden call '{target}.{attr}()'")

    return violations


class TestCliStaticSafetyAudit:
    """AST static safety audit of all Python files under src/tracevault/cli/."""

    def test_cli_module_has_zero_forbidden_imports_or_calls(self) -> None:
        py_files = sorted(CLI_SRC_ROOT.rglob("*.py"))
        assert py_files, f"Expected Python files under {CLI_SRC_ROOT}"

        violations: list[str] = []
        for path in py_files:
            source = path.read_text(encoding="utf-8")
            violations.extend(scan_cli_source_for_forbidden_ast(source, filename=str(path)))

        assert violations == [], "Forbidden AST constructs found in cli/:\n" + "\n".join(violations)

    @pytest.mark.parametrize(
        "snippet",
        [
            "eval('1 + 1')\n",
            "exec('x = 1')\n",
            "compile('1', '<x>', 'eval')\n",
            "__import__('os')\n",
            "import builtins\nbuiltins.eval('1')\n",
            "import pickle\n",
            "import marshal\n",
            "import shelve\n",
            "import os\nos.system('echo hi')\n",
            "import subprocess\n",
            "from subprocess import run\n",
            "import urllib.request\n",
            "from http.client import HTTPConnection\n",
            "import socket\n",
            "import httpx\n",
            "import requests\n",
        ],
    )
    def test_cli_ast_scanner_catches_forbidden_constructs(self, snippet: str) -> None:
        violations = scan_cli_source_for_forbidden_ast(snippet, filename="<synthetic>")
        assert violations, f"AST scanner missed forbidden snippet: {snippet!r}"


class TestCliZeroNetworkAccess:
    """Every CLI command must run 100% offline with socket.socket forbidden."""

    def test_all_cli_commands_make_zero_network_calls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _forbid_socket(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Network access is strictly forbidden during CLI execution")

        monkeypatch.setattr(socket, "socket", _forbid_socket)

        store_a = tmp_path / "store_a"
        store_b = tmp_path / "store_b"

        # 1. version
        res_ver = runner.invoke(app, ["version", "--json"])
        assert res_ver.exit_code == 0

        # 2. init
        res_init = runner.invoke(app, ["init", "-s", str(store_a)])
        assert res_init.exit_code == 0

        # Seed two traces into store_a
        with TraceStore(store_a) as store:
            store.init()
            with CaptureSession(
                "net_audit_agent",
                trace_id="tr_net_01",
                store=store,
                auto_save=True,
            ) as sess_1:
                with sess_1.span("llm_call", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
                    sess_1.record_model_call(
                        request={"provider": "openai", "model": "gpt-4o-mini", "messages": []},
                        response={"model": "gpt-4o-mini", "content": "ok", "finish_reason": "stop"},
                        name="openai.chat.completions",
                    )
                sess_1.set_outputs({"status": "ok"})
            t2 = make_valid_trace(trace_id="tr_net_02")
            store.save(t2)

        # 3. list
        res_list = runner.invoke(app, ["list", "-s", str(store_a)])
        assert res_list.exit_code == 0

        # 4. show
        res_show = runner.invoke(
            app,
            ["show", "tr_net_01", "-s", str(store_a), "--spans", "--events", "--fixtures"],
        )
        assert res_show.exit_code == 0

        # 5. inspect
        res_inspect = runner.invoke(app, ["inspect", "tr_net_01", "-s", str(store_a)])
        assert res_inspect.exit_code == 0

        # 6. freeze
        res_freeze = runner.invoke(app, ["freeze", "tr_net_01", "-s", str(store_a)])
        assert res_freeze.exit_code == 0

        # 7. replay
        res_replay = runner.invoke(
            app,
            [
                "replay",
                "tr_net_01",
                "-s",
                str(store_a),
                "--strict",
                "--fork",
                "--save",
                "--new-id",
                "tr_net_replayed",
            ],
        )
        assert res_replay.exit_code == 0

        # 8. diff
        res_diff = runner.invoke(app, ["diff", "tr_net_01", "tr_net_replayed", "-s", str(store_a)])
        assert res_diff.exit_code == 0

        # 9. export
        export_file = tmp_path / "exported_net.json"
        res_export = runner.invoke(
            app, ["export", "tr_net_01", "-s", str(store_a), "-o", str(export_file)]
        )
        assert res_export.exit_code == 0

        # 10. import
        res_import = runner.invoke(
            app, ["import", str(export_file), "-s", str(store_b), "--freeze"]
        )
        assert res_import.exit_code == 0

        # 11. export-test
        test_file = tmp_path / "test_net_reg.py"
        res_exp_test = runner.invoke(
            app,
            ["export-test", "tr_net_01", "-s", str(store_a), "-o", str(test_file)],
        )
        assert res_exp_test.exit_code == 0

        # 12. test
        res_test = runner.invoke(app, ["test", "tr_net_01", "-s", str(store_a)])
        assert res_test.exit_code == 0

        # 13. verify
        res_verify = runner.invoke(app, ["verify", "tr_net_01", "-s", str(store_b)])
        assert res_verify.exit_code == 0

        # 14. delete
        res_delete = runner.invoke(app, ["delete", "tr_net_02", "-s", str(store_a)])
        assert res_delete.exit_code == 0


class TestCliPathTraversalAndMalformedInputs:
    """Hostile trace IDs, path traversal attempts, and malformed JSON files via CLI."""

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../secret",
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "bad\x00id",
            ".",
            "..",
            "a/b",
            "a\\b",
            "_leading_underscore",
            "has spaces",
            "has.dot",
            "a" * 129,
        ],
    )
    def test_hostile_trace_ids_rejected_across_commands(self, tmp_path: Path, bad_id: str) -> None:
        store_dir = tmp_path / ".tracevault"
        runner.invoke(app, ["init", "-s", str(store_dir)])

        commands_to_check = [
            ["show", bad_id, "-s", str(store_dir), "--json"],
            ["inspect", bad_id, "-s", str(store_dir), "--json"],
            ["freeze", bad_id, "-s", str(store_dir), "--json"],
            ["delete", bad_id, "-s", str(store_dir), "--json"],
            ["replay", bad_id, "-s", str(store_dir), "--json"],
            ["diff", bad_id, "tr_valid_001", "-s", str(store_dir), "--json"],
            ["export", bad_id, "-s", str(store_dir), "-o", str(tmp_path / "out.json"), "--json"],
            [
                "export-test",
                bad_id,
                "-s",
                str(store_dir),
                "-o",
                str(tmp_path / "test_out.py"),
                "--json",
            ],
            ["test", bad_id, "-s", str(store_dir), "--json"],
            ["verify", bad_id, "-s", str(store_dir), "--json"],
        ]

        for cmd_args in commands_to_check:
            res = runner.invoke(app, cmd_args)
            assert res.exit_code == 1, f"Expected exit_code 1 for {cmd_args}, got {res.exit_code}"
            assert "Traceback (most recent call last)" not in res.output
            payload = json.loads(res.stdout)
            assert "error" in payload
            assert payload["error_type"] in {
                "InvalidTraceIdError",
                "TraceNotFoundError",
                "UnsafeTraceError",
            }

    def test_import_rejects_nonexistent_directory_malformed_oversized_nan_and_deep_json(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault"

        # 1. Nonexistent file
        missing_path = tmp_path / "does_not_exist.json"
        res_missing = runner.invoke(
            app, ["import", str(missing_path), "-s", str(store_dir), "--json"]
        )
        assert res_missing.exit_code == 1
        assert json.loads(res_missing.stdout)["error_type"] == "FileNotFoundError"

        # 2. Directory instead of file
        dir_path = tmp_path / "some_dir.json"
        dir_path.mkdir()
        res_dir = runner.invoke(app, ["import", str(dir_path), "-s", str(store_dir), "--json"])
        assert res_dir.exit_code == 1
        assert json.loads(res_dir.stdout)["error_type"] == "UnsafeTraceError"

        # 3. Malformed JSON
        malformed_path = tmp_path / "malformed.json"
        malformed_path.write_text("{unclosed: [1, 2", encoding="utf-8")
        res_malformed = runner.invoke(
            app, ["import", str(malformed_path), "-s", str(store_dir), "--json"]
        )
        assert res_malformed.exit_code == 1
        assert json.loads(res_malformed.stdout)["error_type"] == "UnsafeTraceError"

        # 4. NaN / Infinity JSON
        nan_path = tmp_path / "nan_trace.json"
        valid_dict = json.loads(make_valid_trace().to_json())
        raw_nan_json = json.dumps(valid_dict).replace('"category": "billing"', '"category": NaN')
        nan_path.write_text(raw_nan_json, encoding="utf-8")
        res_nan = runner.invoke(app, ["import", str(nan_path), "-s", str(store_dir), "--json"])
        assert res_nan.exit_code == 1
        assert json.loads(res_nan.stdout)["error_type"] == "UnsafeTraceError"

        # 5. Unknown extra field (extra="forbid")
        extra_path = tmp_path / "extra_field.json"
        extra_dict = json.loads(make_valid_trace().to_json())
        extra_dict["unexpected_hostile_field"] = "forbidden"
        extra_path.write_text(json.dumps(extra_dict), encoding="utf-8")
        res_extra = runner.invoke(app, ["import", str(extra_path), "-s", str(store_dir), "--json"])
        assert res_extra.exit_code == 1
        assert json.loads(res_extra.stdout)["error_type"] == "UnsafeTraceError"

        # 6. Excessive nesting depth
        deep_path = tmp_path / "deep_trace.json"
        deep_dict = json.loads(make_valid_trace().to_json())
        deep_dict["metadata"] = make_deeply_nested_dict(DEFAULT_MAX_JSON_DEPTH + 5)
        deep_path.write_text(json.dumps(deep_dict), encoding="utf-8")
        res_deep = runner.invoke(app, ["import", str(deep_path), "-s", str(store_dir), "--json"])
        assert res_deep.exit_code == 1
        assert json.loads(res_deep.stdout)["error_type"] == "UnsafeTraceError"

        # 7. Oversized file (> DEFAULT_MAX_TRACE_BYTES)
        oversized_path = tmp_path / "oversized.json"
        oversized_path.write_bytes(b"{" + b" " * (DEFAULT_MAX_TRACE_BYTES + 128) + b"}")
        res_oversized = runner.invoke(
            app, ["import", str(oversized_path), "-s", str(store_dir), "--json"]
        )
        assert res_oversized.exit_code == 1
        assert json.loads(res_oversized.stdout)["error_type"] == "UnsafeTraceError"


class TestCliRichMarkupInjectionResistance:
    """Rich markup tags in trace names, spans, tags, payloads, or errors must not crash CLI."""

    @pytest.mark.parametrize(
        "command_factory",
        [
            pytest.param(lambda s: ["list", "-s", s], id="list"),
            pytest.param(
                lambda s: [
                    "show",
                    "tr_markup_01",
                    "-s",
                    s,
                    "--spans",
                    "--events",
                    "--fixtures",
                    "--metadata",
                ],
                id="show",
            ),
            pytest.param(lambda s: ["inspect", "tr_markup_01", "-s", s], id="inspect"),
            pytest.param(lambda s: ["replay", "tr_markup_01", "-s", s], id="replay"),
            pytest.param(lambda s: ["diff", "tr_markup_01", "tr_markup_02", "-s", s], id="diff"),
        ],
    )
    @pytest.mark.parametrize(
        "markup_payload",
        [
            "[bold red]INJECTED[/bold red]",
            "[/bold]",
            "[/red][/]",
            "[link=https://evil.example]click_me[/link]",
            "[on red][bold]alert[/invalid_closing]",
        ],
    )
    def test_hostile_rich_markup_does_not_crash_cli_views(
        self,
        tmp_path: Path,
        command_factory: Any,
        markup_payload: str,
    ) -> None:
        store_dir = tmp_path / ".tracevault"

        err_obj = ExecutionError(
            error_type="HostileMarkupError",
            message=f"Failure caused by {markup_payload}",
        )
        run_1 = make_valid_run(
            run_id="run_markup_1",
            trace_id="tr_markup_01",
            name=f"run_{markup_payload}",
            status=RunStatus.FAILED,
            inputs={"prompt": markup_payload},
            outputs={"answer": markup_payload},
            error=err_obj,
            tags=[markup_payload, "security"],
            metadata={"note": markup_payload},
        )
        span_1 = make_valid_span(
            span_id="sp_markup_1",
            run_id="run_markup_1",
            name=f"span_{markup_payload}",
            status=SpanStatus.ERROR,
            error=err_obj,
            event_ids=["ev_markup_1", "ev_markup_2"],
        )
        req_payload = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": markup_payload}],
        }
        ev_1 = make_valid_event(
            event_id="ev_markup_1",
            run_id="run_markup_1",
            span_id="sp_markup_1",
            event_type=EventKind.MODEL_REQUEST,
            boundary=BoundaryType.MODEL,
            sequence=0,
            payload=req_payload,
        )
        ev_2 = make_valid_event(
            event_id="ev_markup_2",
            run_id="run_markup_1",
            span_id="sp_markup_1",
            event_type=EventKind.MODEL_RESPONSE,
            boundary=BoundaryType.MODEL,
            sequence=1,
            payload={"model": "gpt-4o-mini", "content": markup_payload, "finish_reason": "stop"},
        )
        fx_1 = make_valid_fixture_entry(
            fixture_id="fix_markup_1",
            boundary=BoundaryType.MODEL,
            request=req_payload,
            response={"model": "gpt-4o-mini", "content": markup_payload, "finish_reason": "stop"},
            span_id="sp_markup_1",
            name=f"fx_{markup_payload}",
        )
        trace_1 = make_valid_trace(
            trace_id="tr_markup_01",
            runs=[run_1],
            spans=[span_1],
            events=[ev_1, ev_2],
            fixtures=make_valid_fixture_set([fx_1]),
            metadata={"markup": markup_payload},
        )

        # Second trace with different output so diff renders divergences containing markup
        run_2 = run_1.model_copy(
            update={
                "trace_id": "tr_markup_02",
                "outputs": {"answer": f"changed_{markup_payload}"},
            }
        )
        trace_2 = trace_1.model_copy(update={"trace_id": "tr_markup_02", "runs": [run_2]})

        with TraceStore(store_dir) as store:
            store.init()
            store.save(trace_1)
            store.save(trace_2)

        cmd_args = command_factory(str(store_dir))
        res = runner.invoke(app, cmd_args)
        if cmd_args[0] == "diff":
            assert res.exit_code == 1
            assert "TraceVault Diff Report" in res.stdout
        else:
            assert res.exit_code == 0, (
                f"`tracevault {cmd_args[0]}` crashed on markup {markup_payload!r}: "
                f"{res.exception!r}"
            )
            assert res.exception is None

    def test_hostile_rich_markup_in_cli_error_message_does_not_crash_error_handler(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault"
        res = runner.invoke(
            app,
            ["list", "-s", str(store_dir), "--status", "[/bold red]bad_status"],
        )
        assert res.exit_code == 1
        assert not isinstance(res.exception, Exception) or isinstance(res.exception, SystemExit)


class TestCliSecretRedactionAudit:
    """Verify no unredacted secrets appear in CLI output or error messages."""

    def test_captured_trace_with_secrets_never_leaks_across_cli_commands(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault"
        raw_live_key = "sk-live-supersecret-99999999999999999999"
        all_secrets = [raw_live_key, *SYNTHETIC_SECRETS.values()]

        with TraceStore(store_dir) as store:
            store.init()
            with CaptureSession(
                "secret_cli_audit_agent",
                trace_id="tr_cli_sec_01",
                inputs={
                    "api_key": raw_live_key,
                    "prompt": f"Auth with {SYNTHETIC_SECRETS['openai_key']}",
                },
                metadata={
                    "authorization": SYNTHETIC_SECRETS["bearer_token"],
                    "github_token": SYNTHETIC_SECRETS["github_pat"],
                },
                environment={"OPENAI_API_KEY": SYNTHETIC_SECRETS["openai_proj_key"]},
                store=store,
                auto_save=True,
            ) as session:
                with session.span(
                    "llm_step", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL
                ):
                    session.record_model_call(
                        request={
                            "provider": "openai",
                            "model": "gpt-4o-mini",
                            "api_key": raw_live_key,
                            "messages": [
                                {
                                    "role": "user",
                                    "content": f"aws={SYNTHETIC_SECRETS['aws_access_key']}",
                                }
                            ],
                        },
                        response={
                            "model": "gpt-4o-mini",
                            "content": f"jwt={SYNTHETIC_SECRETS['jwt_token']}",
                            "finish_reason": "stop",
                        },
                        name="openai.chat.completions",
                    )
                session.set_outputs(
                    {
                        "client_secret": raw_live_key,
                        "summary": f"Completed with {SYNTHETIC_SECRETS['openai_key']}",
                    }
                )

        test_out = tmp_path / "test_sec_reg.py"
        commands = [
            ["list", "-s", str(store_dir)],
            ["list", "-s", str(store_dir), "--json"],
            [
                "show",
                "tr_cli_sec_01",
                "-s",
                str(store_dir),
                "--spans",
                "--events",
                "--fixtures",
                "--metadata",
            ],
            ["show", "tr_cli_sec_01", "-s", str(store_dir), "--json"],
            ["inspect", "tr_cli_sec_01", "-s", str(store_dir)],
            ["inspect", "tr_cli_sec_01", "-s", str(store_dir), "--json"],
            [
                "replay",
                "tr_cli_sec_01",
                "-s",
                str(store_dir),
                "--fork",
                "--save",
                "--new-id",
                "tr_cli_sec_02",
            ],
            ["diff", "tr_cli_sec_01", "tr_cli_sec_02", "-s", str(store_dir)],
            ["diff", "tr_cli_sec_01", "tr_cli_sec_02", "-s", str(store_dir), "--verbose"],
            ["diff", "tr_cli_sec_01", "tr_cli_sec_02", "-s", str(store_dir), "--json"],
            ["export-test", "tr_cli_sec_01", "-s", str(store_dir), "-o", str(test_out)],
            ["test", "tr_cli_sec_01", "-s", str(store_dir)],
            ["verify", "tr_cli_sec_01", "-s", str(store_dir)],
        ]

        for cmd in commands:
            res = runner.invoke(app, cmd)
            assert res.exit_code == 0, f"Command {cmd} failed: {res.output}"
            for secret in all_secrets:
                assert secret not in res.output, (
                    f"Secret {secret!r} leaked in `tracevault {cmd[0]}`"
                )

        generated_code = test_out.read_text(encoding="utf-8")
        for secret in all_secrets:
            assert secret not in generated_code, f"Secret {secret!r} leaked in generated test file"

    def test_unredacted_loaded_trace_and_error_messages_redact_secrets_in_cli(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault"
        raw_secret = "sk-live-leaked-in-error-1234567890123456"

        # Construct a manually unredacted trace saved directly to store
        unredacted_run = make_valid_run(
            trace_id="tr_raw_unredacted",
            status=RunStatus.FAILED,
            inputs={"api_key": raw_secret},
            outputs={"token": SYNTHETIC_SECRETS["bearer_token"]},
            error=ExecutionError(
                error_type="AuthError",
                message=f"Rejected key {raw_secret} and {SYNTHETIC_SECRETS['github_pat']}",
            ),
            metadata={"aws_key": SYNTHETIC_SECRETS["aws_access_key"]},
        )
        unredacted_trace = make_valid_trace(
            trace_id="tr_raw_unredacted",
            runs=[unredacted_run],
            redaction_applied=False,
        )
        with TraceStore(store_dir) as store:
            store.init()
            store.save(unredacted_trace)

        # Rich show/inspect redacts inputs, outputs, metadata, and error message on display
        res_inspect = runner.invoke(app, ["inspect", "tr_raw_unredacted", "-s", str(store_dir)])
        assert res_inspect.exit_code == 0
        assert raw_secret not in res_inspect.output
        assert SYNTHETIC_SECRETS["bearer_token"] not in res_inspect.output
        assert SYNTHETIC_SECRETS["github_pat"] not in res_inspect.output
        assert SYNTHETIC_SECRETS["aws_access_key"] not in res_inspect.output

        # `verify` fails with exit 1 on unredacted trace and must NOT leak the raw secret
        for extra_flags in ([], ["--json"]):
            res_verify = runner.invoke(
                app, ["verify", "tr_raw_unredacted", "-s", str(store_dir), *extra_flags]
            )
            assert res_verify.exit_code == 1
            assert raw_secret not in res_verify.output

        # Error message when passing a secret inside an invalid CLI option (--override / --status)
        res_bad_override = runner.invoke(
            app,
            [
                "replay",
                "tr_raw_unredacted",
                "-s",
                str(store_dir),
                "--override",
                f"bad_override_with_{raw_secret}",
            ],
        )
        assert res_bad_override.exit_code == 1
        assert raw_secret not in res_bad_override.output
        assert "[REDACTED]" in res_bad_override.output

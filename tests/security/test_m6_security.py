"""Adversarial security, static AST, secret-redaction, and code-injection tests for M6."""

from __future__ import annotations

import ast
import importlib.util
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    SYNTHETIC_SECRETS,
    make_utc_timestamp,
    make_valid_event,
    make_valid_fixture_entry,
    make_valid_fixture_set,
    make_valid_run,
    make_valid_span,
    make_valid_trace,
)
from tracevault.assertions import (
    assert_diff_matches_expectations,
    assert_error_recorded,
    assert_model_output,
    assert_no_breaking_diffs,
    assert_no_errors,
    assert_no_secrets_leaked,
    assert_replay_clean,
    assert_replay_succeeded,
    assert_run_output,
    assert_run_succeeded,
    assert_tool_output,
    assert_trace_valid,
    assert_traces_equivalent,
    expect_trace,
)
from tracevault.diff import diff_traces
from tracevault.pytest_plugin import load_regression_trace, verify_regression_trace
from tracevault.replay import (
    ReplayEngine,
    export_regression_fixture,
    generate_pytest_regression,
)
from tracevault.schema import (
    DEFAULT_MAX_TRACE_BYTES,
    REDACTED_VALUE,
    BoundaryType,
    DivergenceKind,
    DivergenceSeverity,
    EventKind,
    ExecutionError,
    ReplayMode,
    ReplayResult,
    RunStatus,
    SpanStatus,
    SpanType,
    TraceNotFoundError,
    UnsafeTraceError,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ASSERTIONS_SRC_ROOT = REPO_ROOT / "src" / "tracevault" / "assertions"
PYTEST_PLUGIN_SRC_ROOT = REPO_ROOT / "src" / "tracevault" / "pytest_plugin"
REGRESSION_SRC_FILE = REPO_ROOT / "src" / "tracevault" / "replay" / "regression.py"

FORBIDDEN_M6_MODULES: frozenset[str] = frozenset(
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
FORBIDDEN_M6_BUILTINS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset({"system", "popen"})


def scan_m6_source_for_forbidden_ast(source: str, filename: str = "<memory>") -> list[str]:
    """Audit Python source in M6 modules for forbidden imports and calls."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    os_aliases: set[str] = {"os"}
    builtins_aliases: set[str] = {"builtins"}
    banned_direct_names: set[str] = set(FORBIDDEN_M6_BUILTINS)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                local_name = alias.asname or root_mod
                if root_mod in FORBIDDEN_M6_MODULES:
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
            if root_mod in FORBIDDEN_M6_MODULES:
                violations.append(f"{filename}:{node.lineno}: forbidden import from '{mod}'")
            for alias in node.names:
                local_name = alias.asname or alias.name
                if mod == "os" and alias.name in FORBIDDEN_OS_FUNCS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import 'from os import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)
                elif mod == "builtins" and alias.name in FORBIDDEN_M6_BUILTINS:
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
                target in FORBIDDEN_M6_MODULES
                or (target in builtins_aliases and attr in FORBIDDEN_M6_BUILTINS)
                or (target in os_aliases and attr in FORBIDDEN_OS_FUNCS)
            ):
                violations.append(f"{filename}:{node.lineno}: forbidden call '{target}.{attr}()'")

    return violations


def _load_and_execute_generated_pytest_file(py_path: Path) -> None:
    """Import a generated pytest module dynamically and execute all test_* functions."""
    module_name = f"_generated_m6_test_{py_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, py_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        test_fns = [
            getattr(module, attr)
            for attr in dir(module)
            if attr.startswith("test_") and callable(getattr(module, attr))
        ]
        assert len(test_fns) == 1, f"Expected 1 test function in {py_path}, found {len(test_fns)}"
        test_fns[0]()
    finally:
        sys.modules.pop(module_name, None)


class TestM6StaticSafetyAudit:
    """AST static safety audit of assertions/, pytest_plugin/, and replay/regression.py."""

    def test_m6_modules_have_zero_forbidden_imports_or_calls(self) -> None:
        assertion_files = sorted(ASSERTIONS_SRC_ROOT.rglob("*.py"))
        plugin_files = sorted(PYTEST_PLUGIN_SRC_ROOT.rglob("*.py"))
        assert assertion_files, f"Expected Python files under {ASSERTIONS_SRC_ROOT}"
        assert plugin_files, f"Expected Python files under {PYTEST_PLUGIN_SRC_ROOT}"
        assert REGRESSION_SRC_FILE.is_file(), f"Missing {REGRESSION_SRC_FILE}"

        target_files = [*assertion_files, *plugin_files, REGRESSION_SRC_FILE]
        violations: list[str] = []
        for path in target_files:
            source = path.read_text(encoding="utf-8")
            violations.extend(scan_m6_source_for_forbidden_ast(source, filename=str(path)))

        assert violations == [], "Forbidden AST constructs found in M6 modules:\n" + "\n".join(
            violations
        )

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
            "import os\nos.system('echo pwned')\n",
            "import subprocess\n",
            "from subprocess import Popen\n",
            "import urllib.request\n",
            "import http.client\n",
            "import socket\n",
            "import httpx\n",
            "import requests\n",
        ],
    )
    def test_m6_ast_scanner_catches_forbidden_constructs(self, snippet: str) -> None:
        violations = scan_m6_source_for_forbidden_ast(snippet, filename="<synthetic>")
        assert violations, f"AST scanner missed forbidden snippet: {snippet!r}"


class TestM6ZeroNetworkAccess:
    """Assertions, fixture export, test generation, and regression runner must be 100% offline."""

    def test_zero_network_access_across_assertions_export_generation_and_runner(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _forbid_socket(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Network access is strictly forbidden during M6 operations")

        monkeypatch.setattr(socket, "socket", _forbid_socket)

        run_id = "run_off_001"
        span_id = "sp_off_001"
        req = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Classify invoice #42"}],
        }
        resp = {
            "model": "gpt-4o-mini",
            "content": "billing",
            "finish_reason": "stop",
        }
        trace = make_valid_trace(
            trace_id="tr_m6_offline_001",
            frozen=True,
            runs=[make_valid_run(run_id=run_id, trace_id="tr_m6_offline_001")],
            spans=[make_valid_span(span_id=span_id, run_id=run_id)],
            events=[
                make_valid_event(
                    event_id="ev_001",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_REQUEST,
                    boundary=BoundaryType.MODEL,
                    sequence=0,
                    payload=req,
                ),
                make_valid_event(
                    event_id="ev_002",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_RESPONSE,
                    boundary=BoundaryType.MODEL,
                    sequence=1,
                    payload=resp,
                ),
            ],
            fixtures=make_valid_fixture_set(
                [
                    make_valid_fixture_entry(
                        fixture_id="fix_001",
                        boundary=BoundaryType.MODEL,
                        request=req,
                        response=resp,
                        span_id=span_id,
                    )
                ]
            ),
        )

        assert_trace_valid(trace)
        assert_run_succeeded(trace)
        assert_run_output(trace, expected={"category": "billing"})
        assert_model_output(trace, contains_text="billing")
        assert_no_errors(trace)
        assert_no_secrets_leaked(trace)
        expect_trace(trace).is_valid().succeeded().has_no_errors().has_no_secrets_leaked()

        replay_result = ReplayEngine(trace).replay_trace()
        assert_replay_clean(replay_result)
        report = assert_traces_equivalent(trace, replay_result.candidate_trace)
        assert_no_breaking_diffs(report)
        assert_diff_matches_expectations(report, max_warnings=0)

        fixture_path = tmp_path / "offline_fixture.json"
        test_path = tmp_path / "test_offline_regression.py"

        exported = export_regression_fixture(trace, fixture_path)
        generated = generate_pytest_regression(trace, test_path, trace_path=exported)
        loaded = load_regression_trace(exported)
        verified_report = verify_regression_trace(exported)

        assert loaded.trace_id == trace.trace_id
        assert not verified_report.has_breaking
        _load_and_execute_generated_pytest_file(generated)


class TestM6SecretRedactionInAssertionDiagnostics:
    """AssertionError messages must never leak raw secrets even when inspecting unredacted data."""

    def test_all_assertion_failures_redact_secrets_in_diagnostic_messages(self) -> None:
        raw_sk = "sk-live-secret-token-1234567890abcdef"
        raw_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig99999"
        raw_api_key_val = "my-secret-value-99999999"
        all_secrets = [
            raw_sk,
            raw_bearer,
            raw_api_key_val,
            *SYNTHETIC_SECRETS.values(),
        ]

        secret_error = ExecutionError(
            error_type="UpstreamAuthError",
            message=f"Rejected token {raw_sk} and {raw_bearer}",
            traceback_summary=f"Header Authorization: {SYNTHETIC_SECRETS['jwt_token']}",
            details={
                "api_key": raw_api_key_val,
                "aws_key": SYNTHETIC_SECRETS["aws_access_key"],
            },
        )
        run_id = "run_sec_001"
        span_id = "sp_sec_001"
        trace_id = "tr_m6_secret_diag_001"

        events = [
            make_valid_event(
                event_id="ev_sec_001",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.TOOL_CALL,
                boundary=BoundaryType.TOOL,
                sequence=0,
                payload={
                    "tool_name": "charge_card",
                    "arguments": {"api_key": raw_api_key_val, "token": raw_sk},
                },
            ),
            make_valid_event(
                event_id="ev_sec_002",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.TOOL_RESULT,
                boundary=BoundaryType.TOOL,
                sequence=1,
                payload={
                    "tool_name": "charge_card",
                    "result": {
                        "api_key": raw_api_key_val,
                        "auth": raw_bearer,
                        "pat": SYNTHETIC_SECRETS["github_pat"],
                    },
                },
            ),
            make_valid_event(
                event_id="ev_sec_003",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.MODEL_RESPONSE,
                boundary=BoundaryType.MODEL,
                sequence=2,
                payload={
                    "model": "gpt-4o-mini",
                    "content": f"Leaked {raw_sk} and {SYNTHETIC_SECRETS['openai_proj_key']}",
                    "raw_metadata": {"api_key": raw_api_key_val},
                },
            ),
            make_valid_event(
                event_id="ev_sec_004",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.TOOL_ERROR,
                boundary=BoundaryType.TOOL,
                sequence=3,
                payload={"error": secret_error.model_dump(mode="json")},
            ),
        ]
        span = make_valid_span(
            span_id=span_id,
            run_id=run_id,
            span_type=SpanType.TOOL,
            boundary=BoundaryType.TOOL,
            name="charge_card",
            status=SpanStatus.ERROR,
            error=secret_error,
            event_ids=[ev.event_id for ev in events],
        )
        run = make_valid_run(
            run_id=run_id,
            trace_id=trace_id,
            status=RunStatus.FAILED,
            outputs={
                "api_key": raw_api_key_val,
                "secret_token": raw_sk,
                "authorization": raw_bearer,
            },
            error=secret_error,
        )
        fixture = make_valid_fixture_entry(
            fixture_id="fix_sec_001",
            boundary=BoundaryType.TOOL,
            request={"tool_name": "charge_card", "api_key": raw_api_key_val},
            response={"api_key": raw_api_key_val, "token": raw_sk},
            error=secret_error,
            span_id=span_id,
            name="charge_card",
        )
        unredacted_trace = make_valid_trace(
            trace_id=trace_id,
            runs=[run],
            spans=[span],
            events=events,
            fixtures=make_valid_fixture_set([fixture]),
            redaction_applied=False,
        )

        clean_trace = make_valid_trace(trace_id="tr_m6_clean_diag_001")
        failed_replay = ReplayResult(
            baseline_trace_id=trace_id,
            candidate_trace=unredacted_trace,
            mode=ReplayMode.OFFLINE_STRICT,
            matched_fixtures=0,
            success=False,
            error=secret_error,
        )
        diff_report = diff_traces(clean_trace, unredacted_trace)

        def _assert_message_scrubbed(exc_info: pytest.ExceptionInfo[AssertionError]) -> None:
            msg = str(exc_info.value)
            assert REDACTED_VALUE in msg
            for secret in all_secrets:
                assert secret not in msg, f"Raw secret {secret!r} leaked in AssertionError: {msg}"

        # 1. assert_run_output
        with pytest.raises(AssertionError) as exc_info:
            assert_run_output(unredacted_trace, expected={"api_key": "expected-clean"})
        _assert_message_scrubbed(exc_info)

        # 2. assert_tool_output
        with pytest.raises(AssertionError) as exc_info:
            assert_tool_output(
                unredacted_trace,
                "charge_card",
                expected_result={"status": "ok"},
            )
        _assert_message_scrubbed(exc_info)

        # 3. assert_model_output
        with pytest.raises(AssertionError) as exc_info:
            assert_model_output(
                unredacted_trace,
                contains_text=f"nonexistent_text_{raw_sk}",
            )
        _assert_message_scrubbed(exc_info)

        # 4. assert_error_recorded
        with pytest.raises(AssertionError) as exc_info:
            assert_error_recorded(
                unredacted_trace,
                error_type="NonExistentErrorType",
                message_contains=raw_sk,
            )
        _assert_message_scrubbed(exc_info)

        # 5. assert_no_errors
        with pytest.raises(AssertionError) as exc_info:
            assert_no_errors(unredacted_trace)
        _assert_message_scrubbed(exc_info)

        # 6. assert_replay_succeeded
        with pytest.raises(AssertionError) as exc_info:
            assert_replay_succeeded(failed_replay)
        _assert_message_scrubbed(exc_info)

        # 7. assert_traces_equivalent
        with pytest.raises(AssertionError) as exc_info:
            assert_traces_equivalent(clean_trace, unredacted_trace)
        _assert_message_scrubbed(exc_info)

        # 8. assert_no_breaking_diffs
        with pytest.raises(AssertionError) as exc_info:
            assert_no_breaking_diffs(diff_report)
        _assert_message_scrubbed(exc_info)

        # 9. assert_diff_matches_expectations
        with pytest.raises(AssertionError) as exc_info:
            assert_diff_matches_expectations(
                diff_report,
                allowed_kinds={DivergenceKind.RETRIEVAL_CHANGED},
            )
        _assert_message_scrubbed(exc_info)

        warning_report = diff_report.model_copy(
            update={
                "divergences": [
                    d.model_copy(update={"severity": DivergenceSeverity.WARNING})
                    for d in diff_report.divergences
                ]
            }
        )
        with pytest.raises(AssertionError) as exc_info:
            assert_diff_matches_expectations(warning_report, max_warnings=0)
        _assert_message_scrubbed(exc_info)


class TestM6CodeInjectionAndPathTraversalDefenses:
    """Hostile payloads in trace fields and paths must never inject code or bypass validation."""

    def test_hostile_strings_in_trace_fields_produce_safe_ast_and_never_execute_code(
        self,
        tmp_path: Path,
    ) -> None:
        pwned_sentinel = tmp_path / "pwned_sentinel.txt"
        hostile_tool = (
            f'"; import pathlib; pathlib.Path({str(pwned_sentinel)!r}).write_text("pwned") #'
        )
        hostile_run_name = '"""\nraise SystemExit(1)\n"""'
        hostile_output_key = "key'\"\\`\r\n__import__('os').system('echo pwned')"
        hostile_output_val = (
            'line1\r\nline2\\backslash\\"quotes\'\'\'"""\u202eRTL_OVERRIDE\U0001f680 $(echo pwned)'
        )

        run_id = "run_inj_001"
        span_id = "sp_inj_001"
        trace_id = "tr_inj_001"
        tool_req = {
            "tool_name": hostile_tool,
            "arguments": {"cmd": hostile_output_val, "raw": hostile_run_name},
        }
        tool_res = {"output": hostile_output_val, hostile_output_key: "safe"}

        events = [
            make_valid_event(
                event_id="ev_inj_001",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.TOOL_CALL,
                boundary=BoundaryType.TOOL,
                timestamp=make_utc_timestamp(0.1),
                sequence=0,
                payload=tool_req,
            ),
            make_valid_event(
                event_id="ev_inj_002",
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.TOOL_RESULT,
                boundary=BoundaryType.TOOL,
                timestamp=make_utc_timestamp(0.2),
                sequence=1,
                payload=tool_res,
            ),
        ]
        span = make_valid_span(
            span_id=span_id,
            run_id=run_id,
            span_type=SpanType.TOOL,
            boundary=BoundaryType.TOOL,
            name=hostile_tool,
            event_ids=["ev_inj_001", "ev_inj_002"],
        )
        run = make_valid_run(
            run_id=run_id,
            trace_id=trace_id,
            name=hostile_run_name,
            inputs={"prompt": hostile_run_name, "nested": [hostile_output_val]},
            outputs={hostile_output_key: hostile_output_val},
            tags=[hostile_tool, " unicode_\u03b1\u03b2\u03b3 "],
        )
        fixture = make_valid_fixture_entry(
            fixture_id="fix_inj_001",
            boundary=BoundaryType.TOOL,
            request=tool_req,
            response=tool_res,
            span_id=span_id,
            name=hostile_tool,
        )
        hostile_trace = make_valid_trace(
            trace_id=trace_id,
            frozen=True,
            runs=[run],
            spans=[span],
            events=events,
            fixtures=make_valid_fixture_set([fixture]),
        )

        # Generate both inline and external-fixture pytest regression files
        inline_test_path = tmp_path / "test_hostile_inline.py"
        fixture_path = tmp_path / "hostile_fixture.json"
        external_test_path = tmp_path / "test_hostile_external.py"

        generate_pytest_regression(hostile_trace, inline_test_path)
        generate_pytest_regression(
            hostile_trace,
            external_test_path,
            trace_path=fixture_path,
        )

        for generated_py in (inline_test_path, external_test_path):
            source = generated_py.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(generated_py))
            assert scan_m6_source_for_forbidden_ast(source, filename=str(generated_py)) == []

            # Top-level statements in generated file must only be docstring, imports,
            # one constant assignment (_TRACE_JSON or _TRACE_PATH), and one FunctionDef
            top_fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
            assert len(top_fns) == 1
            for node in tree.body:
                assert isinstance(
                    node,
                    (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef),
                ), f"Unexpected top-level AST node in generated test: {type(node).__name__}"

        bmp_hostile_val = 'line1\r\nline2\\backslash\\"quotes\'\'\'""" $(echo pwned)'
        bmp_req = {
            "tool_name": hostile_tool,
            "arguments": {"cmd": bmp_hostile_val, "raw": hostile_run_name},
        }
        bmp_res = {"output": bmp_hostile_val, hostile_output_key: "safe"}
        bmp_hostile_trace = make_valid_trace(
            trace_id="tr_inj_bmp_001",
            frozen=True,
            runs=[
                run.model_copy(
                    update={
                        "trace_id": "tr_inj_bmp_001",
                        "inputs": {"prompt": hostile_run_name},
                        "outputs": {hostile_output_key: bmp_hostile_val},
                    }
                )
            ],
            spans=[span],
            events=[
                events[0].model_copy(update={"payload": bmp_req}),
                events[1].model_copy(update={"payload": bmp_res}),
            ],
            fixtures=make_valid_fixture_set(
                [
                    make_valid_fixture_entry(
                        fixture_id="fix_inj_001",
                        boundary=BoundaryType.TOOL,
                        request=bmp_req,
                        response=bmp_res,
                        span_id=span_id,
                        name=hostile_tool,
                    )
                ]
            ),
        )
        bmp_inline_test = tmp_path / "test_hostile_bmp_inline.py"
        bmp_ext_test = tmp_path / "test_hostile_bmp_ext.py"
        bmp_ext_fix = tmp_path / "hostile_bmp_fixture.json"
        generate_pytest_regression(bmp_hostile_trace, bmp_inline_test)
        generate_pytest_regression(
            bmp_hostile_trace,
            bmp_ext_test,
            trace_path=bmp_ext_fix,
        )
        _load_and_execute_generated_pytest_file(bmp_inline_test)
        _load_and_execute_generated_pytest_file(bmp_ext_test)

        assert not pwned_sentinel.exists(), "Injected payload executed during test run!"

    def test_inline_generate_pytest_regression_handles_non_bmp_unicode_emojis(
        self,
        tmp_path: Path,
    ) -> None:
        """Inline generated pytest test must execute without UnicodeEncodeError on non-BMP chars."""
        run_id = "run_emoji_001"
        span_id = "sp_emoji_001"
        req = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Launch \U0001f680"}],
        }
        resp = {
            "model": "gpt-4o-mini",
            "content": "Launched \U0001f680",
            "finish_reason": "stop",
        }
        emoji_trace = make_valid_trace(
            trace_id="tr_emoji_inline_001",
            runs=[
                make_valid_run(
                    run_id=run_id,
                    trace_id="tr_emoji_inline_001",
                    outputs={"message": "Rocket launch \U0001f680 successful"},
                )
            ],
            spans=[make_valid_span(span_id=span_id, run_id=run_id)],
            events=[
                make_valid_event(
                    event_id="ev_001",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_REQUEST,
                    boundary=BoundaryType.MODEL,
                    sequence=0,
                    payload=req,
                ),
                make_valid_event(
                    event_id="ev_002",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_RESPONSE,
                    boundary=BoundaryType.MODEL,
                    sequence=1,
                    payload=resp,
                ),
            ],
            fixtures=make_valid_fixture_set(
                [
                    make_valid_fixture_entry(
                        fixture_id="fix_001",
                        boundary=BoundaryType.MODEL,
                        request=req,
                        response=resp,
                        span_id=span_id,
                    )
                ]
            ),
        )
        inline_py = tmp_path / "test_emoji_inline.py"
        generate_pytest_regression(emoji_trace, inline_py)
        _load_and_execute_generated_pytest_file(inline_py)

    def test_export_and_generate_scrub_secrets_on_manually_constructed_unredacted_trace(
        self,
        tmp_path: Path,
    ) -> None:
        raw_sk = "sk-live-secret-token-1234567890abcdef"
        raw_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig99999"
        raw_api_key_val = "my-secret-value-99999999"
        all_secrets = [
            raw_sk,
            raw_bearer,
            raw_api_key_val,
            *SYNTHETIC_SECRETS.values(),
        ]

        req_with_secret = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": raw_api_key_val,
            "messages": [{"role": "user", "content": f"Token {raw_sk}"}],
        }
        resp_with_secret = {
            "model": "gpt-4o-mini",
            "content": f"Auth={raw_bearer} AWS={SYNTHETIC_SECRETS['aws_access_key']}",
            "finish_reason": "stop",
        }
        run_id = "run_unred_001"
        span_id = "sp_unred_001"
        trace_id = "tr_unred_001"

        unredacted_trace = make_valid_trace(
            trace_id=trace_id,
            runs=[
                make_valid_run(
                    run_id=run_id,
                    trace_id=trace_id,
                    inputs={"api_key": raw_api_key_val, "gh": SYNTHETIC_SECRETS["github_pat"]},
                    outputs={"jwt": SYNTHETIC_SECRETS["jwt_token"], "sk": raw_sk},
                )
            ],
            spans=[make_valid_span(span_id=span_id, run_id=run_id)],
            events=[
                make_valid_event(
                    event_id="ev_001",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_REQUEST,
                    boundary=BoundaryType.MODEL,
                    sequence=0,
                    payload=req_with_secret,
                ),
                make_valid_event(
                    event_id="ev_002",
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_RESPONSE,
                    boundary=BoundaryType.MODEL,
                    sequence=1,
                    payload=resp_with_secret,
                ),
            ],
            fixtures=make_valid_fixture_set(
                [
                    make_valid_fixture_entry(
                        fixture_id="fix_001",
                        boundary=BoundaryType.MODEL,
                        request=req_with_secret,
                        response=resp_with_secret,
                        span_id=span_id,
                    )
                ]
            ),
            redaction_applied=False,
        )

        fixture_out = tmp_path / "scrubbed_fixture.json"
        inline_py_out = tmp_path / "test_scrubbed_inline.py"
        ext_py_out = tmp_path / "test_scrubbed_ext.py"

        export_regression_fixture(unredacted_trace, fixture_out)
        generate_pytest_regression(unredacted_trace, inline_py_out)
        generate_pytest_regression(unredacted_trace, ext_py_out, trace_path=fixture_out)

        for path in (fixture_out, inline_py_out, ext_py_out):
            text = path.read_text(encoding="utf-8")
            for secret in all_secrets:
                assert secret not in text, f"Secret {secret!r} leaked into exported file {path}"

        # Furthermore, the scrubbed fixture must have synchronized fingerprints
        loaded_scrubbed = load_regression_trace(fixture_out)
        assert_no_secrets_leaked(loaded_scrubbed)
        report = verify_regression_trace(fixture_out)
        assert not report.has_breaking
        _load_and_execute_generated_pytest_file(inline_py_out)
        _load_and_execute_generated_pytest_file(ext_py_out)

    def test_invalid_extensions_nul_bytes_missing_and_oversized_files_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        trace = make_valid_trace(trace_id="tr_path_sec_001")

        # 1. Invalid extensions for export_regression_fixture & generate_pytest_regression
        for bad_fixture_ext in ("fixture.txt", "fixture.py", "fixture.jsonl", "fixture"):
            with pytest.raises(UnsafeTraceError):
                export_regression_fixture(trace, tmp_path / bad_fixture_ext)
            with pytest.raises(UnsafeTraceError):
                generate_pytest_regression(
                    trace,
                    tmp_path / "test_valid.py",
                    trace_path=tmp_path / bad_fixture_ext,
                )

        for bad_py_ext in ("test_out.json", "test_out.txt", "test_out.pyc", "test_out"):
            with pytest.raises(UnsafeTraceError):
                generate_pytest_regression(trace, tmp_path / bad_py_ext)

        # 2. NUL bytes and empty paths
        for nul_path in ("", "   ", f"{tmp_path}/evil\x00.json", "trace\x00.json"):
            with pytest.raises(UnsafeTraceError):
                export_regression_fixture(trace, nul_path)
            with pytest.raises(UnsafeTraceError):
                load_regression_trace(nul_path)
            with pytest.raises(UnsafeTraceError):
                verify_regression_trace(nul_path)

        with pytest.raises(UnsafeTraceError):
            generate_pytest_regression(trace, f"{tmp_path}/evil\x00.py")

        # 3. Directory target instead of file
        dir_with_json_suffix = tmp_path / "subdir.json"
        dir_with_json_suffix.mkdir()
        with pytest.raises(UnsafeTraceError):
            export_regression_fixture(trace, dir_with_json_suffix)
        with pytest.raises(TraceNotFoundError):
            load_regression_trace(dir_with_json_suffix)

        dir_with_py_suffix = tmp_path / "subdir.py"
        dir_with_py_suffix.mkdir()
        with pytest.raises(UnsafeTraceError):
            generate_pytest_regression(trace, dir_with_py_suffix)

        # 4. Non-.json extension or missing file in load_regression_trace
        txt_file = tmp_path / "not_json.txt"
        txt_file.write_text("{}", encoding="utf-8")
        with pytest.raises(UnsafeTraceError):
            load_regression_trace(txt_file)

        missing_json = tmp_path / "does_not_exist.json"
        with pytest.raises(TraceNotFoundError):
            load_regression_trace(missing_json)

        # 5. Oversized file rejected before parsing in load_regression_trace
        valid_json_path = tmp_path / "oversized.json"
        export_regression_fixture(trace, valid_json_path)
        monkeypatch.setattr(
            "tracevault.pytest_plugin.plugin.DEFAULT_MAX_TRACE_BYTES",
            10,
        )
        assert DEFAULT_MAX_TRACE_BYTES > 10
        with pytest.raises(UnsafeTraceError, match="exceeds maximum allowed"):
            load_regression_trace(valid_json_path)

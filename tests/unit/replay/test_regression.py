"""Unit tests for export_regression_fixture and generate_pytest_regression."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tracevault.capture import capture
from tracevault.replay import export_regression_fixture, generate_pytest_regression
from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    SpanType,
    Trace,
    UnsafeTraceError,
)


def _load_generated_module(py_path: Path, module_name: str = "_generated_test_mod") -> ModuleType:
    """Dynamically load a generated test file via importlib without exec/eval."""
    spec = importlib.util.spec_from_file_location(module_name, py_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_generated_test_functions(py_path: Path) -> int:
    """Load a generated test module and invoke every test_* function in it."""
    module = _load_generated_module(py_path)
    executed = 0
    for attr_name in dir(module):
        if attr_name.startswith("test_"):
            fn = getattr(module, attr_name)
            if callable(fn):
                fn()
                executed += 1
    return executed


def _build_workflow_trace() -> Trace:
    with capture("billing_regression_workflow", inputs={"invoice_id": 42}) as sess:
        with sess.span("classify", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL):
            sess.record_model_call(
                {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Invoice 42"}]},
                {"content": "lookup_needed", "finish_reason": "tool_calls"},
                name="openai.chat.completions",
            )
        with sess.span("lookup", span_type=SpanType.TOOL, boundary=BoundaryType.TOOL):
            sess.record_tool_call(
                "lookup_invoice",
                {"invoice_id": 42},
                result={"amount": 199, "currency": "USD"},
            )
        sess.set_outputs({"decision": "approve_refund", "amount": 199})
    assert sess.trace is not None
    return sess.trace


def test_export_regression_fixture_writes_valid_redacted_json(tmp_path: Path) -> None:
    raw_secret = "sk-secret-key-1234567890abcdef"
    with capture(
        "unredacted_run",
        inputs={"api_key": raw_secret, "prompt": f"token={raw_secret}"},
        redact=False,
    ) as sess:
        sess.record_model_call(
            {"model": "gpt-4o-mini", "authorization": f"Bearer {raw_secret}"},
            {"content": f"response with {raw_secret}"},
        )
        sess.set_outputs({"leaked": raw_secret})
    assert sess.trace is not None
    assert sess.trace.redaction_applied is False

    fixture_path = tmp_path / "fixtures" / "trace_fixture.json"
    written_path = export_regression_fixture(sess.trace, fixture_path)

    assert written_path == fixture_path.resolve()
    assert written_path.is_file()

    raw_json = written_path.read_text(encoding="utf-8")
    assert raw_secret not in raw_json
    assert REDACTED_VALUE in raw_json

    loaded = Trace.from_json(raw_json)
    assert loaded.trace_id == sess.trace.trace_id
    assert loaded.redaction_applied is True
    assert loaded.root_run.inputs["api_key"] == REDACTED_VALUE
    assert loaded.root_run.outputs == {"leaked": REDACTED_VALUE}


def test_export_regression_fixture_validates_output_path(tmp_path: Path) -> None:
    trace = _build_workflow_trace()

    with pytest.raises(UnsafeTraceError, match="NUL bytes"):
        export_regression_fixture(trace, tmp_path / "bad\x00file.json")

    with pytest.raises(UnsafeTraceError, match=r"\.json"):
        export_regression_fixture(trace, tmp_path / "not_json.txt")

    with pytest.raises(UnsafeTraceError, match="directory"):
        export_regression_fixture(trace, tmp_path)


def test_generate_pytest_regression_inline_executes_and_passes_offline(tmp_path: Path) -> None:
    trace = _build_workflow_trace()
    test_file = tmp_path / "test_inline_regression.py"

    out_path = generate_pytest_regression(trace, test_file)
    assert out_path == test_file.resolve()
    assert out_path.is_file()

    source = out_path.read_text(encoding="utf-8")
    ast.parse(source)
    assert "_TRACE_JSON =" in source
    assert "lookup_invoice" in source

    count = _run_generated_test_functions(out_path)
    assert count == 1


def test_generate_pytest_regression_with_external_trace_path_executes_offline(
    tmp_path: Path,
) -> None:
    trace = _build_workflow_trace()
    test_file = tmp_path / "suite" / "test_external_regression.py"
    fixture_file = tmp_path / "suite" / "fixtures" / "billing_trace.json"

    assert not fixture_file.exists()
    out_path = generate_pytest_regression(trace, test_file, trace_path=fixture_file)

    assert out_path == test_file.resolve()
    assert fixture_file.is_file()

    source = out_path.read_text(encoding="utf-8")
    ast.parse(source)
    assert "_TRACE_PATH =" in source

    count = _run_generated_test_functions(out_path)
    assert count == 1


def test_generate_pytest_regression_code_injection_resistance(tmp_path: Path) -> None:
    hostile_run_name = 'x"; raise RuntimeError("pwned_run_name") #\n"""triple"""\\slash'
    hostile_tool_name = 'tool"; import os; raise RuntimeError("pwned_tool") # """\n\\end'
    hostile_output_val = 'out\'); raise RuntimeError("pwned_output") #\r\n"""'

    with capture(hostile_run_name, inputs={"raw": hostile_output_val}) as sess:
        sess.record_tool_call(
            hostile_tool_name,
            {"arg": '"); raise RuntimeError("pwned_arg") #'},
            result={"res": '"""triple_quotes""" and \\backslashes\\'},
        )
        sess.set_outputs({" hostile_key \"'": hostile_output_val})
    assert sess.trace is not None

    test_file = tmp_path / "test_hostile_injection.py"
    out_path = generate_pytest_regression(sess.trace, test_file)

    source = out_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert tree is not None

    # Execute generated test: must succeed and NEVER execute any injected raise/import
    count = _run_generated_test_functions(out_path)
    assert count == 1


def test_generate_pytest_regression_scrubs_secrets_from_test_and_fixture(
    tmp_path: Path,
) -> None:
    raw_secret = "sk-secret-key-1234567890abcdef"
    with capture(
        "secret_regression_workflow",
        inputs={"secret_input": raw_secret},
        redact=False,
    ) as sess:
        sess.record_model_call(
            {"model": "gpt-4o", "prompt": f"use key {raw_secret}"},
            {"content": f"echo {raw_secret}"},
        )
        sess.record_tool_call(
            "secret_tool",
            {"api_key": raw_secret},
            result={"token": raw_secret},
        )
        sess.set_outputs({"final_token": raw_secret})
    assert sess.trace is not None

    inline_test = tmp_path / "test_secret_inline.py"
    generate_pytest_regression(sess.trace, inline_test)
    inline_source = inline_test.read_text(encoding="utf-8")
    assert raw_secret not in inline_source
    assert REDACTED_VALUE in inline_source
    assert _run_generated_test_functions(inline_test) == 1

    ext_test = tmp_path / "test_secret_external.py"
    ext_fixture = tmp_path / "secret_fixture.json"
    generate_pytest_regression(sess.trace, ext_test, trace_path=ext_fixture)
    assert raw_secret not in ext_test.read_text(encoding="utf-8")
    assert raw_secret not in ext_fixture.read_text(encoding="utf-8")
    assert _run_generated_test_functions(ext_test) == 1


def test_generate_pytest_regression_optional_assertion_flags(tmp_path: Path) -> None:
    trace = _build_workflow_trace()
    test_file = tmp_path / "test_minimal_assertions.py"

    out_path = generate_pytest_regression(
        trace,
        test_file,
        include_tool_assertions=False,
        include_status_assertion=False,
        include_output_assertion=False,
    )
    source = out_path.read_text(encoding="utf-8")
    assert "matched_tools" not in source
    assert "root_run.status.value" not in source
    assert "root_run.outputs" not in source
    assert "import json" not in source
    assert "BoundaryType" not in source
    assert _run_generated_test_functions(out_path) == 1


def test_generated_pytest_file_passes_ruff_check(tmp_path: Path) -> None:
    trace = _build_workflow_trace()
    inline_file = tmp_path / "test_ruff_inline.py"
    ext_file = tmp_path / "test_ruff_external.py"
    fixture_file = tmp_path / "ruff_fixture.json"

    generate_pytest_regression(trace, inline_file)
    generate_pytest_regression(trace, ext_file, trace_path=fixture_file)

    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "ruff", "check", str(inline_file), str(ext_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Ruff check failed:\n{proc.stdout}\n{proc.stderr}"

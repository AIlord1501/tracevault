"""Adversarial security, static AST, immutability, secret-handling, and property tests for diff."""

from __future__ import annotations

import ast
import io
import socket
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from rich.console import Console

from conftest import (
    SYNTHETIC_SECRETS,
    make_deeply_nested_dict,
    make_utc_timestamp,
    make_valid_event,
    make_valid_fixture_entry,
    make_valid_fixture_set,
    make_valid_run,
    make_valid_span,
    make_valid_trace,
)
from tracevault.capture import CaptureSession
from tracevault.diff import (
    diff_traces,
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)
from tracevault.schema import (
    DEFAULT_MAX_JSON_DEPTH,
    BoundaryType,
    DiffConfig,
    DivergenceSeverity,
    EventKind,
    RunStatus,
    SpanStatus,
    SpanType,
    Trace,
)

DIFF_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "tracevault" / "diff"

FORBIDDEN_DIFF_MODULES: frozenset[str] = frozenset(
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
FORBIDDEN_DIFF_BUILTINS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset({"system", "popen"})


def scan_diff_source_for_forbidden_ast(source: str, filename: str = "<memory>") -> list[str]:
    """Audit Python source in src/tracevault/diff/ for forbidden imports and calls."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    os_aliases: set[str] = {"os"}
    builtins_aliases: set[str] = {"builtins"}
    banned_direct_names: set[str] = set(FORBIDDEN_DIFF_BUILTINS)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                local_name = alias.asname or root_mod
                if root_mod in FORBIDDEN_DIFF_MODULES:
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
            if root_mod in FORBIDDEN_DIFF_MODULES:
                violations.append(f"{filename}:{node.lineno}: forbidden import from '{mod}'")
            for alias in node.names:
                local_name = alias.asname or alias.name
                if mod == "os" and alias.name in FORBIDDEN_OS_FUNCS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import 'from os import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)
                elif mod == "builtins" and alias.name in FORBIDDEN_DIFF_BUILTINS:
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
                target in FORBIDDEN_DIFF_MODULES
                or (target in builtins_aliases and attr in FORBIDDEN_DIFF_BUILTINS)
                or (target in os_aliases and attr in FORBIDDEN_OS_FUNCS)
            ):
                violations.append(f"{filename}:{node.lineno}: forbidden call '{target}.{attr}()'")

    return violations


class TestDiffStaticSafetyAudit:
    """AST static safety audit of all Python files under src/tracevault/diff/."""

    def test_diff_module_has_zero_forbidden_imports_or_calls(self) -> None:
        py_files = sorted(DIFF_SRC_ROOT.rglob("*.py"))
        assert py_files, f"Expected Python files under {DIFF_SRC_ROOT}"

        violations: list[str] = []
        for path in py_files:
            source = path.read_text(encoding="utf-8")
            violations.extend(scan_diff_source_for_forbidden_ast(source, filename=str(path)))

        assert violations == [], "Forbidden AST constructs found in diff/:\n" + "\n".join(
            violations
        )

    @pytest.mark.parametrize(
        "snippet",
        [
            "eval('1 + 1')\n",
            "exec('x = 1')\n",
            "compile('1', '<x>', 'eval')\n",
            "__import__('os')\n",
            "import builtins\nbuiltins.compile('1', '<x>', 'eval')\n",
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
    def test_diff_ast_scanner_catches_forbidden_constructs(self, snippet: str) -> None:
        violations = scan_diff_source_for_forbidden_ast(snippet, filename="<synthetic>")
        assert violations, f"AST scanner missed forbidden snippet: {snippet!r}"


class TestDiffZeroNetworkAccess:
    """Diffing and rendering must never touch sockets or perform network I/O."""

    def test_zero_network_access_during_diff_and_formatting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _forbid_socket(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Network access is strictly forbidden during diff operations")

        monkeypatch.setattr(socket, "socket", _forbid_socket)

        baseline = make_valid_trace(trace_id="tr_net_base_001")
        candidate = make_valid_trace(
            trace_id="tr_net_cand_001",
            runs=[
                make_valid_run(
                    trace_id="tr_net_cand_001",
                    status=RunStatus.FAILED,
                    outputs={"category": "escalation"},
                )
            ],
        )

        same_report = diff_traces(baseline, baseline)
        diff_report = diff_traces(baseline, candidate)

        assert same_report.identical is True
        assert diff_report.has_breaking is True

        for report in (same_report, diff_report):
            text_brief = format_diff_report(report, verbose=False)
            text_verbose = format_diff_report(report, verbose=True)
            json_out = format_diff_json(report)
            buf = io.StringIO()
            render_diff_rich(report, console=Console(file=buf, force_terminal=False, width=120))

            assert report.baseline_trace_id in text_brief
            assert report.baseline_trace_id in text_verbose
            assert report.baseline_trace_id in json_out
            assert report.baseline_trace_id in buf.getvalue()


class TestDiffHostileAndEdgeCaseInputs:
    """Deep nesting, large traces, regex metacharacters, and Rich markup injection."""

    def test_deeply_nested_json_diffs_without_recursion_error(self) -> None:
        depth = DEFAULT_MAX_JSON_DEPTH - 2
        base_nested = make_deeply_nested_dict(depth)
        cand_nested = make_deeply_nested_dict(depth)

        # Mutate the deepest leaf in candidate
        cursor: dict[str, Any] = cand_nested
        for _ in range(depth - 1):
            cursor = cursor["nested"]
        cursor["nested"] = "mutated_leaf"

        baseline = make_valid_trace(
            trace_id="tr_deep_base_001",
            runs=[make_valid_run(trace_id="tr_deep_base_001", outputs=base_nested)],
        )
        candidate = make_valid_trace(
            trace_id="tr_deep_cand_001",
            runs=[make_valid_run(trace_id="tr_deep_cand_001", outputs=cand_nested)],
        )

        report = diff_traces(baseline, candidate)
        assert report.identical is False
        assert report.has_breaking is True
        assert any(
            d.baseline == "leaf" and d.candidate == "mutated_leaf" for d in report.divergences
        )

    def test_large_traces_diff_deterministically_and_quickly(self) -> None:
        num_spans = 150

        def _build_large_trace(trace_id: str, *, flip_last: bool = False) -> Trace:
            run = make_valid_run(trace_id=trace_id, outputs={"count": num_spans})
            spans = []
            events = []
            fixtures = []
            for idx in range(num_spans):
                sp_id = f"sp_{idx:04d}"
                ev_req_id = f"ev_{idx:04d}_req"
                ev_res_id = f"ev_{idx:04d}_res"
                spans.append(
                    make_valid_span(
                        span_id=sp_id,
                        run_id=run.run_id,
                        span_type=SpanType.TOOL,
                        boundary=BoundaryType.TOOL,
                        name=f"tool_step_{idx:04d}",
                        started_at=make_utc_timestamp(idx * 0.01),
                        ended_at=make_utc_timestamp(idx * 0.01 + 0.005),
                        event_ids=[ev_req_id, ev_res_id],
                    )
                )
                result_val = "CHANGED" if (flip_last and idx == num_spans - 1) else f"ok_{idx}"
                events.append(
                    make_valid_event(
                        event_id=ev_req_id,
                        run_id=run.run_id,
                        span_id=sp_id,
                        event_type=EventKind.TOOL_CALL,
                        boundary=BoundaryType.TOOL,
                        timestamp=make_utc_timestamp(idx * 0.01),
                        sequence=idx * 2,
                        payload={"tool_name": f"tool_{idx}", "arguments": {"i": idx}},
                    )
                )
                events.append(
                    make_valid_event(
                        event_id=ev_res_id,
                        run_id=run.run_id,
                        span_id=sp_id,
                        event_type=EventKind.TOOL_RESULT,
                        boundary=BoundaryType.TOOL,
                        timestamp=make_utc_timestamp(idx * 0.01 + 0.005),
                        sequence=idx * 2 + 1,
                        payload={"tool_name": f"tool_{idx}", "result": result_val},
                    )
                )
                fixtures.append(
                    make_valid_fixture_entry(
                        fixture_id=f"fix_{idx:04d}",
                        boundary=BoundaryType.TOOL,
                        request={"tool_name": f"tool_{idx}", "arguments": {"i": idx}},
                        response={"result": result_val},
                        span_id=sp_id,
                        name=f"tool_{idx}",
                    )
                )
            return make_valid_trace(
                trace_id=trace_id,
                runs=[run],
                spans=spans,
                events=events,
                fixtures=make_valid_fixture_set(fixtures),
            )

        base_large = _build_large_trace("tr_large_base_001", flip_last=False)
        cand_large = _build_large_trace("tr_large_cand_001", flip_last=True)

        t0 = time.perf_counter()
        report_1 = diff_traces(base_large, cand_large)
        elapsed = time.perf_counter() - t0
        report_2 = diff_traces(base_large, cand_large)

        assert elapsed < 5.0, f"Large trace diff took too long: {elapsed:.2f}s"
        assert report_1.model_dump_json() == report_2.model_dump_json()
        assert report_1.has_breaking is True

    def test_hostile_regex_metacharacters_in_ignore_paths_no_redos_or_error(self) -> None:
        baseline = make_valid_trace(
            trace_id="tr_regex_base_001",
            runs=[
                make_valid_run(
                    trace_id="tr_regex_base_001",
                    outputs={"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!": "v1", "normal": 1},
                )
            ],
        )
        candidate = make_valid_trace(
            trace_id="tr_regex_cand_001",
            runs=[
                make_valid_run(
                    trace_id="tr_regex_cand_001",
                    outputs={"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!": "v2", "normal": 2},
                )
            ],
        )

        hostile_ignore_paths = {
            "runs[0].outputs.(a+)+$",
            "events[*].payload.[invalid",
            "spans[0].name.(?P<unclosed",
            "runs[0].outputs.\\1\\2\\3",
            "runs[0].outputs.(((a+)+)+)+$",
        }

        t0 = time.perf_counter()
        report = diff_traces(baseline, candidate, ignore_paths=hostile_ignore_paths)
        elapsed = time.perf_counter() - t0

        assert elapsed < 2.0, f"Potential ReDoS in ignore_paths matching: {elapsed:.2f}s"
        assert report.identical is False
        assert report.has_breaking is True

    @pytest.mark.parametrize(
        "markup_payload",
        [
            "[bold red]INJECTED[/bold red]",
            "[link=https://evil.example]click[/link]",
            "[/bold]",
            "[/red][/]",
        ],
    )
    def test_rich_markup_injection_strings_do_not_crash_render_diff_rich(
        self, markup_payload: str
    ) -> None:
        baseline = make_valid_trace(
            trace_id="tr_markup_base_001",
            runs=[
                make_valid_run(
                    trace_id="tr_markup_base_001",
                    name=f"agent_{markup_payload}",
                    outputs={markup_payload: "old"},
                )
            ],
        )
        candidate = make_valid_trace(
            trace_id="tr_markup_cand_001",
            runs=[
                make_valid_run(
                    trace_id="tr_markup_cand_001",
                    name=f"agent_{markup_payload}",
                    outputs={markup_payload: markup_payload},
                )
            ],
        )

        report = diff_traces(baseline, candidate)
        assert report.has_breaking is True

        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=160)
        render_diff_rich(report, console=console)
        rendered = buf.getvalue()
        assert "TraceVault Diff Report" in rendered


class TestDiffSecretHandling:
    """Redacted traces captured via CaptureSession never leak raw secrets in diff outputs."""

    def test_redacted_traces_never_leak_secrets_in_report_or_formatters(self) -> None:
        raw_secret = "sk-live-secret-1234567890"
        all_secrets = [raw_secret, *SYNTHETIC_SECRETS.values()]

        with CaptureSession(
            "secret_diff_workflow",
            trace_id="tr_sec_diff_base",
            inputs={"api_key": raw_secret, "prompt": f"Use {SYNTHETIC_SECRETS['openai_key']}"},
            metadata={"authorization": SYNTHETIC_SECRETS["bearer_token"]},
        ) as base_session:
            with base_session.span(
                "llm_call", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL
            ):
                base_session.record_model_call(
                    request={
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                        "api_key": raw_secret,
                        "messages": [
                            {
                                "role": "user",
                                "content": f"key={SYNTHETIC_SECRETS['aws_access_key']}",
                            }
                        ],
                    },
                    response={
                        "content": (
                            f"result with {raw_secret} and {SYNTHETIC_SECRETS['github_pat']}"
                        ),
                        "finish_reason": "stop",
                    },
                    name="llm_call",
                )
            base_session.set_outputs(
                {
                    "token": SYNTHETIC_SECRETS["jwt_token"],
                    "answer": f"baseline {raw_secret}",
                }
            )

        with CaptureSession(
            "secret_diff_workflow",
            trace_id="tr_sec_diff_cand",
            inputs={"api_key": raw_secret, "prompt": f"Use {SYNTHETIC_SECRETS['openai_key']}"},
            metadata={"authorization": SYNTHETIC_SECRETS["bearer_token"]},
        ) as cand_session:
            with cand_session.span(
                "llm_call", span_type=SpanType.MODEL, boundary=BoundaryType.MODEL
            ):
                cand_session.record_model_call(
                    request={
                        "provider": "openai",
                        "model": "gpt-4o-mini",
                        "api_key": raw_secret,
                        "messages": [
                            {
                                "role": "user",
                                "content": f"key={SYNTHETIC_SECRETS['aws_access_key']}",
                            }
                        ],
                    },
                    response={
                        "content": f"changed result with {raw_secret}",
                        "finish_reason": "stop",
                    },
                    name="llm_call",
                )
            cand_session.set_outputs(
                {
                    "token": SYNTHETIC_SECRETS["jwt_token"],
                    "answer": f"candidate changed {raw_secret}",
                }
            )

        assert base_session.trace is not None
        assert cand_session.trace is not None

        report = diff_traces(
            base_session.trace,
            cand_session.trace,
            config=DiffConfig(compare_metadata=True),
        )
        assert report.has_breaking is True

        report_dump = report.model_dump_json()
        text_verbose = format_diff_report(report, verbose=True)
        json_out = format_diff_json(report)
        buf = io.StringIO()
        render_diff_rich(report, console=Console(file=buf, force_terminal=False, width=160))
        rich_out = buf.getvalue()

        for secret in all_secrets:
            assert secret not in report_dump, f"Secret leaked in DiffReport: {secret!r}"
            assert secret not in text_verbose, f"Secret leaked in format_diff_report: {secret!r}"
            assert secret not in json_out, f"Secret leaked in format_diff_json: {secret!r}"
            assert secret not in rich_out, f"Secret leaked in render_diff_rich: {secret!r}"


class TestDiffImmutability:
    """diff_traces must never mutate baseline, candidate, config, or ignore_paths."""

    def test_diff_traces_does_not_mutate_inputs(self) -> None:
        baseline = make_valid_trace(
            trace_id="tr_immut_base_001",
            runs=[make_valid_run(trace_id="tr_immut_base_001", outputs={"a": {"b": [1, 2]}})],
        )
        candidate = make_valid_trace(
            trace_id="tr_immut_cand_001",
            runs=[make_valid_run(trace_id="tr_immut_cand_001", outputs={"a": {"b": [1, 99]}})],
        )
        config = DiffConfig(ignore_paths={"runs[0].inputs"}, compare_metadata=True)
        ignore_paths = {"metadata.trace_noise"}

        base_before = baseline.to_json()
        cand_before = candidate.to_json()
        config_before = config.model_dump()
        ignore_before = set(ignore_paths)

        report = diff_traces(baseline, candidate, config=config, ignore_paths=ignore_paths)
        assert report.has_breaking is True

        # Mutate returned divergence payloads if dict/list to ensure defensive copies
        for div in report.divergences:
            if isinstance(div.baseline, dict):
                div.baseline["__tampered__"] = True
            if isinstance(div.candidate, dict):
                div.candidate["__tampered__"] = True

        assert baseline.to_json() == base_before
        assert candidate.to_json() == cand_before
        assert config.model_dump() == config_before
        assert ignore_paths == ignore_before


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------

_SAFE_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126),
    min_size=1,
    max_size=24,
)
_SAFE_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    _SAFE_TEXT,
)
_SAFE_DICT = st.dictionaries(keys=_SAFE_TEXT, values=_SAFE_SCALAR, max_size=4)


@st.composite
def _trace_strategy(draw: st.DrawFn, *, prefix: str = "tr_hyp") -> Trace:
    suffix = draw(st.integers(min_value=1, max_value=99999))
    trace_id = f"{prefix}_{suffix}"
    run_status = draw(st.sampled_from(list(RunStatus)))
    outputs = draw(_SAFE_DICT)
    span_count = draw(st.integers(min_value=0, max_value=4))

    run = make_valid_run(
        run_id=f"run_{suffix}",
        trace_id=trace_id,
        status=run_status,
        outputs=outputs,
    )
    spans = []
    events = []
    fixtures = []
    for idx in range(span_count):
        sp_id = f"sp_{suffix}_{idx}"
        ev_id = f"ev_{suffix}_{idx}"
        sp_status = draw(st.sampled_from(list(SpanStatus)))
        sp_name = draw(st.sampled_from(["step_alpha", "step_beta", "step_gamma"]))
        payload_val = draw(_SAFE_SCALAR)
        spans.append(
            make_valid_span(
                span_id=sp_id,
                run_id=run.run_id,
                span_type=SpanType.TOOL,
                boundary=BoundaryType.TOOL,
                name=sp_name,
                status=sp_status,
                started_at=make_utc_timestamp(idx * 0.1),
                ended_at=make_utc_timestamp(idx * 0.1 + 0.05),
                event_ids=[ev_id],
            )
        )
        events.append(
            make_valid_event(
                event_id=ev_id,
                run_id=run.run_id,
                span_id=sp_id,
                event_type=EventKind.TOOL_RESULT,
                boundary=BoundaryType.TOOL,
                timestamp=make_utc_timestamp(idx * 0.1 + 0.05),
                sequence=idx,
                payload={"tool_name": sp_name, "result": payload_val},
            )
        )
        fixtures.append(
            make_valid_fixture_entry(
                fixture_id=f"fix_{suffix}_{idx}",
                boundary=BoundaryType.TOOL,
                request={"tool_name": sp_name, "idx": idx},
                response={"result": payload_val},
                span_id=sp_id,
                name=sp_name,
            )
        )

    return make_valid_trace(
        trace_id=trace_id,
        runs=[run],
        spans=spans,
        events=events,
        fixtures=make_valid_fixture_set(fixtures),
    )


class TestDiffProperties:
    """Hypothesis property-based invariants for diff_traces."""

    @settings(max_examples=40, deadline=None)
    @given(trace=_trace_strategy(prefix="tr_refl"))
    def test_reflexivity(self, trace: Trace) -> None:
        report = diff_traces(trace, trace)
        assert report.identical is True
        assert len(report.divergences) == 0
        assert report.has_breaking is False
        assert report.summary == {"info": 0, "warning": 0, "breaking": 0, "total": 0}

    @settings(max_examples=40, deadline=None)
    @given(t1=_trace_strategy(prefix="tr_det_a"), t2=_trace_strategy(prefix="tr_det_b"))
    def test_determinism(self, t1: Trace, t2: Trace) -> None:
        report_1 = diff_traces(t1, t2)
        report_2 = diff_traces(t1, t2)
        assert report_1.model_dump_json() == report_2.model_dump_json()

    @settings(max_examples=40, deadline=None)
    @given(t1=_trace_strategy(prefix="tr_inv_a"), t2=_trace_strategy(prefix="tr_inv_b"))
    def test_summary_invariants(self, t1: Trace, t2: Trace) -> None:
        report = diff_traces(t1, t2)
        summary = report.summary
        assert (
            summary["total"]
            == summary["info"] + summary["warning"] + summary["breaking"]
            == len(report.divergences)
        )
        assert report.identical == (summary["total"] == 0)
        assert report.has_breaking == (summary["breaking"] > 0)
        assert summary["info"] == sum(
            1 for d in report.divergences if d.severity == DivergenceSeverity.INFO
        )
        assert summary["warning"] == sum(
            1 for d in report.divergences if d.severity == DivergenceSeverity.WARNING
        )
        assert summary["breaking"] == sum(
            1 for d in report.divergences if d.severity == DivergenceSeverity.BREAKING
        )

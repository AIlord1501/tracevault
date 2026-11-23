"""Regression test and portable redacted fixture generator for TraceVault."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from tracevault.schema import (
    BoundaryType,
    Trace,
    UnsafeTraceError,
    canonical_json,
    compute_fingerprint,
    redact_data,
)


def _validate_file_path(path: Path | str, *, expected_suffix: str) -> Path:
    """Validate an output or fixture file path and enforce the expected extension."""
    if not isinstance(path, (str, Path)):
        raise UnsafeTraceError(f"Expected file path as str or Path, got {type(path).__name__}")
    raw_str = os.fspath(path)
    if isinstance(raw_str, bytes):
        if b"\x00" in raw_str:
            raise UnsafeTraceError("Filesystem path must not contain NUL bytes")
        raw_str = raw_str.decode("utf-8")
    if "\x00" in raw_str:
        raise UnsafeTraceError("Filesystem path must not contain NUL bytes")
    if not raw_str or not raw_str.strip():
        raise UnsafeTraceError("Filesystem path must not be empty")

    candidate = Path(raw_str)
    try:
        resolved = candidate.resolve()
        parent = resolved.parent.resolve()
    except OSError as exc:
        raise UnsafeTraceError(f"Failed to resolve filesystem path {raw_str!r}: {exc}") from exc

    if not resolved.is_relative_to(parent):
        raise UnsafeTraceError(f"Resolved path {resolved} escapes parent directory {parent}")
    if resolved.exists() and resolved.is_dir():
        raise UnsafeTraceError(
            f"Expected file path with {expected_suffix!r} suffix, got directory {resolved}"
        )
    if resolved.suffix.lower() != expected_suffix.lower():
        raise UnsafeTraceError(f"Path {resolved.name!r} must have a {expected_suffix!r} extension")
    return resolved


def _atomic_write_text(target_path: Path, content: str) -> None:
    """Atomically write UTF-8 text to target_path via a same-directory temp file."""
    data = content.encode("utf-8")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target_path.parent,
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, target_path)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()
        raise


def _scrub_trace(trace: Trace, *, redact: bool = True) -> Trace:
    """Return a validated Trace with recursive secret redaction applied when redact=True."""
    if not isinstance(trace, Trace):
        raise UnsafeTraceError(f"Expected a Trace instance, got {type(trace).__name__}")

    if not redact:
        return Trace.model_validate(trace.model_dump(mode="json"))

    raw_payload: dict[str, Any] = trace.model_dump(mode="json")
    redacted_payload: dict[str, Any] = redact_data(raw_payload)

    # Preserve structural trace identifiers that must satisfy validate_trace_id
    redacted_payload["trace_id"] = trace.trace_id
    redacted_payload["parent_trace_id"] = trace.parent_trace_id
    for idx, run_dict in enumerate(redacted_payload.get("runs", [])):
        if isinstance(run_dict, dict) and idx < len(trace.runs):
            run_dict["run_id"] = trace.runs[idx].run_id
            run_dict["trace_id"] = trace.runs[idx].trace_id
            run_dict["parent_run_id"] = trace.runs[idx].parent_run_id

    for idx, span_dict in enumerate(redacted_payload.get("spans", [])):
        if isinstance(span_dict, dict) and idx < len(trace.spans):
            span_dict["span_id"] = trace.spans[idx].span_id
            span_dict["run_id"] = trace.spans[idx].run_id
            span_dict["parent_span_id"] = trace.spans[idx].parent_span_id
            span_dict["event_ids"] = list(trace.spans[idx].event_ids)

    for idx, event_dict in enumerate(redacted_payload.get("events", [])):
        if isinstance(event_dict, dict) and idx < len(trace.events):
            event_dict["event_id"] = trace.events[idx].event_id
            event_dict["run_id"] = trace.events[idx].run_id
            event_dict["span_id"] = trace.events[idx].span_id

    # Keep fixture fingerprints synchronized if any fixture request contained secrets
    fixtures_dict = redacted_payload.get("fixtures")
    if isinstance(fixtures_dict, dict):
        entries_list = fixtures_dict.get("entries")
        if isinstance(entries_list, list):
            any_fp_updated = False
            for idx, entry_dict in enumerate(entries_list):
                if not isinstance(entry_dict, dict) or idx >= len(trace.fixtures.entries):
                    continue
                orig_entry = trace.fixtures.entries[idx]
                entry_dict["fixture_id"] = orig_entry.fixture_id
                entry_dict["span_id"] = orig_entry.span_id
                redacted_req = entry_dict.get("request", {})
                if isinstance(redacted_req, dict):
                    new_fp = compute_fingerprint(orig_entry.boundary, redacted_req)
                    orig_computed_fp = compute_fingerprint(
                        orig_entry.boundary,
                        orig_entry.request,
                    )
                    if (
                        redacted_req != orig_entry.request
                        and orig_entry.fingerprint == orig_computed_fp
                        and entry_dict.get("fingerprint") != new_fp
                    ):
                        entry_dict["fingerprint"] = new_fp
                        any_fp_updated = True

            if any_fp_updated:
                fp_counts: dict[tuple[str, str], int] = {}
                for entry_dict in entries_list:
                    if not isinstance(entry_dict, dict):
                        continue
                    key = (
                        str(entry_dict.get("boundary", "")),
                        str(entry_dict.get("fingerprint", "")),
                    )
                    call_idx = fp_counts.get(key, 0)
                    fp_counts[key] = call_idx + 1
                    entry_dict["call_index"] = call_idx

    redacted_payload["redaction_applied"] = True
    return Trace.model_validate(redacted_payload)


def _extract_tool_names(trace: Trace) -> list[str]:
    """Return ordered unique tool names from recorded TOOL fixtures in trace."""
    names: list[str] = []
    for entry in trace.fixtures.entries:
        if entry.boundary != BoundaryType.TOOL:
            continue
        candidate_name = entry.name
        if not candidate_name:
            req_tool = entry.request.get("tool_name")
            if isinstance(req_tool, str) and req_tool:
                candidate_name = req_tool
        if candidate_name and candidate_name not in names:
            names.append(candidate_name)
    return names


def _safe_test_identifier(trace_id: str) -> str:
    """Derive a strictly alphanumeric/underscore suffix for the generated test function."""
    cleaned = re.sub(r"[^a-z0-9_]+", "_", str(trace_id).lower()).strip("_")
    return cleaned if cleaned else "trace"


def export_regression_fixture(
    trace: Trace,
    output_path: Path | str,
    *,
    redact: bool = True,
) -> Path:
    """Export a Trace to a portable, deterministic JSON regression fixture file.

    By default, applies recursive secret redaction before writing so secrets are
    never persisted into exported regression fixtures.
    """
    resolved_output = _validate_file_path(output_path, expected_suffix=".json")
    export_trace = _scrub_trace(trace, redact=redact)
    json_content = export_trace.to_json(indent=2) + "\n"
    _atomic_write_text(resolved_output, json_content)
    return resolved_output


def generate_pytest_regression(
    trace: Trace,
    output_path: Path | str,
    *,
    trace_path: Path | str | None = None,
    include_tool_assertions: bool = True,
    include_status_assertion: bool = True,
    include_output_assertion: bool = True,
) -> Path:
    """Generate a standalone, Ruff-clean, injection-safe pytest regression test file."""
    resolved_output = _validate_file_path(output_path, expected_suffix=".py")
    redacted_trace = _scrub_trace(trace, redact=True)

    resolved_trace_path: Path | None = None
    if trace_path is not None:
        resolved_trace_path = _validate_file_path(trace_path, expected_suffix=".json")
        if not resolved_trace_path.exists():
            export_regression_fixture(redacted_trace, resolved_trace_path, redact=True)

    has_output_assertion = include_output_assertion and redacted_trace.root_run.outputs is not None
    tool_names = _extract_tool_names(redacted_trace) if include_tool_assertions else []
    has_tool_assertions = len(tool_names) > 0

    stdlib_imports: list[str] = []
    if has_output_assertion:
        stdlib_imports.append("import json")
    if resolved_trace_path is not None:
        stdlib_imports.append("from pathlib import Path")

    schema_imports = ["BoundaryType", "Trace"] if has_tool_assertions else ["Trace"]

    lines: list[str] = [
        "# ruff: noqa: E501, S101",
        '"""Standalone deterministic TraceVault regression test."""',
        "",
        "from __future__ import annotations",
        "",
    ]
    if stdlib_imports:
        lines.extend(stdlib_imports)
        lines.append("")

    lines.extend(
        [
            "from tracevault.diff import diff_traces, format_diff_report",
            "from tracevault.replay import ReplayEngine",
            f"from tracevault.schema import {', '.join(schema_imports)}",
            "",
        ]
    )

    if resolved_trace_path is not None:
        if resolved_trace_path.is_relative_to(resolved_output.parent):
            rel_posix = resolved_trace_path.relative_to(resolved_output.parent).as_posix()
            rel_lit = json.dumps(rel_posix, ensure_ascii=False)
            lines.append(f"_TRACE_PATH = Path(__file__).resolve().parent / {rel_lit}")
        else:
            abs_lit = json.dumps(str(resolved_trace_path), ensure_ascii=False)
            lines.append(f"_TRACE_PATH = Path({abs_lit})")
    else:
        inline_trace_json = redacted_trace.to_json(indent=None)
        lines.append(f"_TRACE_JSON = {json.dumps(inline_trace_json, ensure_ascii=False)}")

    test_fn_name = f"test_tracevault_regression_{_safe_test_identifier(redacted_trace.trace_id)}"
    lines.extend(
        [
            "",
            "",
            f"def {test_fn_name}() -> None:",
        ]
    )

    if resolved_trace_path is not None:
        lines.append('    trace = Trace.from_json(_TRACE_PATH.read_text(encoding="utf-8"))')
    else:
        lines.append("    trace = Trace.from_json(_TRACE_JSON)")

    trace_id_lit = json.dumps(redacted_trace.trace_id, ensure_ascii=False)
    lines.extend(
        [
            "    result = ReplayEngine(trace).replay_trace()",
            f"    assert result.baseline_trace_id == {trace_id_lit}",
            "    assert result.success is True",
            "    assert result.live_calls == 0",
            "    assert result.missing_fixtures == []",
            "",
            "    report = diff_traces(trace, result.candidate_trace)",
            "    assert not report.has_breaking, format_diff_report(report, verbose=True)",
        ]
    )

    if include_status_assertion:
        status_literal = json.dumps(redacted_trace.root_run.status.value, ensure_ascii=False)
        lines.append(f"    assert result.candidate_trace.root_run.status.value == {status_literal}")

    if has_output_assertion and redacted_trace.root_run.outputs is not None:
        outputs_json_literal = json.dumps(
            canonical_json(redacted_trace.root_run.outputs),
            ensure_ascii=False,
        )
        lines.append(
            "    assert result.candidate_trace.root_run.outputs "
            f"== json.loads({outputs_json_literal})"
        )

    if has_tool_assertions:
        lines.extend(
            [
                "    matched_tools = {",
                '        entry.name or entry.request.get("tool_name")',
                "        for entry in result.candidate_trace.fixtures.entries",
                "        if entry.boundary == BoundaryType.TOOL",
                "    }",
            ]
        )
        for tool_name in tool_names:
            lines.append(f"    assert {json.dumps(tool_name, ensure_ascii=False)} in matched_tools")

    source_code = "\n".join(lines) + "\n"
    _atomic_write_text(resolved_output, source_code)
    return resolved_output


__all__ = [
    "export_regression_fixture",
    "generate_pytest_regression",
]

"""Tests for canonical errors, enums, and schema package exports."""

from __future__ import annotations

import ast
from pathlib import Path

import tracevault.schema as schema
from tracevault.schema import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR,
    AdapterError,
    AdapterUnavailableError,
    BoundaryMode,
    BoundaryType,
    DivergenceKind,
    DivergenceSeverity,
    EventKind,
    ExportFormat,
    FixtureNotFoundError,
    InvalidTraceIdError,
    PolicyViolationError,
    ReplayError,
    ReplayMode,
    RunStatus,
    SpanStatus,
    SpanType,
    TraceFrozenError,
    TraceNotFoundError,
    TraceVaultError,
    UnsafeTraceError,
)


def test_error_hierarchy() -> None:
    assert issubclass(TraceVaultError, Exception)
    for exc_cls in (
        InvalidTraceIdError,
        UnsafeTraceError,
        TraceNotFoundError,
        TraceFrozenError,
        FixtureNotFoundError,
        PolicyViolationError,
        ReplayError,
        AdapterError,
        AdapterUnavailableError,
    ):
        assert issubclass(exc_cls, TraceVaultError)
    assert issubclass(AdapterUnavailableError, AdapterError)


def test_schema_version_constants() -> None:
    assert SCHEMA_VERSION == "1.0.0"
    assert SUPPORTED_SCHEMA_MAJOR == 1


def test_all_enum_members_match_contract() -> None:
    assert {m.name: m.value for m in BoundaryType} == {
        "MODEL": "model",
        "TOOL": "tool",
        "RETRIEVAL": "retrieval",
        "CUSTOM": "custom",
    }
    assert {m.name: m.value for m in SpanType} == {
        "AGENT": "agent",
        "WORKFLOW": "workflow",
        "MODEL": "model",
        "TOOL": "tool",
        "RETRIEVAL": "retrieval",
        "CUSTOM": "custom",
    }
    assert {m.name: m.value for m in EventKind} == {
        "RUN_STARTED": "run_started",
        "RUN_COMPLETED": "run_completed",
        "RUN_FAILED": "run_failed",
        "SPAN_STARTED": "span_started",
        "SPAN_COMPLETED": "span_completed",
        "SPAN_FAILED": "span_failed",
        "MODEL_REQUEST": "model_request",
        "MODEL_RESPONSE": "model_response",
        "MODEL_ERROR": "model_error",
        "TOOL_CALL": "tool_call",
        "TOOL_RESULT": "tool_result",
        "TOOL_ERROR": "tool_error",
        "RETRIEVAL_QUERY": "retrieval_query",
        "RETRIEVAL_RESULT": "retrieval_result",
        "RETRIEVAL_ERROR": "retrieval_error",
        "AGENT_TRANSITION": "agent_transition",
        "STATE_CHANGE": "state_change",
        "STREAM_CHUNK": "stream_chunk",
        "EXCEPTION": "exception",
        "CUSTOM": "custom",
    }
    assert {m.name: m.value for m in RunStatus} == {
        "RUNNING": "running",
        "COMPLETED": "completed",
        "FAILED": "failed",
        "CANCELLED": "cancelled",
    }
    assert {m.name: m.value for m in SpanStatus} == {
        "UNSET": "unset",
        "OK": "ok",
        "ERROR": "error",
        "CANCELLED": "cancelled",
    }
    assert {m.name: m.value for m in ReplayMode} == {
        "OFFLINE_STRICT": "offline_strict",
        "OFFLINE_LENIENT": "offline_lenient",
        "BOUNDARY_GOVERNED": "boundary_governed",
    }
    assert {m.name: m.value for m in BoundaryMode} == {
        "RECORDED": "recorded",
        "LIVE": "live",
        "DENY": "deny",
    }
    assert {m.name: m.value for m in DivergenceSeverity} == {
        "INFO": "info",
        "WARNING": "warning",
        "BREAKING": "breaking",
    }
    assert {m.name: m.value for m in DivergenceKind} == {
        "STATUS_CHANGED": "status_changed",
        "OUTPUT_CHANGED": "output_changed",
        "ERROR_CHANGED": "error_changed",
        "SPAN_ADDED": "span_added",
        "SPAN_REMOVED": "span_removed",
        "SPAN_ORDER_CHANGED": "span_order_changed",
        "SPAN_STATUS_CHANGED": "span_status_changed",
        "EVENT_ADDED": "event_added",
        "EVENT_REMOVED": "event_removed",
        "EVENT_PAYLOAD_CHANGED": "event_payload_changed",
        "MODEL_INPUT_CHANGED": "model_input_changed",
        "MODEL_OUTPUT_CHANGED": "model_output_changed",
        "TOOL_ARGS_CHANGED": "tool_args_changed",
        "TOOL_RESULT_CHANGED": "tool_result_changed",
        "RETRIEVAL_CHANGED": "retrieval_changed",
        "AGENT_TRANSITION_CHANGED": "agent_transition_changed",
        "STATE_CHANGE_MISMATCH": "state_change_mismatch",
        "FIXTURE_MISMATCH": "fixture_mismatch",
    }
    assert {m.name: m.value for m in ExportFormat} == {
        "JSON": "json",
        "JSONL": "jsonl",
    }


def test_schema_package_reexports_all_public_symbols() -> None:
    for symbol in schema.__all__:
        assert hasattr(schema, symbol), f"Missing re-exported symbol: {symbol}"


def test_schema_has_zero_non_schema_internal_dependencies() -> None:
    schema_dir = Path(schema.__file__).resolve().parent
    forbidden_prefixes = (
        "tracevault.storage",
        "tracevault.capture",
        "tracevault.replay",
        "tracevault.diff",
        "tracevault.cli",
        "tracevault.adapters",
        "tracevault.assertions",
        "tracevault.pytest_plugin",
    )
    for py_file in schema_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_prefixes)

"""Deterministic structural trace comparison and divergence analysis engine."""

from __future__ import annotations

import copy
import difflib
import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

from tracevault.schema import (
    DiffConfig,
    DiffReport,
    Divergence,
    DivergenceKind,
    DivergenceSeverity,
    Event,
    EventKind,
    ExecutionError,
    FixtureEntry,
    Run,
    Span,
    Trace,
)

DEFAULT_SEVERITY_MAP: dict[DivergenceKind, DivergenceSeverity] = {
    # BREAKING
    DivergenceKind.STATUS_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.OUTPUT_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.ERROR_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.SPAN_REMOVED: DivergenceSeverity.BREAKING,
    DivergenceKind.SPAN_STATUS_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.MODEL_OUTPUT_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.TOOL_ARGS_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.TOOL_RESULT_CHANGED: DivergenceSeverity.BREAKING,
    DivergenceKind.FIXTURE_MISMATCH: DivergenceSeverity.BREAKING,
    # WARNING
    DivergenceKind.SPAN_ADDED: DivergenceSeverity.WARNING,
    DivergenceKind.SPAN_ORDER_CHANGED: DivergenceSeverity.WARNING,
    DivergenceKind.MODEL_INPUT_CHANGED: DivergenceSeverity.WARNING,
    DivergenceKind.RETRIEVAL_CHANGED: DivergenceSeverity.WARNING,
    DivergenceKind.AGENT_TRANSITION_CHANGED: DivergenceSeverity.WARNING,
    DivergenceKind.STATE_CHANGE_MISMATCH: DivergenceSeverity.WARNING,
    DivergenceKind.EVENT_ADDED: DivergenceSeverity.WARNING,
    DivergenceKind.EVENT_REMOVED: DivergenceSeverity.WARNING,
    DivergenceKind.EVENT_PAYLOAD_CHANGED: DivergenceSeverity.WARNING,
}

_EVENT_KIND_TO_DIVERGENCE: dict[EventKind, DivergenceKind] = {
    EventKind.MODEL_REQUEST: DivergenceKind.MODEL_INPUT_CHANGED,
    EventKind.MODEL_RESPONSE: DivergenceKind.MODEL_OUTPUT_CHANGED,
    EventKind.MODEL_ERROR: DivergenceKind.ERROR_CHANGED,
    EventKind.TOOL_CALL: DivergenceKind.TOOL_ARGS_CHANGED,
    EventKind.TOOL_RESULT: DivergenceKind.TOOL_RESULT_CHANGED,
    EventKind.TOOL_ERROR: DivergenceKind.ERROR_CHANGED,
    EventKind.RETRIEVAL_QUERY: DivergenceKind.RETRIEVAL_CHANGED,
    EventKind.RETRIEVAL_RESULT: DivergenceKind.RETRIEVAL_CHANGED,
    EventKind.RETRIEVAL_ERROR: DivergenceKind.ERROR_CHANGED,
    EventKind.AGENT_TRANSITION: DivergenceKind.AGENT_TRANSITION_CHANGED,
    EventKind.STATE_CHANGE: DivergenceKind.STATE_CHANGE_MISMATCH,
    EventKind.EXCEPTION: DivergenceKind.ERROR_CHANGED,
    EventKind.RUN_FAILED: DivergenceKind.ERROR_CHANGED,
    EventKind.SPAN_FAILED: DivergenceKind.ERROR_CHANGED,
    EventKind.STREAM_CHUNK: DivergenceKind.EVENT_PAYLOAD_CHANGED,
    EventKind.CUSTOM: DivergenceKind.EVENT_PAYLOAD_CHANGED,
    EventKind.RUN_STARTED: DivergenceKind.EVENT_PAYLOAD_CHANGED,
    EventKind.RUN_COMPLETED: DivergenceKind.EVENT_PAYLOAD_CHANGED,
    EventKind.SPAN_STARTED: DivergenceKind.EVENT_PAYLOAD_CHANGED,
    EventKind.SPAN_COMPLETED: DivergenceKind.EVENT_PAYLOAD_CHANGED,
}


def _to_json_safe(value: Any) -> Any:
    """Convert any Trace field value into a defensive JSON-safe copy."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(item) for item in value]
    return copy.deepcopy(value)


def _compile_ignore_patterns(ignore_paths: frozenset[str]) -> tuple[re.Pattern[str], ...]:
    """Compile exact, prefix, and wildcard (*, ?) ignore patterns safely."""
    compiled: list[re.Pattern[str]] = []
    for pattern in sorted(ignore_paths):
        escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        compiled.append(re.compile(rf"^{escaped}(?:$|[.\[])"))
    return tuple(compiled)


def _is_path_ignored(path: str, ignore_patterns: tuple[re.Pattern[str], ...]) -> bool:
    """Return True if path matches any compiled exact, prefix, or wildcard ignore pattern."""
    return any(pattern.match(path) is not None for pattern in ignore_patterns)


def _resolve_severity(
    kind: DivergenceKind,
    config: DiffConfig,
    *,
    default_severity: DivergenceSeverity | None = None,
) -> DivergenceSeverity:
    """Resolve effective severity applying config.severity_overrides over defaults."""
    if kind in config.severity_overrides:
        return config.severity_overrides[kind]
    if default_severity is not None:
        return default_severity
    return DEFAULT_SEVERITY_MAP[kind]


def _values_equal(left: Any, right: Any) -> bool:
    """Strict equality that distinguishes booleans from integers."""
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return bool(left == right)


def _longest_increasing_subsequence_indices(values: list[int]) -> set[int]:
    """Return the set of list positions forming a deterministic LIS of values."""
    n = len(values)
    if n == 0:
        return set()
    dp = [1] * n
    prev = [-1] * n
    best_len = 0
    best_end = 0

    for i in range(n):
        for j in range(i):
            if values[j] < values[i] and dp[j] + 1 > dp[i]:
                dp[i] = dp[j] + 1
                prev[i] = j
        if dp[i] > best_len:
            best_len = dp[i]
            best_end = i

    lis_positions: set[int] = set()
    curr = best_end
    while curr != -1:
        lis_positions.add(curr)
        curr = prev[curr]
    return lis_positions


class _DiffCollector:
    """Internal accumulator enforcing ignore_paths and deterministic divergence creation."""

    def __init__(self, config: DiffConfig, ignore_paths: frozenset[str]) -> None:
        self.config = config
        self.ignore_patterns = _compile_ignore_patterns(ignore_paths)
        self.divergences: list[Divergence] = []

    def add(
        self,
        *,
        kind: DivergenceKind,
        path: str,
        message: str,
        baseline: Any = None,
        candidate: Any = None,
        default_severity: DivergenceSeverity | None = None,
    ) -> None:
        if _is_path_ignored(path, self.ignore_patterns):
            return
        severity = _resolve_severity(kind, self.config, default_severity=default_severity)
        self.divergences.append(
            Divergence(
                kind=kind,
                severity=severity,
                path=path,
                message=message,
                baseline=_to_json_safe(baseline),
                candidate=_to_json_safe(candidate),
            )
        )

    def diff_values(
        self,
        base_val: Any,
        cand_val: Any,
        *,
        kind: DivergenceKind,
        path: str,
        label: str,
        default_severity: DivergenceSeverity | None = None,
    ) -> None:
        """Recursively compare nested JSON-safe structures deterministically."""
        if _is_path_ignored(path, self.ignore_patterns):
            return

        if isinstance(base_val, dict) and isinstance(cand_val, dict):
            all_keys = sorted(set(base_val.keys()) | set(cand_val.keys()))
            for key in all_keys:
                child_path = f"{path}.{key}"
                if _is_path_ignored(child_path, self.ignore_patterns):
                    continue
                in_base = key in base_val
                in_cand = key in cand_val
                if in_base and not in_cand:
                    self.add(
                        kind=kind,
                        path=child_path,
                        message=f"{label} key '{key}' removed",
                        baseline=base_val[key],
                        candidate=None,
                        default_severity=default_severity,
                    )
                elif in_cand and not in_base:
                    self.add(
                        kind=kind,
                        path=child_path,
                        message=f"{label} key '{key}' added",
                        baseline=None,
                        candidate=cand_val[key],
                        default_severity=default_severity,
                    )
                else:
                    self.diff_values(
                        base_val[key],
                        cand_val[key],
                        kind=kind,
                        path=child_path,
                        label=label,
                        default_severity=default_severity,
                    )
            return

        if isinstance(base_val, list) and isinstance(cand_val, list):
            common_len = min(len(base_val), len(cand_val))
            for idx in range(common_len):
                self.diff_values(
                    base_val[idx],
                    cand_val[idx],
                    kind=kind,
                    path=f"{path}[{idx}]",
                    label=label,
                    default_severity=default_severity,
                )
            for idx in range(common_len, len(base_val)):
                self.add(
                    kind=kind,
                    path=f"{path}[{idx}]",
                    message=f"{label} item at index {idx} removed",
                    baseline=base_val[idx],
                    candidate=None,
                    default_severity=default_severity,
                )
            for idx in range(common_len, len(cand_val)):
                self.add(
                    kind=kind,
                    path=f"{path}[{idx}]",
                    message=f"{label} item at index {idx} added",
                    baseline=None,
                    candidate=cand_val[idx],
                    default_severity=default_severity,
                )
            return

        if not _values_equal(base_val, cand_val):
            self.add(
                kind=kind,
                path=path,
                message=f"{label} changed at '{path}'",
                baseline=base_val,
                candidate=cand_val,
                default_severity=default_severity,
            )

    def diff_errors(
        self,
        base_err: ExecutionError | None,
        cand_err: ExecutionError | None,
        *,
        path: str,
        label: str,
    ) -> None:
        """Compare optional ExecutionError models."""
        if _is_path_ignored(path, self.ignore_patterns):
            return
        if base_err is None and cand_err is None:
            return
        if base_err is None and cand_err is not None:
            self.add(
                kind=DivergenceKind.ERROR_CHANGED,
                path=path,
                message=f"{label} error introduced: {cand_err.error_type}: {cand_err.message}",
                baseline=None,
                candidate=cand_err,
            )
            return
        if base_err is not None and cand_err is None:
            self.add(
                kind=DivergenceKind.ERROR_CHANGED,
                path=path,
                message=f"{label} error cleared (was {base_err.error_type}: {base_err.message})",
                baseline=base_err,
                candidate=None,
            )
            return
        if base_err is not None and cand_err is not None:
            self.diff_values(
                base_err.model_dump(mode="json"),
                cand_err.model_dump(mode="json"),
                kind=DivergenceKind.ERROR_CHANGED,
                path=path,
                label=f"{label} error",
            )


def _build_run_structural_keys(runs: list[Run]) -> dict[str, tuple[Any, ...]]:
    """Compute deterministic structural keys for runs based on parent hierarchy and name."""
    runs_by_id = {run.run_id: run for run in runs}
    memo: dict[str, tuple[Any, ...]] = {}
    occ_counts: dict[tuple[str, tuple[Any, ...] | None], int] = {}

    def _key_for(run_id: str) -> tuple[Any, ...]:
        if run_id in memo:
            return memo[run_id]
        run = runs_by_id[run_id]
        parent_key = _key_for(run.parent_run_id) if run.parent_run_id is not None else None
        sig = (run.name, parent_key)
        occ = occ_counts.get(sig, 0)
        occ_counts[sig] = occ + 1
        full_key: tuple[Any, ...] = (run.name, parent_key, occ)
        memo[run_id] = full_key
        return full_key

    for run in runs:
        _key_for(run.run_id)
    return memo


def _build_span_structural_keys(spans: list[Span]) -> dict[str, tuple[Any, ...]]:
    """Compute deterministic structural keys for spans based on type, name, and parent tree."""
    spans_by_id = {span.span_id: span for span in spans}
    memo: dict[str, tuple[Any, ...]] = {}
    occ_counts: dict[tuple[str, str, tuple[Any, ...] | None], int] = {}

    def _key_for(span_id: str) -> tuple[Any, ...]:
        if span_id in memo:
            return memo[span_id]
        span = spans_by_id[span_id]
        parent_key = _key_for(span.parent_span_id) if span.parent_span_id is not None else None
        sig = (span.span_type.value, span.name, parent_key)
        occ = occ_counts.get(sig, 0)
        occ_counts[sig] = occ + 1
        full_key: tuple[Any, ...] = (span.span_type.value, span.name, parent_key, occ)
        memo[span_id] = full_key
        return full_key

    for span in spans:
        _key_for(span.span_id)
    return memo


def _compare_trace_level(
    baseline: Trace,
    candidate: Trace,
    collector: _DiffCollector,
) -> None:
    config = collector.config
    if not config.ignore_ids:
        if baseline.trace_id != candidate.trace_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path="trace_id",
                message=f"Trace ID changed from '{baseline.trace_id}' to '{candidate.trace_id}'",
                baseline=baseline.trace_id,
                candidate=candidate.trace_id,
                default_severity=DivergenceSeverity.INFO,
            )
        if baseline.parent_trace_id != candidate.parent_trace_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path="parent_trace_id",
                message="Trace parent_trace_id changed",
                baseline=baseline.parent_trace_id,
                candidate=candidate.parent_trace_id,
                default_severity=DivergenceSeverity.INFO,
            )

    if not config.ignore_timestamps and baseline.created_at != candidate.created_at:
        collector.add(
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path="created_at",
            message="Trace created_at timestamp changed",
            baseline=baseline.created_at,
            candidate=candidate.created_at,
            default_severity=DivergenceSeverity.INFO,
        )

    if config.compare_metadata:
        collector.diff_values(
            baseline.metadata,
            candidate.metadata,
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path="metadata",
            label="Trace metadata",
            default_severity=DivergenceSeverity.INFO,
        )


def _compare_runs(
    baseline: Trace,
    candidate: Trace,
    collector: _DiffCollector,
) -> None:
    config = collector.config
    matched_pairs: list[tuple[int, Run, int, Run]] = []
    unmatched_base: list[tuple[int, Run]] = []
    matched_cand_indices: set[int] = set()

    if not config.ignore_ids:
        cand_by_id: dict[str, tuple[int, Run]] = {
            run.run_id: (idx, run) for idx, run in enumerate(candidate.runs)
        }
        for b_idx, b_run in enumerate(baseline.runs):
            match = cand_by_id.get(b_run.run_id)
            if match is not None:
                c_idx, c_run = match
                matched_pairs.append((b_idx, b_run, c_idx, c_run))
                matched_cand_indices.add(c_idx)
            else:
                unmatched_base.append((b_idx, b_run))
    else:
        base_keys = _build_run_structural_keys(baseline.runs)
        cand_keys = _build_run_structural_keys(candidate.runs)
        cand_by_key: dict[tuple[Any, ...], tuple[int, Run]] = {
            cand_keys[run.run_id]: (idx, run) for idx, run in enumerate(candidate.runs)
        }
        for b_idx, b_run in enumerate(baseline.runs):
            match = cand_by_key.get(base_keys[b_run.run_id])
            if match is not None:
                c_idx, c_run = match
                matched_pairs.append((b_idx, b_run, c_idx, c_run))
                matched_cand_indices.add(c_idx)
            else:
                unmatched_base.append((b_idx, b_run))

        unmatched_cand = [
            (idx, run) for idx, run in enumerate(candidate.runs) if idx not in matched_cand_indices
        ]
        # Fallback: pair single unmatched root runs so status/output/error diffs remain visible
        base_roots = [(i, r) for i, r in unmatched_base if r.parent_run_id is None]
        cand_roots = [(i, r) for i, r in unmatched_cand if r.parent_run_id is None]
        if len(base_roots) == 1 and len(cand_roots) == 1:
            b_idx, b_run = base_roots[0]
            c_idx, c_run = cand_roots[0]
            matched_pairs.append((b_idx, b_run, c_idx, c_run))
            matched_cand_indices.add(c_idx)
            unmatched_base = [(i, r) for i, r in unmatched_base if i != b_idx]

    matched_pairs.sort(key=lambda item: item[0])

    for b_idx, b_run, _c_idx, c_run in matched_pairs:
        prefix = f"runs[{b_idx}]"
        if b_run.name != c_run.name:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.name",
                message=f"Run name changed from '{b_run.name}' to '{c_run.name}'",
                baseline=b_run.name,
                candidate=c_run.name,
                default_severity=DivergenceSeverity.INFO,
            )

        if b_run.status != c_run.status:
            collector.add(
                kind=DivergenceKind.STATUS_CHANGED,
                path=f"{prefix}.status",
                message=(
                    f"Run '{b_run.name}' status changed from "
                    f"'{b_run.status.value}' to '{c_run.status.value}'"
                ),
                baseline=b_run.status.value,
                candidate=c_run.status.value,
            )

        collector.diff_values(
            b_run.outputs,
            c_run.outputs,
            kind=DivergenceKind.OUTPUT_CHANGED,
            path=f"{prefix}.outputs",
            label=f"Run '{b_run.name}' outputs",
        )

        collector.diff_errors(
            b_run.error,
            c_run.error,
            path=f"{prefix}.error",
            label=f"Run '{b_run.name}'",
        )

        collector.diff_values(
            b_run.inputs,
            c_run.inputs,
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path=f"{prefix}.inputs",
            label=f"Run '{b_run.name}' inputs",
            default_severity=DivergenceSeverity.INFO,
        )

        if not config.ignore_ids:
            if b_run.run_id != c_run.run_id:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.run_id",
                    message="Run run_id changed",
                    baseline=b_run.run_id,
                    candidate=c_run.run_id,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_run.parent_run_id != c_run.parent_run_id:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.parent_run_id",
                    message="Run parent_run_id changed",
                    baseline=b_run.parent_run_id,
                    candidate=c_run.parent_run_id,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_run.trace_id != c_run.trace_id:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.trace_id",
                    message="Run trace_id changed",
                    baseline=b_run.trace_id,
                    candidate=c_run.trace_id,
                    default_severity=DivergenceSeverity.INFO,
                )

        if not config.ignore_timestamps:
            if b_run.started_at != c_run.started_at:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.started_at",
                    message="Run started_at timestamp changed",
                    baseline=b_run.started_at,
                    candidate=c_run.started_at,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_run.ended_at != c_run.ended_at:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.ended_at",
                    message="Run ended_at timestamp changed",
                    baseline=b_run.ended_at,
                    candidate=c_run.ended_at,
                    default_severity=DivergenceSeverity.INFO,
                )

        if config.compare_metadata:
            collector.diff_values(
                b_run.metadata,
                c_run.metadata,
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.metadata",
                label=f"Run '{b_run.name}' metadata",
                default_severity=DivergenceSeverity.INFO,
            )
            collector.diff_values(
                b_run.tags,
                c_run.tags,
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.tags",
                label=f"Run '{b_run.name}' tags",
                default_severity=DivergenceSeverity.INFO,
            )
            collector.diff_values(
                b_run.environment,
                c_run.environment,
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.environment",
                label=f"Run '{b_run.name}' environment",
                default_severity=DivergenceSeverity.INFO,
            )

    for b_idx, b_run in unmatched_base:
        collector.add(
            kind=DivergenceKind.STATUS_CHANGED,
            path=f"runs[{b_idx}]",
            message=f"Run '{b_run.name}' was removed",
            baseline={"run_id": b_run.run_id, "name": b_run.name, "status": b_run.status.value},
            candidate=None,
        )

    for c_idx, c_run in enumerate(candidate.runs):
        if c_idx not in matched_cand_indices:
            collector.add(
                kind=DivergenceKind.EVENT_ADDED,
                path=f"runs[{c_idx}]",
                message=f"Run '{c_run.name}' was added",
                baseline=None,
                candidate={
                    "run_id": c_run.run_id,
                    "name": c_run.name,
                    "status": c_run.status.value,
                },
            )


def _compare_spans(
    baseline: Trace,
    candidate: Trace,
    collector: _DiffCollector,
) -> tuple[dict[str, tuple[Any, ...]], dict[str, tuple[Any, ...]]]:
    config = collector.config
    base_keys = _build_span_structural_keys(baseline.spans)
    cand_keys = _build_span_structural_keys(candidate.spans)

    matched_pairs: list[tuple[int, Span, int, Span]] = []
    unmatched_base: list[tuple[int, Span]] = []
    matched_cand_indices: set[int] = set()

    if not config.ignore_ids:
        cand_by_id: dict[str, tuple[int, Span]] = {
            span.span_id: (idx, span) for idx, span in enumerate(candidate.spans)
        }
        for b_idx, b_span in enumerate(baseline.spans):
            match = cand_by_id.get(b_span.span_id)
            if match is not None:
                c_idx, c_span = match
                matched_pairs.append((b_idx, b_span, c_idx, c_span))
                matched_cand_indices.add(c_idx)
            else:
                unmatched_base.append((b_idx, b_span))
    else:
        cand_by_key: dict[tuple[Any, ...], tuple[int, Span]] = {
            cand_keys[span.span_id]: (idx, span) for idx, span in enumerate(candidate.spans)
        }
        for b_idx, b_span in enumerate(baseline.spans):
            match = cand_by_key.get(base_keys[b_span.span_id])
            if match is not None:
                c_idx, c_span = match
                matched_pairs.append((b_idx, b_span, c_idx, c_span))
                matched_cand_indices.add(c_idx)
            else:
                unmatched_base.append((b_idx, b_span))

    # 1. Removed spans
    for b_idx, b_span in unmatched_base:
        collector.add(
            kind=DivergenceKind.SPAN_REMOVED,
            path=f"spans[{b_idx}]",
            message=f"Span '{b_span.name}' ({b_span.span_type.value}) was removed",
            baseline={
                "span_id": b_span.span_id,
                "name": b_span.name,
                "span_type": b_span.span_type.value,
                "status": b_span.status.value,
            },
            candidate=None,
        )

    # 2. Added spans
    for c_idx, c_span in enumerate(candidate.spans):
        if c_idx not in matched_cand_indices:
            collector.add(
                kind=DivergenceKind.SPAN_ADDED,
                path=f"spans[{c_idx}]",
                message=f"Span '{c_span.name}' ({c_span.span_type.value}) was added",
                baseline=None,
                candidate={
                    "span_id": c_span.span_id,
                    "name": c_span.name,
                    "span_type": c_span.span_type.value,
                    "status": c_span.status.value,
                },
            )

    # 3. Relative order check among matched spans
    if config.strict_order and len(matched_pairs) > 1:
        cand_order = [c_idx for _, _, c_idx, _ in matched_pairs]
        lis_positions = _longest_increasing_subsequence_indices(cand_order)
        for pos, (b_idx, b_span, c_idx, _c_span) in enumerate(matched_pairs):
            if pos not in lis_positions:
                collector.add(
                    kind=DivergenceKind.SPAN_ORDER_CHANGED,
                    path=f"spans[{b_idx}]",
                    message=(
                        f"Span '{b_span.name}' changed execution order "
                        f"(baseline index {b_idx}, candidate index {c_idx})"
                    ),
                    baseline=b_idx,
                    candidate=c_idx,
                )

    # 4. Field-level comparison on matched spans
    for b_idx, b_span, _c_idx, c_span in matched_pairs:
        prefix = f"spans[{b_idx}]"
        if b_span.status != c_span.status:
            collector.add(
                kind=DivergenceKind.SPAN_STATUS_CHANGED,
                path=f"{prefix}.status",
                message=(
                    f"Span '{b_span.name}' status changed from "
                    f"'{b_span.status.value}' to '{c_span.status.value}'"
                ),
                baseline=b_span.status.value,
                candidate=c_span.status.value,
            )

        collector.diff_errors(
            b_span.error,
            c_span.error,
            path=f"{prefix}.error",
            label=f"Span '{b_span.name}'",
        )

        if not config.ignore_ids:
            if b_span.name != c_span.name:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.name",
                    message=f"Span name changed from '{b_span.name}' to '{c_span.name}'",
                    baseline=b_span.name,
                    candidate=c_span.name,
                )
            if b_span.span_type != c_span.span_type:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.span_type",
                    message=(
                        f"Span '{b_span.name}' span_type changed from "
                        f"'{b_span.span_type.value}' to '{c_span.span_type.value}'"
                    ),
                    baseline=b_span.span_type.value,
                    candidate=c_span.span_type.value,
                )
            if b_span.parent_span_id != c_span.parent_span_id:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.parent_span_id",
                    message=f"Span '{b_span.name}' parent_span_id changed",
                    baseline=b_span.parent_span_id,
                    candidate=c_span.parent_span_id,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_span.run_id != c_span.run_id:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.run_id",
                    message=f"Span '{b_span.name}' run_id changed",
                    baseline=b_span.run_id,
                    candidate=c_span.run_id,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_span.event_ids != c_span.event_ids:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.event_ids",
                    message=f"Span '{b_span.name}' event_ids changed",
                    baseline=b_span.event_ids,
                    candidate=c_span.event_ids,
                    default_severity=DivergenceSeverity.INFO,
                )

        if not config.ignore_timestamps:
            if b_span.started_at != c_span.started_at:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.started_at",
                    message=f"Span '{b_span.name}' started_at timestamp changed",
                    baseline=b_span.started_at,
                    candidate=c_span.started_at,
                    default_severity=DivergenceSeverity.INFO,
                )
            if b_span.ended_at != c_span.ended_at:
                collector.add(
                    kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                    path=f"{prefix}.ended_at",
                    message=f"Span '{b_span.name}' ended_at timestamp changed",
                    baseline=b_span.ended_at,
                    candidate=c_span.ended_at,
                    default_severity=DivergenceSeverity.INFO,
                )

        if config.compare_metadata:
            collector.diff_values(
                b_span.attributes,
                c_span.attributes,
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.attributes",
                label=f"Span '{b_span.name}' attributes",
                default_severity=DivergenceSeverity.INFO,
            )

    return base_keys, cand_keys


def _event_signature(
    event: Event,
    span_keys: dict[str, tuple[Any, ...]],
) -> tuple[str, str | None, tuple[Any, ...] | None]:
    span_key = span_keys.get(event.span_id) if event.span_id is not None else None
    boundary_val = event.boundary.value if event.boundary is not None else None
    return (event.event_type.value, boundary_val, span_key)


def _compare_matched_events(
    b_idx: int,
    b_event: Event,
    c_event: Event,
    collector: _DiffCollector,
) -> None:
    config = collector.config
    prefix = f"events[{b_idx}]"

    if b_event.event_type != c_event.event_type:
        collector.add(
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path=f"{prefix}.event_type",
            message=(
                f"Event type changed from '{b_event.event_type.value}' "
                f"to '{c_event.event_type.value}'"
            ),
            baseline=b_event.event_type.value,
            candidate=c_event.event_type.value,
        )

    payload_kind = _EVENT_KIND_TO_DIVERGENCE.get(
        b_event.event_type,
        DivergenceKind.EVENT_PAYLOAD_CHANGED,
    )
    b_payload = b_event.payload
    c_payload = c_event.payload
    if config.ignore_ids and b_event.event_type in {
        EventKind.RUN_STARTED,
        EventKind.RUN_COMPLETED,
        EventKind.RUN_FAILED,
        EventKind.SPAN_STARTED,
        EventKind.SPAN_COMPLETED,
        EventKind.SPAN_FAILED,
    }:
        b_payload = {k: v for k, v in b_payload.items() if k not in {"run_id", "span_id"}}
        c_payload = {k: v for k, v in c_payload.items() if k not in {"run_id", "span_id"}}
    collector.diff_values(
        b_payload,
        c_payload,
        kind=payload_kind,
        path=f"{prefix}.payload",
        label=f"Event ({b_event.event_type.value}) payload",
    )

    if not config.ignore_ids:
        if b_event.run_id != c_event.run_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.run_id",
                message="Event run_id changed",
                baseline=b_event.run_id,
                candidate=c_event.run_id,
                default_severity=DivergenceSeverity.INFO,
            )
        if b_event.span_id != c_event.span_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.span_id",
                message="Event span_id changed",
                baseline=b_event.span_id,
                candidate=c_event.span_id,
                default_severity=DivergenceSeverity.INFO,
            )

    if not config.ignore_timestamps and b_event.timestamp != c_event.timestamp:
        collector.add(
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path=f"{prefix}.timestamp",
            message="Event timestamp changed",
            baseline=b_event.timestamp,
            candidate=c_event.timestamp,
            default_severity=DivergenceSeverity.INFO,
        )

    if config.compare_metadata:
        collector.diff_values(
            b_event.metadata,
            c_event.metadata,
            kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
            path=f"{prefix}.metadata",
            label=f"Event ({b_event.event_type.value}) metadata",
            default_severity=DivergenceSeverity.INFO,
        )


def _compare_events(
    baseline: Trace,
    candidate: Trace,
    base_span_keys: dict[str, tuple[Any, ...]],
    cand_span_keys: dict[str, tuple[Any, ...]],
    collector: _DiffCollector,
) -> None:
    config = collector.config
    base_events = sorted(baseline.events, key=lambda e: e.sequence)
    cand_events = sorted(candidate.events, key=lambda e: e.sequence)

    if not config.ignore_ids:
        cand_by_id: dict[str, tuple[int, Event]] = {
            ev.event_id: (idx, ev) for idx, ev in enumerate(cand_events)
        }
        matched_cand_indices: set[int] = set()
        for b_idx, b_ev in enumerate(base_events):
            match = cand_by_id.get(b_ev.event_id)
            if match is not None:
                c_idx, c_ev = match
                matched_cand_indices.add(c_idx)
                _compare_matched_events(b_idx, b_ev, c_ev, collector)
            else:
                collector.add(
                    kind=DivergenceKind.EVENT_REMOVED,
                    path=f"events[{b_idx}]",
                    message=f"Event '{b_ev.event_type.value}' ({b_ev.event_id}) was removed",
                    baseline={
                        "event_id": b_ev.event_id,
                        "event_type": b_ev.event_type.value,
                        "boundary": b_ev.boundary.value if b_ev.boundary else None,
                    },
                    candidate=None,
                )
        for c_idx, c_ev in enumerate(cand_events):
            if c_idx not in matched_cand_indices:
                collector.add(
                    kind=DivergenceKind.EVENT_ADDED,
                    path=f"events[{c_idx}]",
                    message=f"Event '{c_ev.event_type.value}' ({c_ev.event_id}) was added",
                    baseline=None,
                    candidate={
                        "event_id": c_ev.event_id,
                        "event_type": c_ev.event_type.value,
                        "boundary": c_ev.boundary.value if c_ev.boundary else None,
                    },
                )
        return

    base_sigs = [_event_signature(ev, base_span_keys) for ev in base_events]
    cand_sigs = [_event_signature(ev, cand_span_keys) for ev in cand_events]
    matcher = difflib.SequenceMatcher(a=base_sigs, b=cand_sigs, autojunk=False)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                b_idx = i1 + offset
                c_idx = j1 + offset
                _compare_matched_events(b_idx, base_events[b_idx], cand_events[c_idx], collector)
        elif tag == "delete":
            for b_idx in range(i1, i2):
                b_ev = base_events[b_idx]
                collector.add(
                    kind=DivergenceKind.EVENT_REMOVED,
                    path=f"events[{b_idx}]",
                    message=f"Event '{b_ev.event_type.value}' was removed",
                    baseline={
                        "event_type": b_ev.event_type.value,
                        "boundary": b_ev.boundary.value if b_ev.boundary else None,
                        "payload": b_ev.payload,
                    },
                    candidate=None,
                )
        elif tag == "insert":
            for c_idx in range(j1, j2):
                c_ev = cand_events[c_idx]
                collector.add(
                    kind=DivergenceKind.EVENT_ADDED,
                    path=f"events[{c_idx}]",
                    message=f"Event '{c_ev.event_type.value}' was added",
                    baseline=None,
                    candidate={
                        "event_type": c_ev.event_type.value,
                        "boundary": c_ev.boundary.value if c_ev.boundary else None,
                        "payload": c_ev.payload,
                    },
                )
        elif tag == "replace":
            for b_idx in range(i1, i2):
                b_ev = base_events[b_idx]
                collector.add(
                    kind=DivergenceKind.EVENT_REMOVED,
                    path=f"events[{b_idx}]",
                    message=f"Event '{b_ev.event_type.value}' was removed",
                    baseline={
                        "event_type": b_ev.event_type.value,
                        "boundary": b_ev.boundary.value if b_ev.boundary else None,
                        "payload": b_ev.payload,
                    },
                    candidate=None,
                )
            for c_idx in range(j1, j2):
                c_ev = cand_events[c_idx]
                collector.add(
                    kind=DivergenceKind.EVENT_ADDED,
                    path=f"events[{c_idx}]",
                    message=f"Event '{c_ev.event_type.value}' was added",
                    baseline=None,
                    candidate={
                        "event_type": c_ev.event_type.value,
                        "boundary": c_ev.boundary.value if c_ev.boundary else None,
                        "payload": c_ev.payload,
                    },
                )


def _compare_matched_fixtures(
    b_idx: int,
    b_fix: FixtureEntry,
    c_fix: FixtureEntry,
    collector: _DiffCollector,
) -> None:
    config = collector.config
    prefix = f"fixtures[{b_idx}]"
    label = f"Fixture '{b_fix.name or b_fix.fixture_id}'"

    if b_fix.boundary != c_fix.boundary:
        collector.add(
            kind=DivergenceKind.FIXTURE_MISMATCH,
            path=f"{prefix}.boundary",
            message=(
                f"{label} boundary changed from "
                f"'{b_fix.boundary.value}' to '{c_fix.boundary.value}'"
            ),
            baseline=b_fix.boundary.value,
            candidate=c_fix.boundary.value,
        )

    if b_fix.fingerprint != c_fix.fingerprint:
        collector.add(
            kind=DivergenceKind.FIXTURE_MISMATCH,
            path=f"{prefix}.fingerprint",
            message=f"{label} fingerprint mismatch",
            baseline=b_fix.fingerprint,
            candidate=c_fix.fingerprint,
        )

    collector.diff_values(
        b_fix.request,
        c_fix.request,
        kind=DivergenceKind.FIXTURE_MISMATCH,
        path=f"{prefix}.request",
        label=f"{label} request",
    )

    collector.diff_values(
        b_fix.response,
        c_fix.response,
        kind=DivergenceKind.FIXTURE_MISMATCH,
        path=f"{prefix}.response",
        label=f"{label} response",
    )

    if b_fix.error != c_fix.error:
        base_err = b_fix.error.model_dump(mode="json") if b_fix.error is not None else None
        cand_err = c_fix.error.model_dump(mode="json") if c_fix.error is not None else None
        collector.diff_values(
            base_err,
            cand_err,
            kind=DivergenceKind.FIXTURE_MISMATCH,
            path=f"{prefix}.error",
            label=f"{label} error",
        )

    if not config.ignore_ids:
        if b_fix.fixture_id != c_fix.fixture_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.fixture_id",
                message=f"{label} fixture_id changed",
                baseline=b_fix.fixture_id,
                candidate=c_fix.fixture_id,
                default_severity=DivergenceSeverity.INFO,
            )
        if b_fix.span_id != c_fix.span_id:
            collector.add(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                path=f"{prefix}.span_id",
                message=f"{label} span_id changed",
                baseline=b_fix.span_id,
                candidate=c_fix.span_id,
                default_severity=DivergenceSeverity.INFO,
            )


def _compare_fixtures(
    baseline: Trace,
    candidate: Trace,
    collector: _DiffCollector,
) -> None:
    config = collector.config
    base_entries = baseline.fixtures.entries
    cand_entries = candidate.fixtures.entries

    matched_pairs: list[tuple[int, FixtureEntry, int, FixtureEntry]] = []
    matched_base_indices: set[int] = set()
    matched_cand_indices: set[int] = set()

    if not config.ignore_ids:
        cand_by_id: dict[str, tuple[int, FixtureEntry]] = {
            entry.fixture_id: (idx, entry) for idx, entry in enumerate(cand_entries)
        }
        for b_idx, b_fix in enumerate(base_entries):
            match = cand_by_id.get(b_fix.fixture_id)
            if match is not None:
                c_idx, c_fix = match
                matched_pairs.append((b_idx, b_fix, c_idx, c_fix))
                matched_base_indices.add(b_idx)
                matched_cand_indices.add(c_idx)
    else:
        # Pass 1: exact (boundary, fingerprint, call_index)
        cand_by_fp: dict[tuple[str, str, int], list[tuple[int, FixtureEntry]]] = {}
        for c_idx, c_fix in enumerate(cand_entries):
            key = (c_fix.boundary.value, c_fix.fingerprint, c_fix.call_index)
            cand_by_fp.setdefault(key, []).append((c_idx, c_fix))

        for b_idx, b_fix in enumerate(base_entries):
            key = (b_fix.boundary.value, b_fix.fingerprint, b_fix.call_index)
            bucket = cand_by_fp.get(key)
            if bucket:
                c_idx, c_fix = bucket.pop(0)
                matched_pairs.append((b_idx, b_fix, c_idx, c_fix))
                matched_base_indices.add(b_idx)
                matched_cand_indices.add(c_idx)

        # Pass 2: align remaining fixtures by (boundary, name, call_index_within_group)
        cand_by_name: dict[tuple[str, str | None], list[tuple[int, FixtureEntry]]] = {}
        for c_idx, c_fix in enumerate(cand_entries):
            if c_idx in matched_cand_indices:
                continue
            name_key = (c_fix.boundary.value, c_fix.name)
            cand_by_name.setdefault(name_key, []).append((c_idx, c_fix))

        for b_idx, b_fix in enumerate(base_entries):
            if b_idx in matched_base_indices:
                continue
            name_key = (b_fix.boundary.value, b_fix.name)
            bucket = cand_by_name.get(name_key)
            if bucket:
                c_idx, c_fix = bucket.pop(0)
                matched_pairs.append((b_idx, b_fix, c_idx, c_fix))
                matched_base_indices.add(b_idx)
                matched_cand_indices.add(c_idx)

    matched_pairs.sort(key=lambda item: item[0])

    for b_idx, b_fix, _c_idx, c_fix in matched_pairs:
        _compare_matched_fixtures(b_idx, b_fix, c_fix, collector)

    for b_idx, b_fix in enumerate(base_entries):
        if b_idx not in matched_base_indices:
            collector.add(
                kind=DivergenceKind.FIXTURE_MISMATCH,
                path=f"fixtures[{b_idx}]",
                message=(
                    f"Fixture '{b_fix.name or b_fix.fixture_id}' "
                    f"({b_fix.boundary.value}) was removed"
                ),
                baseline={
                    "fixture_id": b_fix.fixture_id,
                    "boundary": b_fix.boundary.value,
                    "name": b_fix.name,
                    "fingerprint": b_fix.fingerprint,
                },
                candidate=None,
            )

    for c_idx, c_fix in enumerate(cand_entries):
        if c_idx not in matched_cand_indices:
            collector.add(
                kind=DivergenceKind.FIXTURE_MISMATCH,
                path=f"fixtures[{c_idx}]",
                message=(
                    f"Fixture '{c_fix.name or c_fix.fixture_id}' ({c_fix.boundary.value}) was added"
                ),
                baseline=None,
                candidate={
                    "fixture_id": c_fix.fixture_id,
                    "boundary": c_fix.boundary.value,
                    "name": c_fix.name,
                    "fingerprint": c_fix.fingerprint,
                },
            )


def diff_traces(
    baseline: Trace,
    candidate: Trace,
    *,
    config: DiffConfig | None = None,
    ignore_paths: set[str] | None = None,
) -> DiffReport:
    """Compare two canonical Traces deterministically without mutating inputs."""
    effective_config = config if config is not None else DiffConfig()
    merged_ignore_paths = frozenset(effective_config.ignore_paths) | (
        frozenset(ignore_paths) if ignore_paths is not None else frozenset()
    )

    collector = _DiffCollector(effective_config, merged_ignore_paths)

    _compare_trace_level(baseline, candidate, collector)
    _compare_runs(baseline, candidate, collector)
    base_span_keys, cand_span_keys = _compare_spans(baseline, candidate, collector)
    _compare_events(baseline, candidate, base_span_keys, cand_span_keys, collector)
    _compare_fixtures(baseline, candidate, collector)

    divergences = collector.divergences
    info_count = sum(1 for d in divergences if d.severity == DivergenceSeverity.INFO)
    warning_count = sum(1 for d in divergences if d.severity == DivergenceSeverity.WARNING)
    breaking_count = sum(1 for d in divergences if d.severity == DivergenceSeverity.BREAKING)

    return DiffReport(
        baseline_trace_id=baseline.trace_id,
        candidate_trace_id=candidate.trace_id,
        identical=len(divergences) == 0,
        divergences=divergences,
        summary={
            "info": info_count,
            "warning": warning_count,
            "breaking": breaking_count,
            "total": len(divergences),
        },
    )


class DiffEngine:
    """Reusable structural trace diff engine bound to a DiffConfig."""

    def __init__(self, config: DiffConfig | None = None) -> None:
        self._config = config if config is not None else DiffConfig()

    @property
    def config(self) -> DiffConfig:
        """Return the immutable DiffConfig governing this engine."""
        return self._config

    def compare(
        self,
        baseline: Trace,
        candidate: Trace,
        *,
        ignore_paths: set[str] | None = None,
    ) -> DiffReport:
        """Compare baseline and candidate traces using this engine's configuration."""
        return diff_traces(
            baseline,
            candidate,
            config=self._config,
            ignore_paths=ignore_paths,
        )


def find_earliest_divergence(report: DiffReport) -> Divergence | None:
    """Return the first non-INFO divergence if any exist, else the first divergence, else None."""
    if not report.divergences:
        return None
    for divergence in report.divergences:
        if divergence.severity != DivergenceSeverity.INFO:
            return divergence
    return report.divergences[0]


__all__ = [
    "DEFAULT_SEVERITY_MAP",
    "DiffEngine",
    "diff_traces",
    "find_earliest_divergence",
]

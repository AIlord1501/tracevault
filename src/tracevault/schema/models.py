"""Canonical Pydantic v2 data models and enums for TraceVault."""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tracevault.schema.errors import InvalidTraceIdError, UnsafeTraceError
from tracevault.schema.validation import (
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR,
    ensure_utc_datetime,
    validate_fingerprint,
    validate_json_safe,
    validate_schema_version,
    validate_trace_id,
)

DEFAULT_MAX_TRACE_BYTES = 50 * 1024 * 1024


class TraceVaultModel(BaseModel):
    """Strict, immutable base model for all canonical TraceVault contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )


class BoundaryType(StrEnum):
    """Canonical replay/instrumentation boundary categories."""

    MODEL = "model"
    TOOL = "tool"
    RETRIEVAL = "retrieval"
    CUSTOM = "custom"


class SpanType(StrEnum):
    """Semantic execution span categories."""

    AGENT = "agent"
    WORKFLOW = "workflow"
    MODEL = "model"
    TOOL = "tool"
    RETRIEVAL = "retrieval"
    CUSTOM = "custom"


class EventKind(StrEnum):
    """Canonical trace event categories."""

    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    SPAN_STARTED = "span_started"
    SPAN_COMPLETED = "span_completed"
    SPAN_FAILED = "span_failed"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    MODEL_ERROR = "model_error"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    TOOL_ERROR = "tool_error"
    RETRIEVAL_QUERY = "retrieval_query"
    RETRIEVAL_RESULT = "retrieval_result"
    RETRIEVAL_ERROR = "retrieval_error"
    AGENT_TRANSITION = "agent_transition"
    STATE_CHANGE = "state_change"
    STREAM_CHUNK = "stream_chunk"
    EXCEPTION = "exception"
    CUSTOM = "custom"


class RunStatus(StrEnum):
    """Lifecycle status of an execution run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SpanStatus(StrEnum):
    """Lifecycle status of an execution span."""

    UNSET = "unset"
    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"


class ReplayMode(StrEnum):
    """Execution mode for trace replay."""

    OFFLINE_STRICT = "offline_strict"
    OFFLINE_LENIENT = "offline_lenient"
    BOUNDARY_GOVERNED = "boundary_governed"


class BoundaryMode(StrEnum):
    """Policy decision mode for a replay boundary."""

    RECORDED = "recorded"
    LIVE = "live"
    DENY = "deny"


class DivergenceSeverity(StrEnum):
    """Severity classification of a trace diff divergence."""

    INFO = "info"
    WARNING = "warning"
    BREAKING = "breaking"


class DivergenceKind(StrEnum):
    """Canonical structural divergence categories."""

    STATUS_CHANGED = "status_changed"
    OUTPUT_CHANGED = "output_changed"
    ERROR_CHANGED = "error_changed"
    SPAN_ADDED = "span_added"
    SPAN_REMOVED = "span_removed"
    SPAN_ORDER_CHANGED = "span_order_changed"
    SPAN_STATUS_CHANGED = "span_status_changed"
    EVENT_ADDED = "event_added"
    EVENT_REMOVED = "event_removed"
    EVENT_PAYLOAD_CHANGED = "event_payload_changed"
    MODEL_INPUT_CHANGED = "model_input_changed"
    MODEL_OUTPUT_CHANGED = "model_output_changed"
    TOOL_ARGS_CHANGED = "tool_args_changed"
    TOOL_RESULT_CHANGED = "tool_result_changed"
    RETRIEVAL_CHANGED = "retrieval_changed"
    AGENT_TRANSITION_CHANGED = "agent_transition_changed"
    STATE_CHANGE_MISMATCH = "state_change_mismatch"
    FIXTURE_MISMATCH = "fixture_mismatch"


class ExportFormat(StrEnum):
    """Supported trace export formats."""

    JSON = "json"
    JSONL = "jsonl"


class ExecutionError(TraceVaultModel):
    """Canonical structured representation of any run, span, or interaction exception."""

    error_type: str = Field(min_length=1)
    message: str
    traceback_summary: str | None = None
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def _validate_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class Event(TraceVaultModel):
    """Ordered, immutable canonical execution event."""

    event_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    span_id: str | None = None
    event_type: EventKind
    boundary: BoundaryType | None = None
    timestamp: datetime
    sequence: int = Field(ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("span_id")
    @classmethod
    def _validate_span_id(cls, value: str | None) -> str | None:
        if value is not None and not value:
            raise ValueError("span_id must be non-empty when provided")
        return value

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator("payload", "metadata")
    @classmethod
    def _validate_json_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class Span(TraceVaultModel):
    """Structured execution span within a run."""

    span_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    parent_span_id: str | None = None
    span_type: SpanType
    boundary: BoundaryType | None = None
    name: str = Field(min_length=1)
    started_at: datetime
    ended_at: datetime | None = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: dict[str, Any] = Field(default_factory=dict)
    error: ExecutionError | None = None
    event_ids: list[str] = Field(default_factory=list)

    @field_validator("parent_span_id")
    @classmethod
    def _validate_parent_span_id(cls, value: str | None) -> str | None:
        if value is not None and not value:
            raise ValueError("parent_span_id must be non-empty when provided")
        return value

    @field_validator("started_at")
    @classmethod
    def _validate_started_at(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator("ended_at")
    @classmethod
    def _validate_ended_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return ensure_utc_datetime(value)

    @field_validator("attributes")
    @classmethod
    def _validate_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value

    @model_validator(mode="after")
    def _validate_invariants(self) -> Span:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("Span ended_at must be >= started_at")
        if self.parent_span_id is not None and self.parent_span_id == self.span_id:
            raise ValueError("Span parent_span_id must not reference itself")
        return self


class Run(TraceVaultModel):
    """Logical execution unit within a trace."""

    run_id: str = Field(min_length=1)
    trace_id: str
    parent_run_id: str | None = None
    name: str = Field(min_length=1)
    started_at: datetime
    ended_at: datetime | None = None
    status: RunStatus = RunStatus.RUNNING
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] | None = None
    error: ExecutionError | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("trace_id")
    @classmethod
    def _validate_trace_id_field(cls, value: str) -> str:
        return validate_trace_id(value)

    @field_validator("parent_run_id")
    @classmethod
    def _validate_parent_run_id(cls, value: str | None) -> str | None:
        if value is not None and not value:
            raise ValueError("parent_run_id must be non-empty when provided")
        return value

    @field_validator("started_at")
    @classmethod
    def _validate_started_at(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator("ended_at")
    @classmethod
    def _validate_ended_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return ensure_utc_datetime(value)

    @field_validator("inputs", "metadata")
    @classmethod
    def _validate_json_dicts(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value

    @field_validator("outputs")
    @classmethod
    def _validate_outputs(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            validate_json_safe(value)
        return value

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str]) -> list[str]:
        for tag in value:
            if not tag or not tag.strip():
                raise ValueError("Run tags must be non-empty strings")
        return value

    @model_validator(mode="after")
    def _validate_invariants(self) -> Run:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("Run ended_at must be >= started_at")
        if self.parent_run_id is not None and self.parent_run_id == self.run_id:
            raise ValueError("Run parent_run_id must not reference itself")
        return self


class FixtureEntry(TraceVaultModel):
    """Single deterministic recorded boundary interaction fixture."""

    fixture_id: str = Field(min_length=1)
    boundary: BoundaryType
    fingerprint: str
    call_index: int = Field(default=0, ge=0)
    request: dict[str, Any] = Field(default_factory=dict)
    response: dict[str, Any] | None = None
    error: ExecutionError | None = None
    span_id: str | None = None
    name: str | None = None

    @field_validator("fingerprint")
    @classmethod
    def _validate_fingerprint_field(cls, value: str) -> str:
        return validate_fingerprint(value)

    @field_validator("request")
    @classmethod
    def _validate_request(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value

    @field_validator("response")
    @classmethod
    def _validate_response(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            validate_json_safe(value)
        return value

    @model_validator(mode="after")
    def _validate_response_or_error(self) -> FixtureEntry:
        if self.response is None and self.error is None:
            raise ValueError(
                "FixtureEntry must provide either response (use {} for empty payload) or error"
            )
        return self


class FixtureSet(TraceVaultModel):
    """Collection of recorded boundary fixtures for deterministic replay."""

    version: str = SCHEMA_VERSION
    entries: list[FixtureEntry] = Field(default_factory=list)

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        return validate_schema_version(value)

    @model_validator(mode="after")
    def _validate_unique_fixture_ids(self) -> FixtureSet:
        seen_ids: set[str] = set()
        for entry in self.entries:
            if entry.fixture_id in seen_ids:
                raise ValueError(f"Duplicate fixture_id in FixtureSet: {entry.fixture_id!r}")
            seen_ids.add(entry.fixture_id)
        return self


def _reject_json_constant(token: str) -> NoReturn:
    raise UnsafeTraceError(f"Non-finite JSON constant is not allowed: {token!r}")


def _check_acyclic(
    parent_map: dict[str, str | None],
    *,
    entity_name: str,
) -> None:
    """Ensure every parent reference exists and the parent graph contains no cycles."""
    for node_id, parent_id in parent_map.items():
        if parent_id is not None and parent_id not in parent_map:
            raise ValueError(f"{entity_name} {node_id!r} references missing parent {parent_id!r}")

    visited: set[str] = set()
    for start_id in parent_map:
        if start_id in visited:
            continue
        path: set[str] = set()
        curr: str | None = start_id
        while curr is not None:
            if curr in path:
                raise ValueError(
                    f"Cyclic parent_{entity_name.lower()}_id reference detected at {curr!r}"
                )
            if curr in visited:
                break
            path.add(curr)
            curr = parent_map[curr]
        visited.update(path)


class Trace(TraceVaultModel):
    """Authoritative canonical AI execution trace artifact."""

    schema_version: str = SCHEMA_VERSION
    trace_id: str
    created_at: datetime
    frozen: bool = False
    parent_trace_id: str | None = None
    runs: list[Run] = Field(min_length=1)
    spans: list[Span] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    fixtures: FixtureSet = Field(default_factory=FixtureSet)
    metadata: dict[str, Any] = Field(default_factory=dict)
    redaction_applied: bool = True

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version_field(cls, value: str) -> str:
        return validate_schema_version(value)

    @field_validator("trace_id")
    @classmethod
    def _validate_trace_id_field(cls, value: str) -> str:
        return validate_trace_id(value)

    @field_validator("parent_trace_id")
    @classmethod
    def _validate_parent_trace_id_field(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_trace_id(value)

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value

    @model_validator(mode="after")
    def _validate_structural_invariants(self) -> Trace:
        # 1. Runs: unique run_id, matching trace_id, valid acyclic parent_run_id
        run_map: dict[str, Run] = {}
        for run in self.runs:
            if run.run_id in run_map:
                raise ValueError(f"Duplicate run_id in Trace.runs: {run.run_id!r}")
            if run.trace_id != self.trace_id:
                raise ValueError(
                    f"Run {run.run_id!r} trace_id {run.trace_id!r} does not match "
                    f"Trace.trace_id {self.trace_id!r}"
                )
            run_map[run.run_id] = run
        _check_acyclic(
            {run_id: run.parent_run_id for run_id, run in run_map.items()},
            entity_name="Run",
        )

        # 2. Spans: unique span_id, valid run_id, valid acyclic parent_span_id
        span_map: dict[str, Span] = {}
        for span in self.spans:
            if span.span_id in span_map:
                raise ValueError(f"Duplicate span_id in Trace.spans: {span.span_id!r}")
            if span.run_id not in run_map:
                raise ValueError(f"Span {span.span_id!r} references unknown run_id {span.run_id!r}")
            span_map[span.span_id] = span
        _check_acyclic(
            {span_id: span.parent_span_id for span_id, span in span_map.items()},
            entity_name="Span",
        )

        # 3. Events: unique event_id, unique sequence, valid run_id and span_id
        event_map: dict[str, Event] = {}
        seen_sequences: set[int] = set()
        for event in self.events:
            if event.event_id in event_map:
                raise ValueError(f"Duplicate event_id in Trace.events: {event.event_id!r}")
            if event.sequence in seen_sequences:
                raise ValueError(f"Duplicate event sequence in Trace.events: {event.sequence}")
            if event.run_id not in run_map:
                raise ValueError(
                    f"Event {event.event_id!r} references unknown run_id {event.run_id!r}"
                )
            if event.span_id is not None and event.span_id not in span_map:
                raise ValueError(
                    f"Event {event.event_id!r} references unknown span_id {event.span_id!r}"
                )
            event_map[event.event_id] = event
            seen_sequences.add(event.sequence)

        # 4. Span.event_ids: every ID must exist in Trace.events with matching span_id
        for span in self.spans:
            for event_id in span.event_ids:
                if event_id not in event_map:
                    raise ValueError(
                        f"Span {span.span_id!r} references unknown event_id {event_id!r}"
                    )
                if event_map[event_id].span_id != span.span_id:
                    raise ValueError(
                        f"Span {span.span_id!r} lists event_id {event_id!r} whose "
                        f"span_id is {event_map[event_id].span_id!r}"
                    )

        return self

    @property
    def root_run(self) -> Run:
        """Return the root run (parent_run_id is None), falling back to runs[0]."""
        for run in self.runs:
            if run.parent_run_id is None:
                return run
        return self.runs[0]

    def get_run(self, run_id: str) -> Run | None:
        """Look up a run by run_id."""
        for run in self.runs:
            if run.run_id == run_id:
                return run
        return None

    def get_span_events(self, span_id: str) -> list[Event]:
        """Return all events belonging to span_id, ordered by sequence."""
        return sorted(
            (event for event in self.events if event.span_id == span_id),
            key=lambda e: e.sequence,
        )

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the trace to strict UTF-8 JSON (rejecting non-finite numbers)."""
        payload = self.model_dump(mode="json")
        return json.dumps(payload, indent=indent, ensure_ascii=False, allow_nan=False)

    @classmethod
    def from_json(
        cls,
        raw: str | bytes,
        *,
        max_bytes: int = DEFAULT_MAX_TRACE_BYTES,
    ) -> Trace:
        """Parse and validate a Trace from strict UTF-8 JSON with size and depth guards."""
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
            raise UnsafeTraceError("max_bytes must be a positive integer")

        if isinstance(raw, bytes):
            if len(raw) > max_bytes:
                raise UnsafeTraceError(
                    f"Trace payload size ({len(raw)} bytes) exceeds max_bytes ({max_bytes})"
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise UnsafeTraceError(f"Trace payload is not valid UTF-8: {exc}") from exc
        elif isinstance(raw, str):
            raw_size = len(raw.encode("utf-8"))
            if raw_size > max_bytes:
                raise UnsafeTraceError(
                    f"Trace payload size ({raw_size} bytes) exceeds max_bytes ({max_bytes})"
                )
            text = raw
        else:
            raise UnsafeTraceError(
                f"Trace.from_json expects str or bytes, got {type(raw).__name__}"
            )

        try:
            parsed: Any = json.loads(text, parse_constant=_reject_json_constant)
        except UnsafeTraceError:
            raise
        except json.JSONDecodeError as exc:
            raise UnsafeTraceError(f"Malformed JSON trace payload: {exc}") from exc
        except RecursionError as exc:
            raise UnsafeTraceError("JSON nesting depth exceeded parser recursion limit") from exc

        if not isinstance(parsed, dict):
            raise UnsafeTraceError(
                f"Trace JSON root must be an object, got {type(parsed).__name__}"
            )

        validate_json_safe(parsed)

        if "schema_version" in parsed:
            validate_schema_version(parsed["schema_version"])
        if "trace_id" in parsed:
            validate_trace_id(parsed["trace_id"])
        if parsed.get("parent_trace_id") is not None:
            validate_trace_id(parsed["parent_trace_id"])

        try:
            return cls.model_validate(parsed)
        except (InvalidTraceIdError, UnsafeTraceError):
            raise
        except ValidationError as exc:
            raise UnsafeTraceError(f"Trace schema validation failed: {exc}") from exc


def _default_boundary_modes() -> dict[BoundaryType, BoundaryMode]:
    return {boundary: BoundaryMode.RECORDED for boundary in BoundaryType}


class SafetyPolicy(TraceVaultModel):
    """Fail-closed authorization policy for live replay boundaries."""

    allow_live_boundaries: set[BoundaryType] = Field(default_factory=set)
    allowed_tools: set[str] = Field(default_factory=set)
    allowed_hosts: set[str] = Field(default_factory=set)
    max_live_calls: int = Field(default=0, ge=0)
    require_explicit_opt_in: bool = True


class ReplayOverride(TraceVaultModel):
    """Targeted response or error override rule applied during replay."""

    fixture_id: str | None = None
    fingerprint: str | None = None
    boundary: BoundaryType | None = None
    name: str | None = None
    call_index: int | None = Field(default=None, ge=0)
    response: dict[str, Any] | None = None
    error: ExecutionError | None = None

    @field_validator("response")
    @classmethod
    def _validate_response(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            validate_json_safe(value)
        return value


class ReplayConfig(TraceVaultModel):
    """Configuration for offline and policy-governed trace replay."""

    trace_id: str | None = None
    mode: ReplayMode = ReplayMode.OFFLINE_STRICT
    fail_on_missing_fixture: bool = True
    boundary_modes: dict[BoundaryType, BoundaryMode] = Field(
        default_factory=_default_boundary_modes
    )
    safety_policy: SafetyPolicy = Field(default_factory=SafetyPolicy)
    overrides: dict[str, Any] = Field(default_factory=dict)
    override_rules: list[ReplayOverride] = Field(default_factory=list)
    deterministic_seed: int | None = None

    @field_validator("trace_id")
    @classmethod
    def _validate_trace_id_field(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_trace_id(value)

    @field_validator("overrides")
    @classmethod
    def _validate_overrides(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value

    @property
    def strict_matching(self) -> bool:
        """Return True when replay enforces strict fingerprint + call_index matching."""
        return self.mode == ReplayMode.OFFLINE_STRICT


class ReplayResult(TraceVaultModel):
    """Outcome summary of a trace replay execution."""

    baseline_trace_id: str
    candidate_trace: Trace
    mode: ReplayMode
    matched_fixtures: int = Field(default=0, ge=0)
    overridden_fixtures: int = Field(default=0, ge=0)
    live_calls: int = Field(default=0, ge=0)
    missing_fixtures: list[str] = Field(default_factory=list)
    success: bool
    error: ExecutionError | None = None

    @field_validator("baseline_trace_id")
    @classmethod
    def _validate_baseline_trace_id(cls, value: str) -> str:
        return validate_trace_id(value)


class BoundaryPolicyDecision(TraceVaultModel):
    """Result of evaluating a SafetyPolicy against a boundary invocation."""

    boundary: BoundaryType
    mode: BoundaryMode
    allowed: bool
    reason: str


class DiffConfig(TraceVaultModel):
    """Configuration controlling structural trace comparison."""

    ignore_paths: set[str] = Field(default_factory=set)
    ignore_timestamps: bool = True
    ignore_ids: bool = True
    compare_metadata: bool = False
    strict_order: bool = True
    severity_overrides: dict[DivergenceKind, DivergenceSeverity] = Field(default_factory=dict)


class Divergence(TraceVaultModel):
    """Single structural difference between a baseline and candidate trace."""

    kind: DivergenceKind
    severity: DivergenceSeverity
    path: str
    message: str
    baseline: Any = None
    candidate: Any = None

    @field_validator("baseline", "candidate")
    @classmethod
    def _validate_values(cls, value: Any) -> Any:
        validate_json_safe(value)
        return value


class DiffReport(TraceVaultModel):
    """Deterministic structural comparison report for two traces."""

    baseline_trace_id: str
    candidate_trace_id: str
    identical: bool
    divergences: list[Divergence] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)

    @field_validator("baseline_trace_id", "candidate_trace_id")
    @classmethod
    def _validate_trace_ids(cls, value: str) -> str:
        return validate_trace_id(value)

    @property
    def has_breaking(self) -> bool:
        """Return True if any divergence has BREAKING severity."""
        return any(d.severity == DivergenceSeverity.BREAKING for d in self.divergences)


__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_MAJOR",
    "DEFAULT_MAX_TRACE_BYTES",
    "TraceVaultModel",
    "BoundaryType",
    "SpanType",
    "EventKind",
    "RunStatus",
    "SpanStatus",
    "ReplayMode",
    "BoundaryMode",
    "DivergenceSeverity",
    "DivergenceKind",
    "ExportFormat",
    "ExecutionError",
    "Event",
    "Span",
    "Run",
    "FixtureEntry",
    "FixtureSet",
    "Trace",
    "SafetyPolicy",
    "ReplayOverride",
    "ReplayConfig",
    "ReplayResult",
    "BoundaryPolicyDecision",
    "DiffConfig",
    "Divergence",
    "DiffReport",
]

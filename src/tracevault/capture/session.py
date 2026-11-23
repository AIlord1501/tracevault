"""Execution capture session and mutable trace builders for TraceVault."""

from __future__ import annotations

import copy
import platform
import threading
import traceback
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import Token
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal

from tracevault.capture.config import CaptureConfig
from tracevault.capture.context import (
    _enter_session_context,
    _exit_session_context,
    _push_run,
    _push_span,
    _reset_run,
    _reset_span,
    get_current_run_id,
    get_current_span_id,
)
from tracevault.schema import (
    AgentTransitionPayload,
    BoundaryType,
    Event,
    EventKind,
    ExceptionPayload,
    ExecutionError,
    FixtureEntry,
    FixtureSet,
    RedactionConfig,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    StateChangePayload,
    StreamChunkPayload,
    ToolCallPayload,
    ToolResultPayload,
    Trace,
    compute_fingerprint,
    redact_data,
    validate_json_safe,
    validate_trace_id,
)

if TYPE_CHECKING:
    from tracevault.storage.repository import TraceRepository

_SessionTokens = tuple[
    Token["CaptureSession | None"],
    Token[tuple[str, ...]],
    Token[tuple[str, ...]],
]


def _utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _ensure_ended_at(started_at: datetime) -> datetime:
    """Return a UTC timestamp guaranteed to satisfy ended_at >= started_at."""
    now = _utc_now()
    return now if now >= started_at else started_at


def _default_environment() -> dict[str, str]:
    """Collect safe, non-secret runtime facts without touching os.environ."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def _dedupe_tags(tags: list[str]) -> list[str]:
    """Validate and deduplicate tags while preserving insertion order."""
    result: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("Tags must be non-empty strings")
        if tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


@dataclass
class _RunRecord:
    """Mutable builder backing an immutable canonical Run model."""

    run_id: str
    trace_id: str
    parent_run_id: str | None
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    status: RunStatus = RunStatus.RUNNING
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] | None = None
    error: ExecutionError | None = None
    environment: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_model(self) -> Run:
        return Run(
            run_id=self.run_id,
            trace_id=self.trace_id,
            parent_run_id=self.parent_run_id,
            name=self.name,
            started_at=self.started_at,
            ended_at=self.ended_at,
            status=self.status,
            inputs=dict(self.inputs),
            outputs=dict(self.outputs) if self.outputs is not None else None,
            error=self.error,
            environment=dict(self.environment),
            tags=list(self.tags),
            metadata=dict(self.metadata),
        )


@dataclass
class _SpanRecord:
    """Mutable builder backing an immutable canonical Span model."""

    span_id: str
    run_id: str
    parent_span_id: str | None
    span_type: SpanType
    boundary: BoundaryType | None
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: dict[str, Any] = field(default_factory=dict)
    error: ExecutionError | None = None
    event_ids: list[str] = field(default_factory=list)

    def to_model(self) -> Span:
        return Span(
            span_id=self.span_id,
            run_id=self.run_id,
            parent_span_id=self.parent_span_id,
            span_type=self.span_type,
            boundary=self.boundary,
            name=self.name,
            started_at=self.started_at,
            ended_at=self.ended_at,
            status=self.status,
            attributes=dict(self.attributes),
            error=self.error,
            event_ids=list(self.event_ids),
        )


class CaptureSession:
    """Thread-safe, contextvar-aware execution capture session."""

    def __init__(
        self,
        name: str,
        *,
        inputs: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        environment: dict[str, str] | None = None,
        store: TraceRepository | None = None,
        auto_save: bool | None = None,
        redact: bool | None = None,
        trace_id: str | None = None,
        parent_trace_id: str | None = None,
        run_id: str | None = None,
        config: CaptureConfig | None = None,
    ) -> None:
        if not name or not name.strip():
            raise ValueError("CaptureSession name must be a non-empty string")

        self._config: CaptureConfig = config if config is not None else CaptureConfig()
        self._redact: bool = redact if redact is not None else self._config.redact
        self._redaction_config: RedactionConfig | None = self._config.redaction_config
        self._auto_save: bool = auto_save if auto_save is not None else self._config.auto_save
        self._overwrite: bool = self._config.overwrite
        self._store: TraceRepository | None = store

        raw_trace_id = trace_id if trace_id is not None else f"tr_{uuid.uuid4().hex[:24]}"
        self._trace_id: str = validate_trace_id(raw_trace_id)

        self._parent_trace_id: str | None = (
            validate_trace_id(parent_trace_id) if parent_trace_id is not None else None
        )

        raw_run_id = run_id if run_id is not None else f"run_{uuid.uuid4().hex[:16]}"
        if not raw_run_id or not raw_run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        self._root_run_id: str = raw_run_id

        self._created_at: datetime = _utc_now()
        self._lock = threading.Lock()
        self._sequence: int = 0
        self._event_counter: int = 0
        self._span_counter: int = 0
        self._fixture_counter: int = 0
        self._call_indices: dict[tuple[BoundaryType, str], int] = {}

        prepared_inputs = self._prepare_dict(inputs)
        prepared_metadata = self._prepare_dict(metadata)
        prepared_tags = _dedupe_tags([*self._config.default_tags, *(tags or [])])
        prepared_env = self._prepare_environment(environment)

        self._trace_metadata: dict[str, Any] = dict(prepared_metadata)
        root_run = _RunRecord(
            run_id=self._root_run_id,
            trace_id=self._trace_id,
            parent_run_id=None,
            name=name,
            started_at=self._created_at,
            status=RunStatus.RUNNING,
            inputs=prepared_inputs,
            environment=prepared_env,
            tags=prepared_tags,
            metadata=prepared_metadata,
        )

        self._runs: list[_RunRecord] = [root_run]
        self._runs_by_id: dict[str, _RunRecord] = {self._root_run_id: root_run}
        self._spans: list[_SpanRecord] = []
        self._spans_by_id: dict[str, _SpanRecord] = {}
        self._events: list[Event] = []
        self._fixtures: list[FixtureEntry] = []

        self._trace: Trace | None = None
        self._is_finalized: bool = False
        self._context_tokens: list[_SessionTokens] = []

        self.record_event(
            EventKind.RUN_STARTED,
            {"name": name, "run_id": self._root_run_id},
            run_id=self._root_run_id,
        )

    @property
    def trace_id(self) -> str:
        """Return the canonical trace_id for this capture session."""
        return self._trace_id

    @property
    def run_id(self) -> str:
        """Return the root run_id for this capture session."""
        return self._root_run_id

    @property
    def trace(self) -> Trace | None:
        """Return the last built/finalized Trace, or None before build_trace/exit."""
        return self._trace

    @property
    def is_finalized(self) -> bool:
        """Return True once the session has been finalized."""
        return self._is_finalized

    def __enter__(self) -> CaptureSession:
        tokens = _enter_session_context(self, self._root_run_id)
        with self._lock:
            self._context_tokens.append(tokens)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        try:
            if exc_val is not None:
                self.finalize(status=RunStatus.FAILED, error=exc_val)
            else:
                self.finalize(status=RunStatus.COMPLETED)
            if self._auto_save and self._store is not None:
                self.persist()
        finally:
            tokens: _SessionTokens | None = None
            with self._lock:
                if self._context_tokens:
                    tokens = self._context_tokens.pop()
            if tokens is not None:
                _exit_session_context(tokens)
        return False

    async def __aenter__(self) -> CaptureSession:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        return self.__exit__(exc_type, exc_val, exc_tb)

    def _prepare_value(self, value: Any) -> Any:
        validate_json_safe(value)
        if self._redact:
            processed = redact_data(value, self._redaction_config)
            validate_json_safe(processed)
            return processed
        return copy.deepcopy(value)

    def _prepare_dict(self, data: dict[str, Any] | None) -> dict[str, Any]:
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict[str, Any] or None, got {type(data).__name__}")
        prepared = self._prepare_value(data)
        if not isinstance(prepared, dict):
            raise TypeError("Prepared mapping must remain a dict")
        return prepared

    def _prepare_environment(self, environment: dict[str, str] | None) -> dict[str, str]:
        env: dict[str, str] = _default_environment() if self._config.capture_environment else {}
        if environment is not None:
            for key, value in environment.items():
                env[str(key)] = str(value)
        if self._redact:
            redacted = redact_data(env, self._redaction_config)
            return {str(k): str(v) for k, v in redacted.items()}
        return env

    def _normalize_error(self, error: ExecutionError | BaseException | str) -> ExecutionError:
        if isinstance(error, ExecutionError):
            if not self._redact:
                return error
            redacted_message = str(redact_data(error.message, self._redaction_config))
            redacted_tb = (
                str(redact_data(error.traceback_summary, self._redaction_config))
                if error.traceback_summary is not None
                else None
            )
            redacted_details = self._prepare_dict(error.details)
            return ExecutionError(
                error_type=error.error_type,
                message=redacted_message,
                traceback_summary=redacted_tb,
                retryable=error.retryable,
                details=redacted_details,
            )

        if isinstance(error, BaseException):
            raw_message = str(error)
            tb_summary: str | None = None
            if error.__traceback__ is not None:
                tb_lines = traceback.format_tb(error.__traceback__, limit=10)
                tb_summary = "".join(tb_lines).strip() or None
            if self._redact:
                message = str(redact_data(raw_message, self._redaction_config))
                tb_summary = (
                    str(redact_data(tb_summary, self._redaction_config))
                    if tb_summary is not None
                    else None
                )
            else:
                message = raw_message
            return ExecutionError(
                error_type=type(error).__name__,
                message=message,
                traceback_summary=tb_summary,
            )

        if isinstance(error, str):
            message = str(redact_data(error, self._redaction_config)) if self._redact else error
            return ExecutionError(error_type="RecordedError", message=message)

        raise TypeError(f"Unsupported error type: {type(error).__name__}")

    def _resolve_run_id(self, explicit_run_id: str | None) -> str:
        if explicit_run_id is not None:
            with self._lock:
                if explicit_run_id not in self._runs_by_id:
                    raise ValueError(f"Unknown run_id for this session: {explicit_run_id!r}")
            return explicit_run_id
        current_run = get_current_run_id()
        if current_run is not None:
            with self._lock:
                if current_run in self._runs_by_id:
                    return current_run
        return self._root_run_id

    def _resolve_span_id(self, explicit_span_id: str | None) -> str | None:
        if explicit_span_id is not None:
            with self._lock:
                if explicit_span_id not in self._spans_by_id:
                    raise ValueError(f"Unknown span_id for this session: {explicit_span_id!r}")
            return explicit_span_id
        current_span = get_current_span_id()
        if current_span is not None:
            with self._lock:
                if current_span in self._spans_by_id:
                    return current_span
        return None

    def _create_span_record(
        self,
        name: str,
        *,
        span_type: SpanType,
        boundary: BoundaryType | None,
        attributes: dict[str, Any] | None,
    ) -> _SpanRecord:
        if not name or not name.strip():
            raise ValueError("Span name must be a non-empty string")
        run_id = self._resolve_run_id(None)
        parent_span_id = self._resolve_span_id(None)
        prepared_attrs = self._prepare_dict(attributes)
        started_at = _utc_now()
        with self._lock:
            self._span_counter += 1
            span_id = f"sp_{self._span_counter:04d}"
            record = _SpanRecord(
                span_id=span_id,
                run_id=run_id,
                parent_span_id=parent_span_id,
                span_type=span_type,
                boundary=boundary,
                name=name,
                started_at=started_at,
                status=SpanStatus.UNSET,
                attributes=prepared_attrs,
            )
            self._spans.append(record)
            self._spans_by_id[span_id] = record
        return record

    def _finish_span_ok(self, record: _SpanRecord) -> None:
        with self._lock:
            record.ended_at = _ensure_ended_at(record.started_at)
            record.status = SpanStatus.OK
        self.record_event(
            EventKind.SPAN_COMPLETED,
            {"name": record.name, "status": SpanStatus.OK.value},
            boundary=record.boundary,
            span_id=record.span_id,
            run_id=record.run_id,
        )

    def _finish_span_error(self, record: _SpanRecord, exc: BaseException) -> None:
        exec_error = self._normalize_error(exc)
        with self._lock:
            record.ended_at = _ensure_ended_at(record.started_at)
            record.status = SpanStatus.ERROR
            record.error = exec_error
        self.record_event(
            EventKind.SPAN_FAILED,
            {
                "name": record.name,
                "status": SpanStatus.ERROR.value,
                "error": exec_error.model_dump(mode="json"),
            },
            boundary=record.boundary,
            span_id=record.span_id,
            run_id=record.run_id,
        )

    @contextmanager
    def span(
        self,
        name: str,
        *,
        span_type: SpanType = SpanType.CUSTOM,
        boundary: BoundaryType | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[Span]:
        """Synchronously record a nested execution span."""
        record = self._create_span_record(
            name,
            span_type=span_type,
            boundary=boundary,
            attributes=attributes,
        )
        token = _push_span(record.span_id)
        try:
            self.record_event(
                EventKind.SPAN_STARTED,
                {"name": name, "span_type": span_type.value},
                boundary=boundary,
                span_id=record.span_id,
                run_id=record.run_id,
            )
            yield record.to_model()
        except BaseException as exc:
            self._finish_span_error(record, exc)
            raise
        else:
            self._finish_span_ok(record)
        finally:
            _reset_span(token)

    @asynccontextmanager
    async def aspan(
        self,
        name: str,
        *,
        span_type: SpanType = SpanType.CUSTOM,
        boundary: BoundaryType | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> AsyncIterator[Span]:
        """Asynchronously record a nested execution span isolated per task context."""
        record = self._create_span_record(
            name,
            span_type=span_type,
            boundary=boundary,
            attributes=attributes,
        )
        token = _push_span(record.span_id)
        try:
            self.record_event(
                EventKind.SPAN_STARTED,
                {"name": name, "span_type": span_type.value},
                boundary=boundary,
                span_id=record.span_id,
                run_id=record.run_id,
            )
            yield record.to_model()
        except BaseException as exc:
            self._finish_span_error(record, exc)
            raise
        else:
            self._finish_span_ok(record)
        finally:
            _reset_span(token)

    def _create_child_run_record(
        self,
        name: str,
        *,
        inputs: dict[str, Any] | None,
        tags: list[str] | None,
        metadata: dict[str, Any] | None,
    ) -> _RunRecord:
        if not name or not name.strip():
            raise ValueError("Child run name must be a non-empty string")
        parent_run_id = self._resolve_run_id(None)
        child_run_id = f"run_{uuid.uuid4().hex[:16]}"
        prepared_inputs = self._prepare_dict(inputs)
        prepared_tags = _dedupe_tags(tags or [])
        prepared_metadata = self._prepare_dict(metadata)
        record = _RunRecord(
            run_id=child_run_id,
            trace_id=self._trace_id,
            parent_run_id=parent_run_id,
            name=name,
            started_at=_utc_now(),
            status=RunStatus.RUNNING,
            inputs=prepared_inputs,
            tags=prepared_tags,
            metadata=prepared_metadata,
        )
        with self._lock:
            self._runs.append(record)
            self._runs_by_id[child_run_id] = record
        return record

    def _finish_child_run_ok(self, record: _RunRecord) -> None:
        with self._lock:
            record.ended_at = _ensure_ended_at(record.started_at)
            record.status = RunStatus.COMPLETED
        self.record_event(
            EventKind.RUN_COMPLETED,
            {"name": record.name, "status": RunStatus.COMPLETED.value},
            run_id=record.run_id,
        )

    def _finish_child_run_error(self, record: _RunRecord, exc: BaseException) -> None:
        exec_error = self._normalize_error(exc)
        with self._lock:
            record.ended_at = _ensure_ended_at(record.started_at)
            record.status = RunStatus.FAILED
            record.error = exec_error
        self.record_event(
            EventKind.RUN_FAILED,
            {
                "name": record.name,
                "status": RunStatus.FAILED.value,
                "error": exec_error.model_dump(mode="json"),
            },
            run_id=record.run_id,
        )

    @contextmanager
    def start_child_run(
        self,
        name: str,
        *,
        inputs: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[Run]:
        """Synchronously execute and record a nested child run linked via parent_run_id."""
        record = self._create_child_run_record(
            name,
            inputs=inputs,
            tags=tags,
            metadata=metadata,
        )
        token = _push_run(record.run_id)
        try:
            self.record_event(
                EventKind.RUN_STARTED,
                {
                    "name": name,
                    "run_id": record.run_id,
                    "parent_run_id": record.parent_run_id,
                },
                run_id=record.run_id,
            )
            yield record.to_model()
        except BaseException as exc:
            self._finish_child_run_error(record, exc)
            raise
        else:
            self._finish_child_run_ok(record)
        finally:
            _reset_run(token)

    @asynccontextmanager
    async def astart_child_run(
        self,
        name: str,
        *,
        inputs: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AsyncIterator[Run]:
        """Asynchronously execute and record a nested child run linked via parent_run_id."""
        record = self._create_child_run_record(
            name,
            inputs=inputs,
            tags=tags,
            metadata=metadata,
        )
        token = _push_run(record.run_id)
        try:
            self.record_event(
                EventKind.RUN_STARTED,
                {
                    "name": name,
                    "run_id": record.run_id,
                    "parent_run_id": record.parent_run_id,
                },
                run_id=record.run_id,
            )
            yield record.to_model()
        except BaseException as exc:
            self._finish_child_run_error(record, exc)
            raise
        else:
            self._finish_child_run_ok(record)
        finally:
            _reset_run(token)

    def record_event(
        self,
        event_type: EventKind,
        payload: dict[str, Any] | None = None,
        *,
        boundary: BoundaryType | None = None,
        metadata: dict[str, Any] | None = None,
        span_id: str | None = None,
        run_id: str | None = None,
    ) -> Event:
        """Record an ordered, validated, optionally redacted Event."""
        effective_run_id = self._resolve_run_id(run_id)
        effective_span_id = self._resolve_span_id(span_id)
        prepared_payload = self._prepare_dict(payload)
        prepared_metadata = self._prepare_dict(metadata)
        timestamp = _utc_now()

        with self._lock:
            sequence = self._sequence
            self._sequence += 1
            self._event_counter += 1
            event_id = f"ev_{self._event_counter:04d}"

            event = Event(
                event_id=event_id,
                run_id=effective_run_id,
                span_id=effective_span_id,
                event_type=event_type,
                boundary=boundary,
                timestamp=timestamp,
                sequence=sequence,
                payload=prepared_payload,
                metadata=prepared_metadata,
            )
            self._events.append(event)
            if effective_span_id is not None:
                self._spans_by_id[effective_span_id].event_ids.append(event_id)
        return event

    def _register_fixture(
        self,
        *,
        boundary: BoundaryType,
        request: dict[str, Any],
        response: dict[str, Any] | None,
        error: ExecutionError | None,
        span_id: str | None,
        name: str | None,
    ) -> FixtureEntry:
        effective_response = response
        if effective_response is None and error is None:
            effective_response = {}

        fingerprint = compute_fingerprint(boundary, request)
        key = (boundary, fingerprint)
        with self._lock:
            call_index = self._call_indices.get(key, 0)
            self._call_indices[key] = call_index + 1
            self._fixture_counter += 1
            fixture_id = f"fix_{self._fixture_counter:04d}"

            entry = FixtureEntry(
                fixture_id=fixture_id,
                boundary=boundary,
                fingerprint=fingerprint,
                call_index=call_index,
                request=request,
                response=effective_response,
                error=error,
                span_id=span_id,
                name=name,
            )
            self._fixtures.append(entry)
        return entry

    def record_model_call(
        self,
        request: dict[str, Any],
        response: dict[str, Any] | None = None,
        *,
        error: ExecutionError | BaseException | str | None = None,
        name: str | None = None,
        span_id: str | None = None,
    ) -> FixtureEntry:
        """Record a model boundary request/response or error and emit a FixtureEntry."""
        effective_span_id = self._resolve_span_id(span_id)
        prepared_request = self._prepare_dict(request)
        prepared_response = self._prepare_dict(response) if response is not None else None
        exec_error = self._normalize_error(error) if error is not None else None

        self.record_event(
            EventKind.MODEL_REQUEST,
            prepared_request,
            boundary=BoundaryType.MODEL,
            span_id=effective_span_id,
        )
        if exec_error is not None:
            error_payload = ExceptionPayload(
                error=exec_error,
                boundary=BoundaryType.MODEL,
            ).model_dump(mode="json")
            self.record_event(
                EventKind.MODEL_ERROR,
                error_payload,
                boundary=BoundaryType.MODEL,
                span_id=effective_span_id,
            )
        else:
            self.record_event(
                EventKind.MODEL_RESPONSE,
                prepared_response if prepared_response is not None else {},
                boundary=BoundaryType.MODEL,
                span_id=effective_span_id,
            )

        return self._register_fixture(
            boundary=BoundaryType.MODEL,
            request=prepared_request,
            response=prepared_response,
            error=exec_error,
            span_id=effective_span_id,
            name=name,
        )

    def record_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: dict[str, Any] | None = None,
        *,
        error: ExecutionError | BaseException | str | None = None,
        span_id: str | None = None,
    ) -> FixtureEntry:
        """Record a tool boundary call/result or error and emit a FixtureEntry."""
        effective_span_id = self._resolve_span_id(span_id)
        prepared_args = self._prepare_dict(args)
        call_payload = ToolCallPayload(
            tool_name=tool_name,
            arguments=prepared_args,
        ).model_dump(mode="json")
        fixture_request: dict[str, Any] = {
            "tool_name": tool_name,
            "arguments": prepared_args,
        }
        prepared_result = self._prepare_dict(result) if result is not None else None
        exec_error = self._normalize_error(error) if error is not None else None

        self.record_event(
            EventKind.TOOL_CALL,
            call_payload,
            boundary=BoundaryType.TOOL,
            span_id=effective_span_id,
        )
        if exec_error is not None:
            error_payload = ExceptionPayload(
                error=exec_error,
                boundary=BoundaryType.TOOL,
            ).model_dump(mode="json")
            self.record_event(
                EventKind.TOOL_ERROR,
                error_payload,
                boundary=BoundaryType.TOOL,
                span_id=effective_span_id,
            )
        else:
            result_payload = ToolResultPayload(
                tool_name=tool_name,
                result=prepared_result if prepared_result is not None else {},
                is_error=False,
            ).model_dump(mode="json")
            self.record_event(
                EventKind.TOOL_RESULT,
                result_payload,
                boundary=BoundaryType.TOOL,
                span_id=effective_span_id,
            )

        return self._register_fixture(
            boundary=BoundaryType.TOOL,
            request=fixture_request,
            response=prepared_result,
            error=exec_error,
            span_id=effective_span_id,
            name=tool_name,
        )

    def record_retrieval(
        self,
        query: dict[str, Any],
        results: dict[str, Any] | None = None,
        *,
        error: ExecutionError | BaseException | str | None = None,
        name: str | None = None,
        span_id: str | None = None,
    ) -> FixtureEntry:
        """Record a retrieval boundary query/results or error and emit a FixtureEntry."""
        effective_span_id = self._resolve_span_id(span_id)
        prepared_query = self._prepare_dict(query)
        prepared_results = self._prepare_dict(results) if results is not None else None
        exec_error = self._normalize_error(error) if error is not None else None

        self.record_event(
            EventKind.RETRIEVAL_QUERY,
            prepared_query,
            boundary=BoundaryType.RETRIEVAL,
            span_id=effective_span_id,
        )
        if exec_error is not None:
            error_payload = ExceptionPayload(
                error=exec_error,
                boundary=BoundaryType.RETRIEVAL,
            ).model_dump(mode="json")
            self.record_event(
                EventKind.RETRIEVAL_ERROR,
                error_payload,
                boundary=BoundaryType.RETRIEVAL,
                span_id=effective_span_id,
            )
        else:
            self.record_event(
                EventKind.RETRIEVAL_RESULT,
                prepared_results if prepared_results is not None else {},
                boundary=BoundaryType.RETRIEVAL,
                span_id=effective_span_id,
            )

        return self._register_fixture(
            boundary=BoundaryType.RETRIEVAL,
            request=prepared_query,
            response=prepared_results,
            error=exec_error,
            span_id=effective_span_id,
            name=name,
        )

    def record_agent_transition(
        self,
        to_agent: str,
        *,
        from_agent: str | None = None,
        reason: str | None = None,
        handoff_state: dict[str, Any] | None = None,
    ) -> Event:
        """Record a validated agent handoff/transition event."""
        prepared_reason = (
            str(redact_data(reason, self._redaction_config))
            if (reason is not None and self._redact)
            else reason
        )
        prepared_state = self._prepare_dict(handoff_state)
        payload = AgentTransitionPayload(
            from_agent=from_agent,
            to_agent=to_agent,
            reason=prepared_reason,
            handoff_state=prepared_state,
        ).model_dump(mode="json")
        return self.record_event(EventKind.AGENT_TRANSITION, payload)

    def record_state_change(
        self,
        key_path: str,
        operation: Literal["set", "delete", "merge"],
        *,
        before: Any = None,
        after: Any = None,
    ) -> Event:
        """Record a validated state mutation event."""
        prepared_before = self._prepare_value(before)
        prepared_after = self._prepare_value(after)
        payload = StateChangePayload(
            key_path=key_path,
            operation=operation,
            before=prepared_before,
            after=prepared_after,
        ).model_dump(mode="json")
        return self.record_event(EventKind.STATE_CHANGE, payload)

    def record_stream_chunk(
        self,
        stream_id: str,
        chunk_index: int,
        delta: dict[str, Any],
        *,
        is_final: bool = False,
        finish_reason: str | None = None,
        usage: dict[str, int] | None = None,
    ) -> Event:
        """Record a validated incremental streaming chunk event."""
        prepared_delta = self._prepare_dict(delta)
        payload = StreamChunkPayload(
            stream_id=stream_id,
            chunk_index=chunk_index,
            delta=prepared_delta,
            is_final=is_final,
            finish_reason=finish_reason,
            usage=usage,
        ).model_dump(mode="json")
        return self.record_event(EventKind.STREAM_CHUNK, payload)

    def record_error(
        self,
        error: BaseException | ExecutionError | str,
        *,
        boundary: BoundaryType | None = None,
        recoverable: bool = False,
        span_id: str | None = None,
        run_id: str | None = None,
    ) -> Event:
        """Record a validated exception event with redacted error metadata."""
        exec_error = self._normalize_error(error)
        payload = ExceptionPayload(
            error=exec_error,
            boundary=boundary,
            recoverable=recoverable,
        ).model_dump(mode="json")
        return self.record_event(
            EventKind.EXCEPTION,
            payload,
            boundary=boundary,
            span_id=span_id,
            run_id=run_id,
        )

    def set_outputs(self, outputs: dict[str, Any]) -> None:
        """Set redacted, JSON-safe outputs on the currently active run."""
        prepared_outputs = self._prepare_dict(outputs)
        active_run_id = self._resolve_run_id(None)
        with self._lock:
            self._runs_by_id[active_run_id].outputs = prepared_outputs

    def add_tags(self, *tags: str) -> None:
        """Append unique, non-empty tags to the currently active run."""
        active_run_id = self._resolve_run_id(None)
        with self._lock:
            run_record = self._runs_by_id[active_run_id]
            run_record.tags = _dedupe_tags([*run_record.tags, *tags])

    def set_metadata(self, key: str, value: Any) -> None:
        """Set a redacted, JSON-safe metadata key on the active run and trace."""
        prepared = self._prepare_dict({key: value})
        active_run_id = self._resolve_run_id(None)
        with self._lock:
            self._runs_by_id[active_run_id].metadata.update(prepared)
            if active_run_id == self._root_run_id:
                self._trace_metadata.update(prepared)

    def finalize(
        self,
        *,
        status: RunStatus | None = None,
        error: BaseException | ExecutionError | str | None = None,
    ) -> Trace:
        """Finalize the root run (idempotently) and return the built immutable Trace."""
        with self._lock:
            if self._is_finalized and self._trace is not None:
                return self._trace
            root_run = self._runs_by_id[self._root_run_id]
            exec_error = self._normalize_error(error) if error is not None else None
            if exec_error is not None:
                final_status = status if status is not None else RunStatus.FAILED
                root_run.error = exec_error
            else:
                final_status = status if status is not None else RunStatus.COMPLETED
            root_run.status = final_status
            root_run.ended_at = _ensure_ended_at(root_run.started_at)
            self._is_finalized = True

        if final_status == RunStatus.FAILED:
            payload: dict[str, Any] = {
                "name": root_run.name,
                "status": final_status.value,
            }
            if exec_error is not None:
                payload["error"] = exec_error.model_dump(mode="json")
            self.record_event(EventKind.RUN_FAILED, payload, run_id=self._root_run_id)
        else:
            self.record_event(
                EventKind.RUN_COMPLETED,
                {"name": root_run.name, "status": final_status.value},
                run_id=self._root_run_id,
            )

        return self.build_trace()

    def persist(
        self,
        *,
        store: TraceRepository | None = None,
        overwrite: bool | None = None,
    ) -> Path:
        """Persist the captured Trace into the configured or provided TraceRepository."""
        target_store = store if store is not None else self._store
        if target_store is None:
            raise ValueError("No TraceRepository store configured for persistence")
        trace = self._trace if self._trace is not None else self.build_trace()
        effective_overwrite = overwrite if overwrite is not None else self._overwrite
        return target_store.save(trace, overwrite=effective_overwrite)

    def build_trace(self) -> Trace:
        """Construct and cache a validated, immutable canonical Trace snapshot."""
        with self._lock:
            runs = [record.to_model() for record in self._runs]
            spans = [record.to_model() for record in self._spans]
            events = list(self._events)
            fixtures = FixtureSet(entries=list(self._fixtures))
            metadata = dict(self._trace_metadata)

        trace = Trace(
            trace_id=self._trace_id,
            created_at=self._created_at,
            parent_trace_id=self._parent_trace_id,
            runs=runs,
            spans=spans,
            events=events,
            fixtures=fixtures,
            metadata=metadata,
            redaction_applied=self._redact,
        )
        self._trace = trace
        return trace


__all__ = ["CaptureSession"]

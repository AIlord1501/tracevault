"""Offline deterministic replay engine and trace forking for TraceVault."""

from __future__ import annotations

import copy
import threading
import uuid
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from types import TracebackType
from typing import TYPE_CHECKING, Any

from tracevault.replay.matcher import FixtureMatcher
from tracevault.schema import (
    BoundaryMode,
    BoundaryType,
    Event,
    EventKind,
    ExceptionPayload,
    ExecutionError,
    FixtureEntry,
    FixtureSet,
    PolicyViolationError,
    ReplayConfig,
    ReplayError,
    ReplayOverride,
    ReplayResult,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    Trace,
    compute_fingerprint,
    redact_data,
    validate_trace_id,
)

if TYPE_CHECKING:
    from tracevault.storage.repository import TraceRepository


_current_replay_engine: ContextVar[ReplayEngine | None] = ContextVar(
    "tracevault_current_replay_engine",
    default=None,
)


def get_current_replay_engine() -> ReplayEngine | None:
    """Return the active ReplayEngine bound to the current execution context, if any."""
    return _current_replay_engine.get()


def _utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _ensure_ended_at(started_at: datetime) -> datetime:
    """Return a UTC timestamp guaranteed to satisfy ended_at >= started_at."""
    now = _utc_now()
    return now if now >= started_at else started_at


def _boundary_event_kinds(
    boundary: BoundaryType,
    *,
    is_error: bool,
) -> tuple[EventKind, EventKind]:
    """Map a BoundaryType to its canonical (request, response/error) EventKind pair."""
    if boundary == BoundaryType.MODEL:
        return (
            EventKind.MODEL_REQUEST,
            EventKind.MODEL_ERROR if is_error else EventKind.MODEL_RESPONSE,
        )
    if boundary == BoundaryType.TOOL:
        return (
            EventKind.TOOL_CALL,
            EventKind.TOOL_ERROR if is_error else EventKind.TOOL_RESULT,
        )
    if boundary == BoundaryType.RETRIEVAL:
        return (
            EventKind.RETRIEVAL_QUERY,
            EventKind.RETRIEVAL_ERROR if is_error else EventKind.RETRIEVAL_RESULT,
        )
    return (
        EventKind.CUSTOM,
        EventKind.EXCEPTION if is_error else EventKind.CUSTOM,
    )


class ReplayEngine:
    """Offline-first deterministic execution replay engine.

    Never mutates its source Trace and never executes live external calls.
    """

    def __init__(self, trace: Trace, config: ReplayConfig | None = None) -> None:
        resolved_config = config if config is not None else ReplayConfig()
        if resolved_config.trace_id is not None and resolved_config.trace_id != trace.trace_id:
            raise ReplayError(
                f"ReplayConfig.trace_id ({resolved_config.trace_id!r}) does not match "
                f"source trace_id ({trace.trace_id!r})"
            )

        self._trace = trace
        self._config = resolved_config
        self._replay_id = f"rp_{uuid.uuid4().hex[:16]}"
        self._started_at = _utc_now()
        self._ended_at: datetime | None = None

        self._lock = threading.Lock()
        self._matcher = FixtureMatcher(trace.fixtures, resolved_config)
        self._source_span_ids: frozenset[str] = frozenset(span.span_id for span in trace.spans)

        # Replay session metrics & builder state
        self._matched_fixtures: int = 0
        self._overridden_fixtures: int = 0
        self._live_calls: int = 0
        self._missing_fixtures: list[str] = []

        self._recorded_events: list[Event] = []
        self._recorded_fixtures: list[FixtureEntry] = []
        self._used_fixture_ids: set[str] = set()
        self._event_seq: int = 0
        self._fixture_seq: int = 0
        self._live_fp_counts: dict[tuple[BoundaryType, str], int] = {}

        self._context_tokens: list[Token[ReplayEngine | None]] = []

    @classmethod
    def from_store(
        cls,
        store: TraceRepository,
        trace_id: str,
        config: ReplayConfig | None = None,
    ) -> ReplayEngine:
        """Load a Trace from a TraceRepository and construct a ReplayEngine for it."""
        trace = store.load(trace_id)
        return cls(trace, config=config)

    @property
    def trace(self) -> Trace:
        """Return the immutable source Trace."""
        return self._trace

    @property
    def config(self) -> ReplayConfig:
        """Return the ReplayConfig governing this engine."""
        return self._config

    @property
    def replay_id(self) -> str:
        """Return the unique identifier for this replay engine instance."""
        return self._replay_id

    @property
    def started_at(self) -> datetime:
        """Return the UTC timestamp when this replay engine was initialized."""
        return self._started_at

    @property
    def ended_at(self) -> datetime | None:
        """Return the UTC timestamp when replay completed, if finalized."""
        return self._ended_at

    @property
    def matched_fixtures(self) -> int:
        """Return the count of matched fixtures recorded by this engine."""
        with self._lock:
            return self._matched_fixtures

    @property
    def overridden_fixtures(self) -> int:
        """Return the count of overridden fixtures recorded by this engine."""
        with self._lock:
            return self._overridden_fixtures

    @property
    def live_calls(self) -> int:
        """Return the count of authorized live boundary calls recorded by this engine."""
        with self._lock:
            return self._live_calls

    @property
    def missing_fixtures(self) -> list[str]:
        """Return a defensive copy of missing fixture keys encountered during replay."""
        with self._lock:
            return list(self._missing_fixtures)

    def __enter__(self) -> ReplayEngine:
        token = _current_replay_engine.set(self)
        self._context_tokens.append(token)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            self._ended_at = _ensure_ended_at(self._started_at)
        finally:
            if self._context_tokens:
                token = self._context_tokens.pop()
                _current_replay_engine.reset(token)

    def replay_interaction(
        self,
        boundary: BoundaryType,
        request: dict[str, Any],
        *,
        name: str | None = None,
    ) -> dict[str, Any]:
        """Deterministically replay a single offline boundary interaction."""
        boundary_mode = self._config.boundary_modes.get(boundary, BoundaryMode.RECORDED)
        if boundary_mode == BoundaryMode.DENY:
            raise PolicyViolationError(
                f"Boundary '{boundary.value}' is denied by ReplayConfig.boundary_modes"
            )
        if boundary_mode == BoundaryMode.LIVE:
            raise PolicyViolationError(
                "Offline ReplayEngine never executes live boundaries; "
                "use BoundaryExecutor with explicit SafetyPolicy"
            )

        match_result = self._matcher.match(boundary, request, name=name)
        redacted_request: dict[str, Any] = redact_data(request)

        with self._lock:
            if match_result.matched:
                self._matched_fixtures += 1
                if match_result.overridden:
                    self._overridden_fixtures += 1
            else:
                missing_key = (
                    f"{boundary.value}:{name or '*'}:"
                    f"{match_result.fingerprint[:12]}:{match_result.call_index}"
                )
                self._missing_fixtures.append(missing_key)

            span_id = (
                match_result.entry.span_id
                if (
                    match_result.entry is not None
                    and match_result.entry.span_id in self._source_span_ids
                )
                else None
            )
            effective_name = name or (
                match_result.entry.name if match_result.entry is not None else None
            )
            preferred_fixture_id = (
                match_result.entry.fixture_id if match_result.entry is not None else None
            )

            self._append_interaction_locked(
                boundary=boundary,
                fingerprint=match_result.fingerprint,
                call_index=match_result.call_index,
                request=redacted_request,
                response=match_result.response,
                error=match_result.error,
                span_id=span_id,
                name=effective_name,
                preferred_fixture_id=preferred_fixture_id,
                metadata={
                    "replay_strategy": match_result.match_strategy,
                    "overridden": match_result.overridden,
                },
            )

        if match_result.error is not None and match_result.response is None:
            raise ReplayError(match_result.error.message)

        return copy.deepcopy(match_result.response) if match_result.response is not None else {}

    def _record_live_interaction(
        self,
        *,
        boundary: BoundaryType,
        request: dict[str, Any],
        response: dict[str, Any],
        name: str | None = None,
    ) -> None:
        """Record an authorized live boundary call onto the candidate trace builder."""
        redacted_request: dict[str, Any] = redact_data(request)
        redacted_response: dict[str, Any] = redact_data(response)
        fp = compute_fingerprint(boundary, redacted_request)

        with self._lock:
            self._live_calls += 1
            key = (boundary, fp)
            call_index = self._live_fp_counts.get(key, 0)
            self._live_fp_counts[key] = call_index + 1

            self._append_interaction_locked(
                boundary=boundary,
                fingerprint=fp,
                call_index=call_index,
                request=redacted_request,
                response=redacted_response,
                error=None,
                span_id=None,
                name=name,
                preferred_fixture_id=None,
                metadata={"replay_strategy": "live", "overridden": False},
            )

    def replay_trace(
        self,
        *,
        fork: bool = False,
        new_trace_id: str | None = None,
    ) -> ReplayResult:
        """Replay all recorded fixtures in the source trace sequentially and build ReplayResult."""
        candidate_trace_id = (
            validate_trace_id(new_trace_id)
            if new_trace_id is not None
            else f"tr_rp_{uuid.uuid4().hex[:16]}"
        )
        run_started = _utc_now()
        matcher = FixtureMatcher(self._trace.fixtures, self._config)

        matched_count = 0
        overridden_count = 0
        missing_keys: list[str] = []
        replay_error: ExecutionError | None = None
        error_span_id: str | None = None

        replayed_events: list[Event] = []
        replayed_fixtures: list[FixtureEntry] = []
        used_fixture_ids: set[str] = set()
        event_seq = 0
        fixture_seq = 0
        root_run_id = self._trace.root_run.run_id

        for entry in self._trace.fixtures.entries:
            boundary_mode = self._config.boundary_modes.get(
                entry.boundary,
                BoundaryMode.RECORDED,
            )
            if boundary_mode == BoundaryMode.DENY:
                raise PolicyViolationError(
                    f"Boundary '{entry.boundary.value}' is denied by ReplayConfig.boundary_modes"
                )
            if boundary_mode == BoundaryMode.LIVE:
                raise PolicyViolationError(
                    "Offline ReplayEngine never executes live boundaries; "
                    "use BoundaryExecutor with explicit SafetyPolicy"
                )

            match_result = matcher.match(
                entry.boundary,
                copy.deepcopy(entry.request),
                name=entry.name,
            )

            if match_result.matched:
                matched_count += 1
                if match_result.overridden:
                    overridden_count += 1
            else:
                missing_keys.append(
                    f"{entry.boundary.value}:{entry.name or '*'}:"
                    f"{match_result.fingerprint[:12]}:{match_result.call_index}"
                )

            span_id = entry.span_id if entry.span_id in self._source_span_ids else None
            redacted_request: dict[str, Any] = redact_data(copy.deepcopy(entry.request))
            is_error = match_result.error is not None and match_result.response is None

            req_kind, res_kind = _boundary_event_kinds(entry.boundary, is_error=is_error)
            now = _utc_now()

            replayed_events.append(
                Event(
                    event_id=f"ev_rp_{event_seq:04d}",
                    run_id=root_run_id,
                    span_id=span_id,
                    event_type=req_kind,
                    boundary=entry.boundary,
                    timestamp=now,
                    sequence=event_seq,
                    payload=redacted_request,
                    metadata={
                        "replay_strategy": match_result.match_strategy,
                        "overridden": match_result.overridden,
                    },
                )
            )
            event_seq += 1

            if is_error and match_result.error is not None:
                res_payload: dict[str, Any] = ExceptionPayload(
                    error=match_result.error,
                    boundary=entry.boundary,
                ).model_dump(mode="json")
            else:
                res_payload = (
                    copy.deepcopy(match_result.response)
                    if match_result.response is not None
                    else {}
                )

            replayed_events.append(
                Event(
                    event_id=f"ev_rp_{event_seq:04d}",
                    run_id=root_run_id,
                    span_id=span_id,
                    event_type=res_kind,
                    boundary=entry.boundary,
                    timestamp=_utc_now(),
                    sequence=event_seq,
                    payload=res_payload,
                    metadata={
                        "replay_strategy": match_result.match_strategy,
                        "overridden": match_result.overridden,
                    },
                )
            )
            event_seq += 1

            fixture_id = entry.fixture_id
            if fixture_id in used_fixture_ids:
                fixture_seq += 1
                fixture_id = f"fix_rp_{fixture_seq:04d}"
            used_fixture_ids.add(fixture_id)

            replayed_fixtures.append(
                FixtureEntry(
                    fixture_id=fixture_id,
                    boundary=entry.boundary,
                    fingerprint=match_result.fingerprint,
                    call_index=match_result.call_index,
                    request=redacted_request,
                    response=copy.deepcopy(match_result.response)
                    if match_result.response is not None
                    else None,
                    error=match_result.error,
                    span_id=span_id,
                    name=entry.name,
                )
            )

            if is_error:
                replay_error = match_result.error
                error_span_id = span_id
                break

        run_ended = _ensure_ended_at(run_started)
        with self._lock:
            self._matched_fixtures = matched_count
            self._overridden_fixtures = overridden_count
            self._missing_fixtures = list(missing_keys)
            self._ended_at = run_ended

        candidate_trace = self._build_candidate_trace(
            candidate_trace_id=candidate_trace_id,
            events=replayed_events,
            fixtures=replayed_fixtures,
            fork=fork,
            started_at=run_started,
            ended_at=run_ended,
            error=replay_error,
            error_span_id=error_span_id,
            preserve_source_events_if_empty=True,
        )

        return ReplayResult(
            baseline_trace_id=self._trace.trace_id,
            candidate_trace=candidate_trace,
            mode=self._config.mode,
            matched_fixtures=matched_count,
            overridden_fixtures=overridden_count,
            live_calls=0,
            missing_fixtures=missing_keys,
            success=replay_error is None,
            error=replay_error,
        )

    def fork(
        self,
        *,
        overrides: dict[str, Any] | None = None,
        override_rules: list[ReplayOverride] | None = None,
        new_trace_id: str | None = None,
    ) -> Trace:
        """Create a forked, non-frozen candidate Trace with optional merged overrides."""
        merged_overrides = copy.deepcopy(self._config.overrides)
        if overrides:
            merged_overrides.update(copy.deepcopy(overrides))

        merged_rules = [*(override_rules or []), *self._config.override_rules]

        fork_config = ReplayConfig(
            trace_id=self._trace.trace_id,
            mode=self._config.mode,
            fail_on_missing_fixture=self._config.fail_on_missing_fixture,
            boundary_modes=dict(self._config.boundary_modes),
            safety_policy=self._config.safety_policy,
            overrides=merged_overrides,
            override_rules=merged_rules,
            deterministic_seed=self._config.deterministic_seed,
        )
        fork_engine = ReplayEngine(self._trace, config=fork_config)
        result = fork_engine.replay_trace(fork=True, new_trace_id=new_trace_id)
        return result.candidate_trace

    def build_result(
        self,
        *,
        fork: bool = False,
        new_trace_id: str | None = None,
        error: ExecutionError | None = None,
    ) -> ReplayResult:
        """Build a ReplayResult from interactive replay calls recorded on this engine."""
        candidate_trace_id = (
            validate_trace_id(new_trace_id)
            if new_trace_id is not None
            else f"tr_rp_{uuid.uuid4().hex[:16]}"
        )
        ended_at = _ensure_ended_at(self._started_at)

        with self._lock:
            self._ended_at = ended_at
            events = list(self._recorded_events)
            fixtures = list(self._recorded_fixtures)
            matched = self._matched_fixtures
            overridden = self._overridden_fixtures
            live_calls = self._live_calls
            missing = list(self._missing_fixtures)

        candidate_trace = self._build_candidate_trace(
            candidate_trace_id=candidate_trace_id,
            events=events,
            fixtures=fixtures,
            fork=fork,
            started_at=self._started_at,
            ended_at=ended_at,
            error=error,
            error_span_id=None,
            preserve_source_events_if_empty=False,
        )

        return ReplayResult(
            baseline_trace_id=self._trace.trace_id,
            candidate_trace=candidate_trace,
            mode=self._config.mode,
            matched_fixtures=matched,
            overridden_fixtures=overridden,
            live_calls=live_calls,
            missing_fixtures=missing,
            success=error is None,
            error=error,
        )

    def _append_interaction_locked(
        self,
        *,
        boundary: BoundaryType,
        fingerprint: str,
        call_index: int,
        request: dict[str, Any],
        response: dict[str, Any] | None,
        error: ExecutionError | None,
        span_id: str | None,
        name: str | None,
        preferred_fixture_id: str | None,
        metadata: dict[str, Any],
    ) -> None:
        root_run_id = self._trace.root_run.run_id
        is_error = error is not None and response is None
        req_kind, res_kind = _boundary_event_kinds(boundary, is_error=is_error)

        self._recorded_events.append(
            Event(
                event_id=f"ev_rp_{self._event_seq:04d}",
                run_id=root_run_id,
                span_id=span_id,
                event_type=req_kind,
                boundary=boundary,
                timestamp=_utc_now(),
                sequence=self._event_seq,
                payload=copy.deepcopy(request),
                metadata=copy.deepcopy(metadata),
            )
        )
        self._event_seq += 1

        if is_error and error is not None:
            res_payload: dict[str, Any] = ExceptionPayload(
                error=error,
                boundary=boundary,
            ).model_dump(mode="json")
        else:
            res_payload = copy.deepcopy(response) if response is not None else {}

        self._recorded_events.append(
            Event(
                event_id=f"ev_rp_{self._event_seq:04d}",
                run_id=root_run_id,
                span_id=span_id,
                event_type=res_kind,
                boundary=boundary,
                timestamp=_utc_now(),
                sequence=self._event_seq,
                payload=res_payload,
                metadata=copy.deepcopy(metadata),
            )
        )
        self._event_seq += 1

        if preferred_fixture_id is not None and preferred_fixture_id not in self._used_fixture_ids:
            fixture_id = preferred_fixture_id
        else:
            self._fixture_seq += 1
            fixture_id = f"fix_rp_{self._fixture_seq:04d}"
            while fixture_id in self._used_fixture_ids:
                self._fixture_seq += 1
                fixture_id = f"fix_rp_{self._fixture_seq:04d}"
        self._used_fixture_ids.add(fixture_id)

        self._recorded_fixtures.append(
            FixtureEntry(
                fixture_id=fixture_id,
                boundary=boundary,
                fingerprint=fingerprint,
                call_index=call_index,
                request=copy.deepcopy(request),
                response=copy.deepcopy(response) if response is not None else None,
                error=error,
                span_id=span_id,
                name=name,
            )
        )

    def _build_candidate_trace(
        self,
        *,
        candidate_trace_id: str,
        events: list[Event],
        fixtures: list[FixtureEntry],
        fork: bool,
        started_at: datetime,
        ended_at: datetime,
        error: ExecutionError | None,
        error_span_id: str | None,
        preserve_source_events_if_empty: bool,
    ) -> Trace:
        root_run_id = self._trace.root_run.run_id
        candidate_runs: list[Run] = []
        for run in self._trace.runs:
            if error is not None and run.run_id == root_run_id:
                candidate_runs.append(
                    Run(
                        run_id=run.run_id,
                        trace_id=candidate_trace_id,
                        parent_run_id=run.parent_run_id,
                        name=run.name,
                        started_at=run.started_at,
                        ended_at=_ensure_ended_at(run.started_at),
                        status=RunStatus.FAILED,
                        inputs=copy.deepcopy(run.inputs),
                        outputs=copy.deepcopy(run.outputs) if run.outputs is not None else None,
                        error=error,
                        environment=dict(run.environment),
                        tags=list(run.tags),
                        metadata=copy.deepcopy(run.metadata),
                    )
                )
            else:
                candidate_runs.append(
                    Run(
                        run_id=run.run_id,
                        trace_id=candidate_trace_id,
                        parent_run_id=run.parent_run_id,
                        name=run.name,
                        started_at=run.started_at,
                        ended_at=run.ended_at,
                        status=run.status,
                        inputs=copy.deepcopy(run.inputs),
                        outputs=copy.deepcopy(run.outputs) if run.outputs is not None else None,
                        error=run.error,
                        environment=dict(run.environment),
                        tags=list(run.tags),
                        metadata=copy.deepcopy(run.metadata),
                    )
                )

        if not events and preserve_source_events_if_empty:
            final_events = list(self._trace.events)
        else:
            final_events = events

        span_event_ids: dict[str, list[str]] = {}
        for event in final_events:
            if event.span_id is not None:
                span_event_ids.setdefault(event.span_id, []).append(event.event_id)

        candidate_spans: list[Span] = []
        for span in self._trace.spans:
            if error is not None and error_span_id is not None and span.span_id == error_span_id:
                span_status = SpanStatus.ERROR
                span_error: ExecutionError | None = error
            else:
                span_status = span.status
                span_error = span.error

            candidate_spans.append(
                Span(
                    span_id=span.span_id,
                    run_id=span.run_id,
                    parent_span_id=span.parent_span_id,
                    span_type=span.span_type,
                    boundary=span.boundary,
                    name=span.name,
                    started_at=span.started_at,
                    ended_at=span.ended_at,
                    status=span_status,
                    attributes=copy.deepcopy(span.attributes),
                    error=span_error,
                    event_ids=span_event_ids.get(span.span_id, []),
                )
            )

        candidate_metadata = copy.deepcopy(self._trace.metadata)
        candidate_metadata["replay"] = {
            "replay_id": self._replay_id,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": round((ended_at - started_at).total_seconds() * 1000.0, 3),
            "mode": self._config.mode.value,
            "source_trace_id": self._trace.trace_id,
        }

        return Trace(
            trace_id=candidate_trace_id,
            created_at=ended_at,
            frozen=False,
            parent_trace_id=self._trace.trace_id if fork else None,
            runs=candidate_runs,
            spans=candidate_spans,
            events=final_events,
            fixtures=FixtureSet(
                version=self._trace.fixtures.version,
                entries=fixtures,
            ),
            metadata=candidate_metadata,
            redaction_applied=True,
        )


__all__ = [
    "ReplayEngine",
    "get_current_replay_engine",
]

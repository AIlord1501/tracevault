"""Shared pytest fixtures and hostile-payload builders for TraceVault tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tracevault.schema import (
    BoundaryType,
    Event,
    EventKind,
    ExecutionError,
    FixtureEntry,
    FixtureSet,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    Trace,
    compute_fingerprint,
)

# Synthetic placeholder secrets ONLY — never real credentials.
SYNTHETIC_SECRETS: dict[str, str] = {
    "openai_key": "sk-test-fake-0000000000000000",
    "openai_proj_key": "sk-proj-fake-11111111111111111111",
    "bearer_token": "Bearer tok_fake_00000000000000000000",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "github_pat": "ghp_000000000000000000000000000000000000",
    "jwt_token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJ0ZXN0LXVzZXIiLCJyb2xlIjoiZGV2In0"
        ".fakesignature000000000000000000000000000000"
    ),
}

HOSTILE_TRACE_IDS: list[Any] = [
    "",
    ".",
    "..",
    "../etc/passwd",
    "..\\windows\\system32",
    "a/b",
    "a\\b",
    "foo\x00bar",
    "valid_id\n",
    "valid_id\r",
    "valid_id\r\n",
    "-leading-dash",
    "_leading_underscore",
    "has spaces",
    "has.dot",
    "a" * 129,
    "tr_\u0430bc",  # Cyrillic 'а' lookalike
    "tr_\uff21BC",  # Fullwidth 'Ａ'
    "tr_\u0660123",  # Arabic-Indic digit
    "tr_emoji_\U0001f680",
    None,
    12345,
    ["tr_list"],
    {"trace_id": "tr_dict"},
]


def make_utc_timestamp(offset_seconds: float = 0.0) -> datetime:
    """Return a deterministic timezone-aware UTC timestamp."""
    base = datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC)
    return base + timedelta(seconds=offset_seconds)


def make_valid_run(
    *,
    run_id: str = "run_001",
    trace_id: str = "tr_valid_001",
    parent_run_id: str | None = None,
    name: str = "support_triage_agent",
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    status: RunStatus = RunStatus.COMPLETED,
    inputs: dict[str, Any] | None = None,
    outputs: dict[str, Any] | None = None,
    error: ExecutionError | None = None,
    environment: dict[str, str] | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Run:
    """Construct a valid canonical Run model."""
    start = started_at or make_utc_timestamp(0.0)
    end = ended_at if ended_at is not None else make_utc_timestamp(1.0)
    return Run(
        run_id=run_id,
        trace_id=trace_id,
        parent_run_id=parent_run_id,
        name=name,
        started_at=start,
        ended_at=end,
        status=status,
        inputs=inputs if inputs is not None else {"ticket": "Billing error on invoice #42"},
        outputs=outputs if outputs is not None else {"category": "billing"},
        error=error,
        environment=environment if environment is not None else {"python": "3.12.10"},
        tags=tags if tags is not None else ["triage"],
        metadata=metadata if metadata is not None else {},
    )


def make_valid_span(
    *,
    span_id: str = "sp_001",
    run_id: str = "run_001",
    parent_span_id: str | None = None,
    span_type: SpanType = SpanType.MODEL,
    boundary: BoundaryType | None = BoundaryType.MODEL,
    name: str = "openai.chat.completions",
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    status: SpanStatus = SpanStatus.OK,
    attributes: dict[str, Any] | None = None,
    error: ExecutionError | None = None,
    event_ids: list[str] | None = None,
) -> Span:
    """Construct a valid canonical Span model."""
    return Span(
        span_id=span_id,
        run_id=run_id,
        parent_span_id=parent_span_id,
        span_type=span_type,
        boundary=boundary,
        name=name,
        started_at=started_at or make_utc_timestamp(0.1),
        ended_at=ended_at if ended_at is not None else make_utc_timestamp(0.9),
        status=status,
        attributes=attributes if attributes is not None else {"model": "gpt-4o-mini"},
        error=error,
        event_ids=event_ids if event_ids is not None else ["ev_001", "ev_002"],
    )


def make_valid_event(
    *,
    event_id: str = "ev_001",
    run_id: str = "run_001",
    span_id: str | None = "sp_001",
    event_type: EventKind = EventKind.MODEL_REQUEST,
    boundary: BoundaryType | None = BoundaryType.MODEL,
    timestamp: datetime | None = None,
    sequence: int = 0,
    payload: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Event:
    """Construct a valid canonical Event model."""
    return Event(
        event_id=event_id,
        run_id=run_id,
        span_id=span_id,
        event_type=event_type,
        boundary=boundary,
        timestamp=timestamp or make_utc_timestamp(0.1),
        sequence=sequence,
        payload=payload
        if payload is not None
        else {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Classify invoice #42"}],
            "parameters": {"temperature": 0.0},
            "tools": [],
            "stream": False,
        },
        metadata=metadata if metadata is not None else {},
    )


def make_valid_fixture_entry(
    *,
    fixture_id: str = "fix_001",
    boundary: BoundaryType = BoundaryType.MODEL,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    error: ExecutionError | None = None,
    call_index: int = 0,
    span_id: str | None = "sp_001",
    name: str | None = "openai.chat.completions",
) -> FixtureEntry:
    """Construct a valid canonical FixtureEntry with a deterministic SHA-256 fingerprint."""
    req = (
        request
        if request is not None
        else {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Classify invoice #42"}],
        }
    )
    resp = (
        response
        if response is not None or error is not None
        else {"model": "gpt-4o-mini", "content": "billing", "finish_reason": "stop"}
    )
    return FixtureEntry(
        fixture_id=fixture_id,
        boundary=boundary,
        fingerprint=compute_fingerprint(boundary, req),
        call_index=call_index,
        request=req,
        response=resp,
        error=error,
        span_id=span_id,
        name=name,
    )


def make_valid_fixture_set(entries: list[FixtureEntry] | None = None) -> FixtureSet:
    """Construct a valid canonical FixtureSet."""
    return FixtureSet(entries=entries if entries is not None else [make_valid_fixture_entry()])


def make_valid_trace(
    *,
    trace_id: str = "tr_valid_001",
    frozen: bool = False,
    parent_trace_id: str | None = None,
    runs: list[Run] | None = None,
    spans: list[Span] | None = None,
    events: list[Event] | None = None,
    fixtures: FixtureSet | None = None,
    metadata: dict[str, Any] | None = None,
    redaction_applied: bool = True,
) -> Trace:
    """Construct a fully valid, self-consistent canonical Trace."""
    resolved_runs = runs if runs is not None else [make_valid_run(trace_id=trace_id)]
    root_run_id = resolved_runs[0].run_id
    resolved_events = (
        events
        if events is not None
        else [
            make_valid_event(
                event_id="ev_001",
                run_id=root_run_id,
                span_id="sp_001",
                event_type=EventKind.MODEL_REQUEST,
                boundary=BoundaryType.MODEL,
                timestamp=make_utc_timestamp(0.1),
                sequence=0,
            ),
            make_valid_event(
                event_id="ev_002",
                run_id=root_run_id,
                span_id="sp_001",
                event_type=EventKind.MODEL_RESPONSE,
                boundary=BoundaryType.MODEL,
                timestamp=make_utc_timestamp(0.9),
                sequence=1,
                payload={
                    "model": "gpt-4o-mini",
                    "content": "billing",
                    "tool_calls": [],
                    "finish_reason": "stop",
                    "usage": {"prompt_tokens": 18, "completion_tokens": 2, "total_tokens": 20},
                    "raw_metadata": {},
                },
            ),
        ]
    )
    resolved_spans = (
        spans
        if spans is not None
        else [
            make_valid_span(
                span_id="sp_001",
                run_id=root_run_id,
                event_ids=[ev.event_id for ev in resolved_events if ev.span_id == "sp_001"],
            )
        ]
    )
    return Trace(
        trace_id=trace_id,
        created_at=make_utc_timestamp(0.0),
        frozen=frozen,
        parent_trace_id=parent_trace_id,
        runs=resolved_runs,
        spans=resolved_spans,
        events=resolved_events,
        fixtures=fixtures if fixtures is not None else make_valid_fixture_set(),
        metadata=metadata if metadata is not None else {},
        redaction_applied=redaction_applied,
    )


def make_deeply_nested_dict(depth: int) -> dict[str, Any]:
    """Build a nested dictionary of exact container depth."""
    current: Any = "leaf"
    for _ in range(depth):
        current = {"nested": current}
    return current  # type: ignore[return-value]


@pytest.fixture
def valid_trace() -> Trace:
    """Return a canonical valid Trace fixture."""
    return make_valid_trace()


@pytest.fixture
def valid_run() -> Run:
    """Return a canonical valid Run fixture."""
    return make_valid_run()


@pytest.fixture
def valid_span() -> Span:
    """Return a canonical valid Span fixture."""
    return make_valid_span()


@pytest.fixture
def valid_event() -> Event:
    """Return a canonical valid Event fixture."""
    return make_valid_event()


@pytest.fixture
def valid_fixture_entry() -> FixtureEntry:
    """Return a canonical valid FixtureEntry fixture."""
    return make_valid_fixture_entry()


@pytest.fixture
def valid_fixture_set() -> FixtureSet:
    """Return a canonical valid FixtureSet fixture."""
    return make_valid_fixture_set()


@pytest.fixture
def hostile_trace_ids() -> list[Any]:
    """Return a list of hostile, path-traversal, and malformed trace IDs."""
    return list(HOSTILE_TRACE_IDS)


@pytest.fixture
def synthetic_secrets() -> dict[str, str]:
    """Return synthetic placeholder secrets for redaction testing."""
    return dict(SYNTHETIC_SECRETS)

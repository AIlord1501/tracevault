"""Comprehensive unit tests for tracevault.diff.engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tracevault.diff import (
    DEFAULT_SEVERITY_MAP,
    DiffEngine,
    diff_traces,
    find_earliest_divergence,
    format_diff_json,
)
from tracevault.replay import ReplayEngine
from tracevault.schema import (
    BoundaryType,
    DiffConfig,
    DivergenceKind,
    DivergenceSeverity,
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

T0 = datetime(2026, 11, 24, 0, 0, 0, tzinfo=UTC)


def _make_trace(
    *,
    trace_id: str = "tr_base_001",
    created_at: datetime = T0,
    frozen: bool = True,
    parent_trace_id: str | None = None,
    runs: list[Run] | None = None,
    spans: list[Span] | None = None,
    events: list[Event] | None = None,
    fixtures: list[FixtureEntry] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Trace:
    if runs is None:
        runs = [
            Run(
                run_id="run_001",
                trace_id=trace_id,
                name="triage_agent",
                started_at=created_at,
                ended_at=created_at + timedelta(seconds=1),
                status=RunStatus.COMPLETED,
                inputs={"ticket": "invoice-42"},
                outputs={"category": "billing", "total": 100},
                metadata={"env": "test"},
            )
        ]
    return Trace(
        trace_id=trace_id,
        created_at=created_at,
        frozen=frozen,
        parent_trace_id=parent_trace_id,
        runs=runs,
        spans=spans if spans is not None else [],
        events=events if events is not None else [],
        fixtures=FixtureSet(entries=fixtures if fixtures is not None else []),
        metadata=metadata if metadata is not None else {},
    )


def _make_model_trace(
    *,
    trace_id: str = "tr_model_001",
    run_id: str = "run_001",
    span_id: str = "sp_001",
    ev1_id: str = "ev_001",
    ev2_id: str = "ev_002",
    fix_id: str = "fix_001",
    created_at: datetime = T0,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    outputs: dict[str, Any] | None = None,
    status: RunStatus = RunStatus.COMPLETED,
    span_status: SpanStatus = SpanStatus.OK,
    frozen: bool = True,
) -> Trace:
    req = request if request is not None else {"model": "gpt-4o-mini", "prompt": "classify #42"}
    res = response if response is not None else {"content": "billing", "finish_reason": "stop"}
    fp = compute_fingerprint(BoundaryType.MODEL, req)

    run = Run(
        run_id=run_id,
        trace_id=trace_id,
        name="triage_agent",
        started_at=created_at,
        ended_at=created_at + timedelta(seconds=1),
        status=status,
        inputs={"ticket": "invoice-42"},
        outputs=outputs if outputs is not None else {"category": "billing"},
    )
    span = Span(
        span_id=span_id,
        run_id=run_id,
        span_type=SpanType.MODEL,
        boundary=BoundaryType.MODEL,
        name="openai.chat",
        started_at=created_at + timedelta(milliseconds=100),
        ended_at=created_at + timedelta(milliseconds=900),
        status=span_status,
        attributes={"model": "gpt-4o-mini"},
        event_ids=[ev1_id, ev2_id],
    )
    ev1 = Event(
        event_id=ev1_id,
        run_id=run_id,
        span_id=span_id,
        event_type=EventKind.MODEL_REQUEST,
        boundary=BoundaryType.MODEL,
        timestamp=created_at + timedelta(milliseconds=100),
        sequence=0,
        payload=req,
    )
    ev2 = Event(
        event_id=ev2_id,
        run_id=run_id,
        span_id=span_id,
        event_type=EventKind.MODEL_RESPONSE,
        boundary=BoundaryType.MODEL,
        timestamp=created_at + timedelta(milliseconds=900),
        sequence=1,
        payload=res,
    )
    fix = FixtureEntry(
        fixture_id=fix_id,
        boundary=BoundaryType.MODEL,
        fingerprint=fp,
        call_index=0,
        request=req,
        response=res,
        span_id=span_id,
        name="openai.chat",
    )
    return _make_trace(
        trace_id=trace_id,
        created_at=created_at,
        frozen=frozen,
        runs=[run],
        spans=[span],
        events=[ev1, ev2],
        fixtures=[fix],
    )


def test_default_severity_map_covers_all_divergence_kinds() -> None:
    assert set(DEFAULT_SEVERITY_MAP.keys()) == set(DivergenceKind)
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.STATUS_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.OUTPUT_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.ERROR_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.SPAN_REMOVED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.SPAN_STATUS_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.MODEL_OUTPUT_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.TOOL_ARGS_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.TOOL_RESULT_CHANGED] == DivergenceSeverity.BREAKING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.FIXTURE_MISMATCH] == DivergenceSeverity.BREAKING

    assert DEFAULT_SEVERITY_MAP[DivergenceKind.SPAN_ADDED] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.SPAN_ORDER_CHANGED] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.MODEL_INPUT_CHANGED] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.RETRIEVAL_CHANGED] == DivergenceSeverity.WARNING
    assert (
        DEFAULT_SEVERITY_MAP[DivergenceKind.AGENT_TRANSITION_CHANGED] == DivergenceSeverity.WARNING
    )
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.STATE_CHANGE_MISMATCH] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.EVENT_ADDED] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.EVENT_REMOVED] == DivergenceSeverity.WARNING
    assert DEFAULT_SEVERITY_MAP[DivergenceKind.EVENT_PAYLOAD_CHANGED] == DivergenceSeverity.WARNING


def test_identical_traces_with_regenerated_ids_and_timestamps() -> None:
    baseline = _make_model_trace(
        trace_id="tr_base_001",
        run_id="run_a",
        span_id="sp_a",
        ev1_id="ev_a1",
        ev2_id="ev_a2",
        fix_id="fix_a1",
        created_at=T0,
    )
    candidate = _make_model_trace(
        trace_id="tr_cand_999",
        run_id="run_b",
        span_id="sp_b",
        ev1_id="ev_b1",
        ev2_id="ev_b2",
        fix_id="fix_b1",
        created_at=T0 + timedelta(hours=2),
        frozen=False,
    )

    report = diff_traces(baseline, candidate)
    assert report.identical is True
    assert report.has_breaking is False
    assert report.divergences == []
    assert report.summary == {"info": 0, "warning": 0, "breaking": 0, "total": 0}
    assert report.baseline_trace_id == "tr_base_001"
    assert report.candidate_trace_id == "tr_cand_999"


def test_unmodified_replay_produces_identical_diff_and_override_produces_breaking() -> None:
    baseline = _make_model_trace(trace_id="tr_replay_base")
    replay_result = ReplayEngine(baseline).replay_trace()
    assert replay_result.success is True

    report = diff_traces(baseline, replay_result.candidate_trace)
    assert report.identical is True
    assert report.has_breaking is False
    assert report.divergences == []

    forked = ReplayEngine(baseline).fork(
        overrides={"fix_001": {"content": "refund", "finish_reason": "stop"}},
        new_trace_id="tr_replay_fork",
    )
    fork_report = diff_traces(baseline, forked)
    assert fork_report.identical is False
    assert fork_report.has_breaking is True
    kinds = {d.kind for d in fork_report.divergences}
    assert DivergenceKind.MODEL_OUTPUT_CHANGED in kinds
    assert DivergenceKind.FIXTURE_MISMATCH in kinds


def test_run_status_output_and_error_changes() -> None:
    baseline = _make_trace(
        trace_id="tr_run_base",
        runs=[
            Run(
                run_id="run_1",
                trace_id="tr_run_base",
                name="agent",
                started_at=T0,
                ended_at=T0 + timedelta(seconds=1),
                status=RunStatus.COMPLETED,
                outputs={"total": 100, "items": ["a", "b"], "flag": True},
            )
        ],
    )
    candidate = _make_trace(
        trace_id="tr_run_cand",
        runs=[
            Run(
                run_id="run_2",
                trace_id="tr_run_cand",
                name="agent",
                started_at=T0,
                ended_at=T0 + timedelta(seconds=1),
                status=RunStatus.FAILED,
                outputs={"total": 250, "items": ["a", "c", "d"], "flag": 1},
                error=ExecutionError(error_type="RuntimeError", message="boom"),
            )
        ],
    )

    report = diff_traces(baseline, candidate)
    assert report.identical is False
    assert report.has_breaking is True

    by_path = {d.path: d for d in report.divergences}
    assert by_path["runs[0].status"].kind == DivergenceKind.STATUS_CHANGED
    assert by_path["runs[0].status"].severity == DivergenceSeverity.BREAKING
    assert by_path["runs[0].outputs.total"].kind == DivergenceKind.OUTPUT_CHANGED
    assert by_path["runs[0].outputs.items[1]"].kind == DivergenceKind.OUTPUT_CHANGED
    assert by_path["runs[0].outputs.items[2]"].kind == DivergenceKind.OUTPUT_CHANGED
    assert by_path["runs[0].outputs.flag"].kind == DivergenceKind.OUTPUT_CHANGED
    assert by_path["runs[0].error"].kind == DivergenceKind.ERROR_CHANGED
    assert by_path["runs[0].error"].severity == DivergenceSeverity.BREAKING


def test_span_added_removed_reordered_and_status_changed() -> None:
    sp_a = Span(
        span_id="sp_a",
        run_id="run_001",
        span_type=SpanType.AGENT,
        name="planner",
        started_at=T0,
        status=SpanStatus.OK,
    )
    sp_b = Span(
        span_id="sp_b",
        run_id="run_001",
        span_type=SpanType.TOOL,
        name="search",
        started_at=T0,
        status=SpanStatus.OK,
    )
    sp_c = Span(
        span_id="sp_c",
        run_id="run_001",
        span_type=SpanType.MODEL,
        name="summarize",
        started_at=T0,
        status=SpanStatus.OK,
    )

    baseline = _make_trace(trace_id="tr_sp_base", spans=[sp_a, sp_b, sp_c])

    # Candidate: sp_b removed, sp_c moved before sp_a, sp_a status ERROR, sp_d added
    sp_c_cand = sp_c.model_copy(update={"span_id": "sp_c_new"})
    sp_a_cand = sp_a.model_copy(
        update={
            "span_id": "sp_a_new",
            "status": SpanStatus.ERROR,
            "error": ExecutionError(error_type="ValueError", message="bad plan"),
        }
    )
    sp_d_cand = Span(
        span_id="sp_d_new",
        run_id="run_001",
        span_type=SpanType.RETRIEVAL,
        name="kb_lookup",
        started_at=T0,
        status=SpanStatus.OK,
    )
    candidate = _make_trace(trace_id="tr_sp_cand", spans=[sp_c_cand, sp_a_cand, sp_d_cand])

    strict_report = diff_traces(baseline, candidate)
    kinds = [d.kind for d in strict_report.divergences]
    assert DivergenceKind.SPAN_REMOVED in kinds
    assert DivergenceKind.SPAN_ADDED in kinds
    assert DivergenceKind.SPAN_ORDER_CHANGED in kinds
    assert DivergenceKind.SPAN_STATUS_CHANGED in kinds
    assert DivergenceKind.ERROR_CHANGED in kinds

    # strict_order=False suppresses SPAN_ORDER_CHANGED
    relaxed_report = diff_traces(baseline, candidate, config=DiffConfig(strict_order=False))
    relaxed_kinds = [d.kind for d in relaxed_report.divergences]
    assert DivergenceKind.SPAN_ORDER_CHANGED not in relaxed_kinds
    assert DivergenceKind.SPAN_REMOVED in relaxed_kinds
    assert DivergenceKind.SPAN_ADDED in relaxed_kinds


@pytest.mark.parametrize(
    ("event_kind", "boundary", "expected_divergence", "expected_severity"),
    [
        (
            EventKind.MODEL_REQUEST,
            BoundaryType.MODEL,
            DivergenceKind.MODEL_INPUT_CHANGED,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.MODEL_RESPONSE,
            BoundaryType.MODEL,
            DivergenceKind.MODEL_OUTPUT_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.MODEL_ERROR,
            BoundaryType.MODEL,
            DivergenceKind.ERROR_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.TOOL_CALL,
            BoundaryType.TOOL,
            DivergenceKind.TOOL_ARGS_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.TOOL_RESULT,
            BoundaryType.TOOL,
            DivergenceKind.TOOL_RESULT_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.TOOL_ERROR,
            BoundaryType.TOOL,
            DivergenceKind.ERROR_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.RETRIEVAL_QUERY,
            BoundaryType.RETRIEVAL,
            DivergenceKind.RETRIEVAL_CHANGED,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.RETRIEVAL_RESULT,
            BoundaryType.RETRIEVAL,
            DivergenceKind.RETRIEVAL_CHANGED,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.RETRIEVAL_ERROR,
            BoundaryType.RETRIEVAL,
            DivergenceKind.ERROR_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.AGENT_TRANSITION,
            None,
            DivergenceKind.AGENT_TRANSITION_CHANGED,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.STATE_CHANGE,
            None,
            DivergenceKind.STATE_CHANGE_MISMATCH,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.EXCEPTION,
            None,
            DivergenceKind.ERROR_CHANGED,
            DivergenceSeverity.BREAKING,
        ),
        (
            EventKind.STREAM_CHUNK,
            BoundaryType.MODEL,
            DivergenceKind.EVENT_PAYLOAD_CHANGED,
            DivergenceSeverity.WARNING,
        ),
        (
            EventKind.CUSTOM,
            BoundaryType.CUSTOM,
            DivergenceKind.EVENT_PAYLOAD_CHANGED,
            DivergenceSeverity.WARNING,
        ),
    ],
)
def test_event_kind_payload_classification(
    event_kind: EventKind,
    boundary: BoundaryType | None,
    expected_divergence: DivergenceKind,
    expected_severity: DivergenceSeverity,
) -> None:
    ev_base = Event(
        event_id="ev_1",
        run_id="run_001",
        event_type=event_kind,
        boundary=boundary,
        timestamp=T0,
        sequence=0,
        payload={"value": "alpha"},
    )
    ev_cand = Event(
        event_id="ev_2",
        run_id="run_001",
        event_type=event_kind,
        boundary=boundary,
        timestamp=T0,
        sequence=0,
        payload={"value": "beta"},
    )
    baseline = _make_trace(trace_id="tr_ev_b", events=[ev_base])
    candidate = _make_trace(trace_id="tr_ev_c", events=[ev_cand])

    report = diff_traces(baseline, candidate)
    assert len(report.divergences) == 1
    div = report.divergences[0]
    assert div.kind == expected_divergence
    assert div.severity == expected_severity
    assert div.path == "events[0].payload.value"
    assert div.baseline == "alpha"
    assert div.candidate == "beta"


def test_event_sequence_alignment_does_not_cascade_on_insert_or_delete() -> None:
    e0 = Event(
        event_id="e0",
        run_id="run_001",
        event_type=EventKind.MODEL_REQUEST,
        boundary=BoundaryType.MODEL,
        timestamp=T0,
        sequence=0,
        payload={"prompt": "hi"},
    )
    e1 = Event(
        event_id="e1",
        run_id="run_001",
        event_type=EventKind.MODEL_RESPONSE,
        boundary=BoundaryType.MODEL,
        timestamp=T0,
        sequence=1,
        payload={"content": "hello"},
    )
    e2 = Event(
        event_id="e2",
        run_id="run_001",
        event_type=EventKind.TOOL_CALL,
        boundary=BoundaryType.TOOL,
        timestamp=T0,
        sequence=2,
        payload={"tool_name": "calc", "arguments": {"x": 1}},
    )

    inserted = Event(
        event_id="e_extra",
        run_id="run_001",
        event_type=EventKind.CUSTOM,
        timestamp=T0,
        sequence=1,
        payload={"note": "debug"},
    )
    e1_shifted = e1.model_copy(update={"sequence": 2})
    e2_shifted = e2.model_copy(update={"sequence": 3})

    baseline = _make_trace(trace_id="tr_seq_b", events=[e0, e1, e2])
    candidate = _make_trace(trace_id="tr_seq_c", events=[e0, inserted, e1_shifted, e2_shifted])

    report = diff_traces(baseline, candidate)
    assert len(report.divergences) == 1
    assert report.divergences[0].kind == DivergenceKind.EVENT_ADDED
    assert report.divergences[0].severity == DivergenceSeverity.WARNING

    # Reverse direction: single EVENT_REMOVED, no cascading payload diffs
    rev_report = diff_traces(candidate, baseline)
    assert len(rev_report.divergences) == 1
    assert rev_report.divergences[0].kind == DivergenceKind.EVENT_REMOVED


def test_fixture_mismatches_modified_added_removed() -> None:
    req1 = {"model": "gpt-4o-mini", "prompt": "hello"}
    req1_mod = {"model": "gpt-4o-mini", "prompt": "hello updated"}
    req2 = {"tool_name": "lookup", "arguments": {"id": 1}}
    req3 = {"tool_name": "notify", "arguments": {"id": 2}}

    f1_base = FixtureEntry(
        fixture_id="fix_1",
        boundary=BoundaryType.MODEL,
        fingerprint=compute_fingerprint(BoundaryType.MODEL, req1),
        call_index=0,
        request=req1,
        response={"content": "ok"},
        name="openai.chat",
    )
    f2_base = FixtureEntry(
        fixture_id="fix_2",
        boundary=BoundaryType.TOOL,
        fingerprint=compute_fingerprint(BoundaryType.TOOL, req2),
        call_index=0,
        request=req2,
        response={"found": True},
        name="lookup",
    )

    f1_cand = FixtureEntry(
        fixture_id="fix_1_c",
        boundary=BoundaryType.MODEL,
        fingerprint=compute_fingerprint(BoundaryType.MODEL, req1_mod),
        call_index=0,
        request=req1_mod,
        response={"content": "changed"},
        name="openai.chat",
    )
    f3_cand = FixtureEntry(
        fixture_id="fix_3_c",
        boundary=BoundaryType.TOOL,
        fingerprint=compute_fingerprint(BoundaryType.TOOL, req3),
        call_index=0,
        request=req3,
        error=ExecutionError(error_type="TimeoutError", message="timed out"),
        name="notify",
    )

    baseline = _make_trace(trace_id="tr_fix_b", fixtures=[f1_base, f2_base])
    candidate = _make_trace(trace_id="tr_fix_c", fixtures=[f1_cand, f3_cand])

    report = diff_traces(baseline, candidate)
    assert report.has_breaking is True
    assert all(d.kind == DivergenceKind.FIXTURE_MISMATCH for d in report.divergences)
    paths = {d.path for d in report.divergences}
    assert "fixtures[0].fingerprint" in paths
    assert "fixtures[0].request.prompt" in paths
    assert "fixtures[0].response.content" in paths
    assert "fixtures[1]" in paths


def test_ignore_paths_exact_prefix_wildcard_and_non_mutation() -> None:
    baseline = _make_trace(
        trace_id="tr_ign_b",
        runs=[
            Run(
                run_id="run_1",
                trace_id="tr_ign_b",
                name="agent",
                started_at=T0,
                status=RunStatus.COMPLETED,
                outputs={"latency_ms": 120, "answer": "yes"},
                metadata={"host": "a", "region": "us-east"},
            )
        ],
        events=[
            Event(
                event_id="ev_1",
                run_id="run_1",
                event_type=EventKind.MODEL_RESPONSE,
                boundary=BoundaryType.MODEL,
                timestamp=T0,
                sequence=0,
                payload={"request_id": "req_aaa", "content": "yes"},
            )
        ],
    )
    candidate = _make_trace(
        trace_id="tr_ign_c",
        runs=[
            Run(
                run_id="run_2",
                trace_id="tr_ign_c",
                name="agent",
                started_at=T0,
                status=RunStatus.COMPLETED,
                outputs={"latency_ms": 999, "answer": "yes"},
                metadata={"host": "b", "region": "eu-west"},
            )
        ],
        events=[
            Event(
                event_id="ev_2",
                run_id="run_2",
                event_type=EventKind.MODEL_RESPONSE,
                boundary=BoundaryType.MODEL,
                timestamp=T0,
                sequence=0,
                payload={"request_id": "req_bbb", "content": "yes"},
            )
        ],
    )

    cfg = DiffConfig(compare_metadata=True, ignore_paths={"runs[0].metadata"})
    extra_ignores = {"runs[*].outputs.latency_ms", "events[*].payload.request_id"}

    report = diff_traces(baseline, candidate, config=cfg, ignore_paths=extra_ignores)
    assert report.identical is True
    assert report.divergences == []
    # Caller's config and set must not be mutated
    assert cfg.ignore_paths == {"runs[0].metadata"}
    assert extra_ignores == {"runs[*].outputs.latency_ms", "events[*].payload.request_id"}


def test_config_flags_timestamps_ids_metadata_and_severity_overrides() -> None:
    baseline = _make_model_trace(
        trace_id="tr_cfg_b",
        run_id="run_a",
        span_id="sp_a",
        ev1_id="ev_1",
        ev2_id="ev_2",
        fix_id="fix_1",
        created_at=T0,
    )
    candidate = _make_model_trace(
        trace_id="tr_cfg_c",
        run_id="run_a",
        span_id="sp_a",
        ev1_id="ev_1",
        ev2_id="ev_2",
        fix_id="fix_1",
        created_at=T0 + timedelta(seconds=5),
        outputs={"category": "refund"},
    )

    # 1. ignore_timestamps=False detects timestamp diffs as INFO
    ts_report = diff_traces(
        baseline,
        candidate,
        config=DiffConfig(ignore_timestamps=False),
    )
    assert any(
        d.path == "created_at" and d.severity == DivergenceSeverity.INFO
        for d in ts_report.divergences
    )
    assert any(d.path == "runs[0].started_at" for d in ts_report.divergences)

    # 2. ignore_ids=False detects trace_id diff as INFO
    id_report = diff_traces(
        baseline,
        candidate,
        config=DiffConfig(ignore_ids=False),
    )
    assert any(
        d.path == "trace_id" and d.severity == DivergenceSeverity.INFO
        for d in id_report.divergences
    )

    # 3. compare_metadata=True detects trace metadata diff as INFO
    cand_meta = candidate.model_copy(update={"metadata": {"build": "42"}})
    meta_report = diff_traces(
        baseline,
        cand_meta,
        config=DiffConfig(compare_metadata=True),
    )
    assert any(
        d.path == "metadata.build" and d.severity == DivergenceSeverity.INFO
        for d in meta_report.divergences
    )

    # 4. severity_overrides downgrades OUTPUT_CHANGED from BREAKING to WARNING
    override_report = diff_traces(
        baseline,
        candidate,
        config=DiffConfig(
            severity_overrides={DivergenceKind.OUTPUT_CHANGED: DivergenceSeverity.WARNING}
        ),
    )
    assert override_report.has_breaking is False
    assert override_report.summary["warning"] == 1
    assert override_report.summary["breaking"] == 0


def test_find_earliest_divergence_and_diff_engine() -> None:
    baseline = _make_model_trace(trace_id="tr_earl_b", created_at=T0)
    candidate = _make_model_trace(
        trace_id="tr_earl_c",
        created_at=T0 + timedelta(seconds=10),
        outputs={"category": "refund"},
    )

    # Identical -> None
    identical_report = DiffEngine().compare(baseline, baseline)
    assert find_earliest_divergence(identical_report) is None

    # INFO first, then BREAKING -> returns BREAKING
    engine = DiffEngine(DiffConfig(ignore_timestamps=False))
    assert engine.config.ignore_timestamps is False
    mixed_report = engine.compare(baseline, candidate)
    earliest = find_earliest_divergence(mixed_report)
    assert earliest is not None
    assert earliest.kind == DivergenceKind.OUTPUT_CHANGED
    assert earliest.severity == DivergenceSeverity.BREAKING

    # Only INFO -> returns first INFO
    only_info_cand = _make_model_trace(
        trace_id="tr_earl_info",
        created_at=T0 + timedelta(seconds=10),
    )
    info_report = engine.compare(baseline, only_info_cand)
    earliest_info = find_earliest_divergence(info_report)
    assert earliest_info is not None
    assert earliest_info.severity == DivergenceSeverity.INFO
    assert earliest_info.path == "created_at"


def test_determinism_and_non_mutation_of_inputs() -> None:
    baseline = _make_model_trace(
        trace_id="tr_det_b",
        outputs={"z": 1, "a": 2, "m": {"k2": "v2", "k1": "v1"}},
    )
    candidate = _make_model_trace(
        trace_id="tr_det_c",
        outputs={"a": 99, "m": {"k1": "changed", "k2": "v2"}, "z": 100},
    )

    base_before = baseline.to_json()
    cand_before = candidate.to_json()

    r1 = diff_traces(baseline, candidate)
    r2 = diff_traces(baseline, candidate)

    assert format_diff_json(r1) == format_diff_json(r2)
    assert [d.path for d in r1.divergences] == [
        "runs[0].outputs.a",
        "runs[0].outputs.m.k1",
        "runs[0].outputs.z",
    ]
    assert baseline.to_json() == base_before
    assert candidate.to_json() == cand_before

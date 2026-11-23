"""Unit tests for the SQLite WAL TraceIndex."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tracevault.schema import (
    BoundaryType,
    Event,
    EventKind,
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
from tracevault.storage.index import TraceIndex
from tracevault.storage.repository import TraceQuery


def _make_trace(
    trace_id: str,
    *,
    run_name: str = "agent_run",
    status: RunStatus = RunStatus.COMPLETED,
    created_at: datetime | None = None,
    frozen: bool = False,
    parent_trace_id: str | None = None,
    tags: list[str] | None = None,
    with_details: bool = False,
) -> Trace:
    ts = created_at or datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
    run_id = f"run_{trace_id}"
    run = Run(
        run_id=run_id,
        trace_id=trace_id,
        name=run_name,
        started_at=ts,
        ended_at=ts + timedelta(seconds=1),
        status=status,
        tags=tags if tags is not None else [],
    )
    spans: list[Span] = []
    events: list[Event] = []
    fixtures = FixtureSet()
    if with_details:
        span_id = f"sp_{trace_id}"
        ev_id = f"ev_{trace_id}"
        spans.append(
            Span(
                span_id=span_id,
                run_id=run_id,
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
                name="model_call",
                started_at=ts,
                ended_at=ts + timedelta(milliseconds=500),
                status=SpanStatus.OK,
                event_ids=[ev_id],
            )
        )
        events.append(
            Event(
                event_id=ev_id,
                run_id=run_id,
                span_id=span_id,
                event_type=EventKind.MODEL_REQUEST,
                boundary=BoundaryType.MODEL,
                timestamp=ts,
                sequence=0,
                payload={"model": "gpt-4o-mini"},
            )
        )
        req = {"model": "gpt-4o-mini", "prompt": "hi"}
        fixtures = FixtureSet(
            entries=[
                FixtureEntry(
                    fixture_id=f"fix_{trace_id}",
                    boundary=BoundaryType.MODEL,
                    fingerprint=compute_fingerprint(BoundaryType.MODEL, req),
                    call_index=0,
                    request=req,
                    response={"content": "hello"},
                    span_id=span_id,
                    name="model_call",
                )
            ]
        )
    return Trace(
        trace_id=trace_id,
        created_at=ts,
        frozen=frozen,
        parent_trace_id=parent_trace_id,
        runs=[run],
        spans=spans,
        events=events,
        fixtures=fixtures,
    )


def test_index_initializes_wal_and_foreign_keys(tmp_path: Path) -> None:
    db_path = tmp_path / "index.db"
    idx = TraceIndex(db_path)
    try:
        idx.initialize()
        assert db_path.is_file()
        conn = sqlite3.connect(str(db_path))
        try:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert str(journal_mode).lower() == "wal"
        finally:
            conn.close()
    finally:
        idx.close()


def test_index_upsert_update_and_tag_replacement(tmp_path: Path) -> None:
    idx = TraceIndex(tmp_path / "index.db")
    try:
        idx.initialize()
        t1 = _make_trace("tr_001", tags=["alpha", "beta", "alpha"], with_details=True)
        idx.upsert(t1)

        results = idx.query(TraceQuery())
        assert len(results) == 1
        summary = results[0]
        assert summary.trace_id == "tr_001"
        assert summary.root_run_id == "run_tr_001"
        assert summary.run_name == "agent_run"
        assert summary.status == RunStatus.COMPLETED
        assert summary.frozen is False
        assert summary.tags == ["alpha", "beta"]
        assert summary.span_count == 1
        assert summary.event_count == 1
        assert summary.fixture_count == 1

        # Update with new tags and frozen=True
        updated_run = t1.root_run.model_copy(
            update={"name": "updated_agent", "status": RunStatus.FAILED, "tags": ["gamma"]}
        )
        t1_updated = t1.model_copy(update={"frozen": True, "runs": [updated_run]})
        idx.upsert(t1_updated)

        results = idx.query(TraceQuery())
        assert len(results) == 1
        assert results[0].run_name == "updated_agent"
        assert results[0].status == RunStatus.FAILED
        assert results[0].frozen is True
        assert results[0].tags == ["gamma"]
        assert idx.query(TraceQuery(tag="alpha")) == []
        assert len(idx.query(TraceQuery(tag="gamma"))) == 1
    finally:
        idx.close()


def test_index_delete_cascades_tags_and_clear(tmp_path: Path) -> None:
    db_path = tmp_path / "index.db"
    idx = TraceIndex(db_path)
    try:
        idx.initialize()
        idx.upsert(_make_trace("tr_a", tags=["t1", "t2"]))
        idx.upsert(_make_trace("tr_b", tags=["t2", "t3"]))

        idx.delete("tr_a")
        remaining = idx.query(TraceQuery())
        assert [r.trace_id for r in remaining] == ["tr_b"]
        assert idx.query(TraceQuery(tag="t1")) == []

        idx.clear()
        assert idx.query(TraceQuery()) == []
    finally:
        idx.close()


def test_index_query_filters_ordering_pagination_and_sql_safety(tmp_path: Path) -> None:
    idx = TraceIndex(tmp_path / "index.db")
    try:
        idx.initialize()
        base = datetime(2026, 11, 24, 10, 0, 0, tzinfo=UTC)
        traces = [
            _make_trace(
                "tr_1",
                run_name="billing_triage",
                status=RunStatus.COMPLETED,
                created_at=base,
                frozen=True,
                tags=["prod", "billing"],
            ),
            _make_trace(
                "tr_2",
                run_name="billing_refund_100%",
                status=RunStatus.FAILED,
                created_at=base + timedelta(microseconds=500_000),
                frozen=False,
                parent_trace_id="tr_1",
                tags=["prod", "refund"],
            ),
            _make_trace(
                "tr_3",
                run_name="search_agent",
                status=RunStatus.COMPLETED,
                created_at=base + timedelta(seconds=2),
                frozen=True,
                parent_trace_id="tr_1",
                tags=["staging"],
            ),
        ]
        for t in traces:
            idx.upsert(t)

        # Ordered by created_at DESC (microsecond precision preserved)
        all_rows = idx.query(TraceQuery())
        assert [r.trace_id for r in all_rows] == ["tr_3", "tr_2", "tr_1"]

        # Status filter
        assert [r.trace_id for r in idx.query(TraceQuery(status=RunStatus.FAILED))] == ["tr_2"]

        # Frozen filter
        assert [r.trace_id for r in idx.query(TraceQuery(frozen=True))] == ["tr_3", "tr_1"]
        assert [r.trace_id for r in idx.query(TraceQuery(frozen=False))] == ["tr_2"]

        # Tag filter
        assert [r.trace_id for r in idx.query(TraceQuery(tag="prod"))] == ["tr_2", "tr_1"]

        # Parent trace filter
        assert [r.trace_id for r in idx.query(TraceQuery(parent_trace_id="tr_1"))] == [
            "tr_3",
            "tr_2",
        ]

        # Substring query (case-insensitive + literal wildcard escaping)
        assert [r.trace_id for r in idx.query(TraceQuery(query="BILLING"))] == ["tr_2", "tr_1"]
        assert [r.trace_id for r in idx.query(TraceQuery(query="100%"))] == ["tr_2"]
        assert [r.trace_id for r in idx.query(TraceQuery(query="search_agent"))] == ["tr_3"]

        # Pagination
        assert [r.trace_id for r in idx.query(TraceQuery(limit=2, offset=0))] == ["tr_3", "tr_2"]
        assert [r.trace_id for r in idx.query(TraceQuery(limit=2, offset=1))] == ["tr_2", "tr_1"]

        # Parameterized SQL safety: injection attempt treated as literal string
        injected = idx.query(TraceQuery(query="'; DROP TABLE traces; --"))
        assert injected == []
        assert len(idx.query(TraceQuery())) == 3
    finally:
        idx.close()

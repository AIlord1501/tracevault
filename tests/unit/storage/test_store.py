"""Unit and failure-mode tests for TraceStore and TraceRepository."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tracevault.schema import (
    BoundaryType,
    Event,
    EventKind,
    ExportFormat,
    FixtureEntry,
    FixtureSet,
    InvalidTraceIdError,
    Run,
    RunStatus,
    Span,
    SpanStatus,
    SpanType,
    Trace,
    TraceFrozenError,
    TraceNotFoundError,
    UnsafeTraceError,
    compute_fingerprint,
)
from tracevault.storage import TraceQuery, TraceRepository, TraceStore, TraceSummary


def _build_trace(
    trace_id: str = "tr_alpha_01",
    *,
    run_name: str = "triage_agent",
    status: RunStatus = RunStatus.COMPLETED,
    created_at: datetime | None = None,
    frozen: bool = False,
    parent_trace_id: str | None = None,
    tags: list[str] | None = None,
    extra_events: bool = True,
) -> Trace:
    ts = created_at or datetime(2026, 11, 24, 15, 30, 0, tzinfo=UTC)
    run_id = f"run_{trace_id}"
    run = Run(
        run_id=run_id,
        trace_id=trace_id,
        name=run_name,
        started_at=ts,
        ended_at=ts + timedelta(seconds=1),
        status=status,
        inputs={"ticket": "Invoice #42"},
        outputs={"category": "billing"},
        tags=tags if tags is not None else ["triage"],
    )
    spans: list[Span] = []
    events: list[Event] = []
    fixtures = FixtureSet()

    if extra_events:
        span_id = f"sp_{trace_id}"
        ev_req = f"ev_{trace_id}_1"
        ev_res = f"ev_{trace_id}_2"
        spans.append(
            Span(
                span_id=span_id,
                run_id=run_id,
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
                name="openai.chat.completions",
                started_at=ts,
                ended_at=ts + timedelta(milliseconds=400),
                status=SpanStatus.OK,
                event_ids=[ev_req, ev_res],
            )
        )
        # Intentionally store events out of sequence order in Trace.events to test JSONL sorting
        events.extend(
            [
                Event(
                    event_id=ev_res,
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_RESPONSE,
                    boundary=BoundaryType.MODEL,
                    timestamp=ts + timedelta(milliseconds=400),
                    sequence=2,
                    payload={"content": "billing"},
                ),
                Event(
                    event_id=ev_req,
                    run_id=run_id,
                    span_id=span_id,
                    event_type=EventKind.MODEL_REQUEST,
                    boundary=BoundaryType.MODEL,
                    timestamp=ts + timedelta(milliseconds=100),
                    sequence=1,
                    payload={"model": "gpt-4o-mini"},
                ),
            ]
        )
        req = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Invoice #42"}]}
        fixtures = FixtureSet(
            entries=[
                FixtureEntry(
                    fixture_id=f"fix_{trace_id}",
                    boundary=BoundaryType.MODEL,
                    fingerprint=compute_fingerprint(BoundaryType.MODEL, req),
                    call_index=0,
                    request=req,
                    response={"content": "billing"},
                    span_id=span_id,
                    name="openai.chat.completions",
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


def test_store_conforms_to_protocol_and_init_idempotent(tmp_path: Path) -> None:
    with TraceStore(tmp_path / ".tracevault") as store:
        assert isinstance(store, TraceRepository)
        first = store.init()
        second = store.init()
        assert first == second == tmp_path / ".tracevault"
        assert (first / "traces").is_dir()
        assert (first / "index.db").is_file()


def test_store_init_rejects_invalid_config(tmp_path: Path) -> None:
    with pytest.raises(UnsafeTraceError):
        TraceStore(tmp_path, max_trace_bytes=0)
    with pytest.raises(UnsafeTraceError):
        TraceStore(tmp_path, max_trace_bytes=True)
    with pytest.raises(UnsafeTraceError):
        TraceStore("bad\x00dir")


def test_save_load_exists_and_duplicate_rejection(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        trace = _build_trace("tr_roundtrip")
        assert store.exists("tr_roundtrip") is False

        saved_path = store.save(trace)
        assert saved_path == store.traces_dir / "tr_roundtrip.json"
        assert saved_path.is_file()
        assert store.exists("tr_roundtrip") is True

        loaded = store.load("tr_roundtrip")
        assert loaded == trace

        # Duplicate save rejected unless overwrite=True
        with pytest.raises(FileExistsError):
            store.save(trace)

        updated_run = trace.root_run.model_copy(update={"name": "updated_agent"})
        updated = trace.model_copy(update={"runs": [updated_run]})
        store.save(updated, overwrite=True)

        reloaded = store.load("tr_roundtrip")
        assert reloaded.root_run.name == "updated_agent"
        summaries = store.list_traces()
        assert len(summaries) == 1
        assert summaries[0].run_name == "updated_agent"


def test_freeze_idempotency_and_immutability(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        trace = _build_trace("tr_freeze_test")
        store.save(trace)

        frozen = store.freeze("tr_freeze_test")
        assert frozen.frozen is True

        # Idempotent second freeze
        frozen_again = store.freeze("tr_freeze_test")
        assert frozen_again == frozen

        # Overwrite rejected even with overwrite=True
        with pytest.raises(TraceFrozenError):
            store.save(trace, overwrite=True)

        # Delete rejected without force=True
        with pytest.raises(TraceFrozenError):
            store.delete("tr_freeze_test")

        # Index reflects frozen=True
        summaries = store.list_traces(frozen=True)
        assert [s.trace_id for s in summaries] == ["tr_freeze_test"]

        # Delete succeeds with force=True
        store.delete("tr_freeze_test", force=True)
        assert store.exists("tr_freeze_test") is False
        assert store.list_traces() == []


def test_delete_unfrozen_and_missing(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        with pytest.raises(TraceNotFoundError):
            store.delete("tr_missing")
        with pytest.raises(TraceNotFoundError):
            store.load("tr_missing")

        trace = _build_trace("tr_del")
        store.save(trace)
        store.delete("tr_del")
        assert store.exists("tr_del") is False
        assert store.list_traces() == []


def test_query_and_list_traces(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        base = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)
        store.save(
            _build_trace(
                "tr_old",
                run_name="alpha_workflow",
                status=RunStatus.COMPLETED,
                created_at=base,
                tags=["prod", "v1"],
            )
        )
        store.save(
            _build_trace(
                "tr_mid",
                run_name="beta_workflow",
                status=RunStatus.FAILED,
                created_at=base + timedelta(seconds=10),
                parent_trace_id="tr_old",
                tags=["prod", "v2"],
            )
        )
        store.save(
            _build_trace(
                "tr_new",
                run_name="gamma_agent",
                status=RunStatus.COMPLETED,
                created_at=base + timedelta(seconds=20),
                frozen=True,
                parent_trace_id="tr_old",
                tags=["staging"],
            )
        )

        all_traces = store.list_traces()
        assert [s.trace_id for s in all_traces] == ["tr_new", "tr_mid", "tr_old"]
        assert all(isinstance(s, TraceSummary) for s in all_traces)

        assert [s.trace_id for s in store.list_traces(status=RunStatus.FAILED)] == ["tr_mid"]
        assert [s.trace_id for s in store.list_traces(tag="prod")] == ["tr_mid", "tr_old"]
        assert [s.trace_id for s in store.list_traces(frozen=True)] == ["tr_new"]
        assert [s.trace_id for s in store.list_traces(query="workflow")] == ["tr_mid", "tr_old"]
        assert [s.trace_id for s in store.list_traces(limit=1, offset=1)] == ["tr_mid"]

        by_parent = store.query(TraceQuery(parent_trace_id="tr_old"))
        assert [s.trace_id for s in by_parent] == ["tr_new", "tr_mid"]


def test_export_trace_json_and_jsonl(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        trace = _build_trace("tr_export")
        store.save(trace)

        json_out = tmp_path / "exports" / "trace.json"
        written_json = store.export_trace("tr_export", json_out, format=ExportFormat.JSON)
        assert written_json == json_out
        reloaded = Trace.from_json(json_out.read_bytes())
        assert reloaded == trace

        jsonl_out = tmp_path / "exports" / "trace.jsonl"
        written_jsonl = store.export_jsonl("tr_export", jsonl_out)
        assert written_jsonl == jsonl_out

        lines = [line for line in jsonl_out.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 3  # 1 header + 2 events
        header = json.loads(lines[0])
        assert header["record_type"] == "trace_header"
        assert header["trace_id"] == "tr_export"
        assert "events" not in header

        ev1 = json.loads(lines[1])
        ev2 = json.loads(lines[2])
        assert ev1["record_type"] == "event"
        assert ev2["record_type"] == "event"
        assert ev1["sequence"] == 1
        assert ev2["sequence"] == 2

        with pytest.raises(UnsafeTraceError):
            store.export_trace("tr_export", "bad\x00path.json")


def test_import_trace_valid_options_and_security(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault", max_trace_bytes=16_384) as store:
        store.init()
        trace = _build_trace("tr_imported_real_id")

        # Untrusted filename must be ignored; internal trace.trace_id is used
        untrusted_file = tmp_path / "evil_filename_ignored.json"
        untrusted_file.write_text(trace.to_json(), encoding="utf-8")

        imported = store.import_trace(untrusted_file, freeze=True)
        assert imported.trace_id == "tr_imported_real_id"
        assert imported.frozen is True
        assert store.exists("tr_imported_real_id") is True
        assert not (store.traces_dir / "evil_filename_ignored.json").exists()

        # Re-importing frozen trace fails even with overwrite=True
        with pytest.raises(TraceFrozenError):
            store.import_trace(untrusted_file, overwrite=True)

        # Unfrozen overwrite works
        t2 = _build_trace("tr_import_overwrite")
        f2 = tmp_path / "t2.json"
        f2.write_text(t2.to_json(), encoding="utf-8")
        store.import_trace(f2)
        with pytest.raises(FileExistsError):
            store.import_trace(f2, overwrite=False)
        store.import_trace(f2, overwrite=True)

        # Missing file
        with pytest.raises(FileNotFoundError):
            store.import_trace(tmp_path / "does_not_exist.json")

        # Directory instead of file
        with pytest.raises(UnsafeTraceError):
            store.import_trace(tmp_path)

        # Null byte in path
        with pytest.raises(UnsafeTraceError):
            store.import_trace("bad\x00file.json")

        # Malformed JSON
        malformed = tmp_path / "malformed.json"
        malformed.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(UnsafeTraceError):
            store.import_trace(malformed)

        # Oversized file rejected before reading
        oversized = tmp_path / "oversized.json"
        oversized.write_bytes(b" " * 20_000)
        with pytest.raises(UnsafeTraceError):
            store.import_trace(oversized)


def test_reindex_rebuilds_deleted_db_and_fails_on_corrupt(tmp_path: Path) -> None:
    vault_dir = tmp_path / "vault"
    with TraceStore(vault_dir) as store:
        store.init()
        store.save(_build_trace("tr_r1"))
        store.save(_build_trace("tr_r2", frozen=True))
        assert len(store.list_traces()) == 2
        store.close()

        # Delete SQLite index files to simulate index loss
        for suffix in ("", "-wal", "-shm"):
            db_file = Path(f"{store.index_path}{suffix}")
            if db_file.exists():
                db_file.unlink()

        count = store.reindex()
        assert count == 2
        summaries = store.list_traces()
        assert {s.trace_id for s in summaries} == {"tr_r1", "tr_r2"}

        # Corrupt trace file causes reindex to raise UnsafeTraceError
        (store.traces_dir / "tr_corrupt.json").write_text("{corrupt", encoding="utf-8")
        with pytest.raises(UnsafeTraceError):
            store.reindex()


def test_atomic_write_failure_cleanup_preserves_previous_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        original = _build_trace("tr_atomic", run_name="original_name")
        store.save(original)

        updated_run = original.root_run.model_copy(update={"name": "new_name"})
        updated = original.model_copy(update={"runs": [updated_run]})

        def _failing_replace(src: object, dst: object) -> None:
            raise OSError("simulated atomic replace failure")

        monkeypatch.setattr(os, "replace", _failing_replace)

        with pytest.raises(OSError, match="simulated atomic replace failure"):
            store.save(updated, overwrite=True)

        # No .tmp files left behind
        tmp_files = list(store.traces_dir.glob("*.tmp"))
        assert tmp_files == []

        # Original trace on disk is completely preserved
        reloaded = store.load("tr_atomic")
        assert reloaded.root_run.name == "original_name"


def test_index_failure_rolls_back_fresh_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        trace = _build_trace("tr_idx_fail")

        def _failing_upsert(t: Trace) -> None:
            raise RuntimeError("sqlite failure")

        monkeypatch.setattr(store._index, "upsert", _failing_upsert)

        with pytest.raises(RuntimeError, match="sqlite failure"):
            store.save(trace)

        assert not (store.traces_dir / "tr_idx_fail.json").exists()
        assert store.exists("tr_idx_fail") is False


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "../escape",
        "..\\escape",
        "a/b",
        "a\\b",
        "bad\x00id",
        "-leading-dash",
        "a" * 129,
    ],
)
def test_invalid_trace_ids_rejected(tmp_path: Path, bad_id: str) -> None:
    with TraceStore(tmp_path / "vault") as store:
        store.init()
        with pytest.raises(InvalidTraceIdError):
            store.load(bad_id)
        with pytest.raises(InvalidTraceIdError):
            store.exists(bad_id)
        with pytest.raises(InvalidTraceIdError):
            store.delete(bad_id)


def test_max_trace_bytes_enforced_on_save_and_load(tmp_path: Path) -> None:
    with TraceStore(tmp_path / "vault", max_trace_bytes=128) as store:
        store.init()
        trace = _build_trace("tr_big")
        with pytest.raises(UnsafeTraceError):
            store.save(trace)

        # Write a file directly exceeding max_trace_bytes and ensure load rejects it before parsing
        big_file = store.traces_dir / "tr_big_disk.json"
        big_file.write_bytes(b"{" + b" " * 200 + b"}")
        with pytest.raises(UnsafeTraceError):
            store.load("tr_big_disk")

"""Adversarial and hostile-input security tests for tracevault.storage."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from conftest import HOSTILE_TRACE_IDS, make_valid_run, make_valid_trace
from tracevault.schema import (
    ExportFormat,
    InvalidTraceIdError,
    TraceFrozenError,
    UnsafeTraceError,
)
from tracevault.storage import TraceQuery, TraceStore


class TestStoragePathTraversal:
    """Path traversal, control-char, length, unicode, and type attacks on TraceStore."""

    @pytest.mark.parametrize("bad_id", HOSTILE_TRACE_IDS)
    def test_store_operations_reject_hostile_trace_ids(self, tmp_path: Path, bad_id: Any) -> None:
        with TraceStore(tmp_path / ".tracevault") as store:
            store.init()

            with pytest.raises(InvalidTraceIdError):
                store.load(bad_id)
            with pytest.raises(InvalidTraceIdError):
                store.exists(bad_id)
            with pytest.raises(InvalidTraceIdError):
                store.delete(bad_id)
            with pytest.raises(InvalidTraceIdError):
                store.freeze(bad_id)
            with pytest.raises(InvalidTraceIdError):
                store.export_trace(bad_id, tmp_path / "out.json")

    def test_null_byte_paths_rejected_in_init_import_and_export(self, tmp_path: Path) -> None:
        with pytest.raises(UnsafeTraceError, match="null bytes"):
            TraceStore(f"{tmp_path}\x00evil")

        with TraceStore(tmp_path / ".tracevault") as store:
            trace = make_valid_trace(trace_id="tr_null_path_001")
            store.save(trace)

            with pytest.raises(UnsafeTraceError, match="null bytes"):
                store.import_trace(f"{tmp_path}/bad\x00file.json")

            with pytest.raises(UnsafeTraceError, match="null bytes"):
                store.export_trace(trace.trace_id, f"{tmp_path}/out\x00file.json")


class TestStorageSqlInjection:
    """SQL injection and LIKE wildcard injection attempts against TraceIndex."""

    @pytest.mark.parametrize(
        "payload",
        [
            "'; DROP TABLE traces; --",
            "'; DROP TABLE trace_tags; --",
            "' OR '1'='1",
            "%' OR 1=1 --",
            '" OR ""="',
            "triage' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "%",
            "_",
            "%%",
        ],
    )
    def test_sql_and_wildcard_injection_in_query_and_tag(
        self, tmp_path: Path, payload: str
    ) -> None:
        with TraceStore(tmp_path / ".tracevault") as store:
            t1 = make_valid_trace(
                trace_id="trsqli001",
                runs=[
                    make_valid_run(
                        run_id="run001",
                        trace_id="trsqli001",
                        name="safeagent",
                        tags=["alpha"],
                    )
                ],
                spans=[],
                events=[],
            )
            t2 = make_valid_trace(
                trace_id="trsqli002",
                runs=[
                    make_valid_run(
                        run_id="run002",
                        trace_id="trsqli002",
                        name="billingbot",
                        tags=["beta"],
                    )
                ],
                spans=[],
                events=[],
            )
            store.save(t1)
            store.save(t2)

            # None of the hostile payloads should match our clean traces or drop tables.
            assert store.list_traces(query=payload) == []
            assert store.list_traces(tag=payload) == []
            assert store.query(TraceQuery(query=payload, tag=payload)) == []
            assert store.query(TraceQuery(parent_trace_id=payload)) == []

            # Verify both tables and rows remain completely intact.
            remaining = store.list_traces()
            assert {s.trace_id for s in remaining} == {"trsqli001", "trsqli002"}
            assert len(store.list_traces(tag="alpha")) == 1
            assert len(store.list_traces(tag="beta")) == 1


class TestCorruptSqliteIndex:
    """Corrupt index.db failure detection and deterministic recovery via reindex()."""

    def test_corrupt_index_fails_cleanly_and_recovers_after_recreation(
        self, tmp_path: Path
    ) -> None:
        store_dir = tmp_path / ".tracevault"
        t1 = make_valid_trace(trace_id="tr_recover_001")
        t2 = make_valid_trace(trace_id="tr_recover_002", frozen=True)

        with TraceStore(store_dir) as store:
            store.save(t1)
            store.save(t2)

        # Corrupt index.db with garbage bytes and clear any WAL sidecars.
        index_path = store_dir / "index.db"
        for sidecar in (store_dir / "index.db-wal", store_dir / "index.db-shm"):
            if sidecar.exists():
                sidecar.unlink()
        index_path.write_bytes(b"CORRUPT GARBAGE BYTES NOT A SQLITE DB" * 100)

        # Opening and querying the corrupted index must fail cleanly with DatabaseError.
        with TraceStore(store_dir) as broken_store, pytest.raises(sqlite3.DatabaseError):
            broken_store.list_traces()

        # Removing the corrupted index and running reindex() rebuilds from JSON source of truth.
        index_path.unlink()
        with TraceStore(store_dir) as recovered_store:
            count = recovered_store.reindex()
            assert count == 2
            summaries = recovered_store.list_traces()
            assert {s.trace_id for s in summaries} == {"tr_recover_001", "tr_recover_002"}
            assert recovered_store.load("tr_recover_002").frozen is True


class TestHostileImportAndTamperedFiles:
    """Hostile files passed to import_trace() and tampered files in traces/."""

    @pytest.mark.parametrize(
        "content",
        [
            b"{not valid json",
            b"[]",
            b"\xff\xfe\xfd",
        ],
    )
    def test_import_trace_rejects_malformed_json(self, tmp_path: Path, content: bytes) -> None:
        bad_file = tmp_path / "malformed.json"
        bad_file.write_bytes(content)

        with TraceStore(tmp_path / ".tracevault") as store, pytest.raises(UnsafeTraceError):
            store.import_trace(bad_file)

    @pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
    def test_import_trace_rejects_non_finite_numbers(self, tmp_path: Path, token: str) -> None:
        raw = make_valid_trace(trace_id="tr_nan_001").to_json()
        tampered = raw.replace('"metadata": {}', f'"metadata": {{"bad": {token}}}', 1)
        bad_file = tmp_path / f"non_finite_{token}.json"
        bad_file.write_text(tampered, encoding="utf-8")

        with TraceStore(tmp_path / ".tracevault") as store, pytest.raises(UnsafeTraceError):
            store.import_trace(bad_file)

    def test_import_trace_rejects_oversized_file(self, tmp_path: Path) -> None:
        big_trace = make_valid_trace(trace_id="tr_big_001", metadata={"blob": "x" * 2048})
        big_file = tmp_path / "oversized.json"
        big_file.write_text(big_trace.to_json(), encoding="utf-8")

        with (
            TraceStore(tmp_path / ".tracevault", max_trace_bytes=512) as store,
            pytest.raises(UnsafeTraceError, match="exceeds"),
        ):
            store.import_trace(big_file)

    def test_import_trace_rejects_directory_path(self, tmp_path: Path) -> None:
        some_dir = tmp_path / "not_a_file"
        some_dir.mkdir()
        with (
            TraceStore(tmp_path / ".tracevault") as store,
            pytest.raises(UnsafeTraceError, match="regular file"),
        ):
            store.import_trace(some_dir)

    def test_import_trace_ignores_untrusted_filename_and_uses_validated_trace_id(
        self, tmp_path: Path
    ) -> None:
        trace = make_valid_trace(trace_id="tr_clean_import_001")
        untrusted_file = tmp_path / "untrusted;name..with.weird.chars.json"
        untrusted_file.write_text(trace.to_json(), encoding="utf-8")

        with TraceStore(tmp_path / ".tracevault") as store:
            imported = store.import_trace(untrusted_file)
            assert imported.trace_id == "tr_clean_import_001"
            expected_path = store.traces_dir / "tr_clean_import_001.json"
            assert expected_path.is_file()
            assert list(store.traces_dir.glob("*.json")) == [expected_path]

    def test_import_trace_rejects_hostile_internal_trace_id(self, tmp_path: Path) -> None:
        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["trace_id"] = "../escape"
        trace_dict["runs"][0]["trace_id"] = "../escape"
        bad_file = tmp_path / "looks_innocent.json"
        bad_file.write_text(json.dumps(trace_dict), encoding="utf-8")

        with TraceStore(tmp_path / ".tracevault") as store, pytest.raises(InvalidTraceIdError):
            store.import_trace(bad_file)

    def test_tampered_mismatched_filename_trace_id_rejected(self, tmp_path: Path) -> None:
        with TraceStore(tmp_path / ".tracevault") as store:
            store.init()
            trace = make_valid_trace(trace_id="tr_internal_001")
            tampered_path = store.traces_dir / "tr_different_002.json"
            tampered_path.write_text(trace.to_json(), encoding="utf-8")

            with pytest.raises(UnsafeTraceError, match="mismatched trace_id"):
                store.load("tr_different_002")

            with pytest.raises(UnsafeTraceError, match="does not match internal trace_id"):
                store.reindex()


class TestInertCodeInjectionPersistence:
    """Code-injection strings persisted to disk and reloaded remain strictly inert data."""

    def test_malicious_strings_round_trip_through_store_and_exports_inertly(
        self, tmp_path: Path
    ) -> None:
        hostile_str = (
            "__import__('os').system('echo pwned'); $(whoami); `id`; '; DROP TABLE traces;"
        )
        trace = make_valid_trace(
            trace_id="tr_inert_001",
            runs=[
                make_valid_run(
                    trace_id="tr_inert_001",
                    name=hostile_str,
                    inputs={"script": hostile_str},
                    outputs={"result": hostile_str},
                    tags=[hostile_str],
                    metadata={"expr": hostile_str},
                )
            ],
            metadata={"note": hostile_str},
        )

        with TraceStore(tmp_path / ".tracevault") as store:
            store.save(trace)
            loaded = store.load("tr_inert_001")
            assert loaded == trace
            assert loaded.root_run.name == hostile_str

            summaries = store.list_traces(tag=hostile_str)
            assert len(summaries) == 1
            assert summaries[0].run_name == hostile_str

            json_out = store.export_trace(
                "tr_inert_001", tmp_path / "export.json", format=ExportFormat.JSON
            )
            jsonl_out = store.export_jsonl("tr_inert_001", tmp_path / "export.jsonl")
            assert json.loads(json_out.read_text(encoding="utf-8"))["metadata"]["note"] == (
                hostile_str
            )
            lines = jsonl_out.read_text(encoding="utf-8").strip().splitlines()
            assert json.loads(lines[0])["metadata"]["note"] == hostile_str


class TestSymlinkContainment:
    """Symlinks escaping traces/ must be rejected with UnsafeTraceError."""

    def test_escaping_symlink_rejected_across_store_operations(self, tmp_path: Path) -> None:
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_trace = make_valid_trace(trace_id="tr_symlink_001")
        outside_file = outside_dir / "tr_symlink_001.json"
        outside_file.write_text(outside_trace.to_json(), encoding="utf-8")

        with TraceStore(tmp_path / ".tracevault") as store:
            store.init()
            symlink_path = store.traces_dir / "tr_symlink_001.json"
            try:
                os.symlink(outside_file, symlink_path)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"OS privileges disallow os.symlink in this environment: {exc}")

            with pytest.raises(UnsafeTraceError, match="escapes"):
                store.load("tr_symlink_001")
            with pytest.raises(UnsafeTraceError, match="escapes"):
                store.exists("tr_symlink_001")
            with pytest.raises(UnsafeTraceError, match="escapes"):
                store.freeze("tr_symlink_001")
            with pytest.raises(UnsafeTraceError, match="escapes"):
                store.delete("tr_symlink_001")
            with pytest.raises(UnsafeTraceError, match="escapes"):
                store.reindex()


class TestFrozenTraceImmutability:
    """Frozen traces cannot be overwritten or deleted without force=True."""

    def test_frozen_trace_blocks_overwrite_and_non_forced_delete(self, tmp_path: Path) -> None:
        with TraceStore(tmp_path / ".tracevault") as store:
            trace = make_valid_trace(trace_id="tr_frozen_001", frozen=False)
            store.save(trace)
            frozen = store.freeze("tr_frozen_001")
            assert frozen.frozen is True

            # Idempotent freeze
            assert store.freeze("tr_frozen_001").frozen is True

            replacement = make_valid_trace(
                trace_id="tr_frozen_001",
                metadata={"tampered": True},
            )
            with pytest.raises(TraceFrozenError):
                store.save(replacement, overwrite=False)
            with pytest.raises(TraceFrozenError):
                store.save(replacement, overwrite=True)

            with pytest.raises(TraceFrozenError):
                store.delete("tr_frozen_001")
            with pytest.raises(TraceFrozenError):
                store.delete("tr_frozen_001", force=False)

            # Original frozen trace remains untouched
            assert store.load("tr_frozen_001").metadata == {}

            # Forced delete succeeds
            store.delete("tr_frozen_001", force=True)
            assert store.exists("tr_frozen_001") is False

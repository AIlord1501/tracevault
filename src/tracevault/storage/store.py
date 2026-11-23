"""Local-first atomic JSON TraceStore with SQLite metadata indexing."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from types import TracebackType

from tracevault.schema import (
    DEFAULT_MAX_TRACE_BYTES,
    ExportFormat,
    RunStatus,
    Trace,
    TraceFrozenError,
    TraceNotFoundError,
    UnsafeTraceError,
    validate_trace_id,
)
from tracevault.storage.index import TraceIndex
from tracevault.storage.repository import TraceQuery, TraceSummary


def _validate_fs_path(path: Path | str) -> Path:
    """Reject null bytes in filesystem paths and return a Path instance."""
    raw_str = os.fspath(path)
    if isinstance(raw_str, bytes):
        if b"\x00" in raw_str:
            raise UnsafeTraceError("Filesystem path must not contain null bytes")
        raw_str = raw_str.decode("utf-8")
    if "\x00" in raw_str:
        raise UnsafeTraceError("Filesystem path must not contain null bytes")
    return Path(raw_str)


def _atomic_write_bytes(target_path: Path, data: bytes) -> None:
    """Atomically write bytes to target_path using a temporary file in the same directory."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target_path.parent,
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, target_path)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()
        raise


class TraceStore:
    """Local-first JSON trace store backed by a rebuildable SQLite WAL index."""

    def __init__(
        self,
        base_dir: Path | str = Path(".tracevault"),
        *,
        max_trace_bytes: int = DEFAULT_MAX_TRACE_BYTES,
    ) -> None:
        if (
            not isinstance(max_trace_bytes, int)
            or isinstance(max_trace_bytes, bool)
            or max_trace_bytes <= 0
        ):
            raise UnsafeTraceError("max_trace_bytes must be a positive integer")

        self.base_dir: Path = _validate_fs_path(base_dir)
        self.traces_dir: Path = self.base_dir / "traces"
        self.index_path: Path = self.base_dir / "index.db"
        self.max_trace_bytes: int = max_trace_bytes
        self._index: TraceIndex = TraceIndex(self.index_path)

    def __enter__(self) -> TraceStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def _resolve_trace_path(self, trace_id: str) -> Path:
        """Validate trace_id and verify resolved path containment within traces_dir."""
        validated_id = validate_trace_id(trace_id)
        traces_root = self.traces_dir.resolve()
        candidate = self.traces_dir / f"{validated_id}.json"

        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise UnsafeTraceError(f"Unable to resolve trace path for {validated_id!r}") from exc

        if not resolved.is_relative_to(traces_root):
            raise UnsafeTraceError(
                f"Trace path for {validated_id!r} escapes traces directory {traces_root}"
            )
        if candidate.is_symlink() and not resolved.is_relative_to(traces_root):
            raise UnsafeTraceError(
                f"Symlink trace path for {validated_id!r} escapes traces directory"
            )
        return candidate

    def _serialize_trace(self, trace: Trace) -> bytes:
        """Serialize a trace to UTF-8 JSON bytes and enforce max_trace_bytes."""
        encoded = trace.to_json(indent=2).encode("utf-8")
        if len(encoded) > self.max_trace_bytes:
            raise UnsafeTraceError(
                f"Serialized trace size ({len(encoded)} bytes) exceeds "
                f"max_trace_bytes ({self.max_trace_bytes})"
            )
        return encoded

    def init(self) -> Path:
        """Idempotently initialize base_dir, traces/, and index.db."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self._index.initialize()
        return self.base_dir

    def save(self, trace: Trace, *, overwrite: bool = False) -> Path:
        """Persist a trace atomically and upsert its metadata in SQLite."""
        target_path = self._resolve_trace_path(trace.trace_id)
        self.init()
        encoded = self._serialize_trace(trace)

        existed = target_path.exists()
        if existed:
            existing = self.load(trace.trace_id)
            if existing.frozen:
                raise TraceFrozenError(
                    f"Trace {trace.trace_id!r} is frozen and cannot be overwritten"
                )
            if not overwrite:
                raise FileExistsError(
                    f"Trace {trace.trace_id!r} already exists; pass overwrite=True to replace"
                )

        _atomic_write_bytes(target_path, encoded)
        try:
            self._index.upsert(trace)
        except Exception:
            if not existed:
                with contextlib.suppress(OSError):
                    target_path.unlink()
            raise

        return target_path

    def load(self, trace_id: str) -> Trace:
        """Load and validate a trace from disk with path and size guards."""
        target_path = self._resolve_trace_path(trace_id)
        if not target_path.exists():
            raise TraceNotFoundError(f"Trace {trace_id!r} not found")
        if not target_path.is_file():
            raise UnsafeTraceError(f"Trace path for {trace_id!r} is not a regular file")

        file_size = target_path.stat().st_size
        if file_size > self.max_trace_bytes:
            raise UnsafeTraceError(
                f"Trace file size ({file_size} bytes) exceeds "
                f"max_trace_bytes ({self.max_trace_bytes})"
            )

        raw = target_path.read_bytes()
        trace = Trace.from_json(raw, max_bytes=self.max_trace_bytes)
        if trace.trace_id != trace_id:
            raise UnsafeTraceError(
                f"Trace file {target_path.name!r} contains mismatched trace_id {trace.trace_id!r}"
            )
        return trace

    def freeze(self, trace_id: str) -> Trace:
        """Mark a trace immutable atomically (idempotent if already frozen)."""
        trace = self.load(trace_id)
        if trace.frozen:
            return trace

        frozen_trace = trace.model_copy(update={"frozen": True})
        target_path = self._resolve_trace_path(trace_id)
        encoded = self._serialize_trace(frozen_trace)
        _atomic_write_bytes(target_path, encoded)
        self._index.upsert(frozen_trace)
        return frozen_trace

    def delete(self, trace_id: str, *, force: bool = False) -> None:
        """Delete a trace from disk and SQLite index (requires force=True if frozen)."""
        target_path = self._resolve_trace_path(trace_id)
        if not target_path.exists():
            raise TraceNotFoundError(f"Trace {trace_id!r} not found")

        if not force:
            existing = self.load(trace_id)
            if existing.frozen:
                raise TraceFrozenError(f"Trace {trace_id!r} is frozen; pass force=True to delete")

        target_path.unlink()
        self._index.delete(trace_id)

    def exists(self, trace_id: str) -> bool:
        """Validate trace_id and return True if its trace file exists."""
        target_path = self._resolve_trace_path(trace_id)
        return target_path.is_file()

    def query(self, query: TraceQuery) -> list[TraceSummary]:
        """Query the SQLite metadata index ordered by created_at DESC."""
        self.init()
        return self._index.query(query)

    def list_traces(
        self,
        *,
        status: RunStatus | None = None,
        tag: str | None = None,
        frozen: bool | None = None,
        query: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TraceSummary]:
        """Ergonomic wrapper building a TraceQuery and querying the index."""
        trace_query = TraceQuery(
            status=status,
            tag=tag,
            frozen=frozen,
            query=query,
            limit=limit,
            offset=offset,
        )
        return self.query(trace_query)

    def export_trace(
        self,
        trace_id: str,
        output_path: Path | str,
        *,
        format: ExportFormat = ExportFormat.JSON,
    ) -> Path:
        """Atomically export a trace as canonical JSON or JSONL."""
        out_path = _validate_fs_path(output_path)
        trace = self.load(trace_id)

        if format == ExportFormat.JSON:
            data = trace.to_json(indent=2).encode("utf-8")
        elif format == ExportFormat.JSONL:
            header_payload = trace.model_dump(mode="json", exclude={"events"})
            header_record = {"record_type": "trace_header", **header_payload}
            lines = [json.dumps(header_record, ensure_ascii=False, allow_nan=False)]
            for event in sorted(trace.events, key=lambda e: e.sequence):
                event_record = {"record_type": "event", **event.model_dump(mode="json")}
                lines.append(json.dumps(event_record, ensure_ascii=False, allow_nan=False))
            data = ("\n".join(lines) + "\n").encode("utf-8")
        else:
            raise UnsafeTraceError(f"Unsupported export format: {format!r}")

        _atomic_write_bytes(out_path, data)
        return out_path

    def export_jsonl(self, trace_id: str, output_path: Path | str) -> Path:
        """Convenience wrapper exporting a trace in JSONL format."""
        return self.export_trace(trace_id, output_path, format=ExportFormat.JSONL)

    def import_trace(
        self,
        input_path: Path | str,
        *,
        overwrite: bool = False,
        freeze: bool = False,
    ) -> Trace:
        """Validate and import an external trace JSON file using its internal trace_id."""
        in_path = _validate_fs_path(input_path)
        if not in_path.exists():
            raise FileNotFoundError(f"Input trace file not found: {in_path}")
        if not in_path.is_file():
            raise UnsafeTraceError(f"Input trace path is not a regular file: {in_path}")

        file_size = in_path.stat().st_size
        if file_size > self.max_trace_bytes:
            raise UnsafeTraceError(
                f"Input trace file size ({file_size} bytes) exceeds "
                f"max_trace_bytes ({self.max_trace_bytes})"
            )

        raw = in_path.read_bytes()
        trace = Trace.from_json(raw, max_bytes=self.max_trace_bytes)
        if freeze and not trace.frozen:
            trace = trace.model_copy(update={"frozen": True})

        self.save(trace, overwrite=overwrite)
        return trace

    def reindex(self) -> int:
        """Rebuild index.db from all JSON trace files in traces/."""
        self.init()
        traces_root = self.traces_dir.resolve()
        loaded_traces: list[Trace] = []

        for path in sorted(self.traces_dir.glob("*.json")):
            try:
                resolved = path.resolve()
            except OSError as exc:
                raise UnsafeTraceError(f"Unable to resolve trace file {path.name!r}") from exc

            if not resolved.is_relative_to(traces_root):
                raise UnsafeTraceError(
                    f"Trace file {path.name!r} escapes traces directory {traces_root}"
                )
            if not path.is_file():
                raise UnsafeTraceError(f"Trace path {path.name!r} is not a regular file")

            file_size = path.stat().st_size
            if file_size > self.max_trace_bytes:
                raise UnsafeTraceError(
                    f"Trace file {path.name!r} ({file_size} bytes) exceeds "
                    f"max_trace_bytes ({self.max_trace_bytes})"
                )

            raw = path.read_bytes()
            trace = Trace.from_json(raw, max_bytes=self.max_trace_bytes)
            if path.stem != trace.trace_id:
                raise UnsafeTraceError(
                    f"Trace file {path.name!r} does not match internal trace_id {trace.trace_id!r}"
                )
            loaded_traces.append(trace)

        self._index.clear()
        for trace in loaded_traces:
            self._index.upsert(trace)
        return len(loaded_traces)

    def close(self) -> None:
        """Close the underlying SQLite connection cleanly."""
        self._index.close()


__all__ = ["TraceStore"]

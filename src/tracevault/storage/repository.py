"""Storage models and TraceRepository protocol for TraceVault."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import Field, field_validator

from tracevault.schema import (
    ExportFormat,
    RunStatus,
    Trace,
    TraceVaultModel,
    ensure_utc_datetime,
)


class TraceSummary(TraceVaultModel):
    """Lightweight indexed summary of a persisted Trace."""

    trace_id: str
    root_run_id: str
    run_name: str
    status: RunStatus
    created_at: datetime
    frozen: bool
    parent_trace_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    span_count: int = Field(default=0, ge=0)
    event_count: int = Field(default=0, ge=0)
    fixture_count: int = Field(default=0, ge=0)

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)


class TraceQuery(TraceVaultModel):
    """Structured filter parameters for querying indexed traces."""

    status: RunStatus | None = None
    tag: str | None = None
    frozen: bool | None = None
    parent_trace_id: str | None = None
    query: str | None = None
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


@runtime_checkable
class TraceRepository(Protocol):
    """Canonical persistence interface for TraceVault trace stores."""

    def init(self) -> Path:
        """Idempotently initialize the trace repository on disk."""
        ...

    def save(self, trace: Trace, *, overwrite: bool = False) -> Path:
        """Persist a trace atomically and update its index metadata."""
        ...

    def load(self, trace_id: str) -> Trace:
        """Load and validate a trace by trace_id."""
        ...

    def freeze(self, trace_id: str) -> Trace:
        """Mark a trace immutable (idempotent if already frozen)."""
        ...

    def delete(self, trace_id: str, *, force: bool = False) -> None:
        """Delete a trace from disk and index (requires force=True if frozen)."""
        ...

    def exists(self, trace_id: str) -> bool:
        """Return True if a trace exists in the repository."""
        ...

    def query(self, query: TraceQuery) -> list[TraceSummary]:
        """Query indexed trace summaries ordered by created_at DESC."""
        ...

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
        """Ergonomic wrapper around query() for listing traces."""
        ...

    def export_trace(
        self,
        trace_id: str,
        output_path: Path | str,
        *,
        format: ExportFormat = ExportFormat.JSON,
    ) -> Path:
        """Export a trace atomically to JSON or JSONL."""
        ...

    def export_jsonl(self, trace_id: str, output_path: Path | str) -> Path:
        """Export a trace atomically to JSONL format."""
        ...

    def import_trace(
        self,
        input_path: Path | str,
        *,
        overwrite: bool = False,
        freeze: bool = False,
    ) -> Trace:
        """Validate and import an external trace JSON file into the repository."""
        ...

    def reindex(self) -> int:
        """Rebuild the metadata index from all trace files on disk."""
        ...

    def close(self) -> None:
        """Release underlying repository resources cleanly."""
        ...


__all__ = [
    "TraceSummary",
    "TraceQuery",
    "TraceRepository",
]

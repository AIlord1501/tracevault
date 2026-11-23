"""SQLite WAL-backed metadata index for TraceVault."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from tracevault.schema import RunStatus, Trace
from tracevault.storage.repository import TraceQuery, TraceSummary

_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS traces (
        trace_id TEXT PRIMARY KEY,
        root_run_id TEXT NOT NULL,
        run_name TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        frozen INTEGER NOT NULL,
        parent_trace_id TEXT,
        span_count INTEGER NOT NULL DEFAULT 0,
        event_count INTEGER NOT NULL DEFAULT 0,
        fixture_count INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS trace_tags (
        trace_id TEXT NOT NULL,
        tag TEXT NOT NULL,
        PRIMARY KEY (trace_id, tag),
        FOREIGN KEY (trace_id) REFERENCES traces(trace_id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_traces_status ON traces(status)",
    "CREATE INDEX IF NOT EXISTS idx_traces_created_at ON traces(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_traces_frozen ON traces(frozen)",
    "CREATE INDEX IF NOT EXISTS idx_traces_parent_trace_id ON traces(parent_trace_id)",
    "CREATE INDEX IF NOT EXISTS idx_trace_tags_tag_trace_id ON trace_tags(tag, trace_id)",
)

_UPSERT_TRACE_SQL = """
INSERT INTO traces (
    trace_id,
    root_run_id,
    run_name,
    status,
    created_at,
    frozen,
    parent_trace_id,
    span_count,
    event_count,
    fixture_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(trace_id) DO UPDATE SET
    root_run_id = excluded.root_run_id,
    run_name = excluded.run_name,
    status = excluded.status,
    created_at = excluded.created_at,
    frozen = excluded.frozen,
    parent_trace_id = excluded.parent_trace_id,
    span_count = excluded.span_count,
    event_count = excluded.event_count,
    fixture_count = excluded.fixture_count
"""

_QUERY_TRACES_SQL = """
SELECT
    t.trace_id,
    t.root_run_id,
    t.run_name,
    t.status,
    t.created_at,
    t.frozen,
    t.parent_trace_id,
    t.span_count,
    t.event_count,
    t.fixture_count
FROM traces AS t
WHERE (? IS NULL OR t.status = ?)
  AND (? IS NULL OR t.frozen = ?)
  AND (? IS NULL OR t.parent_trace_id = ?)
  AND (? IS NULL OR EXISTS (
      SELECT 1 FROM trace_tags AS tt
      WHERE tt.trace_id = t.trace_id AND tt.tag = ?
  ))
  AND (? IS NULL OR (
      LOWER(t.trace_id) LIKE ? ESCAPE '\\'
      OR LOWER(t.run_name) LIKE ? ESCAPE '\\'
      OR LOWER(t.root_run_id) LIKE ? ESCAPE '\\'
  ))
ORDER BY t.created_at DESC, t.trace_id DESC
LIMIT ? OFFSET ?
"""

_SELECT_TAGS_SQL = "SELECT tag FROM trace_tags WHERE trace_id = ? ORDER BY tag ASC"


def _format_utc_timestamp(dt: datetime) -> str:
    """Format a UTC datetime with fixed microsecond precision for exact lexicographical ordering."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _escape_like_pattern(term: str) -> str:
    """Escape SQL LIKE wildcard characters so substring searches match literally."""
    escaped = term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class TraceIndex:
    """SQLite WAL metadata index backing fast TraceStore queries."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path: Path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                conn.close()
                raise
            self._conn = conn
        return self._conn

    def initialize(self) -> None:
        """Create index tables and secondary indexes idempotently."""
        conn = self._connect()
        with conn:
            for statement in _SCHEMA_SQL:
                conn.execute(statement)

    def _ensure_ready(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._connect()

    def upsert(self, trace: Trace) -> None:
        """Insert or update metadata and tags for a trace inside a transaction."""
        conn = self._ensure_ready()
        root_run = trace.root_run
        created_at_str = _format_utc_timestamp(trace.created_at)
        unique_tags = list(dict.fromkeys(root_run.tags))

        with conn:
            conn.execute(
                _UPSERT_TRACE_SQL,
                (
                    trace.trace_id,
                    root_run.run_id,
                    root_run.name,
                    root_run.status.value,
                    created_at_str,
                    1 if trace.frozen else 0,
                    trace.parent_trace_id,
                    len(trace.spans),
                    len(trace.events),
                    len(trace.fixtures.entries),
                ),
            )
            conn.execute("DELETE FROM trace_tags WHERE trace_id = ?", (trace.trace_id,))
            if unique_tags:
                conn.executemany(
                    "INSERT INTO trace_tags (trace_id, tag) VALUES (?, ?)",
                    [(trace.trace_id, tag) for tag in unique_tags],
                )

    def delete(self, trace_id: str) -> None:
        """Remove a trace and its tags from the index."""
        conn = self._ensure_ready()
        with conn:
            conn.execute("DELETE FROM traces WHERE trace_id = ?", (trace_id,))

    def query(self, query: TraceQuery) -> list[TraceSummary]:
        """Query indexed trace summaries using strictly parameterized SQL."""
        conn = self._ensure_ready()

        status_val = query.status.value if query.status is not None else None
        frozen_val = (1 if query.frozen else 0) if query.frozen is not None else None
        parent_val = query.parent_trace_id
        tag_val = query.tag
        like_pattern = _escape_like_pattern(query.query) if query.query is not None else None

        cursor = conn.execute(
            _QUERY_TRACES_SQL,
            (
                status_val,
                status_val,
                frozen_val,
                frozen_val,
                parent_val,
                parent_val,
                tag_val,
                tag_val,
                like_pattern,
                like_pattern,
                like_pattern,
                like_pattern,
                query.limit,
                query.offset,
            ),
        )
        rows = cursor.fetchall()

        summaries: list[TraceSummary] = []
        for row in rows:
            trace_id = str(row["trace_id"])
            tag_rows = conn.execute(_SELECT_TAGS_SQL, (trace_id,)).fetchall()
            tags = [str(tag_row["tag"]) for tag_row in tag_rows]
            summaries.append(
                TraceSummary(
                    trace_id=trace_id,
                    root_run_id=str(row["root_run_id"]),
                    run_name=str(row["run_name"]),
                    status=RunStatus(row["status"]),
                    created_at=datetime.fromisoformat(str(row["created_at"])),
                    frozen=bool(row["frozen"]),
                    parent_trace_id=(
                        str(row["parent_trace_id"]) if row["parent_trace_id"] is not None else None
                    ),
                    tags=tags,
                    span_count=int(row["span_count"]),
                    event_count=int(row["event_count"]),
                    fixture_count=int(row["fixture_count"]),
                )
            )
        return summaries

    def clear(self) -> None:
        """Remove all rows from the metadata index."""
        conn = self._ensure_ready()
        with conn:
            conn.execute("DELETE FROM trace_tags")
            conn.execute("DELETE FROM traces")

    def close(self) -> None:
        """Close the SQLite connection cleanly."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None


__all__ = ["TraceIndex"]

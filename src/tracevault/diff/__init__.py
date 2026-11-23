"""Structural trace comparison, divergence analysis, and diff formatting."""

from __future__ import annotations

from tracevault.diff.engine import (
    DEFAULT_SEVERITY_MAP,
    DiffEngine,
    diff_traces,
    find_earliest_divergence,
)
from tracevault.diff.formatter import (
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)

__all__ = [
    "DEFAULT_SEVERITY_MAP",
    "DiffEngine",
    "diff_traces",
    "find_earliest_divergence",
    "format_diff_json",
    "format_diff_report",
    "render_diff_rich",
]

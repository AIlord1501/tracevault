"""Unit tests for tracevault.diff.formatter."""

from __future__ import annotations

import json

from rich.console import Console

from tracevault.diff import (
    format_diff_json,
    format_diff_report,
    render_diff_rich,
)
from tracevault.schema import (
    DiffReport,
    Divergence,
    DivergenceKind,
    DivergenceSeverity,
)


def _identical_report() -> DiffReport:
    return DiffReport(
        baseline_trace_id="tr_base_001",
        candidate_trace_id="tr_cand_001",
        identical=True,
        divergences=[],
        summary={"info": 0, "warning": 0, "breaking": 0, "total": 0},
    )


def _divergent_report() -> DiffReport:
    return DiffReport(
        baseline_trace_id="tr_base_001",
        candidate_trace_id="tr_cand_002",
        identical=False,
        divergences=[
            Divergence(
                kind=DivergenceKind.EVENT_PAYLOAD_CHANGED,
                severity=DivergenceSeverity.INFO,
                path="created_at",
                message="Trace created_at timestamp changed",
                baseline="2026-11-24T00:00:00+00:00",
                candidate="2026-11-24T00:01:00+00:00",
            ),
            Divergence(
                kind=DivergenceKind.OUTPUT_CHANGED,
                severity=DivergenceSeverity.BREAKING,
                path="runs[0].outputs.category",
                message="Run 'triage' outputs changed at 'runs[0].outputs.category'",
                baseline="billing",
                candidate="refund",
            ),
            Divergence(
                kind=DivergenceKind.SPAN_ADDED,
                severity=DivergenceSeverity.WARNING,
                path="spans[2]",
                message="Span 'extra_step' (tool) was added",
                baseline=None,
                candidate={"name": "extra_step"},
            ),
        ],
        summary={"info": 1, "warning": 1, "breaking": 1, "total": 3},
    )


def test_format_diff_report_identical() -> None:
    text = format_diff_report(_identical_report())
    assert "IDENTICAL" in text
    assert "tr_base_001" in text
    assert "tr_cand_001" in text
    assert "breaking=0, warning=0, info=0, total=0" in text
    assert "Divergences:" not in text


def test_format_diff_report_divergent_concise_and_verbose() -> None:
    report = _divergent_report()

    concise = format_diff_report(report, verbose=False)
    assert "DIVERGENT" in concise
    assert "breaking=1, warning=1, info=1, total=3" in concise
    assert "Earliest : [BREAKING] output_changed at runs[0].outputs.category" in concise
    assert "[BREAKING] output_changed at runs[0].outputs.category" in concise
    assert "[WARNING] span_added at spans[2]" in concise
    assert "[INFO] event_payload_changed at created_at" in concise
    assert "baseline :" not in concise

    verbose = format_diff_report(report, verbose=True)
    assert 'baseline : "billing"' in verbose
    assert 'candidate: "refund"' in verbose
    assert 'candidate: {"name": "extra_step"}' in verbose

    # Deterministic across repeated calls
    assert format_diff_report(report, verbose=True) == verbose


def test_format_diff_json_round_trip() -> None:
    report = _divergent_report()
    raw_json = format_diff_json(report, indent=2)
    parsed = json.loads(raw_json)
    assert parsed["baseline_trace_id"] == "tr_base_001"
    assert parsed["candidate_trace_id"] == "tr_cand_002"
    assert parsed["identical"] is False
    assert len(parsed["divergences"]) == 3

    reconstructed = DiffReport.model_validate_json(raw_json)
    assert reconstructed == report


def test_render_diff_rich_identical_and_divergent() -> None:
    console_identical = Console(record=True, width=120)
    render_diff_rich(_identical_report(), console=console_identical)
    out_identical = console_identical.export_text()
    assert "TraceVault Diff Report" in out_identical
    assert "IDENTICAL" in out_identical
    assert "tr_base_001" in out_identical

    console_div = Console(record=True, width=120)
    render_diff_rich(_divergent_report(), console=console_div)
    out_div = console_div.export_text()
    assert "DIVERGENT" in out_div
    assert "BREAKING" in out_div
    assert "WARNING" in out_div
    assert "INFO" in out_div
    assert "runs[0].outputs.category" in out_div
    assert "spans[2]" in out_div

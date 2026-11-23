"""Deterministic assertions for TraceVault structural diff reports."""

from __future__ import annotations

from typing import Any

from tracevault.diff import diff_traces, format_diff_report
from tracevault.schema import (
    DiffConfig,
    DiffReport,
    Divergence,
    DivergenceKind,
    DivergenceSeverity,
    RedactionConfig,
    Trace,
    redact_data,
)


def _redact_divergence_value(path: str, value: Any, cfg: RedactionConfig) -> Any:
    """Redact a divergence value using both its dotted path context and value patterns."""
    if value is None:
        return None
    segments = [seg.split("[", 1)[0] for seg in path.split(".") if seg]
    for seg in segments:
        if seg and redact_data({seg: "probe"}, config=cfg).get(seg) == cfg.replacement:
            return cfg.replacement
    return redact_data(value, config=cfg)


def _redacted_report(report: DiffReport) -> DiffReport:
    """Return a copy of DiffReport with baseline/candidate values scrubbed for safe diagnostics."""
    cfg = RedactionConfig()
    redacted_divs = [
        Divergence(
            kind=d.kind,
            severity=d.severity,
            path=d.path,
            message=str(redact_data(d.message, config=cfg)),
            baseline=_redact_divergence_value(d.path, d.baseline, cfg),
            candidate=_redact_divergence_value(d.path, d.candidate, cfg),
        )
        for d in report.divergences
    ]
    return DiffReport(
        baseline_trace_id=report.baseline_trace_id,
        candidate_trace_id=report.candidate_trace_id,
        identical=report.identical,
        divergences=redacted_divs,
        summary=dict(report.summary),
    )


def assert_traces_equivalent(
    baseline: Trace,
    candidate: Trace,
    *,
    config: DiffConfig | None = None,
) -> DiffReport:
    """Compare baseline and candidate traces and assert zero divergences."""
    report = diff_traces(baseline, candidate, config=config)
    if not report.identical or report.divergences:
        safe_rep = _redacted_report(report)
        formatted = format_diff_report(safe_rep, verbose=True)
        raise AssertionError(
            f"Traces {baseline.trace_id!r} and {candidate.trace_id!r} are not equivalent:\n"
            f"{formatted}"
        )
    return report


def assert_no_breaking_diffs(report: DiffReport) -> None:
    """Assert that a DiffReport contains zero BREAKING divergences."""
    if report.has_breaking:
        safe_rep = _redacted_report(report)
        breaking = [
            f"{d.kind.value} at {d.path}: {d.message}"
            for d in safe_rep.divergences
            if d.severity == DivergenceSeverity.BREAKING
        ]
        formatted = format_diff_report(safe_rep, verbose=True)
        raise AssertionError(
            f"Expected 0 breaking divergences between {report.baseline_trace_id!r} and "
            f"{report.candidate_trace_id!r}, found {len(breaking)}: {breaking}\n"
            f"{formatted}"
        )


def assert_diff_matches_expectations(
    report: DiffReport,
    *,
    max_warnings: int | None = None,
    allowed_kinds: set[DivergenceKind] | None = None,
) -> None:
    """Assert that a DiffReport satisfies warning thresholds and allowed DivergenceKinds."""
    safe_rep = _redacted_report(report)

    if allowed_kinds is not None:
        disallowed = [
            f"{d.kind.value} at {d.path}"
            for d in safe_rep.divergences
            if d.kind not in allowed_kinds
        ]
        if disallowed:
            formatted = format_diff_report(safe_rep, verbose=True)
            raise AssertionError(
                f"DiffReport contains disallowed divergence kinds {disallowed} "
                f"(allowed={[k.value for k in sorted(allowed_kinds, key=lambda x: x.value)]}):\n"
                f"{formatted}"
            )
    else:
        assert_no_breaking_diffs(report)

    if max_warnings is not None:
        if max_warnings < 0:
            raise ValueError("max_warnings must be >= 0")
        warning_count = sum(
            1 for d in report.divergences if d.severity == DivergenceSeverity.WARNING
        )
        if warning_count > max_warnings:
            formatted = format_diff_report(safe_rep, verbose=True)
            raise AssertionError(
                f"Expected at most {max_warnings} warning divergence(s), "
                f"but found {warning_count}:\n{formatted}"
            )


__all__ = [
    "assert_diff_matches_expectations",
    "assert_no_breaking_diffs",
    "assert_traces_equivalent",
]

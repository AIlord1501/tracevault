"""Deterministic assertions for TraceVault offline replay results."""

from __future__ import annotations

from tracevault.schema import (
    RedactionConfig,
    ReplayResult,
    canonical_json,
    redact_data,
)


def _safe_error_str(result: ReplayResult) -> str:
    if result.error is None:
        return "None"
    redacted = redact_data(result.error.model_dump(mode="json"), config=RedactionConfig())
    return canonical_json(redacted)


def assert_replay_succeeded(result: ReplayResult) -> None:
    """Assert that a ReplayResult succeeded without an execution error."""
    if not result.success or result.error is not None:
        raise AssertionError(
            f"Replay of baseline trace {result.baseline_trace_id!r} (mode={result.mode.value!r}) "
            f"failed: success={result.success}, error={_safe_error_str(result)}"
        )


def assert_all_fixtures_matched(result: ReplayResult) -> None:
    """Assert that every requested fixture during replay was matched (zero missing fixtures)."""
    if result.missing_fixtures:
        raise AssertionError(
            f"Replay of baseline trace {result.baseline_trace_id!r} had "
            f"{len(result.missing_fixtures)} missing fixture(s): {result.missing_fixtures}"
        )
    expected_count = len(result.candidate_trace.fixtures.entries)
    if expected_count > 0 and result.matched_fixtures == 0:
        raise AssertionError(
            f"Replay of baseline trace {result.baseline_trace_id!r} matched 0 fixtures "
            f"(candidate has {expected_count} fixture entries)"
        )


def assert_no_live_calls(result: ReplayResult) -> None:
    """Assert that zero live external boundary calls occurred during replay."""
    if result.live_calls != 0:
        raise AssertionError(
            f"Expected 0 live boundary calls during replay of {result.baseline_trace_id!r}, "
            f"but recorded {result.live_calls} live call(s)"
        )


def assert_replay_clean(result: ReplayResult) -> None:
    """Assert replay succeeded, matched all fixtures, and made zero live calls."""
    assert_replay_succeeded(result)
    assert_no_live_calls(result)
    assert_all_fixtures_matched(result)


__all__ = [
    "assert_all_fixtures_matched",
    "assert_no_live_calls",
    "assert_replay_clean",
    "assert_replay_succeeded",
]

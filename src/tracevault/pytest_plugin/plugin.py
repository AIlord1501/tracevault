"""Pytest plugin, isolated test fixtures, and regression verification runner for TraceVault."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from tracevault.assertions import (
    TraceAssertions,
    assert_all_fixtures_matched,
    assert_no_breaking_diffs,
    assert_no_live_calls,
    assert_replay_succeeded,
    assert_trace_valid,
    expect_trace,
)
from tracevault.diff import diff_traces
from tracevault.replay import ReplayEngine
from tracevault.schema import (
    DEFAULT_MAX_TRACE_BYTES,
    DiffConfig,
    DiffReport,
    ReplayConfig,
    ReplayMode,
    RunStatus,
    Trace,
    TraceNotFoundError,
    UnsafeTraceError,
    validate_trace_id,
)
from tracevault.storage import TraceStore


def _validate_trace_file_path(trace_path: Path | str) -> Path:
    """Validate a regression trace JSON file path for safe loading."""
    raw = str(trace_path)
    if not raw or not raw.strip():
        raise UnsafeTraceError("Trace file path must be non-empty")
    if "\x00" in raw:
        raise UnsafeTraceError("Trace file path must not contain NUL bytes")

    path = Path(raw)
    if path.suffix.lower() != ".json":
        raise UnsafeTraceError(f"Regression trace file must have a .json extension: {raw!r}")
    if not path.exists() or not path.is_file():
        raise TraceNotFoundError(f"Regression trace file not found: {raw!r}")

    size = path.stat().st_size
    if size > DEFAULT_MAX_TRACE_BYTES:
        raise UnsafeTraceError(
            f"Regression trace file size ({size} bytes) exceeds maximum allowed "
            f"({DEFAULT_MAX_TRACE_BYTES} bytes)"
        )
    return path.resolve()


def load_regression_trace(trace_path: Path | str) -> Trace:
    """Safely load and validate a Trace from a JSON regression fixture file."""
    resolved = _validate_trace_file_path(trace_path)
    raw_json = resolved.read_text(encoding="utf-8")
    trace = Trace.from_json(raw_json)
    assert_trace_valid(trace)
    return trace


def verify_regression_trace(
    trace_path: Path | str,
    *,
    config: ReplayConfig | None = None,
    diff_config: DiffConfig | None = None,
) -> DiffReport:
    """Load a trace JSON artifact, execute offline replay, assert invariants, and return diff."""
    baseline = load_regression_trace(trace_path)
    engine = ReplayEngine(baseline, config=config)
    result = engine.replay_trace()

    assert_no_live_calls(result)
    assert_all_fixtures_matched(result)

    if baseline.root_run.status == RunStatus.COMPLETED and baseline.root_run.error is None:
        assert_replay_succeeded(result)

    report = diff_traces(baseline, result.candidate_trace, config=diff_config)
    assert_no_breaking_diffs(report)
    return report


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register optional TraceVault CLI flags with pytest."""
    group = parser.getgroup("tracevault", "TraceVault offline replay & regression testing")
    group.addoption(
        "--tracevault-store",
        action="store",
        default=None,
        help="Optional default directory path for reading captured TraceVault traces.",
    )
    group.addoption(
        "--tracevault-lenient-replay",
        action="store_true",
        default=False,
        help="Default tracevault_replay fixture to OFFLINE_LENIENT mode instead of OFFLINE_STRICT.",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register TraceVault pytest markers without global side effects."""
    config.addinivalue_line(
        "markers",
        "tracevault_regression: mark test as a TraceVault offline replay regression test.",
    )


@pytest.fixture
def tracevault_store(tmp_path: Path) -> Iterator[TraceStore]:
    """Provide an isolated, per-test TraceStore in tmp_path and close it cleanly on teardown."""
    store = TraceStore(tmp_path / ".tracevault")
    store.init()
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def tracevault_load_trace(
    tracevault_store: TraceStore,
    request: pytest.FixtureRequest,
) -> Callable[[Trace | Path | str], Trace]:
    """Factory fixture that loads a Trace from an instance, JSON file path, or trace_id."""
    configured_store_dir = request.config.getoption("--tracevault-store", default=None)

    def _loader(target: Trace | Path | str, *, store: TraceStore | None = None) -> Trace:
        if isinstance(target, Trace):
            assert_trace_valid(target)
            return target

        if isinstance(target, Path) or (
            isinstance(target, str)
            and (target.endswith(".json") or "/" in target or "\\" in target)
        ):
            return load_regression_trace(target)

        trace_id = validate_trace_id(str(target))
        active_store = store or tracevault_store
        if active_store.exists(trace_id):
            return active_store.load(trace_id)

        if configured_store_dir is not None:
            fallback_store = TraceStore(Path(str(configured_store_dir)))
            try:
                if fallback_store.exists(trace_id):
                    return fallback_store.load(trace_id)
            finally:
                fallback_store.close()

        raise TraceNotFoundError(f"Trace {trace_id!r} not found in test store")

    return _loader


@pytest.fixture
def tracevault_replay(
    tracevault_load_trace: Callable[..., Trace],
    request: pytest.FixtureRequest,
) -> Callable[..., ReplayEngine]:
    """Factory fixture creating an isolated offline ReplayEngine from a Trace, path, or trace_id."""
    lenient_flag = bool(request.config.getoption("--tracevault-lenient-replay", default=False))

    def _factory(
        target: Trace | Path | str,
        *,
        config: ReplayConfig | None = None,
        store: TraceStore | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> ReplayEngine:
        trace = tracevault_load_trace(target, store=store)
        effective_config = config
        if effective_config is None:
            mode = ReplayMode.OFFLINE_LENIENT if lenient_flag else ReplayMode.OFFLINE_STRICT
            effective_config = ReplayConfig(
                mode=mode,
                overrides=dict(overrides) if overrides is not None else {},
            )
        elif overrides is not None:
            merged_overrides = {**effective_config.overrides, **overrides}
            effective_config = effective_config.model_copy(update={"overrides": merged_overrides})
        return ReplayEngine(trace, config=effective_config)

    return _factory


@pytest.fixture
def tracevault_expect() -> Callable[[Trace], TraceAssertions]:
    """Fixture providing the fluent expect_trace(trace) assertion builder."""
    return expect_trace


__all__ = [
    "load_regression_trace",
    "pytest_addoption",
    "pytest_configure",
    "tracevault_expect",
    "tracevault_load_trace",
    "tracevault_replay",
    "tracevault_store",
    "verify_regression_trace",
]

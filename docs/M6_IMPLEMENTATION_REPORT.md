# TraceVault M6 — Assertions & Pytest Regression Testing Report

## 1. Summary

Milestone M6 delivers TraceVault's deterministic assertion engine (`src/tracevault/assertions/`), portable regression fixture and pytest generator (`src/tracevault/replay/regression.py`), and `pytest11` plugin (`src/tracevault/pytest_plugin/`), fulfilling `docs/CONTRACTS.md` Sections 9.4 and 12 with zero mandatory LLM judge and zero external network dependencies.

## 2. Architecture & Delivered Components

### Assertion Engine (`src/tracevault/assertions/`)
- **Trace Assertions (`trace.py`)**:
  - `assert_trace_valid`, `assert_run_succeeded`, `assert_run_status`, `assert_run_output` (exact, subset, key/value)
  - `assert_span_exists`, `assert_span_status`, `assert_span_duration_under`
  - `assert_event_exists`, `assert_event_absent`, `assert_event_order` (subsequence & contiguous)
  - `assert_tool_called`, `assert_tool_not_called`, `assert_tool_output`
  - `assert_model_called`, `assert_model_output`, `assert_retrieval_results`
  - `assert_agent_transition`, `assert_state_change`
  - `assert_no_errors`, `assert_error_recorded`, `assert_no_secrets_leaked`
  - `TraceAssertions` / `expect_trace(trace)` fluent declarative builder.
- **Replay Assertions (`replay.py`)**:
  - `assert_replay_succeeded`, `assert_all_fixtures_matched`, `assert_no_live_calls`, `assert_replay_clean`.
- **Diff Assertions (`diff.py`)**:
  - `assert_traces_equivalent`, `assert_no_breaking_diffs`, `assert_diff_matches_expectations` (with path-context-aware redaction in failure diagnostics).

### Portable Regression Fixture & Test Generator (`src/tracevault/replay/regression.py`)
- `export_regression_fixture(trace, output_path, *, redact=True) -> Path`: validates `.json` path, scrubs secrets recursively, recomputes affected fixture fingerprints, and writes atomic canonical JSON.
- `generate_pytest_regression(trace, output_path, *, trace_path=None, ...) -> Path`: emits a standalone, Ruff-clean `.py` pytest test file using `json.dumps(..., ensure_ascii=False)` exclusively (zero raw string interpolation, immune to code injection and UTF-16 lone-surrogate issues).

### Pytest Plugin (`src/tracevault/pytest_plugin/`)
- Registered under `[project.entry-points."pytest11"] tracevault = "tracevault.pytest_plugin.plugin"`.
- Isolated fixtures: `tracevault_store` (closes SQLite on teardown), `tracevault_load_trace`, `tracevault_replay`, `tracevault_expect`.
- Helpers & CLI options: `load_regression_trace`, `verify_regression_trace`, `--tracevault-store`, `--tracevault-lenient-replay`, and `@pytest.mark.tracevault_regression`.

## 3. Agents & Security Audit Findings Resolved

- **Lead Architect**: Implemented `src/tracevault/assertions/`, `src/tracevault/pytest_plugin/`, top-level exports in `src/tracevault/__init__.py`, `docs/ASSERTIONS_AND_PYTEST.md`, and `examples/regression_examples.py`.
- **`replay-engineer` (M6A)**: Implemented `src/tracevault/replay/regression.py` and `tests/unit/replay/test_regression.py`.
- **`qa-security-engineer` (M6B)**: Authored `tests/security/test_m6_security.py` and `tests/integration/test_m6_integration.py`, surfacing two issues that were fixed before commit:
  1. **Path-aware secret redaction in `_redacted_report`** (`src/tracevault/assertions/diff.py`): Leaf scalar values under sensitive path keys (e.g., `runs[0].outputs.api_key`) are now probed against `redact_data({segment: ...})` so non-pattern secrets under sensitive key names are always scrubbed in `AssertionError` diagnostics.
  2. **Non-BMP Unicode handling in `generate_pytest_regression`** (`src/tracevault/replay/regression.py`): Switched emitted Python string literals to `json.dumps(..., ensure_ascii=False)` so emojis/non-BMP characters are written as valid UTF-8 rather than `\ud83d\ude80` surrogate escapes.

## 4. Validation & Commit Log

- `e9149ae` `feat(assertions): add trace, replay, and diff assertion engine`
- `7dc47d8` `feat(regression): add portable regression fixture and pytest generator`
- `c775d25` `feat(pytest): add pytest plugin fixtures and top-level M6 exports`
- `3e9a216` `test(m6): add security and integration tests for assertions and regression`

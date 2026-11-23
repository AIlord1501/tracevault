# TraceVault M4 — Offline Replay Engine Implementation Report

**Milestone**: M4 (Offline Replay Engine & Policy-Governed Boundary Replay)  
**Status**: Completed, Verified, Committed & Pushed  
**Runtime**: Python 3.12.10 (`uv`, Pydantic v2.14.4, pytest 9.2.0, pytest-asyncio 1.5.0, Hypothesis 6.170.17, Ruff 0.17.6, mypy 2.4.1)

---

## 1. Summary

Milestone M4 delivers TraceVault's deterministic offline replay engine (`tracevault.replay`) built strictly on top of M2 canonical schemas (`tracevault.schema`) and M2/M3 storage and capture APIs. Captured traces can now be loaded from `TraceStore`, replayed offline with zero external API calls, forked with targeted fixture overrides, and executed through policy-governed `ModelBoundary`, `ToolBoundary`, and `RetrievalBoundary` adapters that fail closed on unauthorized live calls.

---

## 2. Replay Architecture

`src/tracevault/replay/` preserves the acyclic dependency graph in `docs/ARCHITECTURE.md`:
- Depends at runtime **only** on `tracevault.schema` + Python stdlib (`contextvars`, `threading`, `copy`, `datetime`, `uuid`).
- References `TraceRepository` strictly under `TYPE_CHECKING` in `ReplayEngine.from_store(...)` (zero runtime coupling to `tracevault.storage` internals).
- Source `Trace` and `FixtureSet` remain 100% immutable; returned response payloads are defensive deep copies; candidate/forked traces are newly materialized `Trace` models with `parent_trace_id` lineage and `metadata["replay"]` timing/mode telemetry.

---

## 3. Features & Public APIs

Re-exported from both `tracevault.replay` and top-level `tracevault` (85 total top-level exports):
- **`FixtureMatchResult` & `FixtureMatcher`** (`matcher.py`): Thread-safe deterministic fixture matching, override precedence, consumption tracking, and secret-safe mismatch diagnostics.
- **`ReplayEngine` & `get_current_replay_engine()`** (`engine.py`):
  - `ReplayEngine(trace, config=None)` & `ReplayEngine.from_store(store, trace_id, config=None)`
  - Context manager (`with ReplayEngine(trace) as engine:`) with `ContextVar` isolation
  - `replay_interaction(boundary, request, *, name=None) -> dict[str, Any]` (strictly offline)
  - `replay_trace(*, fork=False, new_trace_id=None) -> ReplayResult`
  - `fork(*, overrides=None, override_rules=None, new_trace_id=None) -> Trace`
  - `build_result(*, fork=False, new_trace_id=None, error=None) -> ReplayResult`
- **`BoundaryExecutor`, `ModelBoundary`, `ToolBoundary`, `RetrievalBoundary`** (`boundaries.py`):
  - `evaluate_policy(boundary, *, tool_name=None, host=None) -> BoundaryPolicyDecision`
  - `execute(...)` enforcing `RECORDED`, `DENY`, and fail-closed `LIVE` execution under `SafetyPolicy`.

---

## 4. Fixture Matching Algorithm

1. Validate incoming `request` with `validate_json_safe(request)` **before** redaction (rejects cycles, non-JSON types, `NaN`/`Infinity`, depth `> 64`).
2. Redact sensitive keys/patterns via `redact_data(request)`.
3. Compute deterministic SHA-256 fingerprint via `compute_fingerprint(boundary, redacted_request)`.
4. Increment monotonic per-`(boundary, fingerprint)` `call_index` (`0, 1, 2, ...`).
5. **Mode resolution**:
   - `OFFLINE_STRICT` (and `RECORDED` boundary lookups): exact `(boundary, fingerprint, call_index)` match; ambiguous duplicates raise `ReplayError`.
   - `OFFLINE_LENIENT`: exact match first → next unconsumed `(boundary, name)` match (if `name` provided) → next unconsumed `boundary` match; fixtures are never double-consumed.
6. **Overrides**: `config.override_rules` (`list[ReplayOverride]`) evaluated in order, followed by `config.overrides` keyed by `fixture_id`, then `fingerprint`.
7. **Misses & Errors**: Missing fixture raises `FixtureNotFoundError` (with secret-safe diagnostics) when `fail_on_missing_fixture=True`, or records miss in `missing_fixtures` and returns `{}` when `False`. Recorded fixture errors raise `ReplayError` in `replay_interaction()` and record `RunStatus.FAILED` (`success=False`) in `replay_trace()`.

---

## 5. Modes & Boundaries

- **`ReplayMode.OFFLINE_STRICT`** (default): Offline exact matching; live calls forbidden.
- **`ReplayMode.OFFLINE_LENIENT`**: Offline lenient fallback; live calls forbidden.
- **`ReplayMode.BOUNDARY_GOVERNED`**: Required for any `BoundaryMode.LIVE` boundary. Every boundary still defaults to `BoundaryMode.RECORDED` and **never** silently falls back to `live_fn` when a fixture is missing.
- **`SafetyPolicy` Fail-Closed Gates for `BoundaryMode.LIVE`**:
  1. `config.mode == ReplayMode.BOUNDARY_GOVERNED`
  2. `boundary in policy.allow_live_boundaries`
  3. `(not policy.require_explicit_opt_in) or policy.max_live_calls > 0`
  4. `engine.live_calls < policy.max_live_calls`
  5. For `TOOL`: `tool_name in policy.allowed_tools`
  6. For `MODEL` / `RETRIEVAL`: `host` verified against `policy.allowed_hosts` when configured/supplied.

---

## 6. Files Changed

### Created
- `src/tracevault/replay/__init__.py`
- `src/tracevault/replay/matcher.py`
- `src/tracevault/replay/engine.py`
- `src/tracevault/replay/boundaries.py`
- `tests/unit/replay/__init__.py`
- `tests/unit/replay/test_matcher.py`
- `tests/unit/replay/test_engine.py`
- `tests/unit/replay/test_boundaries.py`
- `tests/security/test_replay_security.py`
- `tests/integration/test_replay_storage_integration.py`
- `docs/REPLAY.md`
- `examples/replay_examples.py`
- `docs/M4_IMPLEMENTATION_REPORT.md`

### Modified
- `src/tracevault/__init__.py` — wired top-level public replay exports

---

## 7. Agents Used

- **`replay-engineer`** (M4A): Implemented `src/tracevault/replay/` (`matcher.py`, `engine.py`, `boundaries.py`, `__init__.py`) and `tests/unit/replay/` (31 unit tests).
- **`qa-security-engineer`** (M4B, strictly read-only on `src/**`): Implemented `tests/security/test_replay_security.py` (32 adversarial security/policy tests) and `tests/integration/test_replay_storage_integration.py` (3 end-to-end capture→storage→replay tests), verified AST static safety across `src/tracevault/replay/`, and confirmed zero defects.
- **Lead Architect / Orchestrator**: Reviewed all diffs, wired `src/tracevault/__init__.py`, authored `docs/REPLAY.md` and `examples/replay_examples.py`, ran full quality gates, and managed incremental Conventional Commits and pushes.

---

## 8. Tests & Quality Checks

### Test Breakdown (`uv run pytest -q`)
- `tests/unit/schema/`: 71 passed
- `tests/unit/storage/`: 24 passed
- `tests/unit/capture/`: 22 passed
- `tests/unit/replay/`: 31 passed
- `tests/security/` (including `test_replay_security.py` & AST static safety over `replay/`): 278 passed
- `tests/integration/` (capture+storage & capture+storage+replay): 9 passed
- **Total**: **435 passed in 27.42s** (0 warnings, 0 skipped, 0 network calls)

### Quality Gates
- `uv run pytest -q` → **435 passed in 27.42s** (exit code `0`)
- `uv run ruff check src tests examples` → **All checks passed!** (exit code `0`)
- `uv run ruff format --check src tests examples` → **47 files already formatted** (exit code `0`)
- `uv run mypy src` → **Success: no issues found in 21 source files** (exit code `0`)
- `uv run python examples/replay_examples.py` → **Baseline + OfflineReplay + Fork + HybridReplay passed** (exit code `0`)

---

## 9. Security Review

- Zero silent fallback to `live_fn` verified across `ModelBoundary`, `ToolBoundary`, and `RetrievalBoundary` in `RECORDED` mode (both hit and miss paths).
- Every unauthorized `LIVE` and `DENY` path verified to raise `PolicyViolationError` before invoking `live_fn`.
- Hostile inputs (cycles, `NaN`/`Infinity`, non-JSON types, depth `> 64`, hostile `new_trace_id` traversal strings) rejected cleanly; malicious code-injection fixture payloads replayed as inert data.
- Secret redaction verified in `FixtureNotFoundError` diagnostics, candidate traces, and authorized live boundary responses.
- Static AST safety confirmed zero banned imports/calls (`pickle`, `marshal`, `shelve`, `eval`, `exec`, `os.system`, `os.popen`, `subprocess(..., shell=True)`) across all 21 source files.

---

## 10. Limitations & Deviations

### Known Limitations
- `src/tracevault/replay/regression.py` (`generate_pytest_regression`) is intentionally deferred until the Diff Engine (`tracevault.diff`) is implemented so generated regression tests can invoke real `diff_traces(...)`.
- Live boundary execution in `BoundaryExecutor` is synchronous (`Callable[[dict[str, Any]], dict[str, Any]]`); async live boundary wrappers will be paired with async provider adapters in M6.

### Contract Deviations
- **None.** All canonical M2 schema models (`ReplayConfig`, `SafetyPolicy`, `ReplayOverride`, `ReplayResult`, `BoundaryPolicyDecision`) were used verbatim without modifying `src/tracevault/schema/`.

---

## 11. Git Commits, Push & Branch Status

### M4 Commits (on `main`)
- `ea538b4` — `feat(replay): add deterministic fixture matcher with strict/lenient modes and overrides`
- `9d5fdf6` — `feat(replay): implement offline ReplayEngine lifecycle, forking, and context isolation`
- `e424b9c` — `feat(replay): add fail-closed BoundaryExecutor and Model/Tool/Retrieval boundaries`
- `61b8aed` — `test(replay): add security, policy-enforcement, and storage integration tests`
- `c79e866` — `feat(replay): wire top-level public replay exports`
- `5e85c8f` — `docs(m4): document offline replay guide and runnable examples`
- *(Followed by the report commit `docs(m4): add M4 implementation report`)*

### Branch, Remote & Working-Tree Status
- **Branch**: `main` tracking `origin/main` (`https://github.com/AIlord1501/tracevault.git`)
- **Push Status**: All commits pushed cleanly to `origin/main` (`PUSH_EXIT=0`)
- **Working Tree**: Clean after committing this report

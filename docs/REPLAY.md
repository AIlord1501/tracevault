# TraceVault Offline Replay Guide

TraceVault's replay engine (`tracevault.replay`) replays captured AI executions deterministically and offline from recorded `FixtureSet` data without mutating the source trace or making live network calls by default.

---

## 1. Core Guarantees

- **Offline by default**: Every boundary (`model`, `tool`, `retrieval`, `custom`) defaults to `BoundaryMode.RECORDED`.
- **No silent live fallback**: Missing fixtures in `RECORDED` mode raise `FixtureNotFoundError` (or return `{}` when `fail_on_missing_fixture=False`). They **never** fall back to calling a live handler.
- **Source trace immutability**: Replaying or forking never mutates the baseline `Trace`; returned responses are defensive deep copies.
- **Fail-closed live authorization**: Live boundary execution requires `ReplayMode.BOUNDARY_GOVERNED`, `BoundaryMode.LIVE`, AND an explicit `SafetyPolicy` allowing that boundary, tool/host allowlist, and `max_live_calls > 0`.

---

## 2. Replay Configuration (`ReplayConfig`)

```python
from tracevault import BoundaryMode, BoundaryType, ReplayConfig, ReplayMode, SafetyPolicy

# Default: strictly offline, exact fingerprint + call_index matching
strict_cfg = ReplayConfig()

# Lenient offline matching (falls back to unconsumed fixture by name or boundary)
lenient_cfg = ReplayConfig(mode=ReplayMode.OFFLINE_LENIENT, fail_on_missing_fixture=True)

# Policy-governed hybrid boundary replay (explicit live opt-in for one tool)
hybrid_cfg = ReplayConfig(
    mode=ReplayMode.BOUNDARY_GOVERNED,
    boundary_modes={
        BoundaryType.MODEL: BoundaryMode.RECORDED,
        BoundaryType.TOOL: BoundaryMode.LIVE,
        BoundaryType.RETRIEVAL: BoundaryMode.RECORDED,
        BoundaryType.CUSTOM: BoundaryMode.RECORDED,
    },
    safety_policy=SafetyPolicy(
        allow_live_boundaries={BoundaryType.TOOL},
        allowed_tools={"lookup_order"},
        max_live_calls=1,
        require_explicit_opt_in=True,
    ),
)
```

---

## 3. Deterministic Fixture Matching (`FixtureMatcher`)

For every `replay_interaction(boundary, request, name=...)`:
1. `validate_json_safe(request)` validates JSON safety, depth (`<= 64`), finite numbers, and absence of cycles **before** redaction.
2. `redact_data(request)` scrubs sensitive keys and credential patterns.
3. `fingerprint = compute_fingerprint(boundary, redacted_request)` computes a deterministic SHA-256 hex digest from compact sorted-key canonical JSON (`allow_nan=False`).
4. Per-`(boundary, fingerprint)` `call_index` increments monotonically (`0, 1, 2, ...`) to disambiguate repeated identical interactions.
5. **Matching strategy**:
   - `OFFLINE_STRICT` (and `RECORDED` lookups in `BOUNDARY_GOVERNED`): requires exact `(boundary, fingerprint, call_index)`. Ambiguous duplicate entries raise `ReplayError`.
   - `OFFLINE_LENIENT`: tries exact match first; if absent, falls back to the next unconsumed fixture matching `(boundary, name)` (when `name` is provided), then the next unconsumed fixture matching `boundary`. Entries are never double-consumed.
6. **Overrides**: `config.override_rules` (`list[ReplayOverride]`) are evaluated in order (all non-`None` fields must match), followed by `config.overrides` keyed by `fixture_id`, then `fingerprint`.

---

## 4. Replay Modes, Boundaries & Failure Cases

| Scenario | Behavior |
|---|---|
| Missing fixture + `fail_on_missing_fixture=True` | Raises `FixtureNotFoundError` with secret-safe diagnostics (`boundary`, `name`, `fingerprint[:12]`, `call_index`, available count). |
| Missing fixture + `fail_on_missing_fixture=False` | Records miss in `missing_fixtures` and returns `{}`. |
| Ambiguous strict fixture entries | Raises `ReplayError`. |
| Matched fixture recorded an `error` (no override) | Raises `ReplayError` in `replay_interaction()`; records `RunStatus.FAILED` & `success=False` in `replay_trace()`. |
| `BoundaryMode.DENY` | Raises `PolicyViolationError` immediately. |
| `BoundaryMode.LIVE` in `ReplayEngine.replay_interaction()` | Raises `PolicyViolationError` (use `BoundaryExecutor` with explicit `SafetyPolicy`). |
| `BoundaryMode.LIVE` failing any `SafetyPolicy` check | Raises `PolicyViolationError` before invoking `live_fn`. |

---

## 5. Practical Usage

See [examples/replay_examples.py](../examples/replay_examples.py) for a complete runnable offline walkthrough covering:
1. Loading a frozen trace from `TraceStore` via `ReplayEngine.from_store(store, trace_id)`
2. Full trace replay (`engine.replay_trace(fork=True)`) returning `ReplayResult`
3. Interactive replay (`with ReplayEngine(trace) as engine: engine.replay_interaction(...)`) + `engine.build_result()`
4. Forking with response overrides (`engine.fork(overrides={...})`)
5. Policy-governed boundary adapters (`ModelBoundary`, `ToolBoundary`, `RetrievalBoundary`)

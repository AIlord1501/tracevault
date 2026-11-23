# TraceVault Canonical Schema Reference

**Package**: `tracevault.schema`  
**Schema Version**: `1.0.0` (`SUPPORTED_SCHEMA_MAJOR = 1`)  
**Dependencies**: Python 3.12+ standard library + Pydantic v2 only (zero internal TraceVault dependencies).

---

## 1. Design Principles

- **Strict & Immutable Models**: Every model inherits from `TraceVaultModel` with `ConfigDict(extra="forbid", frozen=True, populate_by_name=True)`.
- **Strict UTC Timestamps**: Naive `datetime` objects are rejected; timezone-aware datetimes are normalized to `datetime.UTC`.
- **Safe JSON Only**: Arbitrary Python objects, non-string dict keys, `NaN`/`Infinity`/`-Infinity`, cyclic containers, and nesting deeper than `DEFAULT_MAX_JSON_DEPTH` (64) are rejected with `UnsafeTraceError`.
- **Path-Safe Identifiers**: `trace_id` values must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$` (`InvalidTraceIdError` on violation).
- **Deterministic Fingerprinting**: Requests are hashed with SHA-256 over compact sorted-key canonical JSON (`allow_nan=False`).
- **Default Secret Redaction**: `redact_data()` recursively and idempotently replaces sensitive key values and credential token patterns with `"[REDACTED]"`.

---

## 2. Exception Hierarchy (`errors.py`)

All TraceVault exceptions derive from `TraceVaultError`:

- `InvalidTraceIdError(TraceVaultError)`
- `UnsafeTraceError(TraceVaultError)`
- `TraceNotFoundError(TraceVaultError)`
- `TraceFrozenError(TraceVaultError)`
- `FixtureNotFoundError(TraceVaultError)`
- `PolicyViolationError(TraceVaultError)`
- `ReplayError(TraceVaultError)`
- `AdapterError(TraceVaultError)`
  - `AdapterUnavailableError(AdapterError)`

---

## 3. Canonical Enums (`models.py`)

All enums inherit from `(str, Enum)`:

| Enum | Values |
|---|---|
| `BoundaryType` | `model`, `tool`, `retrieval`, `custom` |
| `SpanType` | `agent`, `workflow`, `model`, `tool`, `retrieval`, `custom` |
| `EventKind` | `run_started`, `run_completed`, `run_failed`, `span_started`, `span_completed`, `span_failed`, `model_request`, `model_response`, `model_error`, `tool_call`, `tool_result`, `tool_error`, `retrieval_query`, `retrieval_result`, `retrieval_error`, `agent_transition`, `state_change`, `stream_chunk`, `exception`, `custom` |
| `RunStatus` | `running`, `completed`, `failed`, `cancelled` |
| `SpanStatus` | `unset`, `ok`, `error`, `cancelled` |
| `ReplayMode` | `offline_strict`, `offline_lenient`, `boundary_governed` |
| `BoundaryMode` | `recorded`, `live`, `deny` |
| `DivergenceSeverity` | `info`, `warning`, `breaking` |
| `DivergenceKind` | `status_changed`, `output_changed`, `error_changed`, `span_added`, `span_removed`, `span_order_changed`, `span_status_changed`, `event_added`, `event_removed`, `event_payload_changed`, `model_input_changed`, `model_output_changed`, `tool_args_changed`, `tool_result_changed`, `retrieval_changed`, `agent_transition_changed`, `state_change_mismatch`, `fixture_mismatch` |
| `ExportFormat` | `json`, `jsonl` |

---

## 4. Core Execution, Replay & Diff Models (`models.py`)

- **Core**: `ExecutionError`, `Event`, `Span`, `Run`, `FixtureEntry`, `FixtureSet`, `Trace`
- **Replay**: `SafetyPolicy`, `ReplayOverride`, `ReplayConfig` (`strict_matching`), `ReplayResult`, `BoundaryPolicyDecision`
- **Diff**: `DiffConfig`, `Divergence`, `DiffReport` (`has_breaking`)

### Structural Invariants on `Trace`
1. `schema_version` must be SemVer `MAJOR.MINOR.PATCH` with `MAJOR == 1`.
2. `trace_id` (and optional `parent_trace_id`) must pass `validate_trace_id`.
3. `runs` is non-empty, `run_id`s are unique, every `run.trace_id == trace.trace_id`, and `parent_run_id` references form a valid DAG.
4. `spans` have unique `span_id`s, valid `run_id`s, and acyclic `parent_span_id` references.
5. `events` have unique `event_id`s, strictly unique non-negative `sequence` numbers, and valid `run_id`/`span_id` references.
6. Every ID in `span.event_ids` exists in `trace.events` with `event.span_id == span.span_id`.
7. `FixtureSet.entries` have unique `fixture_id`s; each `FixtureEntry` has a 64-char lowercase hex `fingerprint` and at least one of `response` or `error`.

### Strict Serialization
- `Trace.to_json(*, indent=2)` emits strict UTF-8 JSON (`allow_nan=False`).
- `Trace.from_json(raw, *, max_bytes=50 * 1024 * 1024)` enforces byte size, UTF-8 decoding, rejection of `NaN`/`Infinity`/`-Infinity`, nesting depth (`<= 64`), schema version compatibility, and full Pydantic validation.

---

## 5. Canonical Interaction Payloads (`interactions.py`)

1. **Model**: `ModelRequestPayload`, `ModelResponsePayload`
2. **Tools**: `ToolCallPayload`, `ToolResultPayload`
3. **Retrieval**: `RetrievalQueryPayload`, `RetrievedDocument`, `RetrievalResultPayload`
4. **Agents**: `AgentTransitionPayload`
5. **State**: `StateChangePayload`
6. **Errors**: `ExceptionPayload`
7. **Streaming**: `StreamChunkPayload`

---

## 6. Utilities

- **Validation (`validation.py`)**: `validate_trace_id`, `validate_json_safe`, `validate_schema_version`, `ensure_utc_datetime`, `validate_finite_float`, `validate_fingerprint`.
- **Fingerprinting (`fingerprint.py`)**: `canonical_json(data)`, `compute_fingerprint(boundary, request)`.
- **Redaction (`redaction.py`)**: `REDACTED_VALUE`, `RedactionConfig`, `redact_data(data, config=None)`.

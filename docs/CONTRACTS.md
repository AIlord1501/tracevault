# TraceVault Canonical Contracts

**Status**: Authoritative Source of Truth (M1)  
**Target Runtime**: Python 3.12+  
**Validation Framework**: Pydantic v2 (`ConfigDict(extra="forbid", frozen=True, populate_by_name=True)`)

> **Mandatory Rule for All Implementation Agents**  
> All modules, classes, fields, enums, error types, signatures, and invariants in this document are **normative**.  
> Implementation agents **must not** invent alternative interfaces or silently change shared contracts. Any proposed contract amendment requires explicit Lead Architect approval before merging.

---

## 1. Module Ownership & Dependency Rules

| Logical Module | Physical Path | Owner | Allowed Internal Dependencies |
|---|---|---|---|
| `schema` | `src/tracevault/schema/` | `schema-engineer` | **None** (stdlib + Pydantic v2 only) |
| `storage` | `src/tracevault/storage/` | `storage-engineer` | `schema` |
| `capture` & `instrumentation` | `src/tracevault/capture/` | `capture-engineer` | `schema` (optional runtime `TraceRepository` duck-type / protocol injection) |
| `diff` | `src/tracevault/diff/` | `diff-engineer` | `schema` |
| `replay` & `boundaries` | `src/tracevault/replay/` | `replay-engineer` | `schema`, `diff` (for regression assertions) |
| `assertions` | `src/tracevault/assertions/` | Lead (or delegated post-M4) | Public APIs of `schema`, `storage`, `replay`, `diff` |
| `pytest_plugin` | `src/tracevault/pytest_plugin/` | Lead (or delegated post-M4) | Public APIs of `schema`, `storage`, `replay`, `diff`, `assertions` |
| `adapters` | `src/tracevault/adapters/` | Lead (or delegated in M6) | Public APIs of `schema`, `capture`, `replay` |
| `cli` | `src/tracevault/cli/` | `cli-engineer` | Public APIs of `schema`, `storage`, `replay`, `diff`, `assertions` |
| Security & QA Suites | `tests/security/`, `tests/conftest.py`, `docs/SECURITY.md` | `qa-security-engineer` | Read-only audit across `src/**` |

### Hard Architectural Constraints
- `schema` **must not** depend on `storage`, `cli`, `adapters`, `replay`, `capture`, `diff`, `assertions`, or `pytest_plugin`.
- `storage` **must not** contain replay matching, boundary authorization, or diff comparison logic.
- `diff` **must** operate solely on canonical `Trace` models.
- `adapters` **must not** read or mutate storage internals (`.tracevault/`, SQLite, or raw trace JSON files).
- `cli` **must** invoke domain services rather than implementing core business logic.
- `pytest_plugin` and `assertions` **must** use public APIs only.

---

## 2. Canonical Error Hierarchy (`src/tracevault/schema/errors.py`)

Owned by: `schema-engineer`. All TraceVault exceptions inherit from `TraceVaultError`.

```python
class TraceVaultError(Exception):
    """Base exception for all TraceVault errors."""

class InvalidTraceIdError(TraceVaultError):
    """Raised when a trace_id violates naming, charset, length, or path-safety rules."""

class UnsafeTraceError(TraceVaultError):
    """Raised when trace data violates JSON safety, size, depth, schema version, or path containment."""

class TraceNotFoundError(TraceVaultError):
    """Raised when a requested trace_id does not exist in the repository."""

class TraceFrozenError(TraceVaultError):
    """Raised when attempting to overwrite a frozen trace or delete it without force=True."""

class FixtureNotFoundError(TraceVaultError):
    """Raised when replay cannot locate a matching recorded fixture and fail_on_missing_fixture=True."""

class PolicyViolationError(TraceVaultError):
    """Raised when a replay boundary violates SafetyPolicy or BoundaryMode.DENY."""

class ReplayError(TraceVaultError):
    """Raised when replay configuration is invalid or a recorded error fixture is replayed."""

class AdapterError(TraceVaultError):
    """Raised when an adapter fails to attach, sanitize, capture, or reconstruct an SDK response."""

class AdapterUnavailableError(AdapterError):
    """Raised when an optional third-party SDK dependency required by an adapter is not installed."""
```

---

## 3. Canonical Schema Base & Enums (`src/tracevault/schema/models.py`)

Owned by: `schema-engineer`.

```python
SCHEMA_VERSION = "1.0.0"
SUPPORTED_SCHEMA_MAJOR = 1

class TraceVaultModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )
```

All enums inherit from `(str, Enum)`:

| Enum | Members (`NAME = "value"`) |
|---|---|
| `BoundaryType` | `MODEL = "model"`, `TOOL = "tool"`, `RETRIEVAL = "retrieval"`, `CUSTOM = "custom"` |
| `SpanType` | `AGENT = "agent"`, `WORKFLOW = "workflow"`, `MODEL = "model"`, `TOOL = "tool"`, `RETRIEVAL = "retrieval"`, `CUSTOM = "custom"` |
| `EventKind` | `RUN_STARTED = "run_started"`, `RUN_COMPLETED = "run_completed"`, `RUN_FAILED = "run_failed"`, `SPAN_STARTED = "span_started"`, `SPAN_COMPLETED = "span_completed"`, `SPAN_FAILED = "span_failed"`, `MODEL_REQUEST = "model_request"`, `MODEL_RESPONSE = "model_response"`, `MODEL_ERROR = "model_error"`, `TOOL_CALL = "tool_call"`, `TOOL_RESULT = "tool_result"`, `TOOL_ERROR = "tool_error"`, `RETRIEVAL_QUERY = "retrieval_query"`, `RETRIEVAL_RESULT = "retrieval_result"`, `RETRIEVAL_ERROR = "retrieval_error"`, `AGENT_TRANSITION = "agent_transition"`, `STATE_CHANGE = "state_change"`, `STREAM_CHUNK = "stream_chunk"`, `EXCEPTION = "exception"`, `CUSTOM = "custom"` |
| `RunStatus` | `RUNNING = "running"`, `COMPLETED = "completed"`, `FAILED = "failed"`, `CANCELLED = "cancelled"` |
| `SpanStatus` | `UNSET = "unset"`, `OK = "ok"`, `ERROR = "error"`, `CANCELLED = "cancelled"` |
| `ReplayMode` | `OFFLINE_STRICT = "offline_strict"`, `OFFLINE_LENIENT = "offline_lenient"`, `BOUNDARY_GOVERNED = "boundary_governed"` |
| `BoundaryMode` | `RECORDED = "recorded"`, `LIVE = "live"`, `DENY = "deny"` |
| `DivergenceSeverity` | `INFO = "info"`, `WARNING = "warning"`, `BREAKING = "breaking"` |
| `DivergenceKind` | `STATUS_CHANGED = "status_changed"`, `OUTPUT_CHANGED = "output_changed"`, `ERROR_CHANGED = "error_changed"`, `SPAN_ADDED = "span_added"`, `SPAN_REMOVED = "span_removed"`, `SPAN_ORDER_CHANGED = "span_order_changed"`, `SPAN_STATUS_CHANGED = "span_status_changed"`, `EVENT_ADDED = "event_added"`, `EVENT_REMOVED = "event_removed"`, `EVENT_PAYLOAD_CHANGED = "event_payload_changed"`, `MODEL_INPUT_CHANGED = "model_input_changed"`, `MODEL_OUTPUT_CHANGED = "model_output_changed"`, `TOOL_ARGS_CHANGED = "tool_args_changed"`, `TOOL_RESULT_CHANGED = "tool_result_changed"`, `RETRIEVAL_CHANGED = "retrieval_changed"`, `AGENT_TRANSITION_CHANGED = "agent_transition_changed"`, `STATE_CHANGE_MISMATCH = "state_change_mismatch"`, `FIXTURE_MISMATCH = "fixture_mismatch"` |
| `ExportFormat` | `JSON = "json"`, `JSONL = "jsonl"` |

---

## 4. Core Execution Contracts (`Trace`, `Run`, `Span`, `Event`, `ExecutionError`)

Owned by: `schema-engineer`.

### 4.1 `ExecutionError`
Canonical structured representation of any run, span, or interaction exception:

| Field | Type | Required | Default | Invariants |
|---|---|---|---|---|
| `error_type` | `str` | Yes | — | Non-empty class/category name (e.g. `"ValueError"`, `"TimeoutError"`) |
| `message` | `str` | Yes | — | Sanitized/redacted error message |
| `traceback_summary` | `str \| None` | No | `None` | Redacted concise stack summary (never raw secrets) |
| `retryable` | `bool` | No | `False` | Indicator for transient failure classification |
| `details` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |

### 4.2 `Event`

| Field | Type | Required | Default | Invariants |
|---|---|---|---|---|
| `event_id` | `str` | Yes | — | Non-empty identifier unique within `Trace.events` |
| `run_id` | `str` | Yes | — | Must reference an existing `Run.run_id` in `Trace.runs` |
| `span_id` | `str \| None` | No | `None` | If set, must reference an existing `Span.span_id` in `Trace.spans` |
| `event_type` | `EventKind` | Yes | — | Canonical event category |
| `boundary` | `BoundaryType \| None` | No | `None` | Required for model/tool/retrieval boundary events |
| `timestamp` | `datetime` | Yes | — | Timezone-aware UTC datetime |
| `sequence` | `int` | Yes | — | `ge=0`; strictly unique across `Trace.events` |
| `payload` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe`; conforms to Section 5 interaction contracts when applicable |
| `metadata` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |

### 4.3 `Span`

| Field | Type | Required | Default | Invariants |
|---|---|---|---|---|
| `span_id` | `str` | Yes | — | Non-empty identifier unique within `Trace.spans` |
| `run_id` | `str` | Yes | — | Must reference an existing `Run.run_id` in `Trace.runs` |
| `parent_span_id` | `str \| None` | No | `None` | If set, must exist in `Trace.spans` and `!= span_id` (acyclic) |
| `span_type` | `SpanType` | Yes | — | Semantic span category (`agent`, `workflow`, `model`, `tool`, `retrieval`, `custom`) |
| `boundary` | `BoundaryType \| None` | No | `None` | Optional replay boundary binding |
| `name` | `str` | Yes | — | Non-empty human-readable span name |
| `started_at` | `datetime` | Yes | — | Timezone-aware UTC datetime |
| `ended_at` | `datetime \| None` | No | `None` | If set, `ended_at >= started_at` |
| `status` | `SpanStatus` | No | `SpanStatus.UNSET` | Transitioned to `OK`/`ERROR`/`CANCELLED` on span exit |
| `attributes` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |
| `error` | `ExecutionError \| None` | No | `None` | Present when `status == SpanStatus.ERROR` |
| `event_ids` | `list[str]` | No | `[]` | If populated, every ID must exist in `Trace.events` with matching `span_id` |

### 4.4 `Run`

| Field | Type | Required | Default | Invariants |
|---|---|---|---|---|
| `run_id` | `str` | Yes | — | Non-empty identifier unique within `Trace.runs` |
| `trace_id` | `str` | Yes | — | Validated via `validate_trace_id`; must equal parent `Trace.trace_id` |
| `parent_run_id` | `str \| None` | No | `None` | If set, must exist in `Trace.runs` and `!= run_id` (acyclic) |
| `name` | `str` | Yes | — | Non-empty logical execution name |
| `started_at` | `datetime` | Yes | — | Timezone-aware UTC datetime |
| `ended_at` | `datetime \| None` | No | `None` | If set, `ended_at >= started_at` |
| `status` | `RunStatus` | No | `RunStatus.RUNNING` | Finalized to `COMPLETED`, `FAILED`, or `CANCELLED` |
| `inputs` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |
| `outputs` | `dict[str, Any] \| None` | No | `None` | Must pass `validate_json_safe` when set |
| `error` | `ExecutionError \| None` | No | `None` | Present when `status == RunStatus.FAILED` |
| `environment` | `dict[str, str]` | No | `{}` | Redacted runtime context (e.g. Python version, OS) — never secrets |
| `tags` | `list[str]` | No | `[]` | Unique/clean non-empty labels |
| `metadata` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |

### 4.5 `Trace`

| Field | Type | Required | Default | Invariants |
|---|---|---|---|---|
| `schema_version` | `str` | No | `"1.0.0"` | SemVer `^\d+\.\d+\.\d+$`; major version must equal `SUPPORTED_SCHEMA_MAJOR` (`1`) |
| `trace_id` | `str` | Yes | — | Validated via `validate_trace_id` (`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`) |
| `created_at` | `datetime` | Yes | — | Timezone-aware UTC datetime |
| `frozen` | `bool` | No | `False` | When `True`, immutable in `TraceStore` (no overwrite or non-forced delete) |
| `parent_trace_id` | `str \| None` | No | `None` | If set, validated via `validate_trace_id` (lineage for forked/replayed traces) |
| `runs` | `list[Run]` | Yes | — | `min_length=1`; all `run.trace_id == trace.trace_id`; unique `run_id`s; valid `parent_run_id` graph |
| `spans` | `list[Span]` | No | `[]` | Unique `span_id`s; every `span.run_id` in `runs`; acyclic `parent_span_id` |
| `events` | `list[Event]` | No | `[]` | Unique `event_id`s; strictly unique non-negative `sequence`; valid `run_id` & `span_id` references |
| `fixtures` | `FixtureSet` | No | `FixtureSet()` | Deterministic recorded boundary fixtures |
| `metadata` | `dict[str, Any]` | No | `{}` | Must pass `validate_json_safe` |
| `redaction_applied` | `bool` | No | `True` | Indicates default secret redaction ran before persistence |

**Required Properties & Methods on `Trace`**:
- `@property def root_run(self) -> Run`: returns the run with `parent_run_id is None` (or `self.runs[0]`).
- `def get_run(self, run_id: str) -> Run | None`
- `def get_span_events(self, span_id: str) -> list[Event]` (sorted by `sequence`)
- `def to_json(self, *, indent: int | None = 2) -> str`: strict UTF-8 JSON (`allow_nan=False`).
- `@classmethod def from_json(cls, raw: str | bytes, *, max_bytes: int = 50 * 1024 * 1024) -> Trace`: enforces byte limit, rejects `NaN`/`Infinity`/`-Infinity`, checks `schema_version` major compatibility, validates JSON depth, and validates via `cls.model_validate(...)` (`UnsafeTraceError` on violation; `InvalidTraceIdError` preserved for invalid IDs).

#### Example Canonical `Trace` JSON
```json
{
  "schema_version": "1.0.0",
  "trace_id": "tr_9f8e7d6c5b4a3210",
  "created_at": "2026-11-24T00:00:00Z",
  "frozen": true,
  "parent_trace_id": null,
  "runs": [
    {
      "run_id": "run_001",
      "trace_id": "tr_9f8e7d6c5b4a3210",
      "parent_run_id": null,
      "name": "support_triage_agent",
      "started_at": "2026-11-24T00:00:00Z",
      "ended_at": "2026-11-24T00:00:01Z",
      "status": "completed",
      "inputs": {"ticket": "Billing error on invoice #42"},
      "outputs": {"category": "billing", "action": "refund_review"},
      "error": null,
      "environment": {"python": "3.12.10"},
      "tags": ["triage", "prod-incident-42"],
      "metadata": {}
    }
  ],
  "spans": [
    {
      "span_id": "sp_001",
      "run_id": "run_001",
      "parent_span_id": null,
      "span_type": "model",
      "boundary": "model",
      "name": "openai.chat.completions",
      "started_at": "2026-11-24T00:00:00.100000Z",
      "ended_at": "2026-11-24T00:00:00.900000Z",
      "status": "ok",
      "attributes": {"model": "gpt-4o-mini"},
      "error": null,
      "event_ids": ["ev_001", "ev_002"]
    }
  ],
  "events": [
    {
      "event_id": "ev_001",
      "run_id": "run_001",
      "span_id": "sp_001",
      "event_type": "model_request",
      "boundary": "model",
      "timestamp": "2026-11-24T00:00:00.100000Z",
      "sequence": 0,
      "payload": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Classify invoice #42"}],
        "parameters": {"temperature": 0.0},
        "tools": [],
        "stream": false
      },
      "metadata": {}
    },
    {
      "event_id": "ev_002",
      "run_id": "run_001",
      "span_id": "sp_001",
      "event_type": "model_response",
      "boundary": "model",
      "timestamp": "2026-11-24T00:00:00.900000Z",
      "sequence": 1,
      "payload": {
        "model": "gpt-4o-mini",
        "content": "billing",
        "tool_calls": [],
        "finish_reason": "stop",
        "usage": {"prompt_tokens": 18, "completion_tokens": 2, "total_tokens": 20},
        "raw_metadata": {}
      },
      "metadata": {}
    }
  ],
  "fixtures": {
    "version": "1.0.0",
    "entries": [
      {
        "fixture_id": "fix_001",
        "boundary": "model",
        "fingerprint": "b4d7c1b3d0f9f8b2a1c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
        "call_index": 0,
        "request": {"provider": "openai", "model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Classify invoice #42"}]},
        "response": {"model": "gpt-4o-mini", "content": "billing", "finish_reason": "stop"},
        "error": null,
        "span_id": "sp_001",
        "name": "openai.chat.completions"
      }
    ]
  },
  "metadata": {},
  "redaction_applied": true
}
```

---

## 5. Canonical Interaction & Fixture Contracts (`src/tracevault/schema/interactions.py`)

Owned by: `schema-engineer`. All models inherit from `TraceVaultModel` (`extra="forbid"`, `frozen=True`).

### 5.1 Model Requests & Responses
- **`ModelRequestPayload`**:
  - `provider: str` (non-empty, e.g. `"openai"`)
  - `model: str` (non-empty)
  - `messages: list[dict[str, Any]] = Field(default_factory=list)`
  - `parameters: dict[str, Any] = Field(default_factory=dict)`
  - `tools: list[dict[str, Any]] = Field(default_factory=list)`
  - `stream: bool = False`
- **`ModelResponsePayload`**:
  - `model: str`
  - `content: str | None = None`
  - `output_messages: list[dict[str, Any]] = Field(default_factory=list)`
  - `tool_calls: list[dict[str, Any]] = Field(default_factory=list)`
  - `finish_reason: str | None = None`
  - `usage: dict[str, int] = Field(default_factory=dict)`
  - `raw_metadata: dict[str, Any] = Field(default_factory=dict)`

### 5.2 Tool Calls & Results
- **`ToolCallPayload`**:
  - `tool_name: str` (non-empty)
  - `call_id: str | None = None`
  - `arguments: dict[str, Any] = Field(default_factory=dict)`
- **`ToolResultPayload`**:
  - `tool_name: str` (non-empty)
  - `call_id: str | None = None`
  - `result: Any = None` (JSON-safe validated)
  - `is_error: bool = False`

### 5.3 Retrieval Inputs & Results
- **`RetrievalQueryPayload`**:
  - `retriever: str` (non-empty)
  - `query: str`
  - `top_k: int = Field(default=5, ge=1)`
  - `filters: dict[str, Any] = Field(default_factory=dict)`
- **`RetrievedDocument`**:
  - `doc_id: str`
  - `content: str`
  - `score: float | None = None` (finite float only)
  - `metadata: dict[str, Any] = Field(default_factory=dict)`
- **`RetrievalResultPayload`**:
  - `retriever: str` (non-empty)
  - `documents: list[RetrievedDocument] = Field(default_factory=list)`

### 5.4 Agent Transitions
- **`AgentTransitionPayload`**:
  - `from_agent: str | None = None`
  - `to_agent: str` (non-empty)
  - `reason: str | None = None`
  - `handoff_state: dict[str, Any] = Field(default_factory=dict)`

### 5.5 State Changes
- **`StateChangePayload`**:
  - `key_path: str` (non-empty)
  - `operation: Literal["set", "delete", "merge"]`
  - `before: Any = None` (JSON-safe validated)
  - `after: Any = None` (JSON-safe validated)

### 5.6 Exceptions
- **`ExceptionPayload`**:
  - `error: ExecutionError`
  - `boundary: BoundaryType | None = None`
  - `recoverable: bool = False`

### 5.7 Streaming Events
- **`StreamChunkPayload`**:
  - `stream_id: str` (non-empty)
  - `chunk_index: int` (`ge=0`)
  - `delta: dict[str, Any] = Field(default_factory=dict)`
  - `is_final: bool = False`
  - `finish_reason: str | None = None`
  - `usage: dict[str, int] | None = None`

### 5.8 Recorded Fixtures (`FixtureEntry`, `FixtureSet`)
- **`FixtureEntry`** (in `schema/models.py`):
  - `fixture_id: str` (non-empty, unique within `FixtureSet`)
  - `boundary: BoundaryType`
  - `fingerprint: str` (64-char lowercase hex SHA-256)
  - `call_index: int = 0` (`ge=0`, disambiguates repeated identical requests)
  - `request: dict[str, Any] = Field(default_factory=dict)`
  - `response: dict[str, Any] | None = None`
  - `error: ExecutionError | None = None`
  - `span_id: str | None = None`
  - `name: str | None = None`
  - Invariant: `response` and `error` cannot both be `None` unless the call returned an empty/null payload explicitly recorded as `response={}` — specifically, if `error is not None`, replay raises `ReplayError`.
- **`FixtureSet`**:
  - `version: str = "1.0.0"`
  - `entries: list[FixtureEntry] = Field(default_factory=list)`

---

## 6. Schema Validation, Fingerprinting & Redaction (`src/tracevault/schema/`)

Owned by: `schema-engineer`.

- **`validation.py`**:
  - `TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")`
  - `validate_trace_id(trace_id: str) -> str`: raises `InvalidTraceIdError` on non-`str`, empty, traversal characters (`/`, `\`, `..`, `\x00`), or pattern mismatch.
  - `validate_json_safe(data: Any, *, max_depth: int = 64) -> Any`: accepts only `None`, `bool`, `int`, finite `float` (`math.isfinite`), `str`, `list`/`tuple`, and `dict` with `str` keys; enforces nesting depth `<= max_depth`; raises `UnsafeTraceError` on violation.
  - `validate_schema_version(version: str) -> str`: enforces SemVer `^\d+\.\d+\.\d+$` and major version `== SUPPORTED_SCHEMA_MAJOR`, else raises `UnsafeTraceError`.
- **`fingerprint.py`**:
  - `canonical_json(data: Any) -> str`: `json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
  - `compute_fingerprint(boundary: BoundaryType | str, request: dict[str, Any]) -> str`: SHA-256 hex digest of `canonical_json({"boundary": boundary_str, "request": request})`.
- **`redaction.py`**:
  - `REDACTED_VALUE = "[REDACTED]"`
  - `RedactionConfig(TraceVaultModel)`: `sensitive_keys: frozenset[str]`, `redact_patterns: tuple[str, ...]`, `replacement: str = REDACTED_VALUE`.
  - `redact_data(data: Any, config: RedactionConfig | None = None) -> Any`: recursively & idempotently redacts sensitive keys (case-insensitive substring match against `api_key`, `apikey`, `authorization`, `auth_token`, `access_token`, `refresh_token`, `secret`, `password`, `passwd`, `credential`, `private_key`, `bearer`, `x-api-key`, `openai_api_key`) and credential string patterns (`sk-[A-Za-z0-9_-]{10,}`, `Bearer\s+\S+`, `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{20,}`, JWTs `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).

**Package Re-export Rule**: `src/tracevault/schema/__init__.py` **must** re-export all public error classes, `SCHEMA_VERSION`, `SUPPORTED_SCHEMA_MAJOR`, `TraceVaultModel`, all enums, all core and interaction models, and all validation/fingerprinting/redaction utilities (`validate_trace_id`, `validate_json_safe`, `validate_schema_version`, `canonical_json`, `compute_fingerprint`, `REDACTED_VALUE`, `RedactionConfig`, `redact_data`).

---

## 7. Storage Contract (`src/tracevault/storage/`)

Owned by: `storage-engineer`.

### 7.1 Models (`repository.py`)
- **`TraceSummary(TraceVaultModel)`**:
  - `trace_id: str`, `root_run_id: str`, `run_name: str`, `status: RunStatus`, `created_at: datetime`, `frozen: bool`, `parent_trace_id: str | None = None`, `tags: list[str] = Field(default_factory=list)`, `span_count: int = 0`, `event_count: int = 0`, `fixture_count: int = 0`.
- **`TraceQuery(TraceVaultModel)`**:
  - `status: RunStatus | None = None`, `tag: str | None = None`, `frozen: bool | None = None`, `parent_trace_id: str | None = None`, `query: str | None = None`, `limit: int = Field(default=100, ge=1, le=10000)`, `offset: int = Field(default=0, ge=0)`.

### 7.2 `TraceRepository` Protocol & `TraceStore` (`store.py`)
`TraceStore` implements `TraceRepository`:
- `__init__(self, base_dir: Path | str = Path(".tracevault"), *, max_trace_bytes: int = 50 * 1024 * 1024)`
- `init(self) -> Path`: idempotently initializes `base_dir`, `traces/`, and SQLite `index.db` (WAL mode).
- `save(self, trace: Trace, *, overwrite: bool = False) -> Path`:
  - Validates `trace.trace_id` and path containment (`.resolve().is_relative_to(...)`).
  - Checks serialized byte size `<= max_trace_bytes` (`UnsafeTraceError`).
  - Checks existing state: if existing trace on disk is `frozen=True` → raises `TraceFrozenError` (even if `overwrite=True`); if existing is unfrozen and `overwrite=False` → raises `FileExistsError`.
  - Writes atomically via `tempfile.NamedTemporaryFile(dir=self.traces_dir, delete=False)` + flush + `os.replace()`.
  - Upserts metadata in SQLite `index.db` using parameterized queries.
- `load(self, trace_id: str) -> Trace`:
  - Validates `trace_id` (`InvalidTraceIdError`) and path containment (`UnsafeTraceError`).
  - Checks existence (`TraceNotFoundError`).
  - Checks byte size `<= max_trace_bytes` (`UnsafeTraceError`).
  - Parses via `Trace.from_json(...)`.
- `freeze(self, trace_id: str) -> Trace`: sets `frozen=True` atomically (idempotent if already frozen).
- `delete(self, trace_id: str, *, force: bool = False) -> None`: raises `TraceNotFoundError` if missing, `TraceFrozenError` if frozen and `not force`; removes JSON file and SQLite rows.
- `exists(self, trace_id: str) -> bool`: validates `trace_id` and checks file presence.
- `query(self, query: TraceQuery) -> list[TraceSummary]`: queries SQLite index using parameterized SQL, ordered by `created_at DESC`.
- `list_traces(self, *, status: RunStatus | None = None, tag: str | None = None, frozen: bool | None = None, query: str | None = None, limit: int = 100, offset: int = 0) -> list[TraceSummary]`: ergonomic wrapper building `TraceQuery`.
- `export_trace(self, trace_id: str, output_path: Path | str, *, format: ExportFormat = ExportFormat.JSON) -> Path`: atomic write of canonical JSON or JSONL (header line + ordered event lines).
- `export_jsonl(self, trace_id: str, output_path: Path | str) -> Path`: convenience wrapper for `ExportFormat.JSONL`.
- `import_trace(self, input_path: Path | str, *, overwrite: bool = False, freeze: bool = False) -> Trace`: validates `input_path` is an existing regular file with byte size `<= max_trace_bytes` before reading (`UnsafeTraceError` if oversized), parses/validates via `Trace.from_json`, optionally sets `frozen=True`, and persists via `save()`.
- `reindex(self) -> int`: rebuilds `index.db` from all valid `.json` files in `traces/`, raising `UnsafeTraceError` on corrupt/oversized trace files and returning total indexed traces.
- `close(self) -> None`: closes SQLite connection cleanly.

**Package Re-export Rule**: `src/tracevault/storage/__init__.py` **must** re-export `TraceRepository`, `TraceStore`, `TraceSummary`, `TraceQuery`.

---

## 8. Capture & Instrumentation Contract (`src/tracevault/capture/`)

Owned by: `capture-engineer`.

- **`CaptureSession`** (`session.py`):
  - `__init__(self, name: str, *, inputs: dict[str, Any] | None = None, tags: list[str] | None = None, metadata: dict[str, Any] | None = None, environment: dict[str, str] | None = None, store: TraceRepository | None = None, auto_save: bool = False, redact: bool = True, trace_id: str | None = None, parent_trace_id: str | None = None, run_id: str | None = None)`
  - Properties: `trace_id: str`, `run_id: str`, `trace: Trace | None` (populated upon exit or `build_trace()`).
  - Context managers:
    - `span(self, name: str, *, span_type: SpanType = SpanType.CUSTOM, boundary: BoundaryType | None = None, attributes: dict[str, Any] | None = None) -> Iterator[Span]`
    - `aspan(self, name: str, *, span_type: SpanType = SpanType.CUSTOM, boundary: BoundaryType | None = None, attributes: dict[str, Any] | None = None) -> AsyncIterator[Span]`
  - Recording methods:
    - `start_child_run(self, name: str, *, inputs: dict[str, Any] | None = None, tags: list[str] | None = None, metadata: dict[str, Any] | None = None) -> Iterator[Run]` (optional nested run support using `parent_run_id`)
    - `record_event(self, event_type: EventKind, payload: dict[str, Any] | None = None, *, boundary: BoundaryType | None = None, metadata: dict[str, Any] | None = None, span_id: str | None = None, run_id: str | None = None) -> Event`
    - `record_model_call(self, request: dict[str, Any], response: dict[str, Any] | None = None, *, error: ExecutionError | str | None = None, name: str | None = None, span_id: str | None = None) -> FixtureEntry`
    - `record_tool_call(self, tool_name: str, args: dict[str, Any], result: dict[str, Any] | None = None, *, error: ExecutionError | str | None = None, span_id: str | None = None) -> FixtureEntry`
    - `record_retrieval(self, query: dict[str, Any], results: dict[str, Any] | None = None, *, error: ExecutionError | str | None = None, name: str | None = None, span_id: str | None = None) -> FixtureEntry`
    - `record_agent_transition(self, to_agent: str, *, from_agent: str | None = None, reason: str | None = None, handoff_state: dict[str, Any] | None = None) -> Event`
    - `record_state_change(self, key_path: str, operation: Literal["set", "delete", "merge"], *, before: Any = None, after: Any = None) -> Event`
    - `record_stream_chunk(self, stream_id: str, chunk_index: int, delta: dict[str, Any], *, is_final: bool = False, finish_reason: str | None = None) -> Event`
    - `set_outputs(self, outputs: dict[str, Any]) -> None`
    - `build_trace(self) -> Trace`
  - **Immutability & Error Normalization Invariants**:
    - Because `Run` and `Span` are frozen `TraceVaultModel` instances, `CaptureSession` maintains mutable in-memory builder records during active execution and constructs validated frozen `Run`, `Span`, `Event`, `FixtureEntry`, and `Trace` models on exit / `build_trace()` (with `span()`/`aspan()` yielding the initial `Span` snapshot containing `span_id`, `run_id`, `parent_span_id`, `started_at`, etc.).
    - Whenever `error` is passed as a `str` to `record_model_call`, `record_tool_call`, or `record_retrieval`, it is normalized to `ExecutionError(error_type="RecordedError", message=<redacted_str>)`.
- **Context Propagation** (`context.py`):
  - `capture(name: str, **kwargs: Any) -> Iterator[CaptureSession]`
  - `acapture(name: str, **kwargs: Any) -> AsyncIterator[CaptureSession]`
  - `get_current_session() -> CaptureSession | None`
  - `get_current_span_id() -> str | None`
  - `get_current_run_id() -> str | None`
- **Decorators / Instrumentation** (`decorators.py`):
  - `trace_span(name: str | None = None, *, span_type: SpanType = SpanType.CUSTOM, boundary: BoundaryType | None = None)`
  - `trace_model(name: str | None = None)`
  - `trace_tool(name: str | None = None)`
  - `trace_retrieval(name: str | None = None)`
  - Invariant: work seamlessly on both sync and `async def` functions; when no `CaptureSession` is active in the current context, execute the wrapped function transparently with zero errors or side effects.

---

## 9. Replay & Boundary Replay Contract (`src/tracevault/replay/`)

Owned by: `replay-engineer`.

### 9.1 Models (`ReplayConfig`, `SafetyPolicy`, `ReplayOverride`, `ReplayResult`)
- **`SafetyPolicy(TraceVaultModel)`** (in `schema/models.py`):
  - `allow_live_boundaries: set[BoundaryType] = Field(default_factory=set)`
  - `allowed_tools: set[str] = Field(default_factory=set)`
  - `allowed_hosts: set[str] = Field(default_factory=set)`
  - `max_live_calls: int = Field(default=0, ge=0)`
  - `require_explicit_opt_in: bool = True`
- **`ReplayOverride(TraceVaultModel)`** (in `schema/models.py`):
  - `fixture_id: str | None = None`
  - `fingerprint: str | None = None`
  - `boundary: BoundaryType | None = None`
  - `name: str | None = None`
  - `call_index: int | None = Field(default=None, ge=0)`
  - `response: dict[str, Any] | None = None`
  - `error: ExecutionError | None = None`
- **`ReplayConfig(TraceVaultModel)`** (in `schema/models.py`):
  - `trace_id: str | None = None`
  - `mode: ReplayMode = ReplayMode.OFFLINE_STRICT`
  - `fail_on_missing_fixture: bool = True`
  - `boundary_modes: dict[BoundaryType, BoundaryMode]` defaulting to all `BoundaryType` keys mapped to `BoundaryMode.RECORDED`
  - `safety_policy: SafetyPolicy = Field(default_factory=SafetyPolicy)`
  - `overrides: dict[str, Any] = Field(default_factory=dict)`
  - `override_rules: list[ReplayOverride] = Field(default_factory=list)`
  - `deterministic_seed: int | None = None`
  - Property: `@property def strict_matching(self) -> bool` → `self.mode == ReplayMode.OFFLINE_STRICT`.
- **`ReplayResult(TraceVaultModel)`** (in `schema/models.py`):
  - `baseline_trace_id: str`
  - `candidate_trace: Trace`
  - `mode: ReplayMode`
  - `matched_fixtures: int = Field(default=0, ge=0)`
  - `overridden_fixtures: int = Field(default=0, ge=0)`
  - `live_calls: int = Field(default=0, ge=0)`
  - `missing_fixtures: list[str] = Field(default_factory=list)`
  - `success: bool`
  - `error: ExecutionError | None = None`

### 9.2 `ReplayEngine` (`engine.py`)
- `__init__(self, trace: Trace, config: ReplayConfig | None = None)`
- `replay_interaction(self, boundary: BoundaryType, request: dict[str, Any], *, name: str | None = None) -> dict[str, Any]`:
  - **Strict offline guarantee**: never executes network or live calls.
  - Matching order:
    1. Redact `request`, compute `fp = compute_fingerprint(boundary, redacted_request)`, increment `call_index` for `(boundary, fp)`.
    2. `OFFLINE_STRICT`: require exact `(boundary, fp, call_index)` match in `trace.fixtures.entries`.
    3. `OFFLINE_LENIENT`: try strict match; else match `(boundary, name, boundary_call_index)` if `name` provided; else match `(boundary, boundary_call_index)`.
  - Override resolution: checks `override_rules` then `overrides` (keyed by `fixture_id` or `fingerprint`).
  - If matched entry has `error is not None` and no override response → raises `ReplayError(entry.error.message)`.
  - If missing and `fail_on_missing_fixture=True` → raises `FixtureNotFoundError`; if `False` → records missing fixture key and returns `{}`.
- `replay_trace(self, *, fork: bool = False, new_trace_id: str | None = None) -> ReplayResult`:
  - Replays all `trace.fixtures.entries` sequentially, builds candidate `Trace` (`parent_trace_id=trace.trace_id` when `fork=True`, `frozen=False`), returns `ReplayResult`.
- `fork(self, *, overrides: dict[str, Any] | None = None, new_trace_id: str | None = None) -> Trace`:
  - Convenience wrapper running `replay_trace(fork=True, ...)` with overrides and returning `result.candidate_trace`.

### 9.3 Policy-Governed Boundary Replay (`boundaries.py`)
- **`BoundaryPolicyDecision(TraceVaultModel)`**: `boundary: BoundaryType`, `mode: BoundaryMode`, `allowed: bool`, `reason: str`.
- **`BoundaryExecutor`** + boundary adapters **`ModelBoundary`**, **`ToolBoundary`**, **`RetrievalBoundary`**:
  - Default mode for every boundary is `BoundaryMode.RECORDED`.
  - `BoundaryMode.DENY` → always raises `PolicyViolationError`.
  - `BoundaryMode.LIVE` → allowed **only** if:
    1. `config.mode == ReplayMode.BOUNDARY_GOVERNED` (or live boundary mode explicitly configured) AND `boundary in policy.allow_live_boundaries`.
    2. If `policy.require_explicit_opt_in` is `True`, `policy.max_live_calls > 0`.
    3. Current live call count `< policy.max_live_calls`.
    4. For `TOOL`: `tool_name in policy.allowed_tools`.
    5. For `MODEL` / `RETRIEVAL`: if `host` is supplied or `policy.allowed_hosts` is checked, `host in policy.allowed_hosts` (empty `allowed_hosts` denies live host calls when `host` is specified).
    - On any check failure → raises `PolicyViolationError` before calling `live_fn`.
  - Records live response (redacted) onto candidate trace and increments `live_calls`.

### 9.4 Regression Test Generator (`regression.py`)
- `generate_pytest_regression(trace: Trace, output_path: Path | str, *, trace_path: Path | str | None = None) -> Path`:
  - Emits a standalone, Ruff-clean pytest file that loads the frozen trace JSON, invokes `ReplayEngine(trace).replay_trace()`, and asserts via `diff_traces` that `not report.has_breaking`.
  - All trace strings/IDs serialized exclusively via `json.dumps(...)` (zero string interpolation into raw code blocks).

---

## 10. Diff Contract (`src/tracevault/diff/`)

Owned by: `diff-engineer`.

### 10.1 Models (`schema/models.py`)
- **`DiffConfig(TraceVaultModel)`**:
  - `ignore_paths: set[str] = Field(default_factory=set)`
  - `ignore_timestamps: bool = True`
  - `ignore_ids: bool = True`
  - `compare_metadata: bool = False`
  - `strict_order: bool = True`
  - `severity_overrides: dict[DivergenceKind, DivergenceSeverity] = Field(default_factory=dict)`
- **`Divergence(TraceVaultModel)`**:
  - `kind: DivergenceKind`
  - `severity: DivergenceSeverity`
  - `path: str` (e.g. `"runs[0].status"`, `"spans[1].name"`, `"events[3].payload.arguments"`)
  - `message: str`
  - `baseline: Any = None`
  - `candidate: Any = None`
- **`DiffReport(TraceVaultModel)`**:
  - `baseline_trace_id: str`
  - `candidate_trace_id: str`
  - `identical: bool`
  - `divergences: list[Divergence] = Field(default_factory=list)`
  - `summary: dict[str, int] = Field(default_factory=dict)` (`"info"`, `"warning"`, `"breaking"`, `"total"`)
  - `@property def has_breaking(self) -> bool` → `any(d.severity == DivergenceSeverity.BREAKING for d in self.divergences)`.

### 10.2 Functions (`engine.py`, `formatter.py`)
- `diff_traces(baseline: Trace, candidate: Trace, *, config: DiffConfig | None = None, ignore_paths: set[str] | None = None) -> DiffReport` (if both `config` and `ignore_paths` are supplied, `ignore_paths` merges with `config.ignore_paths`).
- `format_diff_report(report: DiffReport, *, verbose: bool = False) -> str`
- `render_diff_rich(report: DiffReport, *, console: Console | None = None) -> None`

Default severity mapping:
- **`BREAKING`**: `STATUS_CHANGED`, `OUTPUT_CHANGED`, `ERROR_CHANGED`, `SPAN_REMOVED`, `SPAN_STATUS_CHANGED`, `MODEL_OUTPUT_CHANGED`, `TOOL_ARGS_CHANGED`, `TOOL_RESULT_CHANGED`, `FIXTURE_MISMATCH`.
- **`WARNING`**: `SPAN_ADDED`, `SPAN_ORDER_CHANGED`, `MODEL_INPUT_CHANGED`, `RETRIEVAL_CHANGED`, `AGENT_TRANSITION_CHANGED`, `STATE_CHANGE_MISMATCH`, `EVENT_ADDED`, `EVENT_REMOVED`, `EVENT_PAYLOAD_CHANGED`.
- **`INFO`**: metadata/non-breaking path changes.

---

## 11. Adapter Contract (`src/tracevault/adapters/`)

Owned by: Lead (or explicit M6 adapter assignee).

### 11.1 `TraceAdapter` Protocol & Lifecycle (`base.py`)
```python
class TraceAdapter(Protocol):
    name: str
    adapter_version: str
    supported_sdk_versions: str  # e.g. ">=1.30,<2.0"
    boundary: BoundaryType

    def attach(
        self,
        client: Any,
        *,
        session: CaptureSession | None = None,
        replay_engine: ReplayEngine | None = None,
        boundary_executor: BoundaryExecutor | None = None,
    ) -> Any: ...

    def detach(self) -> None: ...
```
### 11.2 Guarantees
1. **Capture Lifecycle**: intercept boundary call → redact request (`redact_data`) → if replay/boundary mode active, resolve fixture or enforce `SafetyPolicy`; else invoke real SDK → redact response/error → record `Event` + `FixtureEntry` → return SDK-native response (or reconstructed SDK-compatible object on replay).
2. **Instrumentation Boundaries**: hook only explicit SDK boundary methods (e.g., OpenAI `chat.completions.create`). Never patch Python builtins (`socket`, `open`, `builtins`) or touch `TraceStore` internals.
3. **Provider/Framework Separation**: optional SDK imports happen inside the adapter module and raise `AdapterUnavailableError` with install instructions (`pip install tracevault[openai]`) if missing.
4. **Error Handling**: provider errors capture `ExecutionError` cleanly and re-raise the original SDK error during live/capture mode without exposing auth headers or API keys.
5. **Version Compatibility**: declare `supported_sdk_versions` and handle minor response field additions gracefully without crashing capture.

---

## 12. Assertions & `pytest` Integration Contract (`src/tracevault/assertions/`, `src/tracevault/pytest_plugin/`)

Owned by: Lead (or explicitly assigned in M5). Must use **public APIs only**.

### 12.1 Assertions (`src/tracevault/assertions/`)
- **Trace Assertions** (`trace.py`):
  - `assert_trace_valid(trace: Trace) -> None`
  - `assert_run_succeeded(trace: Trace, *, run_id: str | None = None) -> None`
  - `assert_span_exists(trace: Trace, name: str, *, span_type: SpanType | None = None) -> Span`
  - `assert_tool_called(trace: Trace, tool_name: str, *, min_calls: int = 1) -> list[Event]`
  - `assert_no_secrets_leaked(trace: Trace) -> None`
- **Replay Assertions** (`replay.py`):
  - `assert_replay_succeeded(result: ReplayResult) -> None`
  - `assert_all_fixtures_matched(result: ReplayResult) -> None`
  - `assert_no_live_calls(result: ReplayResult) -> None`
- **Diff Assertions** (`diff.py`):
  - `assert_traces_equivalent(baseline: Trace, candidate: Trace, *, config: DiffConfig | None = None) -> DiffReport`
  - `assert_no_breaking_diffs(report: DiffReport) -> None`
  - `assert_diff_matches_expectations(report: DiffReport, *, max_warnings: int | None = None, allowed_kinds: set[DivergenceKind] | None = None) -> None`

On failure, every assertion raises standard `AssertionError` with structured human-readable diagnostics (including formatted `DiffReport` when comparing traces).

### 12.2 Pytest Integration (`src/tracevault/pytest_plugin/`)
- `tracevault_store(tmp_path: Path) -> TraceStore`: isolated per-test `TraceStore` fixture.
- `tracevault_replay`: factory fixture creating `ReplayEngine` from a trace path or `trace_id`.
- `verify_regression_trace(trace_path: Path | str, *, config: ReplayConfig | None = None, diff_config: DiffConfig | None = None) -> DiffReport`: standard helper called by generated regression tests.

---

## 13. CLI Contract (`src/tracevault/cli/app.py`)

Owned by: `cli-engineer`.

Entrypoint: `tracevault = "tracevault.cli.app:app"` (`typer.Typer(name="tracevault", no_args_is_help=True)`).

| Command | Arguments & Options | Behavior & Exit Codes |
|---|---|---|
| `init` | `[--store / -s PATH]` | Calls `TraceStore(store).init()`; exit `0`. |
| `list` | `[--store / -s] [--status] [--tag] [--frozen/--unfrozen] [--limit] [--json]` | Queries `TraceStore.list_traces(...)` and prints Rich table or JSON; exit `0`. |
| `show` | `TRACE_ID [--store / -s] [--events] [--fixtures] [--json]` | Loads trace and renders Run/Span/Event/Fixture summary; exit `1` if `TraceNotFoundError`. |
| `freeze` | `TRACE_ID [--store / -s]` | Calls `TraceStore.freeze(trace_id)`; exit `0` (or `1` if missing). |
| `replay` | `TRACE_ID [--store / -s] [--strict/--lenient] [--fork] [--save] [--json]` | Lazily imports `ReplayEngine`, executes offline replay (`OFFLINE_STRICT` vs `OFFLINE_LENIENT`), optionally saves forked trace; exit `0` on success, `1` on replay/missing errors. |
| `diff` | `BASELINE_ID CANDIDATE_ID [--store / -s] [--json]` | Loads both traces, runs `diff_traces`, renders Rich/JSON diff; exits **`1` if `report.has_breaking`**, **`0` otherwise** (or `1` on load error). |
| `export-test` | `TRACE_ID [--store / -s] --output / -o PATH` | Lazily imports `generate_pytest_regression`, writes test file; exit `0`. |
| `verify` | `TRACE_ID [--store / -s]` | Loads trace, verifies schema validity (`Trace.from_json`), checks `redaction_applied` and secret scan; exit `0` if valid, `1` on failure. |
| `delete` | `TRACE_ID [--store / -s] [--force / -f]` | Calls `TraceStore.delete(trace_id, force=force)`; exit `1` on `TraceFrozenError` or `TraceNotFoundError`. |

---

## 14. Security & Quality Non-Negotiables

1. **Zero `pickle`, `marshal`, `shelve`, `eval`, `exec`, `os.system`, or `subprocess(..., shell=True)`** anywhere in `src/tracevault/`.
2. **Zero external network calls** in `schema`, `storage`, `capture`, `diff`, `assertions`, `cli`, and offline `replay`.
3. **Strict `extra="forbid"`** on every `TraceVaultModel`.
4. **Validated file paths** on all reads, writes, imports, and exports.
5. **No real API keys or secrets** in code, tests, fixtures, or CLI output.
6. Every merged module must pass `uv run pytest`, `uv run ruff check`, and `uv run mypy`.

---

## 15. Documented Architectural Assumptions & Unresolved Decisions (M1)

1. **Canonical Naming (`adapters` vs `integrations`)**: M1 standardizes the provider/framework integration package on `src/tracevault/adapters/` (replacing earlier informal references to `integrations/`). No runtime code existed prior to M1, so downstream agents should target `src/tracevault/adapters/`.
2. **Multi-Run Traces**: `Trace.runs` is a non-empty `list[Run]` rather than a single `Trace.run` field so multi-agent or parent/child sub-runs serialize portably in one trace, with `Trace.root_run` providing single-run convenience.
3. **Normalized Event Storage**: Canonical events live once in `Trace.events` (ordered by `sequence`), while `Span.event_ids` optionally indexes event IDs for span-centric traversal without duplicating mutable payloads.
4. **Pending User/Lead Decisions for M5–M6**:
   - **Pytest Plugin Auto-Discovery**: Should `pyproject.toml` expose `[project.entry-points."pytest11"]` by default in M5, or require explicit `pytest_plugins = ["tracevault.pytest_plugin"]`? *(Default assumption: expose `pytest11` entry point only if it produces zero side effects when TraceVault fixtures aren't used; decide before M5 merge.)*
   - **Default `ReplayOverride` Matching Precedence**: Specified as `override_rules` evaluated in order (most specific match first), followed by `overrides` dict keyed by `fixture_id` then `fingerprint`. Confirm if any regex/wildcard override matching is needed post-MVP.
   - **Corrupt File Behavior in `TraceStore.reindex()`**: Currently specified to fail loudly (`UnsafeTraceError`) on corrupt `.json` files in `traces/`; confirm in M2 whether a `--skip-corrupt` flag is desired for disaster recovery.

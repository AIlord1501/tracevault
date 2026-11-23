# TraceVault M2 — Schema & Storage Implementation Report

**Milestone**: M2 (Schema & Storage)  
**Status**: Completed & Verified  
**Runtime**: Python 3.12.10 (`uv`, Pydantic v2.14.4, pytest 9.2.0, Hypothesis 6.170.17, Ruff 0.17.6, mypy 2.4.1)

---

## 1. Components Implemented

### A. Canonical Schema (`src/tracevault/schema/`)
Implemented by `schema-engineer` (M2A):
- **Error Hierarchy** (`errors.py`): `TraceVaultError` and all 9 canonical subclasses (`InvalidTraceIdError`, `UnsafeTraceError`, `TraceNotFoundError`, `TraceFrozenError`, `FixtureNotFoundError`, `PolicyViolationError`, `ReplayError`, `AdapterError`, `AdapterUnavailableError`).
- **Validation & Safety** (`validation.py`): `TRACE_ID_PATTERN`, `validate_trace_id`, cycle-safe & depth-bounded `validate_json_safe` (`max_depth=64`, finite floats only, string dict keys only), SemVer `validate_schema_version` (`SUPPORTED_SCHEMA_MAJOR = 1`), timezone-aware UTC normalization (`ensure_utc_datetime`), `validate_finite_float`, and SHA-256 `validate_fingerprint`.
- **Canonical Models & Enums** (`models.py`): `TraceVaultModel` (`extra="forbid"`, `frozen=True`, `populate_by_name=True`), all 10 `StrEnum` enums, `ExecutionError`, `Event`, `Span`, `Run`, `FixtureEntry`, `FixtureSet`, `Trace` (with full structural integrity validators, `root_run`, `get_run`, `get_span_events`, strict UTF-8 `to_json`, size/depth/finite-JSON-guarded `from_json`), plus `SafetyPolicy`, `ReplayOverride`, `ReplayConfig` (`strict_matching`), `ReplayResult`, `BoundaryPolicyDecision`, `DiffConfig`, `Divergence`, and `DiffReport` (`has_breaking`).
- **Interaction Payloads** (`interactions.py`): All 7 canonical interaction groups (`ModelRequestPayload`, `ModelResponsePayload`, `ToolCallPayload`, `ToolResultPayload`, `RetrievalQueryPayload`, `RetrievedDocument`, `RetrievalResultPayload`, `AgentTransitionPayload`, `StateChangePayload`, `ExceptionPayload`, `StreamChunkPayload`).
- **Deterministic Fingerprinting** (`fingerprint.py`): `canonical_json` (`sort_keys=True`, compact separators, `allow_nan=False`) and SHA-256 `compute_fingerprint`.
- **Secret Redaction** (`redaction.py`): `REDACTED_VALUE`, `RedactionConfig`, and recursive, cycle-safe, idempotent `redact_data`.
- **Package Exports & Docs** (`schema/__init__.py`, `docs/SCHEMA.md`).

### B. Local-First Storage & SQLite Indexing (`src/tracevault/storage/`)
Implemented by `storage-engineer` (M2B):
- **Repository Contract** (`repository.py`): `TraceSummary`, `TraceQuery`, and `@runtime_checkable` `TraceRepository` protocol.
- **SQLite WAL Metadata Index** (`index.py`): `TraceIndex` with `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, normalized `traces` + `trace_tags` tables with cascading deletes and secondary indexes, strictly parameterized SQL (`?` placeholders, escaped `LIKE` wildcards), fixed-precision UTC timestamp ordering, transaction management, and leak-free connection teardown.
- **Filesystem JSON Store** (`store.py`): `TraceStore` implementing `init`, `save`, `load`, `freeze`, `delete`, `exists`, `query`, `list_traces`, `export_trace`, `export_jsonl`, `import_trace`, `reindex`, `close`, and context manager support. Enforces `validate_trace_id`, `.resolve().is_relative_to(...)` path containment, symlink escape rejection, pre-read `max_trace_bytes` limits, atomic `NamedTemporaryFile` + `fsync` + `os.replace` writes, fresh-save rollback on index errors, and freeze immutability.

### C. Integration & Public Exports (Lead)
- Wired top-level public exports in `src/tracevault/__init__.py` (66 symbols exported via `__all__`).
- Fixed a real file-handle leak in `TraceIndex._connect()` uncovered by `qa-security-engineer` where a `sqlite3.DatabaseError` during `PRAGMA journal_mode=WAL` on a corrupt `index.db` left the OS handle open on Windows.

---

## 2. Files Created & Modified

### Created
- `src/tracevault/schema/__init__.py`
- `src/tracevault/schema/errors.py`
- `src/tracevault/schema/validation.py`
- `src/tracevault/schema/models.py`
- `src/tracevault/schema/interactions.py`
- `src/tracevault/schema/fingerprint.py`
- `src/tracevault/schema/redaction.py`
- `src/tracevault/storage/__init__.py`
- `src/tracevault/storage/repository.py`
- `src/tracevault/storage/index.py`
- `src/tracevault/storage/store.py`
- `tests/conftest.py`
- `tests/unit/schema/test_errors_and_enums.py`
- `tests/unit/schema/test_validation.py`
- `tests/unit/schema/test_fingerprint_and_redaction.py`
- `tests/unit/schema/test_interactions.py`
- `tests/unit/schema/test_models.py`
- `tests/unit/storage/test_index.py`
- `tests/unit/storage/test_store.py`
- `tests/security/test_static_safety.py`
- `tests/security/test_hostile_schema.py`
- `tests/security/test_redaction_and_secrets.py`
- `tests/security/test_properties.py`
- `tests/security/test_hostile_storage.py`
- `docs/SCHEMA.md`
- `docs/SECURITY.md`
- `docs/M2_IMPLEMENTATION_REPORT.md`

### Modified
- `src/tracevault/__init__.py` (top-level public exports for M2 `schema` and `storage`)

---

## 3. Tests Created & Verification Results

| Suite | Location | Tests | Result |
|---|---|---:|---|
| Schema unit tests | `tests/unit/schema/` | 71 | **71 passed** |
| Storage unit tests | `tests/unit/storage/` | 24 | **24 passed** |
| Security, AST & Hypothesis property tests | `tests/security/` | 184 | **184 passed** |
| **Total (`uv run pytest -v`)** | `tests/` | **279** | **279 passed in 3.85s** |

### Quality Gate Outputs
- `uv run pytest -v`: **279 passed in 3.85s** (exit code `0`)
- `uv run ruff check src tests`: **All checks passed!** (exit code `0`)
- `uv run ruff format --check src tests`: **25 files already formatted** (exit code `0`)
- `uv run mypy src`: **Success: no issues found in 12 source files** (exit code `0`)
- `uv run python -c "import tracevault; ..."`: **Exports: 66, version: 0.1.0** (exit code `0`)

---

## 4. Security Tests & Audit Highlights

Implemented and executed by `qa-security-engineer` (strictly read-only on `src/**`):
- **Static AST Safety (`test_static_safety.py`)**: Scans every `.py` file under `src/tracevault/` confirming zero imports or calls to `pickle`, `cPickle`, `_pickle`, `marshal`, `shelve`, `eval`, `exec`, `os.system`, `os.popen`, or `subprocess.*(..., shell=True)`.
- **Hostile Schema Inputs (`test_hostile_schema.py`)**: Path traversal IDs, control characters, unicode lookalikes, non-strings, malformed JSON, invalid UTF-8, `NaN`/`Infinity`/`-Infinity`, nesting depth `> 64`, cyclic Python containers, unsupported object types, non-string dict keys, byte-size caps, `extra="forbid"`, incompatible `schema_version`, naive datetimes, temporal inversions, and `Run`/`Span` parent cycles.
- **Redaction & Secret Leakage (`test_redaction_and_secrets.py`)**: Sensitive keys, credential patterns (`sk-...`, `sk-proj-...`, `Bearer ...`, `AKIA...`, `ghp_...`, JWTs), nested structures, `Trace.to_json()` leakage audit, and idempotency.
- **Hypothesis Property Tests (`test_properties.py`)**: `validate_trace_id` boundary properties, `compute_fingerprint` key-order determinism, `redact_data` idempotency, and `Trace` JSON round-trip equivalence.
- **Hostile Storage Inputs (`test_hostile_storage.py`)**: Path traversal and null-byte paths, SQL injection & SQL `LIKE` wildcard injection, corrupt SQLite `index.db` recovery, hostile `import_trace` files, code-injection metadata round-trips, symlink escape containment (executed and passed on Windows), and frozen trace immutability.
- **Defect Caught & Resolved During Audit**: `test_corrupt_index_fails_cleanly_and_recovers_after_recreation` exposed an unclosed SQLite handle in `TraceIndex._connect()` when `PRAGMA journal_mode=WAL` failed on corrupt `index.db`. Lead fixed `TraceIndex._connect()` to close `conn` in `except Exception:`, and all 279 tests now pass.

---

## 5. Known Limitations

1. **Redaction is defense-in-depth, not exhaustive**: Custom/unstructured secrets that do not match configured `sensitive_keys` or `redact_patterns` require callers to pass a custom `RedactionConfig` or pre-scrub payloads.
2. **Non-cyclic recursion depth in `redact_data()`**: `redact_data()` handles cyclic references safely, but does not enforce a fixed max-depth cap on non-cyclic Python objects deeper than Python's recursion limit (whereas `validate_json_safe()` enforces `max_depth=64`). Callers validating untrusted payloads should rely on `validate_json_safe()` / `Trace.from_json()`.
3. **Single-host local SQLite concurrency**: SQLite WAL supports safe local single-machine reads/writes, but is not designed for multi-host network filesystems.
4. **Pytest-asyncio deprecation notice**: `pytest-asyncio` 1.5 emits a deprecation warning because `asyncio_default_fixture_loop_scope` is not yet set in `pyproject.toml` (will be configured in M3 when async capture tests are added).

---

## 6. Contract Deviations & Decisions Requiring Architect Approval

- **Contract Deviations**: **None.** Every model, enum, exception, invariant, and method signature matches `docs/CONTRACTS.md` verbatim. (Note: all 10 string enums inherit from `enum.StrEnum`, which is a subclass of both `str` and `enum.Enum` in Python 3.12+, satisfying Ruff `UP042` with full `(str, Enum)` runtime compatibility.)
- **Decisions for Architect Approval (Non-Blocking)**:
  1. Should `redact_data()` enforce an optional `max_depth` limit (e.g. `DEFAULT_MAX_JSON_DEPTH = 64`) or keep depth enforcement solely in `validate_json_safe()`?
  2. Should `TraceStore.reindex()` remain strict (`UnsafeTraceError` on any corrupt file in `traces/`, as currently implemented per `docs/CONTRACTS.md`) or add an optional `strict: bool = True` flag for disaster-recovery reindexing?

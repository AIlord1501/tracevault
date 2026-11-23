# TraceVault Security Model & Guarantees

**Status**: Authoritative Security Baseline  
**Related Documents**: [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md), [`docs/CONTRACTS.md`](./CONTRACTS.md)

---

## 1. Security Posture & Trust Boundaries

TraceVault is a **local-first** AI execution capture, replay, comparison, and regression-testing engine. Because trace files may be shared across developers, committed to Git repositories, imported from CI artifacts, or captured from production incidents, TraceVault treats **all trace JSON files, imported artifacts, and trace identifiers as untrusted input**.

Core security principles:
- **Fail-closed by default**: Replay is strictly offline (`BoundaryMode.RECORDED`) unless live boundaries are explicitly authorized via `SafetyPolicy`.
- **Data is never code**: Traces are strictly validated UTF-8 JSON data — never deserialized with executable formats or interpolated into raw Python code.
- **Defense-in-depth**: Multiple independent layers (ID validation, byte-size caps, depth caps, Pydantic strict schemas, path containment, and automatic secret redaction) protect local workspaces and CI runners.

---

## 2. Threat Model

| Threat Vector | Mitigation in TraceVault |
|---|---|
| **Arbitrary Code Execution via Deserialization** | Zero use of `pickle`, `cPickle`, `marshal`, `shelve`, `eval`, `exec`, `os.system`, `os.popen`, or `subprocess(..., shell=True)` anywhere in `src/tracevault/`. Enforced continuously by static AST tests (`tests/security/test_static_safety.py`). |
| **Path Traversal & Symlink Escape** | `trace_id` and `parent_trace_id` must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$` (`InvalidTraceIdError`). Storage resolves target paths and enforces `.resolve().is_relative_to(base.resolve())` (`UnsafeTraceError`). |
| **Denial of Service (Oversized / Deeply Nested / Cyclic Payloads)** | `Trace.from_json()` and `TraceStore` enforce `max_trace_bytes` (default `50 MiB`, measured in UTF-8 bytes) before parsing. `validate_json_safe()` caps container nesting depth at `64` and rejects cyclic object graphs with `UnsafeTraceError`. |
| **Schema Confusion & Field Injection** | Every `TraceVaultModel` sets `ConfigDict(extra="forbid", frozen=True)`. Unknown fields, non-finite JSON constants (`NaN`, `Infinity`, `-Infinity`), naive datetimes, temporal inversions, parent-ID cycles, and incompatible `schema_version` major numbers are rejected. |
| **SQL Injection in Local Index** | All SQLite queries in `index.db` use strictly parameterized `?` placeholders; trace IDs and query filters are never interpolated into SQL strings. |
| **Accidental Live API Spend or Side Effects During Replay** | `ReplayEngine` never performs network calls. Policy-governed replay defaults every boundary to `BoundaryMode.RECORDED` and blocks `BoundaryMode.LIVE` with `PolicyViolationError` unless `SafetyPolicy` explicitly allows the boundary, tool/host, and call budget. |
| **Code Injection in Generated Regression Tests** | `generate_pytest_regression()` serializes all trace identifiers and string literals exclusively via `json.dumps(...)`, never raw string interpolation into executable code blocks. |
| **Credential / Secret Leakage** | `redact_data()` automatically scrubs known sensitive keys and token formats prior to persistence when `redact=True` (default). |

---

## 3. Serialization & Schema Invariants

1. **Strict UTF-8 JSON**: `Trace.to_json()` serializes with `allow_nan=False`. `Trace.from_json()` rejects invalid UTF-8, malformed JSON, non-object JSON roots, and non-finite JSON constants (`NaN`, `Infinity`, `-Infinity`) via a custom `parse_constant` handler.
2. **JSON-Safe Primitives Only**: `validate_json_safe()` accepts only `None`, `bool`, `int`, finite `float`, `str`, `list`/`tuple`, and `dict` with `str` keys. Arbitrary Python objects, `bytes`, `set`, non-string dictionary keys, non-finite floats, cyclic containers, and structures deeper than `max_depth=64` raise `UnsafeTraceError`.
3. **Immutable Strict Models**: All canonical models inherit from `TraceVaultModel` (`extra="forbid"`, `frozen=True`), preventing unknown field injection and accidental in-place mutation.
4. **Schema Version Compatibility**: `schema_version` must match SemVer `^\d+\.\d+\.\d+$` with major version `1` (`SUPPORTED_SCHEMA_MAJOR`). Incompatible versions fail fast with `UnsafeTraceError`.
5. **Deterministic Fingerprinting**: Request fingerprints are SHA-256 digests of `canonical_json({"boundary": ..., "request": ...})` using sorted keys, compact separators, and `allow_nan=False`.

---

## 4. Path Validation & Storage Containment

- **Trace Identifier Rules**: `validate_trace_id()` rejects non-strings, empty strings, strings longer than 128 characters, path separators (`/`, `\`), parent traversal (`..`), null bytes (`\x00`), newlines (`\n`, `\r`), whitespace, and non-ASCII Unicode lookalikes.
- **Storage Containment**: `TraceStore` validates `trace_id` on every operation (`save`, `load`, `freeze`, `delete`, `exists`, `export_trace`) and verifies resolved file paths stay strictly inside the store's `traces/` directory.
- **Atomic Persistence & Freeze Immutability**: Writes use temporary files in `traces/` followed by `os.replace()`. Frozen traces (`frozen=True`) cannot be overwritten (even with `overwrite=True`) and cannot be deleted without `force=True` (`TraceFrozenError`).

---

## 5. Secret Redaction Guarantees & Limitations

`tracevault.schema.redact_data()` recursively, cycle-safely, and idempotently replaces sensitive values with `"[REDACTED]"`:
- **Sensitive Keys** (case-insensitive substring match): `api_key`, `apikey`, `authorization`, `auth_token`, `access_token`, `refresh_token`, `secret`, `password`, `passwd`, `credential`, `private_key`, `bearer`, `x-api-key`, `openai_api_key`.
- **Credential String Patterns**: OpenAI-style keys (`sk-...`), `Bearer <token>`, AWS access key IDs (`AKIA...`), GitHub personal access tokens (`ghp_...`), and JWTs (`eyJ...`).

> **Important Limitation (Defense-in-Depth Only)**  
> Automatic secret redaction in TraceVault is a **defense-in-depth** safeguard and is **not claimed to be exhaustive**. Custom credential formats, opaque internal tokens, proprietary headers, or sensitive user PII may not match default key names or regex patterns. Applications handling sensitive data should configure custom `RedactionConfig` rules, scrub sensitive fields before capture, and review traces before committing or sharing them.

---

## 6. Replay Safety Policies

Live boundary execution is **fail-closed**:
- Every boundary (`MODEL`, `TOOL`, `RETRIEVAL`, `CUSTOM`) defaults to `BoundaryMode.RECORDED`.
- `BoundaryMode.DENY` unconditionally raises `PolicyViolationError`.
- `BoundaryMode.LIVE` raises `PolicyViolationError` before invoking any live handler unless:
  1. The boundary is explicitly listed in `SafetyPolicy.allow_live_boundaries`.
  2. When `require_explicit_opt_in=True` (default), `max_live_calls > 0` and the live call count has not reached `max_live_calls`.
  3. For `TOOL` boundaries, the tool name is explicitly allowlisted in `SafetyPolicy.allowed_tools`.
  4. For `MODEL` / `RETRIEVAL` boundaries with a specified host, the host is explicitly allowlisted in `SafetyPolicy.allowed_hosts`.

---

## 7. Running the Security Test Suite

```bash
uv run pytest tests/security -v
```

The security suite includes:
- `tests/security/test_static_safety.py`: AST audit of `src/tracevault/` for banned modules and calls.
- `tests/security/test_hostile_schema.py`: Hostile trace IDs, malformed/non-finite JSON, deep nesting, cyclic objects, oversized payloads, strict schema enforcement, and graph cycles.
- `tests/security/test_redaction_and_secrets.py`: Sensitive key/pattern redaction, idempotency, and end-to-end zero-secret-leakage checks using synthetic placeholder tokens.
- `tests/security/test_properties.py`: Hypothesis property-based tests for `validate_trace_id`, `compute_fingerprint`, `redact_data`, and `Trace` JSON round-trips.

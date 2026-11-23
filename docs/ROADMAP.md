# TraceVault Roadmap

Milestones are strictly ordered by technical dependencies so parallel agent waves never build on unstable interfaces.

---

## M0: Repository and Agent Setup *(Completed)*
- **Objective**: Establish repository packaging scaffold and reusable workspace custom subagents with clear ownership boundaries.
- **Deliverables**: `pyproject.toml`, `.gitignore`, `LICENSE`, `README.md`, `src/tracevault/__init__.py`, `.agents/agents/{schema,storage,capture,replay,diff,cli,qa-security}-engineer.md`.
- **Dependencies**: None.
- **Acceptance Criteria**: All 7 agent definitions exist, pass frontmatter validation, and enforce contract-first/security rules.
- **Agents Involved**: Lead Architect.

---

## M1: Architecture and Contracts *(Current Milestone)*
- **Objective**: Lock down system architecture, canonical Pydantic v2 data contracts, module dependency DAG, and multi-agent workflow before implementation begins.
- **Deliverables**: `docs/ARCHITECTURE.md`, `docs/CONTRACTS.md`, `docs/AGENT_WORKFLOW.md`, `docs/ROADMAP.md`.
- **Dependencies**: M0.
- **Acceptance Criteria**:
  - Zero contradictions across architecture, contracts, module dependencies, and agent ownership.
  - All core models (`Trace`, `Run`, `Span`, `Event`, `ExecutionError`, interactions, `FixtureEntry`, `ReplayConfig`, `SafetyPolicy`, `DiffConfig`, `DiffReport`, `TraceRepository`, `TraceAdapter`, assertions, CLI) specified with exact fields, types, invariants, and error behaviors.
  - Mermaid diagrams validate cleanly.
- **Agents Involved**: Lead Architect.

---

## M2: Schema and Storage
- **Objective**: Implement the canonical zero-dependency `schema` foundation and local-first atomic `storage` layer.
- **Deliverables**:
  - `src/tracevault/schema/` (`errors.py`, `models.py`, `interactions.py`, `validation.py`, `redaction.py`, `fingerprint.py`), `tests/schema/`, `docs/SCHEMA.md`
  - `src/tracevault/storage/` (`repository.py`, `store.py`, `index.py`), `tests/storage/`
  - Initial `tests/conftest.py` and `docs/SECURITY.md`
- **Dependencies**: M1 (`docs/CONTRACTS.md`), Git repo + `uv` `.venv` (Python 3.12+) initialized.
- **Acceptance Criteria**:
  - M2A (`schema-engineer`) merges first and passes `pytest tests/schema`, `ruff`, `mypy`.
  - M2B (`storage-engineer`) implements atomic writes, freeze immutability, SQLite WAL indexing, query/list, JSON/JSONL export, validated import, and `reindex()`.
  - Path traversal, `NaN`/`Infinity`, oversized payloads, and `extra="forbid"` rejections verified by tests.
- **Agents Involved**: `schema-engineer` (sequential first), then `storage-engineer` + `qa-security-engineer` (parallel).

---

## M3: Capture Engine
- **Objective**: Implement sync/async execution capture, nested span tracking, `contextvars` propagation, automatic fixture fingerprinting, and instrumentation decorators.
- **Deliverables**:
  - `src/tracevault/capture/` (`session.py`, `context.py`, `decorators.py`, `__init__.py`)
  - `tests/capture/` (including concurrent `asyncio.gather` isolation and secret redaction tests)
- **Dependencies**: M2A (`schema` merged; can run in parallel with M2B `storage-engineer`).
- **Acceptance Criteria**:
  - Sync (`capture`) and async (`acapture`) sessions record runs, nested spans, monotonic sequences, and fixtures accurately.
  - Secrets matching redaction rules are scrubbed by default (`redact=True`).
  - Decorators pass through cleanly when no session is active.
- **Agents Involved**: `capture-engineer` (parallel with M2B/M4A), `qa-security-engineer`.

---

## M4: Replay and Diff
- **Objective**: Implement deterministic offline fixture replay, trace forking, policy-governed boundary replay, and structural diffing.
- **Deliverables**:
  - `src/tracevault/diff/` (`engine.py`, `formatter.py`, `__init__.py`), `tests/diff/`
  - `src/tracevault/replay/` (`engine.py`, `boundaries.py`, `regression.py`, `__init__.py`), `tests/replay/`
- **Dependencies**: M2 (`schema`, `storage`), M3 (`capture` contracts/fixtures). (`diff-engineer` can start immediately after M2A `schema`; `replay-engineer` runs once `schema` and `diff` are ready.)
- **Acceptance Criteria**:
  - `ReplayEngine` replays fixtures deterministically offline (`0` network calls), supports strict/lenient modes and `fork()` overrides, and re-raises recorded errors cleanly.
  - `ModelBoundary`, `ToolBoundary`, and `RetrievalBoundary` fail closed (`PolicyViolationError`) on unauthorized `LIVE` or `DENY` calls.
  - `diff_traces` detects run, span, event, interaction, and fixture divergences with deterministic severity classification and `ignore_paths`.
- **Agents Involved**: `diff-engineer`, `replay-engineer`, `qa-security-engineer`.

---

## M5: CLI and `pytest` Integration
- **Objective**: Expose TraceVault workflows through the Typer/Rich CLI, public assertion helpers, and `pytest` integration/regression generation.
- **Deliverables**:
  - `src/tracevault/cli/app.py`, `tests/cli/`
  - `src/tracevault/assertions/` (`trace.py`, `replay.py`, `diff.py`), `tests/assertions/`
  - `src/tracevault/pytest_plugin/` (`plugin.py`), `tests/pytest_plugin/`
  - `src/tracevault/__init__.py` top-level public API exports & `tests/integration/test_end_to_end.py`
- **Dependencies**: M2, M3, M4 (`cli-engineer` can scaffold early with lazy imports, verified fully once `replay` & `diff` land).
- **Acceptance Criteria**:
  - All CLI commands (`init`, `list`, `show`, `freeze`, `replay`, `diff`, `export-test`, `verify`, `delete`) work cleanly via `tracevault` entrypoint (`diff` exits `1` on breaking divergence).
  - Generated pytest regression files execute and pass offline under `uv run pytest`, and hostile trace strings cannot inject Python code.
- **Agents Involved**: `cli-engineer`, `replay-engineer` (`regression.py`), Lead Architect (`assertions`, `pytest_plugin`, integration wiring), `qa-security-engineer`.

---

## M6: SDK Adapters
- **Objective**: Deliver the `TraceAdapter` abstraction and the first official provider adapter for the OpenAI Python SDK.
- **Deliverables**:
  - `src/tracevault/adapters/` (`base.py`, `openai.py`, `__init__.py`)
  - `tests/adapters/test_openai.py` using `httpx.MockTransport` (zero credentials, zero live HTTP calls)
  - `examples/basic_workflow.py`
- **Dependencies**: M3 (`capture`), M4 (`replay`, `boundaries`), M5 integration checkpoint.
- **Acceptance Criteria**:
  - Sync `OpenAI` and async `AsyncOpenAI` `chat.completions.create` calls capture sanitized payloads without leaking API keys or Authorization headers.
  - Offline replay intercepts SDK calls and returns reconstructed SDK-compatible responses with zero network activity.
  - Core `tracevault` install works without `openai` installed; missing extra raises `AdapterUnavailableError`.
- **Agents Involved**: Lead Architect (or delegated adapter engineer), `qa-security-engineer`.

---

## M7: Security Hardening
- **Objective**: Complete adversarial, property-based, and static security verification across the integrated codebase.
- **Deliverables**:
  - `tests/security/` (`test_hostile_traces.py`, `test_redaction_and_secrets.py`, `test_static_safety.py`, `test_properties.py`)
  - `docs/SECURITY.md` finalized and audited against actual implementation
- **Dependencies**: M2–M6 integrated on `main`.
- **Acceptance Criteria**:
  - AST static scan proves zero usage of `pickle`, `marshal`, `shelve`, `eval`, `exec`, `os.system`, or `subprocess(..., shell=True)` in `src/`.
  - Hypothesis property tests pass for schema round-trips, `trace_id` validation, fingerprint determinism, and redaction idempotency.
  - Hostile path traversal, non-finite JSON, deep nesting, tampered frozen traces, and code-injection payloads are all safely rejected or neutralized.
- **Agents Involved**: `qa-security-engineer`, Lead Architect (fixes and reviews).

---

## M8: MVP Release (`v0.1.0`)
- **Objective**: Validate clean-environment installation, CI automation, examples, and full end-to-end MVP readiness.
- **Deliverables**: `.github/workflows/ci.yml`, verified clean-venv wheel/editable install, passing end-to-end examples, tagged `v0.1.0` release readiness report.
- **Dependencies**: M7.
- **Acceptance Criteria**:
  - Clean `uv venv --python 3.12` install passes `pytest -v`, `ruff check`, `ruff format --check`, `mypy src`.
  - All 12 MVP acceptance criteria verified end-to-end (`Capture → Persist → Freeze → Replay → Fork → Diff → Regression test`).
- **Agents Involved**: Lead Architect, `qa-security-engineer`.

---

## M9: Developer Adoption *(Post-MVP)*
- **Objective**: Expand ergonomic integrations, cookbook documentation, and framework adapters for broader Python AI adoption.
- **Deliverables**:
  - Additional adapters (Anthropic SDK, Google GenAI SDK, LangGraph/PydanticAI hooks)
  - Rich streaming replay support (chunk-level stream reconstruction)
  - Cookbook tutorials, troubleshooting guide, and PyPI publishing automation
- **Dependencies**: M8.
- **Acceptance Criteria**: New adapters implement `TraceAdapter` cleanly with offline mocked test suites and zero changes to core `schema` major version `1.x`.
- **Agents Involved**: Lead Architect + delegated adapter engineers + `qa-security-engineer`.

---

## M10: Performance and Ecosystem Scaling *(Post-MVP)*
- **Objective**: Scale local trace handling to large multi-step agent workloads and enable community extensions.
- **Deliverables**:
  - Optional gzip/zstd compressed trace storage & streaming JSON parser optimizations
  - Indexed SQLite full-text/attribute search and faster large-tree diff alignment
  - Redaction policy profiles & trace minimization/shrinking for bug reports
  - Entry-point discovery for community-maintained adapters and diff plugins
- **Dependencies**: M9.
- **Acceptance Criteria**: Backward-compatible `1.x` trace portability preserved; benchmark suite validates sub-second load/diff on multi-thousand-event traces.
- **Agents Involved**: Lead Architect + subsystem engineers (`storage-engineer`, `diff-engineer`, `replay-engineer`, `qa-security-engineer`).

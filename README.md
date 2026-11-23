# TraceVault

**TraceVault** is a local-first, open-source AI execution capture, replay, comparison, and regression testing engine.

Workflow:

```
Production failure → Capture → Freeze → Replay → Fork → Compare → Verify fix → Regression test
```

## Core Principles

- **Local-first**: Traces persist as portable JSON files indexed in local SQLite (`index.db`). No mandatory cloud or server daemon.
- **Framework-agnostic & provider-agnostic**: Canonical Pydantic v2 trace schema works across any Python AI application.
- **Deterministic offline replay**: Recorded boundary fixtures (model, tool, retrieval) replay deterministically with zero external network calls by default.
- **Secure by default**: Strict Pydantic validation (`extra="forbid"`), path-traversal guards, automatic secret redaction, no `pickle` or dynamic code execution, and explicit `SafetyPolicy` opt-in for any live boundary execution.

## Quickstart

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
tracevault --help
```

Initialize a local store and inspect traces:

```bash
tracevault init
tracevault list
tracevault show <trace_id>
tracevault inspect <trace_id>
tracevault freeze <trace_id>
tracevault replay <trace_id>
tracevault diff <baseline_id> <candidate_id>
tracevault export-test <trace_id> -o tests/test_regression.py
tracevault test <trace_id>
tracevault verify <trace_id>
tracevault export <trace_id> -o trace.json
tracevault import trace.json --freeze
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Contracts](docs/CONTRACTS.md)
- [Roadmap](docs/ROADMAP.md)
- [Schema](docs/SCHEMA.md)
- [Capture & Instrumentation](docs/CAPTURE.md)
- [Offline Replay & Boundaries](docs/REPLAY.md)
- [Structural Diff & Divergence Analysis](docs/DIFF.md)
- [Assertions & Pytest Regression Testing](docs/ASSERTIONS_AND_PYTEST.md)
- [CLI & Developer Workflow](docs/CLI.md)
- [Security](docs/SECURITY.md)

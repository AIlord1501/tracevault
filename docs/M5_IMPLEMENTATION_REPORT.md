# TraceVault M5 — Structural Trace Diff & Divergence Analysis Report

## 1. Summary

Milestone M5 implements TraceVault's deterministic, offline structural trace diff and divergence analysis engine (`src/tracevault/diff/`), fulfilling `docs/CONTRACTS.md` Section 10 and Section 14 without modifying any M2–M4 subsystem internals.

### Key Capabilities Delivered
- **Structural Diff Engine (`src/tracevault/diff/engine.py`)**:
  - `diff_traces(baseline, candidate, *, config=None, ignore_paths=None) -> DiffReport`
  - `DiffEngine(config=None)` OOP wrapper and `DEFAULT_SEVERITY_MAP`
  - `find_earliest_divergence(report) -> Divergence | None`
  - Structural alignment across **runs**, **spans** (including LIS-based `SPAN_ORDER_CHANGED` detection), **events** (sequence-aware alignment via `difflib.SequenceMatcher` with per-`EventKind` divergence classification), and **fixtures** (`FIXTURE_MISMATCH`).
  - Compiled exact, prefix, and `[*]` wildcard `ignore_paths` support; `ignore_timestamps`, `ignore_ids`, `compare_metadata`, `strict_order`, and `severity_overrides`.
  - Strict immutability (never mutates input traces, configs, or ignore path sets) and deterministic ordering.
- **Human, Rich, and JSON Formatters (`src/tracevault/diff/formatter.py`)**:
  - `format_diff_report(report, *, verbose=False) -> str`
  - `render_diff_rich(report, *, console=None) -> None` (with Rich `Text(...)` cell escaping to prevent markup injection / `MarkupError`)
  - `format_diff_json(report, *, indent=2) -> str`
- **Public API Exports (`src/tracevault/__init__.py`)**:
  - Re-exported `DEFAULT_SEVERITY_MAP`, `DiffEngine`, `diff_traces`, `find_earliest_divergence`, `format_diff_json`, `format_diff_report`, and `render_diff_rich`.
- **Documentation & Runnable Examples**:
  - `docs/DIFF.md` — API reference, configuration table, severity mapping, and usage guide.
  - `examples/diff_examples.py` — offline end-to-end capture → freeze → fork → diff → text/JSON/Rich formatting example.

## 2. QA & Security Audit Findings Resolved

During M5 security and integration testing (`qa-security-engineer`), two real defects were surfaced and fixed prior to commit:
1. **Rich Markup Injection / `MarkupError` DoS in `render_diff_rich`** (`src/tracevault/diff/formatter.py`): Plain strings in table cells were parsed as Rich console markup, crashing on unmatched closing tags like `[/bold]` or interpreting injected tags. Fixed by wrapping table cell values in `rich.text.Text(...)`.
2. **Lifecycle `run_id` / `span_id` false positives under `ignore_ids=True`** (`src/tracevault/diff/engine.py`): `CaptureSession` emits `run_id` inside `RUN_STARTED` event payloads, causing false-positive `WARNING` diffs on structurally identical traces with regenerated IDs. Fixed by stripping `run_id` / `span_id` keys from lifecycle event payloads when `config.ignore_ids` is `True`.

## 3. Validation Results

| Check | Command | Result |
| --- | --- | --- |
| Full test suite | `uv run pytest -q` | **498 passed** in 24.68s (63 new M5 tests: 29 unit + 34 security/integration) |
| Lint | `uv run ruff check src tests examples` | **All checks passed!** |
| Formatting | `uv run ruff format --check src tests examples` | **56 files already formatted** |
| Type checking | `uv run mypy src` | **Success: no issues found in 24 source files** |
| Offline examples | `uv run python examples/diff_examples.py` | **Exit 0** (text, JSON, and Rich rendering verified) |

## 4. Commit History

- `b2091b6` `feat(diff): implement structural diff engine and formatters`
- `eadb331` `feat(diff): wire top-level public diff exports`
- `e576bfa` `test(diff): add security, property, and integration tests`
- `1c19b16` `docs(m5): add diff usage guide and runnable examples`

# TraceVault M7 — CLI, Developer Workflow & Integration Report

## 1. Summary

Milestone M7 delivers TraceVault's terminal CLI (`src/tracevault/cli/`) and integrated end-to-end developer workflow built on **Typer** and **Rich**, connecting all M2–M6 subsystems (`schema`, `storage`, `capture`, `replay`, `diff`, `assertions`, and `pytest_plugin`) behind the `tracevault` command-line entrypoint.

## 2. CLI Architecture

- **Entrypoint**: `tracevault = "tracevault.cli.app:app"` (`typer.Typer(name="tracevault", no_args_is_help=True)`).
- **Thin Orchestration Layer**: The CLI contains zero duplicated domain logic; it delegates storage operations to `TraceStore`, replay/forking to `ReplayEngine`, regression codegen to `generate_pytest_regression`, comparisons to `diff_traces` / `render_diff_rich` / `format_diff_report` / `format_diff_json`, and verification to `assert_trace_valid` / `assert_no_secrets_leaked` / `assert_no_breaking_diffs`.
- **Resource & Windows SQLite Safety**: Every store-backed command uses `_open_store(...)` (`with TraceStore(path) as store:`) so SQLite WAL connections are deterministically closed before command exit.
- **Dual Human / Automation Output**: Every command supports Rich terminal panels/tables by default and deterministic machine-readable `--json` output for CI/CD pipelines.
- **Safe Domain Error Handling**: `_handle_cli_error` intercepts all expected `TraceVaultError`, `AssertionError`, `FileExistsError`, `FileNotFoundError`, and `ValueError` exceptions, scrubs any sensitive tokens via `redact_data`, escapes Rich markup via `rich.text.Text`, and exits with code `1`.

## 3. Command Reference

| Command | Arguments & Options | Exit Code |
| --- | --- | --- |
| `tracevault version` | `[--json]` (plus root `--version / -V`) | `0` |
| `tracevault init` | `[--store / -s PATH] [--json]` | `0` |
| `tracevault list` | `[--store / -s] [--status] [--tag] [--frozen/--unfrozen] [--query / -q] [--limit] [--json]` | `0` (`1` on invalid status) |
| `tracevault show` | `TRACE_ID [--store / -s] [--spans] [--events] [--fixtures] [--metadata] [--json]` | `0` (`1` on missing/invalid) |
| `tracevault inspect` | `TRACE_ID [--store / -s] [--spans/--no-spans] [--events/--no-events] [--fixtures/--no-fixtures] [--metadata/--no-metadata] [--json]` | `0` (`1` on missing/invalid) |
| `tracevault freeze` | `TRACE_ID [--store / -s] [--json]` | `0` (`1` on missing/invalid) |
| `tracevault delete` | `TRACE_ID [--store / -s] [--force / -f] [--json]` | `0` (`1` on frozen/missing) |
| `tracevault replay` | `TRACE_ID [--store / -s] [--strict/--lenient] [--fork] [--save] [--new-id] [--override KEY=JSON ...] [--json]` | `0` on clean replay, `1` on error/missing fixture |
| `tracevault diff` | `BASELINE_ID CANDIDATE_ID [--store / -s] [--ignore-path ...] [--compare-metadata] [--verbose / -v] [--json]` | `0` if no breaking diffs, **`1` if `report.has_breaking`** |
| `tracevault export` | `TRACE_ID --output / -o PATH [--store / -s] [--format json\|jsonl] [--json]` | `0` (`1` on error) |
| `tracevault import` | `INPUT_PATH [--store / -s] [--overwrite] [--freeze] [--json]` | `0` (`1` on duplicate/invalid) |
| `tracevault export-test` | `TRACE_ID --output / -o PATH [--fixture-output PATH] [--store / -s] [--json]` | `0` (`1` on error) |
| `tracevault test` | `TARGET [--store / -s] [--export-test PATH] [--fixture-output PATH] [--strict/--lenient] [--json]` | `0` on pass, `1` on failure |
| `tracevault verify` | `TRACE_ID [--store / -s] [--json]` | `0` if valid & redacted, `1` on failure |

## 4. Configuration

- **Store Directory**: Controlled via `--store / -s PATH` per command, falling back to the `TRACEVAULT_STORE` environment variable, and defaulting to `.tracevault`.
- **Output Mode**: `--json` on any command switches output to UTF-8 indented JSON (`allow_nan=False`).
- **Replay Mode**: `--strict` (`ReplayMode.OFFLINE_STRICT`, default) or `--lenient` (`ReplayMode.OFFLINE_LENIENT`).

## 5. Files Changed & Agent Contributions

- **`cli-engineer` (M7A)**:
  - `src/tracevault/cli/app.py`
  - `src/tracevault/cli/__init__.py`
  - `tests/unit/cli/__init__.py`
  - `tests/unit/cli/test_cli.py`
- **`qa-security-engineer` (M7B)**:
  - `tests/security/test_cli_security.py` (59 security tests covering AST safety, zero network calls across all 14 commands, path traversal, hostile trace IDs, Rich markup injection, and secret redaction)
  - `tests/integration/test_cli_end_to_end.py` (14-step end-to-end offline workflow test)
- **Lead Architect**:
  - Applied `rich.text.Text` escaping fix in `src/tracevault/cli/app.py` to neutralize Rich console markup injection across CLI tables/panels/error output.
  - Authored `docs/CLI.md`, `examples/cli_workflow_example.py`, updated `README.md`, and compiled `docs/M7_IMPLEMENTATION_REPORT.md`.

## 6. End-to-End Validation & Quality Checks

The 14-step local workflow was executed both via `uv run python examples/cli_workflow_example.py` and `tests/integration/test_cli_end_to_end.py` with `socket.socket` blocked:
1. Initialized store A (`tracevault init`)
2. Captured a synthetic AI execution with model, tool, retrieval, state change, and secret input
3. Persisted trace to store A
4. Inspected via `tracevault list`, `tracevault show`, and `tracevault inspect`
5. Froze trace via `tracevault freeze` (verified unforced `delete` exits `1`)
6. Replayed offline (`tracevault replay --strict --save`) and forked with override (`--fork --save --override`)
7. Compared original vs replayed (`tracevault diff` -> exit `0`) and original vs modified fork (`tracevault diff` -> exit `1`)
8. Generated standalone pytest regression test (`tracevault export-test`)
9. Executed generated pytest test function and `tracevault test` offline (exit `0`)
10. Exported trace to JSON and JSONL (`tracevault export`)
11. Imported trace into isolated store B (`tracevault import --freeze`, verified duplicate without `--overwrite` exits `1`)
12. Verified imported trace integrity and secret hygiene (`tracevault verify` -> exit `0`)

| Check | Command | Result |
| --- | --- | --- |
| Full pytest suite | `uv run pytest -q` | **614 passed** in 33.82s (69 new M7 CLI tests) |
| Ruff lint | `uv run ruff check src tests examples` | **All checks passed!** |
| Ruff format | `uv run ruff format --check src tests examples` | **78 files already formatted** |
| Mypy typecheck | `uv run mypy src` | **Success: no issues found in 33 source files** |
| CLI entrypoint & E2E script | `uv run tracevault --help` & `uv run python examples/cli_workflow_example.py` | **Exit 0** |

## 7. Security Review, Limitations & Deviations

- **Security Finding Resolved**: `qa-security-engineer` identified that raw trace strings (`run_name`, `tags`, `span.name`, `event.payload`, `metadata`, and error messages) passed to Rich `Table.add_row` / `Panel` / `err_console.print` could trigger `rich.errors.MarkupError` on unmatched tags like `[/bold]`. Fixed by wrapping untrusted strings in `rich.text.Text(...)`.
- **Deviations**: None. All contracts in `docs/CONTRACTS.md` Section 13 are satisfied, and additive developer-experience commands (`inspect`, `export`, `import`, `test`, `version`) were integrated cleanly into the same flat Typer hierarchy.
- **Limitations**: Live boundary replay remains strictly opt-in via programmatic `BoundaryExecutor` + `SafetyPolicy`; the CLI `replay` command is intentionally offline-only by design.

## 8. Commits, Push Status & Working-Tree Status

- `587e2f0` `feat(cli): implement Typer and Rich CLI command suite`
- `de39175` `test(cli): add CLI security audit and 14-step end-to-end integration tests`
- `df110de` `docs(m7): add CLI guide, E2E workflow script, and update README`
- Branch: `main` (pushed to `origin/main`, clean working tree).

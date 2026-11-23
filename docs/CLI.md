# TraceVault CLI & Developer Workflow Guide

TraceVault provides a local-first terminal workflow built on **Typer** and **Rich** via the `tracevault` executable.

## Core Terminal Workflow

```bash
# 1. Initialize local store (.tracevault/)
tracevault init

# 2. List and filter captured traces
tracevault list --status failed --tag prod

# 3. Inspect a trace (summary, spans, events, fixtures, metadata)
tracevault show <trace_id>
tracevault inspect <trace_id>

# 4. Freeze a production failure trace to make it immutable
tracevault freeze <trace_id>

# 5. Replay offline (strict or lenient) or fork with fixture overrides
tracevault replay <trace_id> --strict
tracevault replay <trace_id> --fork --save --override 'fix_0001={"status":"ok"}'

# 6. Structurally diff baseline vs candidate (exits 1 on breaking divergences)
tracevault diff <baseline_id> <candidate_id>
tracevault diff <baseline_id> <candidate_id> --verbose
tracevault diff <baseline_id> <candidate_id> --json

# 7. Export a standalone pytest regression test and verify offline
tracevault export-test <trace_id> -o tests/test_regression.py
tracevault test <trace_id>
tracevault verify <trace_id>

# 8. Portable JSON/JSONL export and validated import
tracevault export <trace_id> -o backups/trace.json
tracevault import backups/trace.json --freeze
```

## Command Reference

| Command | Synopsis | Exit Codes |
| --- | --- | --- |
| `tracevault version` | Display package and schema version (`--json` supported). | `0` |
| `tracevault init` | Initialize `.tracevault/traces/` and SQLite `index.db`. | `0` |
| `tracevault list` | List traces with `--status`, `--tag`, `--frozen/--unfrozen`, `--query`, `--limit`, `--json`. | `0` (`1` on invalid filter) |
| `tracevault show` | Show trace summary and optional `--spans`, `--events`, `--fixtures`, `--metadata`, `--json`. | `0` (`1` if not found/invalid) |
| `tracevault inspect` | Detailed inspection with spans, events, fixtures, and metadata enabled by default. | `0` (`1` if not found/invalid) |
| `tracevault freeze` | Mark a trace immutable (`frozen=True`). | `0` (`1` if not found/invalid) |
| `tracevault delete` | Delete a trace (`--force / -f` required for frozen traces). | `0` (`1` if frozen or missing) |
| `tracevault replay` | Offline replay (`--strict/--lenient`, `--fork`, `--save`, `--new-id`, `--override`, `--json`). | `0` on clean replay, `1` on error/missing fixture |
| `tracevault diff` | Compare two traces by ID or `.json` path (`--ignore-path`, `--compare-metadata`, `--verbose`, `--json`). | `0` if no breaking diffs, **`1` if breaking** |
| `tracevault export` | Export trace to `.json` or `.jsonl` (`--format json\|jsonl`). | `0` (`1` on error) |
| `tracevault import` | Validate and import a `.json` trace file (`--overwrite`, `--freeze`). | `0` (`1` on duplicate/invalid) |
| `tracevault export-test` | Generate a standalone pytest regression file (`-o PATH`, `--fixture-output PATH`). | `0` (`1` on error) |
| `tracevault test` | Execute offline replay + diff + secret hygiene regression check on a trace ID or `.json` file. | `0` on pass, `1` on failure |
| `tracevault verify` | Validate canonical schema integrity and `assert_no_secrets_leaked` on a trace. | `0` if valid, `1` on failure |

## Configuration & Environment Variables

- `--store / -s PATH`: Path to the TraceVault storage directory. Defaults to `$TRACEVAULT_STORE` if set, otherwise `.tracevault` in the current working directory.
- `--json`: Supported across all commands for deterministic machine-readable CI/CD scripting.

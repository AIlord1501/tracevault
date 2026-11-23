"""Static AST safety audit enforcing zero unsafe deserialization or shell execution in src/."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

BANNED_MODULES: frozenset[str] = frozenset({"pickle", "cPickle", "_pickle", "marshal", "shelve"})
BANNED_BUILTINS: frozenset[str] = frozenset({"eval", "exec"})
BANNED_OS_FUNCS: frozenset[str] = frozenset({"system", "popen"})
SUBPROCESS_CALL_FUNCS: frozenset[str] = frozenset(
    {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
)

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "tracevault"


def scan_source_for_unsafe_ast(source: str, filename: str = "<memory>") -> list[str]:
    """Parse Python source with ast and return any banned import or call violations."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    os_aliases: set[str] = {"os"}
    subprocess_aliases: set[str] = {"subprocess"}
    builtins_aliases: set[str] = {"builtins"}
    banned_direct_names: set[str] = set(BANNED_BUILTINS)
    subprocess_direct_funcs: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_mod = alias.name.split(".", 1)[0]
                local_name = alias.asname or root_mod
                if root_mod in BANNED_MODULES:
                    violations.append(
                        f"{filename}:{node.lineno}: banned module import '{alias.name}'"
                    )
                elif alias.name == "os":
                    os_aliases.add(local_name)
                elif alias.name == "subprocess":
                    subprocess_aliases.add(local_name)
                elif alias.name == "builtins":
                    builtins_aliases.add(local_name)

        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root_mod = mod.split(".", 1)[0]
            if root_mod in BANNED_MODULES:
                violations.append(f"{filename}:{node.lineno}: banned import from '{mod}'")
            for alias in node.names:
                local_name = alias.asname or alias.name
                if mod == "os" and alias.name in BANNED_OS_FUNCS:
                    violations.append(
                        f"{filename}:{node.lineno}: banned import 'from os import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)
                elif mod == "builtins" and alias.name in BANNED_BUILTINS:
                    violations.append(
                        f"{filename}:{node.lineno}: "
                        f"banned import 'from builtins import {alias.name}'"
                    )
                    banned_direct_names.add(local_name)
                elif mod == "subprocess" and alias.name in SUBPROCESS_CALL_FUNCS:
                    subprocess_direct_funcs.add(local_name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        if isinstance(func, ast.Name):
            if func.id in banned_direct_names:
                violations.append(f"{filename}:{node.lineno}: banned call '{func.id}()'")
            elif func.id in subprocess_direct_funcs and _has_shell_true(node):
                violations.append(
                    f"{filename}:{node.lineno}: banned subprocess call '{func.id}(..., shell=True)'"
                )

        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target = func.value.id
            attr = func.attr
            if (
                target in BANNED_MODULES
                or (target in builtins_aliases and attr in BANNED_BUILTINS)
                or (target in os_aliases and attr in BANNED_OS_FUNCS)
            ):
                violations.append(f"{filename}:{node.lineno}: banned call '{target}.{attr}()'")
            elif target in subprocess_aliases and _has_shell_true(node):
                violations.append(
                    f"{filename}:{node.lineno}: "
                    f"banned subprocess call '{target}.{attr}(..., shell=True)'"
                )

    return violations


def _has_shell_true(call_node: ast.Call) -> bool:
    """Return True if a call node passes shell=True (or any truthy constant for shell)."""
    for kw in call_node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and bool(kw.value.value):
            return True
    return False


def test_src_tree_contains_python_files() -> None:
    """Ensure the static safety audit actually scans source files."""
    py_files = sorted(SRC_ROOT.rglob("*.py"))
    assert py_files, f"Expected Python files under {SRC_ROOT}"


def test_src_tree_has_zero_unsafe_imports_or_calls() -> None:
    """Every .py file under src/tracevault/ must have zero banned imports or calls."""
    py_files = sorted(SRC_ROOT.rglob("*.py"))
    all_violations: list[str] = []
    for path in py_files:
        source = path.read_text(encoding="utf-8")
        all_violations.extend(scan_source_for_unsafe_ast(source, filename=str(path)))
    assert all_violations == [], "Unsafe AST constructs found:\n" + "\n".join(all_violations)


@pytest.mark.parametrize(
    "snippet",
    [
        "import pickle\n",
        "import cPickle\n",
        "import marshal\n",
        "import shelve\n",
        "from pickle import loads\n",
        "eval('1 + 1')\n",
        "exec('x = 1')\n",
        "import builtins\nbuiltins.eval('1')\n",
        "import os\nos.system('echo hi')\n",
        "import os as _os\n_os.popen('id')\n",
        "from os import system\nsystem('ls')\n",
        "import subprocess\nsubprocess.run('echo hi', shell=True)\n",
        "import subprocess as sp\nsp.Popen('echo hi', shell=True)\n",
        "from subprocess import call\ncall('echo hi', shell=True)\n",
    ],
)
def test_ast_scanner_detects_banned_constructs(snippet: str) -> None:
    """Verify the AST scanner catches every banned module and call pattern."""
    violations = scan_source_for_unsafe_ast(snippet, filename="<synthetic>")
    assert violations, f"AST scanner failed to detect banned snippet: {snippet!r}"


def test_ast_scanner_allows_safe_subprocess_without_shell() -> None:
    """Verify subprocess with shell=False is not falsely flagged."""
    snippet = "import subprocess\nsubprocess.run(['echo', 'hi'], shell=False, check=True)\n"
    assert scan_source_for_unsafe_ast(snippet, filename="<synthetic>") == []

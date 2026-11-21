"""Catch a name used but never bound, anywhere in the project's own code.

`process_error` called reported_violation() while the import list next to it
named only unmodelled_calls_in_source. Every one of the 612 unit tests passed:
the statement sits inside a branch no test reaches, so the NameError only
surfaced in a real run, four minutes in, after the LLM calls had been paid for.

That is a whole class of failure -- a name that resolves nowhere -- and it is
decidable without running anything. The analysis here is deliberately
conservative: it reports a name only when it can see every binding that could
have supplied it and none did. Anything it cannot model (star imports, globals
declared elsewhere, class attribute scope) makes it stay quiet, because a false
report here would be worse than the bug it looks for.
"""
from __future__ import annotations

import ast
import builtins
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AREAS = ("src",)
BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__spec__"}


def _bound_by(node: ast.AST) -> set:
    """Every name a statement or expression binds in its own scope."""
    bound = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(child.name)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            bound.add(child.id)
        elif isinstance(child, ast.arg):
            bound.add(child.arg)
        elif isinstance(child, ast.alias):
            bound.add((child.asname or child.name).split(".")[0])
        elif isinstance(child, ast.ExceptHandler) and child.name:
            bound.add(child.name)
        elif isinstance(child, ast.Global):
            bound.update(child.names)
        elif isinstance(child, ast.Nonlocal):
            bound.update(child.names)
    return bound


def _module_bindings(tree: ast.Module) -> set:
    bound = set()
    for node in tree.body:
        bound |= _bound_by(node)
    return bound


def undefined_names(path: Path) -> list:
    """Names loaded in a function that nothing in scope binds."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    # A star import can supply anything; nothing here is knowable after one.
    if any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(tree)
    ):
        return []

    module_scope = _module_bindings(tree) | BUILTINS
    reported = []

    def visit(node: ast.AST, enclosing: set) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = enclosing | _bound_by(child)
                for inner in child.body:
                    for used in ast.walk(inner):
                        if (isinstance(used, ast.Name)
                                and isinstance(used.ctx, ast.Load)
                                and used.id not in scope):
                            reported.append((child.name, used.id, used.lineno))
                visit(child, scope)
            elif isinstance(child, ast.ClassDef):
                # Class bodies see their own namespace plus the module's; the
                # methods inside do not see the class scope, so they are
                # visited against the enclosing scope only.
                visit(child, enclosing)
            else:
                visit(child, enclosing)

    visit(tree, module_scope)
    return reported


class UndefinedNameTests(unittest.TestCase):
    def test_no_module_uses_a_name_nothing_binds(self):
        failures = []
        for area in AREAS:
            for path in sorted((ROOT / area).rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                for function, name, line in undefined_names(path):
                    failures.append(
                        "%s:%d %s() uses undefined name %r"
                        % (path.relative_to(ROOT).as_posix(), line, function, name)
                    )
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_the_check_reports_a_missing_import(self):
        # The shape of the real bug: a helper called without being imported.
        source = (
            "import json\n"
            "\n"
            "def handle(payload):\n"
            "    parsed = json.loads(payload)\n"
            "    return reported_violation(parsed)\n"
        )
        path = ROOT / "tests" / "_undefined_name_fixture.py"
        path.write_text(source, encoding="utf-8")
        try:
            found = undefined_names(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(
            [(name, used) for name, used, _ in found],
            [("handle", "reported_violation")],
        )

    def test_the_check_accepts_names_bound_in_any_reachable_scope(self):
        source = (
            "import json\n"
            "TOP = 1\n"
            "\n"
            "def outer(items):\n"
            "    total = 0\n"
            "    def inner():\n"
            "        return total + TOP + len(items) + json.dumps({})\n"
            "    for value in items:\n"
            "        total += value\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError as error:\n"
            "        print(error)\n"
            "    return inner\n"
        )
        path = ROOT / "tests" / "_undefined_name_fixture.py"
        path.write_text(source, encoding="utf-8")
        try:
            self.assertEqual(undefined_names(path), [])
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

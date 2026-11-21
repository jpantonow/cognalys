"""The patches maintainers accepted must keep passing every patch check.

The checks in contract_gates were written from patches that were wrong; a
check that also stops one of these would have withheld a change a
maintainer merged. Each fixture is the diff of a pull request that was
merged (or, for BombusMod#316, applied by hand), as the pipeline proposed it.
"""
import json
import re
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import contract_gates  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    statements_without_effect, validate_coordinated_semantics)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "accepted_prs"
_FILE = re.compile(r"^diff --git a/\S+ b/(?P<path>\S+)$")


def edits_from_diff(diff: str) -> list:
    """One edit per hunk: the lines it had before and after."""
    edits, path, before, after = [], "", None, None

    def close():
        if before is not None:
            edits.append({"source_file_path": path, "original_code": "\n".join(before),
                          "corrected_code": "\n".join(after),
                          "edit_kind": "test" if contract_gates._is_test_path(path) else "method"})

    for line in diff.splitlines():
        header = _FILE.match(line)
        if header:
            close()
            path, before, after = header.group("path"), None, None
        elif line.startswith("@@"):
            close()
            before, after = [], []
        elif before is not None and not line.startswith(("---", "+++", "\\")):
            if line.startswith("-"):
                before.append(line[1:])
            elif line.startswith("+"):
                after.append(line[1:])
            else:
                before.append(line[1:])
                after.append(line[1:])
    close()
    return edits


class AcceptedPullRequestTests(unittest.TestCase):
    def test_every_accepted_patch_passes_the_patch_checks(self):
        fixtures = sorted(FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 6)
        for fixture in fixtures:
            accepted = json.loads(fixture.read_text(encoding="utf-8"))
            edits = edits_from_diff(accepted["diff"])
            error = {key: accepted[key] for key in ("spec", "csv_class", "method_name")}
            with self.subTest(pull_request=accepted["pull_request"]):
                self.assertTrue(edits)
                issues = (
                    contract_gates.rewritten_test_expectations(error, edits)
                    + contract_gates.changed_stored_derivations(error, edits)
                    + contract_gates.source_text_tests(edits)
                    + contract_gates.kept_constant_key_material(error, edits)
                    + contract_gates.protocol_algorithm_changes(error, edits)
                    + statements_without_effect(edits)
                    # Every check the coordinated validator runs, the rename,
                    # test-module and TLS checks of 2026-10-29 among them.
                    + validate_coordinated_semantics(error, edits)["errors"]
                )
                self.assertEqual([issue["code"] for issue in issues], [])

    def test_the_diff_reader_keeps_context_on_both_sides(self):
        diff = ("diff --git a/src/A.java b/src/A.java\n--- a/src/A.java\n+++ b/src/A.java\n"
                "@@ -1,3 +1,3 @@\n class A {\n-  int x = 1;\n+  int x = 2;\n }\n")
        [edit] = edits_from_diff(diff)
        self.assertEqual(edit["original_code"], "class A {\n  int x = 1;\n}")
        self.assertEqual(edit["corrected_code"], "class A {\n  int x = 2;\n}")


if __name__ == "__main__":
    unittest.main()

"""A validation heuristic that crashes still reports nothing -- but says so.

These checks are built never to stop a run, so a failure inside one returns
the same empty result as a clean pass. Unlogged, "it crashed" and "it found
no problem" looked identical in every run's logs.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import semantic_validation  # noqa: E402


class HeuristicFailureTests(unittest.TestCase):
    def test_a_crashed_import_check_returns_nothing_and_logs_it(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(semantic_validation, "mismatched_imports",
                             side_effect=RuntimeError("index unreadable")), \
                self.assertLogs(semantic_validation.__name__, "WARNING") as logs:
            issues = semantic_validation.import_issues(
                {"repository_path": directory}, [{"source_file_path": "A.java"}])
        self.assertEqual(issues, [])
        self.assertIn("index unreadable", logs.output[0])

    def test_a_crashed_signature_check_keeps_what_it_had_and_logs_it(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(semantic_validation, "changed_symbol_names",
                             side_effect=RuntimeError("parse failed")), \
                self.assertLogs(semantic_validation.__name__, "WARNING") as logs:
            issues = semantic_validation.signature_change_issues(
                {"repository_path": directory}, [])
        self.assertEqual(issues, [])
        self.assertTrue(any("parse failed" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()

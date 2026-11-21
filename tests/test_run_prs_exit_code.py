import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
MODULE_PATH = ROOT / "src" / "cognalys" / "prs" / "run_prs.py"
SPEC = importlib.util.spec_from_file_location("run_prs", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class _FakeGenerator:
    def __init__(self, summary, **kwargs):
        self._summary = summary

    def generate_prs(self):
        return self._summary


class RunPrsExitCodeTests(unittest.TestCase):
    def _run_main(self, summary):
        args = [
            "run_prs.py",
            "--execution-report", "execution.json",
            "--output-dir", "out",
        ]
        with patch.object(
            MODULE, "PrGenerator",
            lambda **kwargs: _FakeGenerator(summary, **kwargs),
        ), patch.object(sys, "argv", args):
            return MODULE.main()

    def test_nonzero_exit_when_pr_generation_reports_failures(self):
        # Reproduces the real bug: generate_prs()'s summary was discarded and
        # main() always returned 0, so a run where every PR failed still
        # looked like a clean pipeline step to run_pipeline.py.
        self.assertEqual(
            self._run_main({"generated": 0, "failed": 2}), 1
        )

    def test_zero_exit_when_pr_generation_succeeds(self):
        self.assertEqual(
            self._run_main({"generated": 3, "failed": 0}), 0
        )


if __name__ == "__main__":
    unittest.main()

import importlib.util
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py"
SPEC = importlib.util.spec_from_file_location("run_pipeline", MODULE_PATH)
run_pipeline = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = run_pipeline
SPEC.loader.exec_module(run_pipeline)


class PipelineDurationTests(unittest.TestCase):
    def test_formats_elapsed_time_with_unbounded_hours(self):
        self.assertEqual(
            run_pipeline.format_elapsed_time(27 * 3600 + 4 * 60 + 5),
            "27h 04m 05s",
        )

    def test_rounds_and_clamps_elapsed_time(self):
        self.assertEqual(run_pipeline.format_elapsed_time(65.6), "00h 01m 06s")
        self.assertEqual(run_pipeline.format_elapsed_time(-1), "00h 00m 00s")


class StepTimingsTests(unittest.TestCase):
    """A run resumed step by step keeps every invocation's timings.

    run_20260927_175748 ended with step_timings.json holding only `publish`,
    because each invocation rewrote the file with its own steps.
    """

    def test_a_later_invocation_adds_to_the_recorded_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = SimpleNamespace(
                error_solutions_dir=Path(directory) / "error_solutions")
            run_pipeline.record_step_timings(paths, [{"step": "llm"}])
            earlier = run_pipeline.earlier_step_timings(paths)
            run_pipeline.record_step_timings(
                paths, [{"step": "publish"}], earlier)
            recorded = json.loads(
                (Path(directory) / "step_timings.json").read_text())
        self.assertEqual(
            [item["step"] for item in recorded["steps"]], ["llm", "publish"])

    def test_an_unreadable_file_contributes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "step_timings.json").write_text("{truncated")
            paths = SimpleNamespace(
                error_solutions_dir=Path(directory) / "error_solutions")
            self.assertEqual(run_pipeline.earlier_step_timings(paths), [])


if __name__ == "__main__":
    unittest.main()

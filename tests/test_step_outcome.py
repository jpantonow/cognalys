import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.step_outcome import (  # noqa: E402
    PARTIAL_SUCCESS_EXIT_CODE,
    step_exit_code,
)


class StepExitCodeTests(unittest.TestCase):
    """One bad APK in a batch must not end the run for the good ones.

    Every step loops over projects and already survives one failing: the
    clone times out, Gradle cannot resolve an SDK, the documented branch is
    gone. The loop records it and moves on. The exit code then collapsed
    that back to "the step failed", and run_pipeline stops the whole run on
    any non-zero step -- so nineteen healthy repositories were abandoned
    after their work had already been paid for.
    """

    def test_everything_succeeding_is_success(self):
        self.assertEqual(step_exit_code(20, 0), 0)

    def test_everything_failing_is_failure(self):
        self.assertEqual(step_exit_code(0, 20), 1)

    def test_a_mixture_is_partial(self):
        self.assertEqual(step_exit_code(19, 1), PARTIAL_SUCCESS_EXIT_CODE)
        self.assertEqual(step_exit_code(1, 19), PARTIAL_SUCCESS_EXIT_CODE)

    def test_an_empty_batch_is_not_a_failure(self):
        """An empty batch is a fact about the input, not a broken step."""
        self.assertEqual(step_exit_code(0, 0), 0)

    def test_the_partial_code_does_not_collide_with_the_existing_ones(self):
        # 0 success, 1 failure, 2 usage error (argparse, and apk_build's own
        # bad-arguments path). A collision would make a mistyped flag look
        # like a partly successful batch.
        self.assertNotIn(PARTIAL_SUCCESS_EXIT_CODE, (0, 1, 2))


class RepositorySetupExitTests(unittest.TestCase):
    """The step that first exposed this: `return 1 if failed else 0`."""

    def _run(self, repositories):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            projects = root / "projects"
            projects.mkdir()
            for repository, valid in repositories:
                directory = projects / repository
                (directory / ".git").mkdir(parents=True)
                if valid:
                    subprocess.run(["git", "init", "-q", str(directory)],
                                   capture_output=True)
            return subprocess.run(
                [sys.executable,
                 str(ROOT / "src" / "cognalys" / "extraction" / "prepare_repository_branches.py"),
                 "--projects-dir", str(projects),
                 "--report", str(root / "report.json")],
                capture_output=True, text=True,
            ).returncode

    def test_every_repository_failing_still_fails_the_step(self):
        self.assertEqual(self._run([("a.apk", False), ("b.apk", False)]), 1)

    def test_no_repositories_at_all_is_reported_as_a_failure(self):
        # Distinct from an empty batch inside a step: there is nothing to
        # work on, so the later steps have nothing to do either.
        self.assertEqual(self._run([]), 1)


class OrchestratorTests(unittest.TestCase):
    """run_pipeline must carry on past a partial step, and say so."""

    def test_the_partial_code_is_imported_from_one_place(self):
        from cognalys.orchestration import run_pipeline
        self.assertEqual(
            run_pipeline.PARTIAL_SUCCESS_EXIT_CODE, PARTIAL_SUCCESS_EXIT_CODE,
        )

    def test_a_partial_step_does_not_abort_and_does_not_claim_success(self):
        source = (ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py").read_text(
            encoding="utf-8"
        )
        # The branch for the partial code must be tested before the generic
        # non-zero branch, or it would never be reached.
        partial = source.index("if result.returncode == PARTIAL_SUCCESS_EXIT_CODE")
        generic = source.index("elif result.returncode != 0")
        self.assertLess(partial, generic)
        self.assertIn("partial_steps.append(step)", source)
        self.assertIn("Pipeline finished with partial coverage.", source)

    def test_a_run_that_left_projects_behind_does_not_exit_zero(self):
        source = (ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py").read_text(
            encoding="utf-8"
        )
        # An operator scripting a batch has to be able to see it from the
        # exit code, not only from the text on the terminal.
        self.assertIn("finished_exit_code(partial_steps, warning_steps)", source)

    def test_partial_coverage_wins_over_a_context_warning(self):
        # A partial run that also had a spec_context warning exited 0.
        from cognalys.orchestration.run_pipeline import finished_exit_code

        warning = [("spec_context", 1)]
        self.assertEqual(finished_exit_code(["llm"], warning), PARTIAL_SUCCESS_EXIT_CODE)
        self.assertEqual(finished_exit_code(["llm"], []), PARTIAL_SUCCESS_EXIT_CODE)
        self.assertEqual(finished_exit_code([], warning), 0)
        self.assertEqual(finished_exit_code([], []), 0)


if __name__ == "__main__":
    unittest.main()

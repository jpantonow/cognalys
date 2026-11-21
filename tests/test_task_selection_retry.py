import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation import applied_solutions as MODULE  # noqa: E402
from cognalys.validation.applied_solutions import (  # noqa: E402
    run_build_phase_resolving_tasks,
    tasks_after_selection_failure,
)

AMBIGUOUS = (
    "* What went wrong:\n"
    "Cannot locate tasks that match ':app:testDebugUnitTest' as task "
    "'testDebugUnitTest' is ambiguous in project ':app'. Candidates are: "
    "'testGmsDebugUnitTest', 'testFossDebugUnitTest'.\n"
)
MISSING = (
    "* What went wrong:\n"
    "Cannot locate tasks that match ':app:assembleAmazonDebug' as task "
    "'assembleAmazonDebug' not found in project ':app'.\n"
)


class TaskSelectionRetryTests(unittest.TestCase):
    """Gradle refusing a task name the static flavor reading invented.

    BetterUntis declares foss and gms where the build-file reading does not
    look, so :app:testDebugUnitTest was refused as ambiguous; FairEmail's
    :app:assembleAmazonDebug was refused as not found and then recorded as a
    pre-existing failure because the baseline was refused the same way.
    """

    def _log(self, directory: str, text: str) -> Path:
        path = Path(directory) / "build.log"
        path.write_text(text, encoding="utf-8")
        return path

    def test_an_ambiguous_task_takes_the_first_candidate_gradle_names(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, AMBIGUOUS)
            self.assertEqual(
                tasks_after_selection_failure(log, [":app:testDebugUnitTest"]),
                [":app:testFossDebugUnitTest"],
            )

    def test_a_missing_flavored_task_loses_its_flavor(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, MISSING)
            self.assertEqual(
                tasks_after_selection_failure(log, [":app:assembleAmazonDebug"]),
                [":app:assembleDebug"],
            )

    def test_tasks_gradle_did_not_refuse_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, AMBIGUOUS)
            self.assertEqual(
                tasks_after_selection_failure(
                    log, [":core:testDebugUnitTest", ":app:testDebugUnitTest"],
                ),
                [":core:testDebugUnitTest", ":app:testFossDebugUnitTest"],
            )

    def test_a_failure_that_names_no_alternative_gives_none(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, "e: Unresolved reference: foo\n")
            self.assertIsNone(
                tasks_after_selection_failure(log, [":app:assembleDebug"]),
            )
            unflavored = self._log(
                directory,
                "Cannot locate tasks that match ':app:assembleDebug' as task "
                "'assembleDebug' not found in project ':app'.\n",
            )
            self.assertIsNone(
                tasks_after_selection_failure(unflavored, [":app:assembleDebug"]),
            )

    def test_the_build_is_retried_through_both_refusals(self):
        """A flavor that does not exist, then an unqualified name that is
        ambiguous: two retries, and the caller learns which tasks ran."""
        with tempfile.TemporaryDirectory() as directory:
            missing = self._log(directory, MISSING)
            ambiguous = Path(directory) / "second.log"
            ambiguous.write_text(
                "Cannot locate tasks that match ':app:assembleDebug' as task "
                "'assembleDebug' is ambiguous in project ':app'. Candidates "
                "are: 'assembleFossDebug', 'assembleGmsDebug'.\n",
                encoding="utf-8",
            )
            results = iter([
                {"status": "failed", "log_file": str(missing)},
                {"status": "failed", "log_file": str(ambiguous)},
                {"status": "success", "log_file": ""},
            ])
            calls = []

            def fake_build(args, project, output_dir, tasks=None, **options):
                calls.append((tasks, options.get("clean_first")))
                return dict(next(results))

            with patch.object(MODULE, "run_build_phase", fake_build):
                result, ran = run_build_phase_resolving_tasks(
                    argparse.Namespace(), Path(directory), Path(directory),
                    [":app:assembleAmazonDebug"], clean_first=True,
                )

            self.assertEqual(result["status"], "success")
            self.assertEqual(ran, [":app:assembleFossDebug"])
            self.assertEqual(result["task_selection_retry"], {
                "refused": [":app:assembleDebug"],
                "ran": [":app:assembleFossDebug"],
            })
            # Only the first build cleans; the retries reuse its work.
            self.assertEqual([clean for _, clean in calls], [True, False, False])

    def test_a_failure_in_the_patch_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(
                directory,
                "> Task :app:compileDebugKotlin FAILED\n"
                "Execution failed for task ':app:compileDebugKotlin'.\n",
            )
            calls = []

            def fake_build(args, project, output_dir, tasks=None, **options):
                calls.append(tasks)
                return {"status": "failed", "log_file": str(log)}

            with patch.object(MODULE, "run_build_phase", fake_build):
                result, ran = run_build_phase_resolving_tasks(
                    argparse.Namespace(), Path(directory), Path(directory),
                    [":app:assembleDebug"],
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(ran, [":app:assembleDebug"])
            self.assertNotIn("task_selection_retry", result)


MISSING_PROJECT = (
    "* What went wrong:\n"
    "Cannot locate tasks that match ':comencryptbwt:app:assembleDebugAndroidTest' "
    "as project 'comencryptbwt' not found in root project 'com.encrypt.bwt'.\n"
)


class MissingProjectRetryTests(unittest.TestCase):
    """A task named from the repository when Gradle runs one level down.

    BWT's settings file sits in comencryptbwt/, and Gradle refused
    ':comencryptbwt:app:assembleDebugAndroidTest' (rvsec_bwt_20261024). The
    leading segment is dropped only while what remains is a directory under
    the root Gradle runs from.
    """

    def _repository(self, directory: str) -> Path:
        worktree = Path(directory) / "worktree"
        root = worktree / "comencryptbwt"
        (root / "app").mkdir(parents=True)
        (root / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
        return worktree

    def test_the_task_is_rebased_on_the_gradle_root(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._repository(directory)
            log = Path(directory) / "build.log"
            log.write_text(MISSING_PROJECT, encoding="utf-8")
            self.assertEqual(
                tasks_after_selection_failure(
                    log, [":comencryptbwt:app:assembleDebugAndroidTest"],
                    worktree / "comencryptbwt",
                ),
                [":app:assembleDebugAndroidTest"],
            )

    def test_without_a_matching_directory_nothing_is_rebased(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._repository(directory)
            log = Path(directory) / "build.log"
            log.write_text(MISSING_PROJECT.replace(":app:", ":ap:"), encoding="utf-8")
            self.assertIsNone(
                tasks_after_selection_failure(
                    log, [":comencryptbwt:ap:assembleDebugAndroidTest"],
                    worktree / "comencryptbwt",
                ),
            )
            # Nor without knowing the root.
            log.write_text(MISSING_PROJECT, encoding="utf-8")
            self.assertIsNone(
                tasks_after_selection_failure(
                    log, [":comencryptbwt:app:assembleDebugAndroidTest"],
                ),
            )

    def test_the_build_retries_against_the_root_it_runs_from(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._repository(directory)
            log = Path(directory) / "build.log"
            log.write_text(MISSING_PROJECT, encoding="utf-8")
            results = iter([
                {"status": "failed", "log_file": str(log)},
                {"status": "success", "log_file": ""},
            ])

            def fake_build(args, project, output_dir, tasks=None, **options):
                return dict(next(results))

            with patch.object(MODULE, "run_build_phase", fake_build):
                result, ran = run_build_phase_resolving_tasks(
                    argparse.Namespace(), worktree, Path(directory),
                    [":comencryptbwt:app:assembleDebugAndroidTest"],
                )
            self.assertEqual(result["status"], "success")
            self.assertEqual(ran, [":app:assembleDebugAndroidTest"])


if __name__ == "__main__":
    unittest.main()

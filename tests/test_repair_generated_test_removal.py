"""The one repair the validation stage may make without the model.

When every compiler diagnostic is in a test file the patch itself created,
those files can be removed: nothing that existed before the patch is
touched, and the production fix -- which compiles -- is not lost with them.
einkbro's restoreLegacyBackupData patch (run_20260917_230558) was exactly
this shape and the whole finding was discarded instead.

The conditions are conjunctive on purpose, and most of these tests pin the
cases where the removal must NOT happen.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation.repair import (  # noqa: E402
    record_removed_tests,
    remove_patch_created_tests,
)


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(repo), *arguments],
                   check=True, capture_output=True, text=True)


class RemovePatchCreatedTestsTests(unittest.TestCase):

    TEST_PATH = "app/src/test/java/app/GeneratedTest.kt"
    PRODUCTION_PATH = "app/src/main/java/app/Backup.kt"

    def _repository(self, directory: str) -> tuple:
        """A base repo at a commit, plus a worktree with the patch applied."""
        root = Path(directory)
        base = root / "base"
        base.mkdir()
        _git(base, "init", "-q")
        _git(base, "config", "user.email", "t@example.com")
        _git(base, "config", "user.name", "Test")
        production = base / self.PRODUCTION_PATH
        production.parent.mkdir(parents=True)
        production.write_text("class Backup {}", encoding="utf-8")
        _git(base, "add", "-A")
        _git(base, "commit", "-q", "-m", "base")
        commit = subprocess.run(
            ["git", "-C", str(base), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

        worktree = root / "worktree"
        worktree.mkdir()
        (worktree / self.PRODUCTION_PATH).parent.mkdir(parents=True)
        (worktree / self.PRODUCTION_PATH).write_text(
            "class Backup { fun safe() {} }", encoding="utf-8"
        )
        created = worktree / self.TEST_PATH
        created.parent.mkdir(parents=True)
        created.write_text(
            "import org.robolectric.RobolectricTestRunner\n", encoding="utf-8"
        )
        return worktree, base, commit

    def test_a_test_the_patch_created_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, commit = self._repository(directory)
            removed = remove_patch_created_tests(
                worktree, base, commit, [self.TEST_PATH], dry_run=False,
            )
            self.assertEqual(removed, [self.TEST_PATH])
            self.assertFalse((worktree / self.TEST_PATH).exists())
            # The fix itself is untouched.
            self.assertTrue((worktree / self.PRODUCTION_PATH).is_file())

    def test_a_dry_run_reports_without_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, commit = self._repository(directory)
            removed = remove_patch_created_tests(
                worktree, base, commit, [self.TEST_PATH], dry_run=True,
            )
            self.assertEqual(removed, [self.TEST_PATH])
            self.assertTrue((worktree / self.TEST_PATH).is_file())

    def test_a_production_diagnostic_stops_the_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, commit = self._repository(directory)
            removed = remove_patch_created_tests(
                worktree, base, commit,
                [self.TEST_PATH, self.PRODUCTION_PATH], dry_run=False,
            )
            self.assertEqual(removed, [])
            self.assertTrue((worktree / self.TEST_PATH).is_file())

    def test_a_test_that_predates_the_patch_is_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, commit = self._repository(directory)
            # The same test path also exists at the base commit: the patch
            # edited it, it did not create it.
            preexisting = base / self.TEST_PATH
            preexisting.parent.mkdir(parents=True)
            preexisting.write_text("class GeneratedTest", encoding="utf-8")
            _git(base, "add", "-A")
            _git(base, "commit", "-q", "-m", "add test")
            later = subprocess.run(
                ["git", "-C", str(base), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            removed = remove_patch_created_tests(
                worktree, base, later, [self.TEST_PATH], dry_run=False,
            )
            self.assertEqual(removed, [])
            self.assertTrue((worktree / self.TEST_PATH).is_file())

    def test_without_a_base_commit_nothing_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, _commit = self._repository(directory)
            self.assertEqual(
                remove_patch_created_tests(
                    worktree, base, "", [self.TEST_PATH], dry_run=False,
                ),
                [],
            )
            self.assertTrue((worktree / self.TEST_PATH).is_file())

    def test_the_solution_stops_naming_a_removed_test(self):
        # The removal entry appended to coordinated_edits kept the test's
        # path there: the PR text still said a test was added, and the
        # revalidation rebuilt that module's test task.
        solution = {
            "coordinated_edits": [
                {"source_file": self.PRODUCTION_PATH, "edit_kind": "method"},
                {"source_file_path": self.TEST_PATH, "edit_kind": "test"},
            ],
            "changed_files": [self.PRODUCTION_PATH, self.TEST_PATH],
            "required_tests": ["restore rejects an entry outside the target"],
        }
        record_removed_tests(solution, [self.TEST_PATH], "The test was removed.")
        self.assertEqual(
            solution["coordinated_edits"],
            [{"source_file": self.PRODUCTION_PATH, "edit_kind": "method"}],
        )
        self.assertEqual(solution["changed_files"], [self.PRODUCTION_PATH])
        self.assertEqual(solution["removed_generated_tests"], [self.TEST_PATH])
        self.assertEqual(solution["required_tests"], [])
        self.assertEqual(
            solution["review_assumptions"],
            ["The test was removed. Check by hand: "
             "restore rejects an entry outside the target"],
        )
        self.assertTrue(solution["manual_review_required"])
        # The summary still announces the test: the PR step rewrites it.
        self.assertIs(solution["summary_stale"], True)

    def test_a_removed_path_the_edits_never_named_leaves_the_summary(self):
        # Only a dropped edit makes the summary describe a change the diff
        # no longer has.
        solution = {
            "coordinated_edits": [
                {"source_file": self.PRODUCTION_PATH, "edit_kind": "method"},
            ],
            "changed_files": [self.PRODUCTION_PATH],
        }
        record_removed_tests(solution, [self.TEST_PATH], "The test was removed.")
        self.assertNotIn("summary_stale", solution)
        self.assertEqual(solution["removed_generated_tests"], [self.TEST_PATH])

    def test_no_diagnostics_removes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, base, commit = self._repository(directory)
            self.assertEqual(
                remove_patch_created_tests(
                    worktree, base, commit, [], dry_run=False,
                ),
                [],
            )


if __name__ == "__main__":
    unittest.main()

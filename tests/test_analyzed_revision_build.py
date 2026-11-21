"""A patch whose base branch cannot build is compiled on the analysed revision."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation import applied_solutions  # noqa: E402
from cognalys.utils.disposition import BUILD_VALIDATION_PASSING_STATUSES  # noqa: E402


def git(repo, *arguments):
    return subprocess.run(["git", "-C", str(repo), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


class AnalyzedRevisionBuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.clone = root / "clone"
        self.clone.mkdir()
        git(self.clone, "init", "-q")
        git(self.clone, "config", "user.email", "t@t")
        git(self.clone, "config", "user.name", "t")
        (self.clone / "Main.kt").write_text('val random = SecureRandom("seed".toByteArray())\n')
        (self.clone / "build.gradle").write_text('hilt = "2.57.1"\n')
        git(self.clone, "add", "-A")
        git(self.clone, "commit", "-qm", "analysed")
        self.analyzed = git(self.clone, "rev-parse", "HEAD")
        (self.clone / "build.gradle").write_text('hilt = "2.58"\n')
        git(self.clone, "commit", "-qam", "upstream breaks its build")
        self.base = git(self.clone, "rev-parse", "HEAD")
        self.patched = root / "patched"
        git(self.clone, "worktree", "add", "-q", "--detach", str(self.patched), self.base)
        git(self.clone, "checkout", "-q", "--detach", self.analyzed)
        (self.patched / "Main.kt").write_text("val random = SecureRandom()\n")
        self.output = root / "out"

    def tearDown(self):
        self.directory.cleanup()

    def build(self, status="success"):
        seen = {}

        def fake_build(args, worktree, output, tasks=None, clean_first=False):
            seen["main"] = (Path(worktree) / "Main.kt").read_text()
            seen["gradle"] = (Path(worktree) / "build.gradle").read_text()
            return {"status": status}

        with patch.object(applied_solutions, "run_build_phase", fake_build):
            result = applied_solutions.run_analyzed_revision_build(
                SimpleNamespace(), self.clone, self.base, self.patched,
                ["assembleDebug"], self.output)
        return result, seen

    def test_the_patch_is_built_on_the_analysed_revision(self):
        result, seen = self.build()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["commit"], self.analyzed)
        self.assertEqual(seen["main"], "val random = SecureRandom()\n")
        self.assertEqual(seen["gradle"], 'hilt = "2.57.1"\n')

    def test_no_distinct_analysed_revision_is_no_claim(self):
        git(self.clone, "checkout", "-q", "--detach", self.base)
        result, _ = self.build()
        self.assertIsNone(result)

    def test_a_patch_that_does_not_apply_is_no_claim(self):
        git(self.clone, "checkout", "-q", "--detach", self.analyzed)
        (self.patched / "build.gradle").write_text('hilt = "2.59"\n')
        (self.clone / "build.gradle").write_text('hilt = "something else"\n')
        git(self.clone, "commit", "-qam", "diverge")
        result, _ = self.build()
        self.assertEqual(result["status"], "not_applicable")

    def test_the_status_counts_as_a_pass_everywhere(self):
        self.assertIn(applied_solutions.ANALYZED_REVISION_PASS, BUILD_VALIDATION_PASSING_STATUSES)
        self.assertEqual(set(applied_solutions.PASSING_STATUSES), set(BUILD_VALIDATION_PASSING_STATUSES))


if __name__ == "__main__":
    unittest.main()

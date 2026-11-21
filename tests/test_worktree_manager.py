import logging
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.solutions.worktree_manager import WorktreeManager  # noqa: E402


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


class WorktreeManagerTests(unittest.TestCase):
    @staticmethod
    def _solution():
        return {
            "apk_name": "app.apk",
            "method_name": "calculateChildType",
            "spec": "Spec",
            "unique_error_id": "finding-one",
            "coordinated_edits": [{
                "source_file_path": "Source.java",
                "edit_kind": "method",
                "original_code": "class Source {}",
                "corrected_code": "class Source { int fixed; }",
            }],
        }

    @staticmethod
    def _repository(root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Test")
        git(repo, "config", "user.email", "test@example.com")
        (repo / "Source.java").write_text("class Source {}", encoding="utf-8")
        git(repo, "add", "Source.java")
        git(repo, "commit", "-m", "initial")
        return repo

    def test_creates_independent_worktree_for_each_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.com")
            (repo / "Source.java").write_text("class Source {}", encoding="utf-8")
            git(repo, "add", "Source.java")
            git(repo, "commit", "-m", "initial")

            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))
            first = manager.prepare(repo, {
                "apk_name": "app.apk", "method_name": "first",
                "spec": "Spec", "unique_error_id": "finding-one",
            })
            second = manager.prepare(repo, {
                "apk_name": "app.apk", "method_name": "second",
                "spec": "Spec", "unique_error_id": "finding-two",
            })

            self.assertNotEqual(first["worktree_path"], second["worktree_path"])
            self.assertNotEqual(first["branch"], second["branch"])
            self.assertTrue((Path(first["worktree_path"]) / "Source.java").is_file())
            self.assertTrue((Path(second["worktree_path"]) / "Source.java").is_file())
            self.assertEqual(git(repo, "status", "--porcelain"), "")

    def test_prepare_normalizes_pure_line_ending_noise_before_creating_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            # Simulate a clone made before core.autocrlf=false was pinned on
            # clone: every tracked file appears modified, but only its line
            # endings flipped from LF to CRLF -- no real content changed.
            (repo / "Source.java").write_bytes(b"class Source {}\r\n")
            self.assertNotEqual(git(repo, "status", "--porcelain"), "")

            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))
            result = manager.prepare(repo, self._solution())

            self.assertTrue(
                (Path(result["worktree_path"]) / "Source.java").is_file()
            )
            self.assertEqual(git(repo, "status", "--porcelain"), "")

    def test_prepare_falls_back_to_clear_error_when_normalize_checkout_fails(self):
        # A repo whose diff cache disagrees with its own working tree (seen
        # in practice: content removed outside git, leaving the index
        # believing nothing changed) can pass the line-ending-only check yet
        # still have `git checkout -- .` itself reject the pathspec. That
        # must surface the standard diagnostic, not a raw git plumbing error.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            (repo / "Source.java").write_bytes(b"class Source {}\r\n")
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            real_git = WorktreeManager._git

            def fake_git(repo_arg, *args, **kwargs):
                if "checkout" in args:
                    raise RuntimeError(
                        "git checkout failed: pathspec '.' did not match "
                        "any file(s) known to git"
                    )
                return real_git(repo_arg, *args, **kwargs)

            with patch.object(WorktreeManager, "_git", staticmethod(fake_git)):
                with self.assertRaisesRegex(RuntimeError, "uncommitted changes"):
                    manager.prepare(repo, self._solution())

    def test_prepare_still_rejects_a_genuinely_dirty_base_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            (repo / "Source.java").write_text(
                "class Source { /* real edit */ }", encoding="utf-8"
            )
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            with self.assertRaisesRegex(RuntimeError, "uncommitted changes"):
                manager.prepare(repo, self._solution())

    def test_prepare_still_rejects_an_untracked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            (repo / "new_file.txt").write_text("new", encoding="utf-8")
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            with self.assertRaisesRegex(RuntimeError, "uncommitted changes"):
                manager.prepare(repo, self._solution())

    def test_reuses_only_pristine_worktree_for_same_solution_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            first = manager.prepare(repo, self._solution())
            reused = manager.prepare(repo, self._solution())

            self.assertEqual(first["worktree_path"], reused["worktree_path"])
            self.assertEqual(reused["worktree_attempt"], 1)

    def test_allocates_fresh_attempt_when_previous_worktree_was_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            first = manager.prepare(repo, self._solution())
            first_source = Path(first["worktree_path"]) / "Source.java"
            first_source.write_text("class Source { int fixed; }", encoding="utf-8")

            second = manager.prepare(repo, self._solution())

            self.assertNotEqual(first["worktree_path"], second["worktree_path"])
            self.assertEqual(second["worktree_attempt"], 2)
            self.assertEqual(
                (Path(second["worktree_path"]) / "Source.java").read_text(
                    encoding="utf-8"
                ),
                "class Source {}",
            )
            self.assertEqual(first_source.read_text(encoding="utf-8"),
                             "class Source { int fixed; }")

    def test_skips_and_preserves_unregistered_attempt_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repository(root)
            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))

            first = manager.prepare(repo, self._solution())
            first_source = Path(first["worktree_path"]) / "Source.java"
            first_source.write_text("class Source { int fixed; }", encoding="utf-8")

            second_path = Path(first["worktree_path"] + "-2")
            second_path.mkdir(parents=True)
            marker = second_path / "interrupted-run.txt"
            marker.write_text("preserve me", encoding="utf-8")

            result = manager.prepare(repo, self._solution())

            self.assertEqual(result["worktree_attempt"], 3)
            self.assertEqual(
                result["orphaned_worktree_paths"], [str(second_path.resolve())]
            )
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve me")
            self.assertEqual(
                (Path(result["worktree_path"]) / "Source.java").read_text(
                    encoding="utf-8"
                ),
                "class Source {}",
            )

    def test_a_tag_sharing_the_base_branchs_name_does_not_abort_worktree_creation(self):
        """run_20260927_175748's TagMo finding, reproduced end to end.

        TagMo's base branch and a tag share the short name "master". Building
        the worktree used to pass that bare name straight to
        `git worktree add`, which refused with "fatal: ambiguous object name:
        'master'" and took the whole remaining run down with it -- eight other
        findings never reached validation because one repository's ref
        happened to collide with a tag.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            git(repo, "init", "-q", "-b", "master")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.com")
            (repo / "Source.java").write_text("class Source {}", encoding="utf-8")
            git(repo, "add", "Source.java")
            git(repo, "commit", "-qm", "initial")
            # The collision: an annotated tag with the same short name as the
            # branch this worktree is about to be built from.
            git(repo, "tag", "-a", "master", "-m", "release tag named like the branch")

            manager = WorktreeManager(root / "worktrees", logging.getLogger(__name__))
            result = manager.prepare(repo, self._solution())

            self.assertEqual(result["base_branch"], "master")
            self.assertTrue(Path(result["worktree_path"]).is_dir())
            self.assertTrue(
                (Path(result["worktree_path"]) / "Source.java").is_file()
            )
            # The worktree was built from the branch tip, not the colliding
            # tag object.
            self.assertEqual(
                result["base_commit"], git(repo, "rev-parse", "refs/heads/master"),
            )


if __name__ == "__main__":
    unittest.main()

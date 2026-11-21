import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "extraction" / "prepare_repository_branches.py"
SPEC = importlib.util.spec_from_file_location("prepare_repository_branches", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _repository(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.com")
    (repo / "Source.java").write_bytes(b"class Source {\n    int x;\n}\n")
    git(repo, "add", "Source.java")
    git(repo, "commit", "-m", "initial")
    git(repo, "branch", "develop")
    # prepare() always resolves the documented base branch through a remote
    # fetch, even when a local branch of that name already exists -- point
    # a self-referential "origin" at this same repo so that fetch succeeds
    # without needing a real second remote.
    git(repo, "remote", "add", "origin", str(repo))
    return repo


class ProjectSelectionTests(unittest.TestCase):
    """Only the named clones are prepared, and --project can be repeated."""

    def _clone(self, projects: Path, name: str) -> None:
        repo = projects / name
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Test")
        git(repo, "config", "user.email", "test@example.com")
        (repo / "README").write_text("x\n", encoding="utf-8")
        git(repo, "add", "README")
        git(repo, "commit", "-m", "initial")

    def _prepared(self, *projects: str) -> list:
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clones = root / "clones"
            clones.mkdir()
            for name in ("a.one_1.apk", "b.two_2.apk", "c.old_3.apk"):
                self._clone(clones, name)
            report = root / "report.json"
            argv = ["prepare", "--projects-dir", str(clones), "--report", str(report)]
            for name in projects:
                argv += ["--project", name]
            with patch.object(sys, "argv", argv):
                MODULE.main()
            return [item["repository"] for item in
                    json.loads(report.read_text(encoding="utf-8"))["repositories"]]

    def test_repeated_projects_select_exactly_those_clones(self):
        self.assertEqual(
            self._prepared("a.one_1.apk", "b.two_2.apk"), ["a.one_1.apk", "b.two_2.apk"],
        )

    def test_a_single_project_still_works(self):
        self.assertEqual(self._prepared("c.old_3.apk"), ["c.old_3.apk"])

    def test_no_project_prepares_every_clone(self):
        self.assertEqual(
            self._prepared(), ["a.one_1.apk", "b.two_2.apk", "c.old_3.apk"],
        )


class HasOnlyLineEndingChangesTests(unittest.TestCase):
    def test_true_for_a_pure_crlf_flip(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            (repo / "Source.java").write_bytes(b"class Source {\r\n    int x;\r\n}\r\n")
            self.assertTrue(MODULE.has_only_line_ending_changes(repo))

    def test_false_for_a_real_content_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            (repo / "Source.java").write_text(
                "class Source { /* real edit */ }", encoding="utf-8"
            )
            self.assertFalse(MODULE.has_only_line_ending_changes(repo))

    def test_false_for_an_untracked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            (repo / "new_file.txt").write_text("new", encoding="utf-8")
            self.assertFalse(MODULE.has_only_line_ending_changes(repo))


class PrepareUncommittedChangesTests(unittest.TestCase):
    def _prepare_with_forced_base(self, repo: Path) -> dict:
        with patch.object(MODULE, "discover_repository_guidance", return_value=[]), \
             patch.object(
                 MODULE, "infer_branch_policy",
                 return_value={"recommended_base_branch": "develop"},
             ):
            return MODULE.prepare(repo)

    def test_normalizes_pure_line_ending_noise_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            (repo / "Source.java").write_bytes(b"class Source {\r\n    int x;\r\n}\r\n")

            result = self._prepare_with_forced_base(repo)

            self.assertEqual(result["repository"], repo.name)
            self.assertEqual(git(repo, "status", "--porcelain"), "")

    def test_still_raises_for_a_genuinely_dirty_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            (repo / "Source.java").write_text(
                "class Source { /* real edit */ }", encoding="utf-8"
            )

            with self.assertRaisesRegex(RuntimeError, "uncommitted changes"):
                self._prepare_with_forced_base(repo)

    # aShell (2026-11-02): the guidance named a branch the remote does not
    # have; the step failed three times and four app findings were lost.
    def test_a_missing_documented_branch_keeps_the_clone_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(Path(directory))
            before = git(repo, "rev-parse", "--abbrev-ref", "HEAD")

            with patch.object(MODULE, "discover_repository_guidance", return_value=[]), \
                 patch.object(
                     MODULE, "infer_branch_policy",
                     return_value={"recommended_base_branch": "no-such-branch"},
                 ):
                result = MODULE.prepare(repo)

            self.assertEqual(result["status"], "documented_branch_missing")
            self.assertEqual(result["documented_branch"], "no-such-branch")
            self.assertEqual(result["selected_branch"], before)
            self.assertEqual(git(repo, "rev-parse", "--abbrev-ref", "HEAD"), before)


if __name__ == "__main__":
    unittest.main()

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.pr_generator import PrGenerator  # noqa: E402


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


class RerunIdempotencyTests(unittest.TestCase):
    """A rerun over a branch an earlier run committed must not fail.

    Re-entering the PR step for a finding whose branch already carries its
    commit leaves a clean worktree. That used to be indistinguishable from
    "the patch was never applied", so the step reported a failed PR and
    aborted every later step of the run.
    """

    def make_repo(self, directory: str) -> Path:
        repo = Path(directory) / "repo"
        (repo / "src").mkdir(parents=True)
        git(repo.parent, "init", "--quiet", "-b", "master", str(repo))
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "Test")
        source = repo / "src" / "Strconv.java"
        source.write_text("class Strconv { void a() {} }\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "--quiet", "-m", "base")
        return repo

    def make_generator(self, directory: str) -> PrGenerator:
        report = Path(directory) / "execution.json"
        report.write_text("{}", encoding="utf-8")
        return PrGenerator(str(report), str(Path(directory) / "prs"))

    def commit_fix(self, repo: Path) -> str:
        git(repo, "checkout", "--quiet", "-b", "fix/branch")
        source = repo / "src" / "Strconv.java"
        source.write_text("class Strconv { void b() {} }\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "--quiet", "-m", "Fix a")
        return git(repo, "rev-parse", "HEAD")

    def test_already_committed_patch_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            base = git(repo, "rev-parse", "HEAD")
            head = self.commit_fix(repo)
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.commit_changes(repo, "Fix a"), "",
                "a clean worktree must still produce no new commit",
            )
            self.assertEqual(
                generator.find_existing_fix_commit(
                    repo,
                    {"base_commit": base, "base_branch": "master"},
                    ["src/Strconv.java"],
                ),
                head,
            )

    def test_untracked_build_output_does_not_force_an_empty_commit(self):
        """rssreader: the branch carried the fix and the validation build left
        app/build/ untracked; committing nothing raised an empty error."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            self.commit_fix(repo)
            (repo / "build").mkdir()
            (repo / "build" / "out.class").write_bytes(b"\0")
            generator = self.make_generator(directory)
            self.assertEqual(
                generator.commit_changes(repo, "Fix a", changed_files=["src/Strconv.java"]), "")

    def test_base_branch_alone_anchors_the_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            head = self.commit_fix(repo)
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.find_existing_fix_commit(
                    repo, {"base_branch": "master"}, ["src/Strconv.java"]
                ),
                head,
            )

    def test_unapplied_patch_is_not_mistaken_for_a_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            base = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "--quiet", "-b", "fix/branch")
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.find_existing_fix_commit(
                    repo,
                    {"base_commit": base, "base_branch": "master"},
                    ["src/Strconv.java"],
                ),
                "",
            )

    def test_unrelated_commit_on_the_branch_is_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            base = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "--quiet", "-b", "fix/branch")
            (repo / "README.md").write_text("docs\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "--quiet", "-m", "Unrelated")
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.find_existing_fix_commit(
                    repo,
                    {"base_commit": base, "base_branch": "master"},
                    ["src/Strconv.java"],
                ),
                "",
            )

    def test_missing_base_metadata_keeps_the_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            self.commit_fix(repo)
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.find_existing_fix_commit(repo, {}, []), ""
            )

    def test_diff_spans_every_commit_on_the_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            base = git(repo, "rev-parse", "HEAD")
            self.commit_fix(repo)
            source = repo / "src" / "Strconv.java"
            source.write_text("class Strconv { void c() {} }\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "--quiet", "-m", "Repair")
            generator = self.make_generator(directory)
            solution = {"base_commit": base, "base_branch": "master"}

            diff = generator.get_diff(
                repo, generator.diff_base_ref(repo, solution)
            )
            self.assertIn("void a", diff)
            self.assertIn("void c", diff)
            # HEAD~1 would only describe the repair commit.
            self.assertNotIn("void b", diff)

    def test_a_diff_ending_on_a_blank_context_line_still_applies(self):
        """rssreader: the hunk's last context line was a blank source line,
        whose diff line is a single space; stripping the output dropped it
        and git apply rejected the stored diff as corrupt."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            source = repo / "src" / "Strconv.java"
            source.write_text("class Strconv {\n    void a() {}\n\n}\n", encoding="utf-8")
            git(repo, "commit", "--quiet", "-am", "blank line")
            base = git(repo, "rev-parse", "HEAD")
            source.write_text("class Strconv {\n    void b() {}\n\n}\n", encoding="utf-8")
            git(repo, "commit", "--quiet", "-am", "fix")
            diff = self.make_generator(directory).get_diff(repo, base)
            git(repo, "checkout", "--quiet", base)
            patch = Path(directory) / "fix.diff"
            patch.write_text(diff, encoding="utf-8")
            git(repo, "apply", "--check", str(patch))

    def test_diff_base_is_ignored_when_it_is_not_an_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            self.commit_fix(repo)
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.diff_base_ref(
                    repo, {"base_commit": "0" * 40, "base_branch": "missing"}
                ),
                "",
            )


class CommittedDiffTests(unittest.TestCase):
    """Clash Fest (2026-10-28): the Go build left the clash submodule dirty,
    and "Subproject commit ...-dirty" reached the preview and the upstream
    check although the pushed commit touched only two Kotlin files."""

    make_repo = RerunIdempotencyTests.make_repo
    make_generator = RerunIdempotencyTests.make_generator
    commit_fix = RerunIdempotencyTests.commit_fix

    def add_dirty_submodule(self, directory: str, repo: Path) -> None:
        library = Path(directory) / "library"
        git(Path(directory), "init", "--quiet", "-b", "master", str(library))
        git(library, "config", "user.email", "test@example.com")
        git(library, "config", "user.name", "Test")
        (library / "go.mod").write_text("module clash\n", encoding="utf-8")
        git(library, "add", ".")
        git(library, "commit", "--quiet", "-m", "library")
        git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "--quiet",
            str(library), "core/clash")
        git(repo, "commit", "--quiet", "-m", "add submodule")

    def test_the_diff_is_the_commit_without_a_dirty_submodule(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            self.add_dirty_submodule(directory, repo)
            base = git(repo, "rev-parse", "HEAD")
            self.commit_fix(repo)
            (repo / "core" / "clash" / "go.mod").write_text("module built\n", encoding="utf-8")
            (repo / "src" / "Other.java").write_text("class Other {}\n", encoding="utf-8")
            generator = self.make_generator(directory)

            diff = generator.get_diff(repo, generator.diff_base_ref(
                repo, {"base_commit": base, "base_branch": "master"}))

            self.assertIn("void b", diff)
            self.assertNotIn("Subproject commit", diff)
            self.assertNotIn("core/clash", diff)

    def test_a_built_edit_the_commit_lacks_is_still_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.make_repo(directory)
            self.add_dirty_submodule(directory, repo)
            self.commit_fix(repo)
            source = repo / "src" / "Strconv.java"
            source.write_text("class Strconv { void c() {} }\n", encoding="utf-8")
            (repo / "core" / "clash" / "go.mod").write_text("module built\n", encoding="utf-8")
            generator = self.make_generator(directory)

            self.assertEqual(
                generator.uncommitted_patch_files(repo, ["src/Strconv.java", "core/clash"]),
                ["src/Strconv.java"],
            )
            self.assertEqual(generator.uncommitted_patch_files(repo, []), [])


if __name__ == "__main__":
    unittest.main()

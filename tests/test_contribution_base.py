import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.contribution_base import (  # noqa: E402
    base_branch_name,
    code_exists_at,
    code_gone_from_base,
    contribution_base_status,
    path_exists_at,
    resolve_base_ref,
)


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repo, capture_output=True, text=True,
        check=True,
    ).stdout.strip()


class ContributionBaseTests(unittest.TestCase):
    """A finding analysed at one revision and contributed at another.

    run_20260909_125353 analysed mifos at tag v1.0.0, where the reported
    SelfServiceOkHttpClient.java exists, and the applicator built its worktree
    from origin/dev, a Kotlin Multiplatform rewrite that contains neither the
    file nor its package. 1h50m of model time produced a 90%-confidence fix
    with nowhere to land, and the run was reported as FAILED.
    """

    def _clone(self, directory: str) -> tuple[Path, str]:
        """A clone detached at a revision its default branch has moved past."""
        upstream = Path(directory) / "upstream"
        upstream.mkdir()
        _git(upstream, "init", "-q", "-b", "dev")
        _git(upstream, "config", "user.email", "t@example.invalid")
        _git(upstream, "config", "user.name", "Test")
        (upstream / "kept.java").write_text("class Kept {}", encoding="utf-8")
        (upstream / "removed.java").write_text(
            "class Removed {}", encoding="utf-8",
        )
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "historical revision")
        historical = _git(upstream, "rev-parse", "HEAD")
        (upstream / "removed.java").unlink()
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "upstream rewrite removes the file")

        repo = Path(directory) / "repo"
        subprocess.run(
            ["git", "clone", "-q", str(upstream), str(repo)],
            capture_output=True, text=True, check=True,
        )
        _git(repo, "checkout", "-q", "--detach", historical)
        return repo, historical

    def test_a_file_removed_upstream_is_reported_absent_from_the_base(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)

            status = contribution_base_status(repo, "removed.java")

            self.assertEqual(status["base_branch"], "dev")
            self.assertFalse(status["target_present"])
            # Present at the revision the finding was analysed at, which is
            # exactly why nothing noticed before the worktree was built.
            self.assertTrue(path_exists_at(repo, "HEAD", "removed.java"))

    def test_a_body_the_base_has_since_changed_is_reported_absent(self):
        """The file being there is not enough. Element Android's
        MainActivity.kt is on develop, so target_present was true and the run
        proceeded -- but develop has carried the fix for CVE-2024-26131 since
        1.6.12 and the reviewed v1.6.10 body is gone. 34 minutes of analysis
        and an 18-minute worktree later, the applicator said so."""
        with tempfile.TemporaryDirectory() as directory:
            repo, historical = self._clone(directory)
            body = "fun vulnerable() { start(next) }"
            _git(repo, "checkout", "-q", "dev")
            (repo / "kept.java").write_text(
                "class Kept { fun fixed() { start(check(next)) } }",
                encoding="utf-8",
            )
            _git(repo, "config", "user.email", "t@example.invalid")
            _git(repo, "config", "user.name", "Test")
            _git(repo, "commit", "-qam", "upstream ships the fix")
            _git(repo, "checkout", "-q", "--detach", historical)

            status = contribution_base_status(repo, "kept.java", method_body=body)

            self.assertTrue(status["target_present"])
            self.assertFalse(status["analyzed_code_present"])

    def _base_edits(self, directory: str, base_text: str, added: dict | None = None) -> Path:
        """kept.java at the analysed revision holds a hash method; dev rewrites
        it (and adds the files in ``added``)."""
        repo, _ = self._clone(directory)
        _git(repo, "config", "user.email", "t@example.invalid")
        _git(repo, "config", "user.name", "Test")
        _git(repo, "checkout", "-q", "dev")
        (repo / "kept.java").write_text(
            'class Kept {\n  String hash(String s) {\n    log("hashing");\n'
            '    byte[] d = MessageDigest.getInstance("MD5").digest(s.getBytes());\n'
            "    return hex(d);\n  }\n}\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "analysed revision")
        analysed = _git(repo, "rev-parse", "HEAD")
        (repo / "kept.java").write_text(base_text, encoding="utf-8")
        for name, text in (added or {}).items():
            (repo / name).write_text(text, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "upstream edit")
        _git(repo, "checkout", "-q", "--detach", analysed)
        return repo

    BODY = ('String hash(String s) {\n    log("hashing");\n'
            '    byte[] d = MessageDigest.getInstance("MD5").digest(s.getBytes());\n'
            "    return hex(d);\n  }")
    STATEMENT = '    byte[] d = MessageDigest.getInstance("MD5").digest(s.getBytes());'

    def test_an_unrelated_edit_in_the_method_leaves_the_reported_statement_present(self):
        """analyzed_code_present is False for any change to the body; the
        violation is still there and still worth an issue."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self._base_edits(directory, (
                'class Kept {\n  String hash(String s) {\n    log("hashing " + s.length());\n'
                '    byte[] d = MessageDigest.getInstance("MD5").digest(s.getBytes());\n'
                "    return hex(d);\n  }\n}\n"))
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement=self.STATEMENT)
            self.assertFalse(status["analyzed_code_present"])
            self.assertTrue(status["reported_statement_present"])
            self.assertEqual(code_gone_from_base(status), "")

    def test_a_statement_rewritten_around_its_call_is_still_present(self):
        """Where's hmacSha256 (2026-10-28): main rewrote the reported
        SecretKeySpec(key, "HmacSHA256") line around the same call, the
        caller's key still reaching it, and a text comparison called the
        violation gone."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self._base_edits(directory, (
                'class Kept {\n  String hash(String s) {\n'
                '    byte[] d = MessageDigest\n'
                '        .getInstance("MD5")\n'
                '        .digest(s.isEmpty() ? new byte[1] : s.getBytes());\n'
                "    return hex(d);\n  }\n}\n"))
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement=self.STATEMENT)
            self.assertFalse(status["analyzed_code_present"])
            self.assertTrue(status["reported_statement_present"])
            self.assertEqual(code_gone_from_base(status), "")
        # The literal moved into a constant of the same file: still the value passed.
        with tempfile.TemporaryDirectory() as directory:
            repo = self._base_edits(directory, (
                'class Kept {\n  static final String ALGORITHM = "MD5";\n'
                '  String hash(String s) {\n'
                '    byte[] d = MessageDigest.getInstance(ALGORITHM).digest(s.getBytes());\n'
                "    return hex(d);\n  }\n}\n"))
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement=self.STATEMENT)
            self.assertTrue(status["reported_statement_present"])

    def test_a_statement_moved_to_another_file_is_still_present(self):
        """A helper extracted into a new file still carries the violation,
        whether or not git sees a rename."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self._base_edits(
                directory,
                'class Kept {\n  String hash(String s) {\n    return Hashes.md5(s);\n  }\n}\n',
                {"Hashes.java": (
                    'class Hashes {\n  static String md5(String s) {\n'
                    '    return hex(MessageDigest.getInstance("MD5").digest(s.getBytes()));\n'
                    "  }\n}\n")})
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement=self.STATEMENT)
            self.assertTrue(status["reported_statement_present"])
            self.assertEqual(code_gone_from_base(status), "")
            # The reported file gone altogether, the statement elsewhere.
            status = contribution_base_status(repo, "removed.java", statement=self.STATEMENT)
            self.assertFalse(status["target_present"])
            self.assertTrue(status["reported_statement_present"])
            self.assertEqual(code_gone_from_base(status), "")

    def test_a_reported_statement_removed_upstream_is_gone_from_the_base(self):
        """AmaRadio (misuse3 run7, 2026-10-16): md5() and its MD5 line were
        gone from master, which hashes with SHA-256."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self._base_edits(directory, (
                'class Kept {\n  String hash(String s) {\n'
                '    return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes()));\n'
                "  }\n}\n"))
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement=self.STATEMENT)
            self.assertFalse(status["reported_statement_present"])
            self.assertIn("reported statement is no longer in kept.java", code_gone_from_base(status))
            # A line that calls nothing proves nothing: the question is not asked.
            status = contribution_base_status(repo, "kept.java", method_body=self.BODY,
                                              statement="  }")
            self.assertNotIn("reported_statement_present", status)
            self.assertEqual(code_gone_from_base(status), "")

    def test_a_body_still_on_the_base_is_reported_present(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)

            status = contribution_base_status(
                repo, "kept.java", method_body="class Kept {}",
            )

            self.assertTrue(status["target_present"])
            self.assertTrue(status["analyzed_code_present"])

    def test_indentation_alone_does_not_decide_the_match(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)
            self.assertTrue(code_exists_at(
                repo, "dev", "kept.java", "class    Kept\n   {}",
            ))

    def test_an_unaskable_code_question_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)
            self.assertIsNone(code_exists_at(repo, "dev", "kept.java", "   "))
            self.assertIsNone(code_exists_at(repo, "dev", "gone.java", "x"))
            self.assertIsNone(
                contribution_base_status(repo, "kept.java")[
                    "analyzed_code_present"
                ]
            )

    def test_a_file_still_present_on_the_base_is_reported_present(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)

            self.assertTrue(
                contribution_base_status(repo, "kept.java")["target_present"]
            )

    def test_the_base_is_read_from_the_remote_on_a_detached_checkout(self):
        """A pinned revision leaves a detached HEAD, where the current-branch
        fallback is empty; the remote's default branch is the answer."""
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)

            self.assertEqual(_git(repo, "branch", "--show-current"), "")
            self.assertEqual(base_branch_name(repo, {}), "dev")

    def test_the_recommended_base_branch_wins_over_the_remote_default(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)
            _git(repo, "branch", "release/4.0")

            self.assertEqual(
                base_branch_name(
                    repo, {"recommended_base_branch": "release/4.0"}
                ),
                "release/4.0",
            )
            self.assertEqual(base_branch_name(repo, {}), "dev")

    def test_an_unanswerable_question_is_unknown_and_not_an_absence(self):
        """An unknown must never read as "the file is gone": an absence stops
        a finding, and a base nobody could resolve has established nothing."""
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)

            self.assertIsNone(
                contribution_base_status(repo, "")["target_present"]
            )
            self.assertEqual(resolve_base_ref(repo, "", fetch=False), "")
            self.assertEqual(
                resolve_base_ref(repo, "no-such-branch", fetch=False), "",
            )

    def test_the_check_makes_no_network_call_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._clone(directory)
            _git(repo, "remote", "set-url", "origin", "https://example.invalid/x")

            # Resolvable from the remote-tracking ref the clone already has,
            # so an unreachable remote changes nothing.
            self.assertEqual(base_branch_name(repo, {}), "dev")
            self.assertTrue(
                contribution_base_status(repo, "kept.java")["target_present"]
            )


class AmbiguousShortNameTests(unittest.TestCase):
    """TagMo's own repository crashed a whole run over one finding.

    Its base branch and a tag share the short name "master". Passed bare, that
    name is exactly what `git worktree add -b <branch> <path> master` refused
    with "fatal: ambiguous object name: 'master'" in run_20260927_175748,
    aborting every remaining finding along with it.
    """

    def _repo_with_colliding_tag(self, directory: str, branch: str = "master") -> Path:
        repo = Path(directory) / "repo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", branch)
        _git(repo, "config", "user.email", "t@example.invalid")
        _git(repo, "config", "user.name", "Test")
        (repo / "kept.java").write_text("class Kept {}", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "initial")
        # An annotated tag sharing the branch's short name is exactly what a
        # bare `git rev-parse`/`git worktree add master` cannot disambiguate.
        _git(repo, "tag", "-a", branch, "-m", "release tag named like the branch")
        return repo

    def test_the_returned_ref_is_qualified_so_the_short_name_is_never_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo_with_colliding_tag(directory)
            branch_commit = _git(repo, "rev-parse", "refs/heads/master")

            ref = resolve_base_ref(repo, "master", fetch=False)

            self.assertEqual(ref, "refs/heads/master")
            # The qualified ref this function returns always resolves to the
            # branch, cleanly, with no warning.
            self.assertEqual(_git(repo, "rev-parse", "--verify", ref), branch_commit)
            # The bare short name it used to return is worse than a crash: git
            # rev-parse only warns and silently resolves "master" to the tag's
            # object -- a different commit than the branch -- rather than
            # failing loudly. git worktree add's own resolution of the same
            # bare name is what turns that same ambiguity into the fatal error
            # this run actually hit (covered end to end in
            # test_worktree_manager.py).
            bare_result = subprocess.run(
                ["git", "rev-parse", "--verify", "master"],
                cwd=repo, capture_output=True, text=True,
            )
            self.assertEqual(bare_result.returncode, 0)
            self.assertIn("ambiguous", bare_result.stderr)
            self.assertNotEqual(bare_result.stdout.strip(), branch_commit)

    def test_a_colliding_tag_on_a_remote_tracking_branch_is_also_disambiguated(self):
        with tempfile.TemporaryDirectory() as directory:
            upstream = self._repo_with_colliding_tag(directory, branch="release")
            repo = Path(directory) / "clone"
            subprocess.run(
                ["git", "clone", "-q", str(upstream), str(repo)],
                capture_output=True, text=True, check=True,
            )
            _git(repo, "checkout", "-q", "--detach", "HEAD")
            _git(repo, "branch", "-D", "release")

            ref = resolve_base_ref(repo, "release", fetch=False)

            self.assertEqual(ref, "refs/remotes/origin/release")
            _git(repo, "rev-parse", "--verify", ref)


if __name__ == "__main__":
    unittest.main()

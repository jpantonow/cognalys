import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli, corrections, review  # noqa: E402

ORIGINAL = 'class Hasher {\n  String h() { return md("MD5"); }\n}\n'
FIXED = 'class Hasher {\n  String h() { return md("SHA-256"); }\n}\n'


def _git(path, *arguments):
    return subprocess.run(["git", "-C", str(path), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


def _repo(path: Path) -> str:
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "t@x.invalid")
    _git(path, "config", "user.name", "T")
    (path / "Hasher.java").write_text(ORIGINAL, encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "base")
    return _git(path, "rev-parse", "HEAD")


class CorrectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.base = _repo(root / "clone")
        # The pipeline's worktree: the base plus the correction, a committed
        # edit and a new test file it has not committed.
        self.worktree = root / "worktree"
        _git(root / "clone", "worktree", "add", "-q", str(self.worktree), self.base)
        (self.worktree / "Hasher.java").write_text(FIXED, encoding="utf-8")
        (self.worktree / "HasherTest.java").write_text("class HasherTest {}\n", encoding="utf-8")
        self.run = root / "run"
        report = self.run / "application_results" / "execution_report.json"
        report.parent.mkdir(parents=True)
        report.write_text(json.dumps({"per_solution_details": [
            self._solution("aaa111", "FIX_SUPPORTED", False, "success"),
            self._solution("bbb222", "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", True, "success"),
            {"status": "FAILED", "finding_id": "ccc333"},
        ]}), encoding="utf-8")
        self.user = root / "user"
        _repo(self.user)

    def _solution(self, finding, decision, manual, build):
        return {"status": "SUCCESS", "finding_id": finding, "apk_name": "app.apk",
                "method_name": "h", "spec": "MessageDigestSpec", "decision": decision,
                "manual_review_required": manual, "build_validation": {"status": build},
                "worktree_path": str(self.worktree), "base_commit": self.base,
                "explanation": "MD5 is not allowed.", "changed_files": ["Hasher.java"]}

    def tearDown(self):
        self.directory.cleanup()

    def test_safe_and_review_are_told_apart(self):
        found = {item.finding_id: item for item in corrections.corrections(self.run)}
        self.assertEqual(set(found), {"aaa111", "bbb222"})
        self.assertTrue(found["aaa111"].safe)
        self.assertEqual(found["bbb222"].level, "review")

    def test_the_patch_includes_new_files(self):
        [item, _] = corrections.corrections(self.run)
        text = corrections.patch(item)
        self.assertIn('+  String h() { return md("SHA-256"); }', text)
        self.assertIn("HasherTest.java", text)

    def test_apply_writes_to_the_users_checkout_without_committing(self):
        [item, _] = corrections.corrections(self.run)
        ok, message = corrections.apply(item, self.user)
        self.assertTrue(ok, message)
        self.assertEqual((self.user / "Hasher.java").read_text(encoding="utf-8"), FIXED)
        self.assertEqual(_git(self.user, "rev-list", "--count", "HEAD"), "1")

    def test_check_writes_nothing(self):
        [item, _] = corrections.corrections(self.run)
        ok, _message = corrections.apply(item, self.user, check_only=True)
        self.assertTrue(ok)
        self.assertEqual((self.user / "Hasher.java").read_text(encoding="utf-8"), ORIGINAL)

    def test_all_safe_never_applies_a_review_correction(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["apply", str(self.run), "--all-safe", "--repo", str(self.user)])
        self.assertEqual(code, 0)
        self.assertIn("aaa111", out.getvalue())
        self.assertNotIn("bbb222", out.getvalue())

    def test_apply_needs_a_finding_or_all_safe(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["apply", str(self.run), "--repo", str(self.user)]), 2)

    def test_diff_writes_one_patch_per_correction(self):
        target = Path(self.directory.name) / "patches"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["diff", str(self.run), "-o", str(target)]), 0)
        self.assertEqual(len(list(target.glob("*.patch"))), 2)

    def test_review_records_each_decision(self):
        answers = iter(["d", "r", "maintainer prefers MD5 here", "a"])
        published = []
        session = review.review(self.run, self.user, lambda finding, dry: published.append(dry) or 0,
                                ask=lambda prompt: next(answers), say=lambda text: None)
        self.assertEqual(session, {"aaa111": "rejected", "bbb222": "applied"})
        decisions = review.load_decisions(self.run)
        self.assertEqual(decisions["aaa111"]["note"], "maintainer prefers MD5 here")
        self.assertEqual(published, [])

    def test_publishing_needs_the_typed_confirmation(self):
        answers = iter(["p", "yes", "s", "q"])
        calls = []
        review.review(self.run, None, lambda finding, dry: calls.append((finding, dry)) or 0,
                      ask=lambda prompt: next(answers), say=lambda text: None)
        # Only the dry run happened: "yes" is not "publish".
        self.assertEqual(calls, [("aaa111", True)])

    def test_pending_skips_decided_corrections(self):
        [item, _] = corrections.corrections(self.run)
        review.record(self.run, item, "rejected", "no")
        answers = iter(["s"])
        session = review.review(self.run, None, lambda finding, dry: 0,
                                ask=lambda prompt: next(answers), say=lambda text: None,
                                only_pending=True)
        self.assertEqual(session, {"bbb222": "skipped"})


if __name__ == "__main__":
    unittest.main()

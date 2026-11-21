import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.pr_github import (  # noqa: E402
    configured_author,
    sign_off_branch_commits,
    signoff_check_failure,
    unsigned_branch_commits,
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


class SignoffCheckDetectionTests(unittest.TestCase):
    """Recognising the failure whose remedy is not a code change.

    The LLM revision pipeline cannot fix a missing Signed-off-by -- there is
    no file to edit -- so routing it there burns a call and leaves the pull
    request blocked anyway. nextcloud/news-android#1716 was blocked by a
    check literally named "DCO".
    """

    def _pr(self, runs):
        return {
            "base": {"repo": {"full_name": "nextcloud/news-android"}},
            "head": {"sha": "f" * 40},
            "_runs": runs,
        }

    def _with_runs(self, runs):
        import cognalys.prs.pr_github as module
        original = module.fetch_check_runs
        module.fetch_check_runs = lambda owner_repo, ref: runs
        self.addCleanup(setattr, module, "fetch_check_runs", original)

    def test_a_failing_dco_check_is_recognised(self):
        self._with_runs([
            {"name": "DCO", "conclusion": "failure",
             "html_url": "https://example.invalid/dco"},
        ])
        found = signoff_check_failure(self._pr([]))
        self.assertIsNotNone(found)
        self.assertEqual(found["check_name"], "DCO")

    def test_the_wording_in_the_output_is_enough(self):
        self._with_runs([
            {"name": "compliance", "conclusion": "failure",
             "output": {"title": "Commit is missing a Signed-off-by line"}},
        ])
        self.assertIsNotNone(signoff_check_failure(self._pr([])))

    def test_an_ordinary_build_failure_is_not_mistaken_for_one(self):
        self._with_runs([
            {"name": "build", "conclusion": "failure"},
            {"name": "ktlint", "conclusion": "failure"},
        ])
        self.assertIsNone(signoff_check_failure(self._pr([])))

    def test_action_required_blocks_just_as_failure_does(self):
        # What nextcloud/news-android#1716 actually reported. Filtering on
        # "failure" alone made every CI code path here blind to it while it
        # blocked the merge.
        self._with_runs([
            {"name": "DCO", "conclusion": "action_required",
             "html_url": "https://example.invalid/dco"},
        ])
        found = signoff_check_failure(self._pr([]))
        self.assertIsNotNone(found)
        self.assertEqual(found["conclusion"], "action_required")

    def test_the_model_path_never_receives_a_commit_form_check(self):
        # There is no file for a revision to edit, so handing it over would
        # spend a model call and leave the pull request blocked anyway.
        from cognalys.prs.pr_github import ci_failures_from_pr
        self._with_runs([
            {"name": "DCO", "conclusion": "action_required", "id": 1},
        ])
        self.assertEqual(ci_failures_from_pr(self._pr([])), [])

    def test_an_ordinary_action_required_check_still_reaches_the_model(self):
        from cognalys.prs.pr_github import ci_failures_from_pr
        import cognalys.prs.pr_github as module
        self._with_runs([
            {"name": "build", "conclusion": "action_required", "id": 7},
        ])
        original_log = module.fetch_job_log_excerpt
        original_base = module.job_reproduces_on_base
        module.fetch_job_log_excerpt = lambda owner_repo, job_id: "boom"
        module.job_reproduces_on_base = lambda owner_repo, name, ref: False
        self.addCleanup(
            setattr, module, "fetch_job_log_excerpt", original_log
        )
        self.addCleanup(
            setattr, module, "job_reproduces_on_base", original_base
        )
        pr = self._pr([])
        pr["base"]["ref"] = "master"
        self.assertEqual(
            [item.get("check_name") for item in ci_failures_from_pr(pr)],
            ["build"],
        )

    def test_a_passing_dco_check_is_not_a_failure(self):
        self._with_runs([{"name": "DCO", "conclusion": "success"}])
        self.assertIsNone(signoff_check_failure(self._pr([])))

    def test_a_network_failure_degrades_to_no_evidence(self):
        import cognalys.prs.pr_github as module
        original = module.fetch_check_runs

        def boom(owner_repo, ref):
            raise RuntimeError("offline")

        module.fetch_check_runs = boom
        self.addCleanup(setattr, module, "fetch_check_runs", original)
        self.assertIsNone(signoff_check_failure(self._pr([])))


class SignoffRewriteTests(unittest.TestCase):
    """Rewriting only this branch's own commits, and only the author's own.

    A Signed-off-by is an attestation by the commit's author. Adding it on
    someone else's behalf would assert something they never did, so a branch
    carrying a foreign commit is refused outright rather than partly signed.
    """

    AUTHOR = "jpantonow <jpantonow@gmail.com>"

    def _repo(self, directory: Path) -> Path:
        repo = directory / "repo"
        repo.mkdir()
        _git(repo.parent, "init", "-q", str(repo))
        _git(repo, "config", "user.name", "jpantonow")
        _git(repo, "config", "user.email", "jpantonow@gmail.com")
        return repo

    def _commit(self, repo: Path, name: str, signoff: bool = False,
                author: str = "") -> None:
        (repo / f"{name}.txt").write_text(name, encoding="utf-8")
        _git(repo, "add", "-A")
        args = ["commit", "-q", "-m", name]
        if signoff:
            args.insert(1, "--signoff")
        if author:
            args.extend(["--author", author])
        _git(repo, *args)

    def test_the_configured_identity_is_read_as_git_writes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self.assertEqual(configured_author(repo), self.AUTHOR)

    def test_an_unsigned_commit_is_found_and_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self._commit(repo, "base", signoff=True)
            self._commit(repo, "change")
            self.assertEqual(
                len(unsigned_branch_commits(repo, "HEAD~1")), 1
            )
            signed = sign_off_branch_commits(repo, "HEAD~1", self.AUTHOR)
            self.assertEqual(len(signed), 1)
            self.assertEqual(unsigned_branch_commits(repo, "HEAD~1"), [])
            self.assertIn("Signed-off-by: " + self.AUTHOR,
                          _git(repo, "log", "-1", "--format=%B"))

    def test_the_base_history_is_never_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self._commit(repo, "base")
            base_sha = _git(repo, "rev-parse", "HEAD")
            self._commit(repo, "change")
            sign_off_branch_commits(repo, "HEAD~1", self.AUTHOR)
            self.assertEqual(_git(repo, "rev-parse", "HEAD~1"), base_sha)
            # The base commit keeps its own missing trailer: it belongs to
            # the base branch, not to this pull request.
            self.assertNotIn(
                "Signed-off-by",
                _git(repo, "log", "-1", "--format=%B", base_sha),
            )

    def test_a_commit_by_another_author_is_refused_outright(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self._commit(repo, "base", signoff=True)
            self._commit(repo, "theirs", author="Someone <someone@example.com>")
            with self.assertRaisesRegex(RuntimeError, "attestation"):
                sign_off_branch_commits(repo, "HEAD~1", self.AUTHOR)
            # And nothing was rewritten.
            self.assertEqual(len(unsigned_branch_commits(repo, "HEAD~1")), 1)

    def test_an_already_signed_branch_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self._commit(repo, "base", signoff=True)
            self._commit(repo, "change", signoff=True)
            head = _git(repo, "rev-parse", "HEAD")
            self.assertEqual(
                sign_off_branch_commits(repo, "HEAD~1", self.AUTHOR), []
            )
            self.assertEqual(_git(repo, "rev-parse", "HEAD"), head)

    def test_every_commit_on_a_multi_commit_branch_is_signed(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            self._commit(repo, "base", signoff=True)
            self._commit(repo, "one")
            self._commit(repo, "two")
            signed = sign_off_branch_commits(repo, "HEAD~2", self.AUTHOR)
            self.assertEqual(len(signed), 2)
            self.assertEqual(unsigned_branch_commits(repo, "HEAD~2"), [])


class RevalidationWiringTests(unittest.TestCase):
    """The repair has to run in the step that carries --publish.

    fix_prs diagnoses and revalidation_fix_prs publishes. Wiring the repair
    into the first one made it detect the DCO failure on
    nextcloud/news-android#1716 and then record
    "DETECTED_NOT_PUBLISHED" -- the fix_prs invocation has no --publish --
    while the step that does have it never looked at the record.

    It also has to run before the status filter: a missing sign-off is a
    property of the commits, so the record has no changed files and the
    filter would drop it.
    """

    def _report(self, directory: Path, **extra) -> Path:
        record = {
            "project": "app.apk",
            "finding_id": "finding-1",
            "status": "NO_FEEDBACK",
            "checkout": str(directory),
            "branch": "fix/thing",
            "signoff_failure": {
                "check_name": "DCO",
                "conclusion": "action_required",
                "head_sha": "a" * 40,
                "commits": 1,
            },
        }
        record.update(extra)
        path = directory / "report.json"
        path.write_text(
            __import__("json").dumps({"results": [record]}), encoding="utf-8"
        )
        return path

    def _args(self, output: Path, publish: bool = True, dry_run: bool = False,
              approve=("finding-1",)):
        import argparse
        return argparse.Namespace(
            output=str(output), publish=publish, dry_run=dry_run, project="",
            approve_revision=list(approve), pull_requests_dir=str(output.parent),
            skip_compile_validation=True, commit_message="Fix {method_name}",
            build_script="", build_variant="debug", build_timeout=10,
            projects_dir=str(output.parent), worktrees_dir=str(output.parent),
        )

    def _patched(self, result):
        import cognalys.prs.pr_feedback as module
        calls = []

        def fake(project_root, branch, head_sha, commits, logger):
            calls.append(
                {"branch": branch, "head_sha": head_sha, "commits": commits}
            )
            return result

        original = module.repair_missing_signoff
        module.repair_missing_signoff = fake
        self.addCleanup(
            setattr, module, "repair_missing_signoff", original
        )
        return calls

    def test_a_record_with_no_changed_files_is_still_repaired(self):
        import cognalys.prs.pr_feedback as module
        with tempfile.TemporaryDirectory() as directory:
            output = self._report(Path(directory))
            calls = self._patched({"status": "PUBLISHED", "commits_signed": 1})
            module.run_revalidation(self._args(output))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["commits"], 1)
            written = __import__("json").loads(
                output.read_text(encoding="utf-8")
            )["results"][0]
            self.assertEqual(written["status"], "SIGNOFF_REPAIRED")

    def test_nothing_is_rewritten_without_publish(self):
        import cognalys.prs.pr_feedback as module
        with tempfile.TemporaryDirectory() as directory:
            output = self._report(Path(directory))
            calls = self._patched({"status": "PUBLISHED"})
            module.run_revalidation(self._args(output, publish=False))
            self.assertEqual(calls, [])

    def test_nothing_is_rewritten_on_a_dry_run(self):
        import cognalys.prs.pr_feedback as module
        with tempfile.TemporaryDirectory() as directory:
            output = self._report(Path(directory))
            calls = self._patched({"status": "PUBLISHED"})
            module.run_revalidation(self._args(output, dry_run=True))
            self.assertEqual(calls, [])

    def test_nothing_is_rewritten_for_a_finding_not_approved(self):
        # The force-push of a sign-off rewrites a published branch: --publish
        # alone did it for every record (batch6 audit, 2026-10-30).
        import cognalys.prs.pr_feedback as module
        with tempfile.TemporaryDirectory() as directory:
            output = self._report(Path(directory))
            calls = self._patched({"status": "PUBLISHED"})
            module.run_revalidation(self._args(output, approve=("another",)))
            self.assertEqual(calls, [])
            written = __import__("json").loads(
                output.read_text(encoding="utf-8")
            )["results"][0]
            self.assertEqual(written["signoff_repair"]["status"], "NOT_APPROVED")
            self.assertIn("--approve-revision finding-1", written["signoff_repair"]["detail"])

    def test_a_failing_repair_is_recorded_and_does_not_raise(self):
        import cognalys.prs.pr_feedback as module
        with tempfile.TemporaryDirectory() as directory:
            output = self._report(Path(directory))

            def boom(*args, **kwargs):
                raise RuntimeError("remote rejected")

            original = module.repair_missing_signoff
            module.repair_missing_signoff = boom
            self.addCleanup(
                setattr, module, "repair_missing_signoff", original
            )
            module.run_revalidation(self._args(output))
            written = __import__("json").loads(
                output.read_text(encoding="utf-8")
            )["results"][0]
            self.assertEqual(written["signoff_repair"]["status"], "FAILED")
            self.assertIn("remote rejected", written["signoff_repair"]["detail"])


if __name__ == "__main__":
    unittest.main()

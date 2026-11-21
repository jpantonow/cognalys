"""Nothing reaches GitHub without the approval of that specific finding.

CLAUDE.md: pull requests and issues are published only after the user
approves that finding, through the library. The batch5 review (2026-10-30)
found that `cognalys publish --refresh-text` sent edited descriptions with no
finding named; the audit that followed found four more paths that wrote with
a blanket flag or none: pr_creator opened every draft whose own verdict was
publishable, issue_creator opened an issue for every candidate,
issue_cleanup and cleanup_pipeline closed every recorded issue and pull
request (and deleted the branches), and pr_feedback --publish pushed every
revalidated revision. Each now writes only for a finding named on its command
line and is otherwise a dry run. The HTTP layer is mocked throughout: any
write that slips through is recorded, never sent.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import pr_creator  # noqa: E402
from cognalys.prs.publication_checks import current_review_contract_version  # noqa: E402


class FakeResponse:

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class RecordingHttp:
    """Answers reads, records every call, and answers each write as a success."""

    class RequestException(Exception):
        pass

    def __init__(self, reads=None):
        self.reads = reads or {}
        self.calls = []

    def _record(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "GET":
            return self.reads.get(url, FakeResponse(404, {"message": "Not Found"}))
        status = {"POST": 201, "DELETE": 204}.get(method, 200)
        return FakeResponse(status, {"html_url": url, "number": 1})

    def get(self, url, **kwargs):
        return self._record("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._record("POST", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._record("PATCH", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._record(method, url, **kwargs)

    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]


def quietly(function, *args, **kwargs):
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        result = function(*args, **kwargs)
    return result, printed.getvalue()


class PullRequestCreationTests(unittest.TestCase):
    """A draft whose own verdict is publishable is still a dry run unless named."""

    def _metadata(self, directory: Path) -> Path:
        # Laid out as a run, so the duplicate check searches only this root.
        directory = directory / "run_1" / "pull_requests"
        directory.mkdir(parents=True)
        path = directory / "app_method_pr.json"
        path.write_text(json.dumps({
            "finding_id": "finding-1", "decision": "FIX_SUPPORTED", "publishable": True,
            "build_validation": {"status": "success"}, "commit_hash": "abc123",
            "repository": str(directory), "branch": "fix/branch",
            "repo_host": "github.com", "repo_owner": "owner", "repo_name": "repo",
            "title": "Use TLS for the sync connection",
            "body": "The sync client asked for SSL; it now asks for TLS.",
            "review_contract_version": current_review_contract_version(),
        }), encoding="utf-8")
        return path

    def _creator(self, approved, directory):
        creator = pr_creator.AutomatedPRCreator(
            pull_requests_dir=str(directory), approved_reviewed_findings=approved,
            dry_run=True)
        # The state a run with a token is in; the gate must hold without
        # relying on a global dry run.
        creator.dry_run = False
        creator.username = "jpantonow"
        return creator

    def test_an_unnamed_publishable_draft_writes_only_a_dry_run_record(self):
        http = RecordingHttp()
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._metadata(root)
            creator = self._creator([], path.parent)
            with mock.patch.object(pr_creator, "requests", http), \
                    mock.patch.object(creator, "run_command",
                                      lambda command, cwd, env=None: commands.append(command)):
                _, printed = quietly(creator.process_pr_file, path)
            record = json.loads((path.parent / "app_method_pr_created.json")
                                .read_text(encoding="utf-8"))
        self.assertEqual(http.writes(), [])
        self.assertFalse([command for command in commands if "push" in command])
        self.assertTrue(record["dry_run"])
        self.assertIn("pass --approve-reviewed-finding finding-1 to publish it", printed)

    def test_another_findings_approval_does_not_cover_it(self):
        http = RecordingHttp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._metadata(root)
            creator = self._creator(["finding-2"], path.parent)
            with mock.patch.object(pr_creator, "requests", http), \
                    mock.patch.object(creator, "run_command", lambda *a, **k: ""):
                quietly(creator.process_pr_file, path)
        self.assertEqual(http.writes(), [])

    def test_a_dry_run_keeps_the_record_of_a_published_pull_request(self):
        # --reprocess-existing with no approval made every published pull
        # request a dry run, and its *_pr_created.json (URL, number) was
        # replaced by a dry-run marker (batch6 review, 2026-10-30).
        published = {"html_url": "https://github.com/owner/repo/pull/7", "number": 7,
                     "url": "https://api.github.com/repos/owner/repo/pulls/7"}
        http = RecordingHttp()
        with tempfile.TemporaryDirectory() as directory:
            path = self._metadata(Path(directory))
            created = path.parent / "app_method_pr_created.json"
            created.write_text(json.dumps(published), encoding="utf-8")
            creator = self._creator([], path.parent)
            creator.skip_existing = False
            with mock.patch.object(pr_creator, "requests", http), \
                    mock.patch.object(creator, "run_command", lambda *a, **k: ""):
                _, printed = quietly(creator.process_pr_file, path)
            record = json.loads(created.read_text(encoding="utf-8"))
        self.assertEqual(http.writes(), [])
        self.assertEqual(record, published)
        self.assertIn("records the published pull request", printed)

    def test_the_command_line_is_a_dry_run_without_an_approval(self):
        seen = []

        class Creator:
            def __init__(self, **kwargs):
                seen.append(kwargs)

            def run(self):
                return {"success": 0, "failed": 0, "blocked": 0}

        with mock.patch.object(pr_creator, "AutomatedPRCreator", Creator):
            for argv, dry_run in ((["--pull-requests-dir", "d"], True),
                                  (["--pull-requests-dir", "d",
                                    "--approve-reviewed-finding", "f1"], False)):
                with mock.patch("sys.argv", ["pr_creator", *argv]):
                    pr_creator.main()
                self.assertEqual(seen[-1]["dry_run"], dry_run)


class IssueCreationTests(unittest.TestCase):

    def _write(self, directory: Path, name: str, finding: str = "") -> Path:
        path = directory / f"{name}_pr.json"
        path.write_text(json.dumps({
            **({"finding_id": finding} if finding else {}),
            "repo_host": "github.com", "repo_owner": "owner", "repo_name": "repo",
            "source_file": "app/src/main/java/A.java", "spec": "SSLContextSpec",
            "method_name": "connect", "csv_class": "a.A", "error_message": "m",
        }), encoding="utf-8")
        return path

    def _run(self, approved, files=(("a", "f1"), ("b", "f2"))):
        from cognalys.issues import issue_creator

        http = RecordingHttp({"https://api.github.com/user":
                              FakeResponse(200, {"login": "jpantonow"})})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, finding in files:
                self._write(root, name, finding)
            with mock.patch.object(issue_creator, "requests", http):
                creator = issue_creator.IssueCreator(
                    pull_requests_dir=str(root), issue_candidates_dir=None,
                    issues_dir=str(root / "issues"), title="t", body="b",
                    github_token="token", approved_reviewed_findings=approved)
                _, printed = quietly(creator.run)
            records = {path.name: json.loads(path.read_text(encoding="utf-8"))
                       for path in sorted((root / "issues").glob("*.json"))}
        return http, records, printed

    def test_no_issue_is_opened_without_a_named_finding(self):
        http, records, printed = self._run([])
        self.assertEqual(http.calls, [])
        self.assertTrue(all(record["dry_run"] for record in records.values()))
        self.assertIn("pass --approve-reviewed-finding f1 to open it", printed)

    def test_only_the_named_finding_is_opened(self):
        http, records, _ = self._run(["f2"])
        self.assertEqual([(method, url) for method, url, _ in http.writes()],
                         [("POST", "https://api.github.com/repos/owner/repo/issues")])
        self.assertTrue(records["a_pr_issue_created.json"]["dry_run"])
        self.assertEqual(records["b_pr_issue_created.json"]["finding_id"], "f2")
        self.assertNotIn("dry_run", records["b_pr_issue_created.json"])

    def test_an_approved_issue_on_a_closed_repository_is_blocked_not_opened(self):
        # PLANO_CORRECOES_DEFESA A7: the issue path read nothing from GitHub.
        import base64

        from cognalys.issues import issue_creator

        readme = base64.b64encode(b"Please note that I am currently not accepting PRs.").decode()
        http = RecordingHttp({
            "https://api.github.com/user": FakeResponse(200, {"login": "jpantonow"}),
            "https://api.github.com/repos/owner/repo/contents": FakeResponse(
                200, [{"path": "README.md", "name": "README.md", "type": "file"}]),
            "https://api.github.com/repos/owner/repo/contents/README.md": FakeResponse(
                200, {"path": "README.md", "content": readme}),
        })
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write(root, "a", "f1")
            with mock.patch.object(issue_creator, "requests", http):
                creator = issue_creator.IssueCreator(
                    pull_requests_dir=str(root), issue_candidates_dir=None,
                    issues_dir=str(root / "issues"), title="t", body="b",
                    github_token="token", approved_reviewed_findings=["f1"])
                summary, printed = quietly(creator.run)
                self.assertEqual(http.writes(), [])
                self.assertEqual(summary["blocked"], 1)
                self.assertIn("--allow-closed-repository", printed)
                creator.allow_closed_repository = True
                creator.skip_existing = False
                quietly(creator.run)
        self.assertEqual([(method, url) for method, url, _ in http.writes()],
                         [("POST", "https://api.github.com/repos/owner/repo/issues")])

    def test_a_dry_run_keeps_the_record_of_an_opened_issue(self):
        from cognalys.issues import issue_creator

        opened = {"html_url": "https://github.com/owner/repo/issues/9", "number": 9,
                  "finding_id": "f1"}
        http = RecordingHttp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write(root, "a", "f1")
            record_file = root / "issues" / "a_pr_issue_created.json"
            record_file.parent.mkdir()
            record_file.write_text(json.dumps(opened), encoding="utf-8")
            with mock.patch.object(issue_creator, "requests", http):
                creator = issue_creator.IssueCreator(
                    pull_requests_dir=str(root), issue_candidates_dir=None,
                    issues_dir=str(root / "issues"), title="t", body="b",
                    skip_existing=False, approved_reviewed_findings=[])
                summary, _ = quietly(creator.run)
            record = json.loads(record_file.read_text(encoding="utf-8"))
        self.assertEqual(http.calls, [])
        self.assertEqual(record, opened)
        self.assertEqual(summary["skipped"], 1)

    def test_a_candidate_without_a_finding_id_is_named_by_its_directory_and_stem(self):
        from cognalys.issues.issue_creator import issue_approval_name

        self.assertEqual(issue_approval_name(
            {}, Path("issue_candidates/app.apk/3_getOrCreateKey_issue.json")),
            "app.apk/3_getOrCreateKey_issue")
        self.assertEqual(issue_approval_name({"finding_id": "f1"}, Path("x/y.json")), "f1")


class IssueCleanupTests(unittest.TestCase):

    def _run(self, *argv):
        from cognalys.issues import issue_cleanup

        http = RecordingHttp({"https://api.github.com/user":
                              FakeResponse(200, {"login": "jpantonow"})})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, number, finding in (("a", 5, "f1"), ("b", 6, "")):
                (root / f"{name}_issue_created.json").write_text(json.dumps({
                    "number": number, "repository_url": "https://api.github.com/repos/o/r",
                    **({"finding_id": finding} if finding else {})}), encoding="utf-8")
            with mock.patch.object(issue_cleanup, "requests", http):
                _, printed = quietly(issue_cleanup.main,
                                     ["--issues-dir", str(root), "--github-token", "t", *argv])
        return [url for method, url, _ in http.writes()], printed

    def test_the_old_confirmation_alone_closes_nothing(self):
        closed, printed = self._run("--confirm-issue-cleanup")
        self.assertEqual(closed, [])
        self.assertIn("names no issue", printed)

    def test_an_issue_is_closed_by_its_finding_or_its_reference(self):
        closed, _ = self._run("--approve-issue-cleanup", "f1")
        self.assertEqual(closed, ["https://api.github.com/repos/o/r/issues/5"])
        closed, _ = self._run("--approve-issue-cleanup", "o/r#6")
        self.assertEqual(closed, ["https://api.github.com/repos/o/r/issues/6"])


class PullRequestCleanupTests(unittest.TestCase):

    def _run(self, *argv):
        from cognalys.maintenance import cleanup_pipeline

        http = RecordingHttp({"https://api.github.com/user":
                              FakeResponse(200, {"login": "jpantonow"}),
                              "https://api.github.com/repos/o/r":
                              FakeResponse(200, {"default_branch": "main"})})

        class Session(RecordingHttp):
            headers = {}

        session = Session(http.reads)
        resets = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, number, finding in (("a", 5, "f1"), ("b", 6, "f2")):
                (root / f"{name}_pr.json").write_text(json.dumps({
                    "finding_id": finding, "repo_owner": "o", "repo_name": "r",
                    "branch": f"fix/{name}", "repository": str(root / name)}), encoding="utf-8")
                (root / f"{name}_pr_created.json").write_text(json.dumps(
                    {"number": number, "base": {"ref": "main"}}), encoding="utf-8")
            with mock.patch.object(cleanup_pipeline.requests, "Session", lambda: session), \
                    mock.patch.object(cleanup_pipeline, "reset_clone",
                                      lambda *args: resets.append(args)), \
                    mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t"}):
                _, printed = quietly(cleanup_pipeline.main,
                                     ["--pull-requests-dir", str(root), *argv])
        return [(method, url) for method, url, _ in session.writes()], resets, printed

    def test_the_old_confirmation_alone_closes_and_deletes_nothing(self):
        writes, resets, printed = self._run("--confirm-cleanup")
        self.assertEqual(writes, [])
        self.assertTrue(all(args[-1] is False for args in resets))
        self.assertIn("names no finding", printed)

    def test_only_the_named_findings_pull_request_and_branch_change(self):
        writes, resets, _ = self._run("--approve-cleanup", "f2")
        self.assertEqual(writes, [
            ("PATCH", "https://api.github.com/repos/o/r/pulls/6"),
            ("DELETE", "https://api.github.com/repos/jpantonow/r/git/refs/heads/fix/b")])
        self.assertEqual([args[-1] for args in resets], [False, True])


class PipelineForwardingTests(unittest.TestCase):
    """run_pipeline forwards each approval to its step, and nothing more."""

    def _command(self, step, **overrides):
        from test_run_pipeline_commands import MODULE, _args, _paths as paths
        return MODULE.command_for_step(step, _args(**overrides), paths())

    def test_each_publishing_step_receives_its_named_findings(self):
        self.assertEqual(self._command("issues", approve_reviewed_finding=["f1"])[-2:],
                         ["--approve-reviewed-finding", "f1"])
        revalidation = self._command("revalidation_fix_prs", publish_fix_prs=True,
                                     approve_revision=["f2"])
        self.assertEqual(revalidation[-3:], ["--publish", "--approve-revision", "f2"])
        cleanup = self._command("cleanup", confirm_cleanup=True, approve_cleanup=["f3"])
        self.assertIn("--approve-cleanup", cleanup)
        issues_cleanup = self._command("issues_cleanup", confirm_issue_cleanup=True,
                                       approve_cleanup=["f3"])
        self.assertEqual(issues_cleanup[-2:], ["--approve-issue-cleanup", "f3"])

    def test_an_approval_is_not_forwarded_without_its_step_being_asked(self):
        self.assertNotIn("--approve-revision",
                         self._command("revalidation_fix_prs", approve_revision=["f2"]))
        self.assertNotIn("--approve-cleanup",
                         self._command("cleanup", confirm_cleanup=False, approve_cleanup=["f3"]))


if __name__ == "__main__":
    unittest.main()

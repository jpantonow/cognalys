import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import pr_creator  # noqa: E402
from cognalys.prs.pr_creator import AutomatedPRCreator  # noqa: E402
from cognalys.prs.publication_checks import current_review_contract_version  # noqa: E402


API = "https://api.github.com"


class FakeResponse:

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


class FakeGitHub:
    """Routes requests.get/post by (method, url) and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def _answer(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        answer = self.routes.get((method, url))
        if answer is None:
            return FakeResponse(404, {"message": "Not Found"})
        if isinstance(answer, list):
            return answer.pop(0) if len(answer) > 1 else answer[0]
        return answer

    def get(self, url, **kwargs):
        return self._answer("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._answer("POST", url, **kwargs)


class ForkResolutionTests(unittest.TestCase):
    """Publishing to a repository renamed or transferred after it was cloned.

    com.ivanovsky.passnotes_11700.apk was cloned as aivanovski/kpassnotes,
    since renamed aivanovski/keepassvault. GitHub redirected the fork request
    and created jpantonow/keepassvault, but the push went to the assumed
    jpantonow/kpassnotes and failed with "Repository not found".
    """

    def _creator(self):
        creator = AutomatedPRCreator(dry_run=True)
        creator.username = "jpantonow"
        creator.fork_wait_seconds = 10
        return creator

    def _patch(self, routes):
        github = FakeGitHub(routes)
        return github, mock.patch.object(pr_creator, "requests", github)

    def test_a_renamed_upstream_resolves_to_its_current_name(self):
        github, patch = self._patch({
            ("GET", f"{API}/repos/aivanovski/kpassnotes"):
                FakeResponse(200, {"full_name": "aivanovski/keepassvault"}),
        })
        with patch:
            self.assertEqual(
                self._creator().resolve_canonical_repository(
                    "aivanovski", "kpassnotes"
                ),
                ("aivanovski", "keepassvault"),
            )

    def test_an_unknown_upstream_is_an_error_not_a_guess(self):
        _, patch = self._patch({})
        with patch, self.assertRaisesRegex(RuntimeError, "HTTP 404"):
            self._creator().resolve_canonical_repository("gone", "repo")

    def test_the_fork_name_comes_from_github_not_from_the_upstream_name(self):
        # A same-named repository already in the account makes GitHub
        # suffix the fork.
        _, patch = self._patch({
            ("POST", f"{API}/repos/aivanovski/keepassvault/forks"):
                FakeResponse(202, {"full_name": "jpantonow/keepassvault-1"}),
        })
        with patch:
            self.assertEqual(
                self._creator().create_fork("aivanovski", "keepassvault"),
                "jpantonow/keepassvault-1",
            )

    def test_a_refused_fork_request_reuses_a_real_existing_fork(self):
        _, patch = self._patch({
            ("POST", f"{API}/repos/aivanovski/keepassvault/forks"):
                FakeResponse(403, {"message": "Forbidden"}),
            ("GET", f"{API}/repos/jpantonow/keepassvault"):
                FakeResponse(200, {
                    "full_name": "jpantonow/keepassvault",
                    "fork": True,
                    "parent": {"full_name": "aivanovski/keepassvault"},
                }),
        })
        with patch:
            self.assertEqual(
                self._creator().create_fork("aivanovski", "keepassvault"),
                "jpantonow/keepassvault",
            )

    def test_a_same_named_repository_that_is_not_that_fork_is_never_used(self):
        _, patch = self._patch({
            ("POST", f"{API}/repos/aivanovski/keepassvault/forks"):
                FakeResponse(422, {"message": "Unprocessable"}),
            ("GET", f"{API}/repos/jpantonow/keepassvault"):
                FakeResponse(200, {
                    "full_name": "jpantonow/keepassvault",
                    "fork": True,
                    "parent": {"full_name": "someone-else/keepassvault"},
                }),
        })
        with patch, self.assertRaisesRegex(RuntimeError, "no fork of it"):
            self._creator().create_fork("aivanovski", "keepassvault")

    def test_waits_until_the_fork_has_branches(self):
        branches = f"{API}/repos/jpantonow/keepassvault/branches"
        github, patch = self._patch({
            ("GET", branches): [
                FakeResponse(404, {"message": "Not Found"}),
                FakeResponse(200, []),
                FakeResponse(200, [{"name": "master"}]),
            ],
        })
        with patch, mock.patch.object(pr_creator.time, "sleep") as sleep:
            self._creator().wait_for_fork("jpantonow/keepassvault")
        self.assertEqual(len(github.calls), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_gives_up_on_a_fork_that_never_becomes_ready(self):
        _, patch = self._patch({})
        clock = iter([0, 5, 11])
        with patch, \
                mock.patch.object(pr_creator.time, "sleep"), \
                mock.patch.object(
                    pr_creator.time, "monotonic", side_effect=lambda: next(clock)
                ), \
                self.assertRaisesRegex(RuntimeError, "not ready after 10s"):
            self._creator().wait_for_fork("jpantonow/keepassvault")

    def test_publication_pushes_to_the_fork_github_created(self):
        github, patch = self._patch({
            ("GET", f"{API}/repos/aivanovski/kpassnotes"):
                FakeResponse(200, {"full_name": "aivanovski/keepassvault"}),
            ("POST", f"{API}/repos/aivanovski/keepassvault/forks"):
                FakeResponse(202, {"full_name": "jpantonow/keepassvault"}),
            ("GET", f"{API}/repos/jpantonow/keepassvault/branches"):
                FakeResponse(200, [{"name": "master"}]),
            ("POST", f"{API}/repos/aivanovski/keepassvault/pulls"):
                FakeResponse(201, {"html_url": "https://github.com/pr/1"}),
        })
        with tempfile.TemporaryDirectory() as directory:
            metadata_path = Path(directory) / "app_method_pr.json"
            metadata_path.write_text(json.dumps({
                "finding_id": "finding-1",
                "build_validation": {"status": "success"},
                "commit_hash": "abc123",
                "repository": directory,
                "branch": "fix/branch",
                "repo_host": "github.com",
                "repo_owner": "aivanovski",
                "repo_name": "kpassnotes",
                "title": "Title",
                "body": "Body",
                "base_branch": "master",
                "review_contract_version": current_review_contract_version(),
            }), encoding="utf-8")

            creator = AutomatedPRCreator(
                approved_reviewed_findings=["finding-1"], dry_run=True,
            )
            creator.dry_run = False
            creator.username = "jpantonow"
            commands = []

            def run_command(command, cwd, env=None):
                commands.append(command)
                return ""

            with patch, mock.patch.object(creator, "run_command", run_command):
                creator.process_pr_file(metadata_path)

        self.assertIn(
            ["git", "remote", "add", "origin",
             "https://github.com/jpantonow/keepassvault.git"],
            commands,
        )
        self.assertIn(
            ["git", "remote", "add", "upstream",
             "https://github.com/aivanovski/keepassvault.git"],
            commands,
        )
        pull = [call for call in github.calls if call[1].endswith("/pulls")]
        self.assertEqual(pull[0][2]["json"]["head"], "jpantonow:fix/branch")


if __name__ == "__main__":
    unittest.main()

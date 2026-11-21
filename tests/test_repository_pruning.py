import json
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
from cognalys.maintenance import repository_pruning as pruning
from cognalys.utils.repository_lock import RepositoryUsageLock, RepositoryBusyError
from cognalys.maintenance import prune_unused_repositories as cli
def pull(number=1, state="closed", merged=False, author="tester", branch="fix"):
    return {"number": number, "state": state, "merged_at": "2026-01-01T00:00:00Z" if merged else None,
            "user": {"login": author}, "head": {"ref": branch, "sha": "a" * 40, "repo": {
                "full_name": f"{author}/project", "owner": {"login": author}}}}


class FakeAPI:
    login = "tester"

    def __init__(self, prs=()):
        self.prs = list(prs)

    def repository(self, slug):
        return {"fork": False, "full_name": "owner/project"}

    def pulls(self, slug):
        return self.prs

    def pull(self, slug, number):
        return next(p for p in self.prs if p["number"] == number)


class DecisionTests(unittest.TestCase):
    def decision(self, prs=(), records=()):
        return pruning.remote_decision(FakeAPI(prs), "owner/project", {"owner/project"}, records)[0]

    def test_status_matrix(self):
        for prs, expected in [
            ([], "no_pr"), ([pull()], "closed_pr"),
            ([pull(state="open")], "has_open_pr"),
            ([{**pull(state="open"), "draft": True}], "has_open_pr"),
            ([{**pull(state="open"), "review_state": "APPROVED"}], "has_open_pr"),
            ([pull(merged=True)], "merged_pr"),
            ([pull(), pull(2, state="open")], "has_open_pr"),
            ([pull(), pull(2, merged=True)], "merged_pr"),
            ([pull(merged=True), pull(2, state="open")], "has_open_pr"),
        ]:
            with self.subTest(prs=prs):
                self.assertEqual(self.decision(prs), expected)

    def test_third_party_pr_does_not_protect_unrelated_work(self):
        self.assertEqual(self.decision([pull(state="open", author="other")]), "no_pr")

    def test_known_pr_protected_even_with_another_author(self):
        receipt = {"kind": "receipt", "data": {"number": 1}}
        self.assertEqual(self.decision([pull(state="open", author="other")], [receipt]), "has_open_pr")

    def test_missing_receipt_still_discovers_authors_pr(self):
        self.assertEqual(self.decision([pull(state="open")]), "has_open_pr")

    def test_pending_metadata_and_local_solution_protect(self):
        for kind, data in [("pr", {"branch": "unpublished"}),
                           ("solution", {"worktree_path": "outputs/trees/new"})]:
            self.assertTrue(pruning.has_pending_metadata([], [{"kind": kind, "data": data}]))
            self.assertEqual(self.decision([], [{"kind": kind, "data": data}]), "no_pr")

    def test_published_closed_branch_is_not_pending(self):
        self.assertEqual(self.decision([pull()], [{"kind": "pr", "data": {
            "branch": "fix", "commit_hash": "a" * 40}}]), "closed_pr")

    def test_unpublished_revision_of_a_closed_finding_is_pending(self):
        records = [
            {"kind": "pr", "data": {"branch": "fix", "commit_hash": "a" * 40,
                "finding_id": "same", "solution_revision": "old"}},
            {"kind": "solution", "data": {"finding_id": "same", "solution_revision": "new",
                "corrected_method_body": "new patch"}},
        ]
        _, prs = pruning.remote_decision(FakeAPI([pull()]), "owner/project", {"owner/project"}, records)
        self.assertTrue(pruning.has_pending_metadata(prs, records))
        self.assertEqual(self.decision([pull()], records), "closed_pr")

    def test_missing_merge_data_and_unknown_states_are_not_closed(self):
        for data in [{"number": 1, "state": "closed"},
                     {"number": 1, "state": "unexpected", "merged_at": None}]:
            with self.assertRaises(pruning.InventoryError):
                pruning.pr_state(data)


class GitHubTests(unittest.TestCase):
    def api(self):
        api = object.__new__(pruning.GitHub)
        api.session = Mock()
        return api

    def test_http_failures_remain_unknown(self):
        for status in (401, 403, 404, 429, 500):
            api = self.api()
            api.session.get.return_value = Mock(status_code=status)
            with self.subTest(status=status), self.assertRaises(pruning.InventoryError):
                api.get("https://api.github.com/repos/o/r")

    def test_does_not_send_token_to_other_hosts_or_follow_redirects(self):
        api = self.api()
        with self.assertRaises(pruning.InventoryError):
            api.get("https://attacker.example/pr")
        api.session.get.assert_not_called()

    def test_pagination_is_complete_and_failure_on_next_page_is_fatal(self):
        api = self.api()
        first = Mock(status_code=200, links={"next": {"url": "https://api.github.com/next"}})
        first.json.return_value = [pull()]
        second = Mock(status_code=200, links={})
        second.json.return_value = [pull(2, state="open")]
        api.session.get.side_effect = [first, second]
        self.assertEqual(len(api.pulls("o/r")), 2)
        self.assertEqual(api.session.get.call_args_list[0].args[0],
                         "https://api.github.com/repos/o/r/pulls?state=all&per_page=100")
        api.session.get.side_effect = [first, Mock(status_code=403)]
        with self.assertRaises(pruning.InventoryError):
            api.pulls("o/r")

    def test_invalid_json_timeout_and_no_token(self):
        api = self.api()
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("bad json")
        api.session.get.return_value = response
        with self.assertRaises(pruning.InventoryError):
            api.get("https://api.github.com/user")
        api.session.get.side_effect = pruning.requests.Timeout()
        with self.assertRaises(pruning.InventoryError):
            api.get("https://api.github.com/user")
        with self.assertRaises(pruning.InventoryError):
            pruning.GitHub("")


class LocalPruningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.outputs = self.root / "outputs"
        self.clones = self.outputs / "cloned_projects"
        self.trees = self.outputs / "finding_worktrees"
        self.clones.mkdir(parents=True)
        self.trees.mkdir()
        self.repo = self.clones / "app_1.apk"
        self.repo.mkdir()
        self.run_git(self.repo, "init")
        self.run_git(self.repo, "config", "core.autocrlf", "false")
        (self.repo / "file.txt").write_text("base\n", encoding="utf-8")
        self.run_git(self.repo, "add", ".")
        self.run_git(self.repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "base")
        self.run_git(self.repo, "remote", "add", "origin", "https://github.com/owner/project.git")
        self.sha = self.run_git(self.repo, "rev-parse", "HEAD")
        real_git = pruning.git

        def offline_git(repo, *args):
            if args[0] == "ls-remote":
                return f"{self.sha}\trefs/heads/main"
            return real_git(repo, *args)
        self.git_mock = patch.object(pruning, "git", side_effect=offline_git)
        self.git_mock.start()
        self.addCleanup(self.git_mock.stop)

    def run_git(self, repo, *args):
        result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def prune(self, mode="preview", api=None, project="", **options):
        with contextlib.redirect_stdout(io.StringIO()):
            return pruning.prune(self.root, self.clones, self.trees, self.outputs, mode, project, api or FakeAPI(), **options)

    def markdown(self):
        return sorted((self.outputs / "cleanup_reports").glob("*.md"))[-1].read_text(encoding="utf-8")

    def second_project(self):
        other = self.clones / "z_other.apk"
        self.run_git(self.clones, "clone", str(self.repo), str(other))
        self.run_git(other, "remote", "set-url", "origin", "https://github.com/owner/other.git")
        return other

    def test_initial_markdown_exists_before_inventory_work(self):
        original = pruning.metadata_inventory
        def inventory(outputs):
            self.assertIn("inventário", self.markdown())
            self.assertIn("Nenhum resultado confirmado", self.markdown())
            return original(outputs)
        with patch.object(pruning, "metadata_inventory", side_effect=inventory):
            self.assertEqual(self.prune()[0], 0)

    def test_all_modes_only_report_and_preserve_clone_and_worktree_contents(self):
        tree = self.trees / "finding"
        self.run_git(self.repo, "worktree", "add", "--detach", str(tree), "HEAD")
        (tree / "pending.txt").write_text("work", encoding="utf-8")
        before = {str(p): p.read_bytes() for root in [self.repo, tree] for p in root.rglob("*") if p.is_file()}
        for mode in ("report", "preview", "apply"):
            with self.subTest(mode=mode):
                code, report = self.prune(mode)
                self.assertEqual(code, 0)
                self.assertEqual(report["mode"], "report")
                self.assertEqual(report["repositories"][0]["action"], "listed")
                self.assertIn(str(tree), self.markdown())
                after = {str(p): p.read_bytes() for root in [self.repo, tree] for p in root.rglob("*") if p.is_file()}
                self.assertEqual(before, after)
        self.assertFalse(any(c.args[1:3] == ("worktree", "remove") for c in pruning.git.call_args_list))
        self.assertFalse(any(c.args[1] in {"status", "ls-remote"} for c in pruning.git.call_args_list))

    def test_merged_closed_and_no_pr_are_listed_but_open_is_excluded(self):
        for prs, decision, listed in [([], "no_pr", 1), ([pull()], "closed_pr", 1),
                ([pull(merged=True)], "merged_pr", 1), ([pull(state="open")], "has_open_pr", 0),
                ([pull(merged=True), pull(2, state="open")], "has_open_pr", 0)]:
            with self.subTest(prs=prs):
                code, report = self.prune("apply", FakeAPI(prs))
                self.assertEqual(code, 0)
                self.assertEqual(report["repositories"][0]["decision"], decision)
                self.assertEqual(report["summary"]["listed"], listed)
                self.assertIn(f"critérios ({listed})", self.markdown())
                self.assertTrue(self.repo.exists())
                if prs and listed:
                    self.assertIn("[#1]", self.markdown())
                    self.assertIn("https://github.com/owner/project/pull/1", self.markdown())

    def test_size_walk_is_opt_in(self):
        with patch.object(pruning, "estimate_bytes", return_value=123) as estimate:
            code, report = self.prune()
            self.assertEqual(code, 0)
            estimate.assert_not_called()
            self.assertIsNone(report["summary"]["estimated_bytes"])
            code, report = self.prune("apply", estimate_size=True)
            self.assertEqual(code, 0)
            estimate.assert_called_once()
            self.assertEqual(report["summary"]["estimated_bytes"], 123)
            self.assertIn("123 bytes", self.markdown())

    def test_progress_is_visible_before_pr_lookup_finishes(self):
        stream = io.StringIO()
        api = FakeAPI()
        def lookup(slug):
            self.assertIn("Modo report", stream.getvalue())
            self.assertIn("Repositório 1/1", stream.getvalue())
            return []
        api.pulls = lookup
        with contextlib.redirect_stdout(stream):
            code, _ = pruning.prune(self.root, self.clones, self.trees, self.outputs, api=api)
        self.assertEqual(code, 0)

    def test_pending_solution_is_listed_with_note(self):
        directory = self.outputs / "run_old" / "error_solutions" / self.repo.name
        directory.mkdir(parents=True)
        (directory / "case_solution.json").write_text(json.dumps({
            "solution_metadata": {"apk_name": self.repo.name, "manual_review_required": True},
            "original_error": {"unique_error_id": "finding", "method_body": "before"},
            "corrected_implementation": {"method_body": "after"},
        }), encoding="utf-8")
        code, report = self.prune("report")
        self.assertEqual(code, 0)
        self.assertEqual(report["repositories"][0]["action"], "listed")
        self.assertIn("ainda não publicado", self.markdown())

    def test_pending_metadata_in_old_nested_run_is_not_silently_discarded(self):
        directory = self.outputs / "experiments" / "old" / "pull_requests"
        directory.mkdir(parents=True)
        (directory / "case_pr.json").write_text(json.dumps({
            "repo_owner": "owner", "repo_name": "project", "repository": str(self.repo),
            "branch": "unpublished", "manual_review_required": True,
        }), encoding="utf-8")
        _, report = self.prune("apply")
        self.assertEqual(report["summary"]["listed"], 1)
        self.assertIn("ainda não publicado", self.markdown())

    def test_malformed_remote_shape_is_unknown(self):
        code, report = self.prune("apply", FakeAPI([{**pull(), "head": "invalid"}]))
        self.assertEqual(code, 1)
        self.assertEqual(report["repositories"][0]["decision"], "unknown")
        self.assertEqual(report["summary"]["listed"], 0)
        self.assertIn("Não verificado", self.markdown())

    def test_corrupt_inventory_reports_error_without_claiming_no_pr(self):
        directory = self.outputs / "run_old" / "pull_requests"
        directory.mkdir(parents=True)
        (directory / "case_pr.json").write_text("{broken", encoding="utf-8")
        code, report = self.prune("apply")
        self.assertEqual(code, 1)
        self.assertTrue(report["errors"])
        self.assertEqual(report["summary"]["listed"], 0)
        self.assertIn("Unreadable metadata", self.markdown())
        self.assertTrue(self.repo.exists())

    def test_read_failure_in_inventory_is_reported(self):
        with patch.object(pruning.os, "walk") as walk:
            def unreadable(*args, **kwargs):
                kwargs["onerror"](PermissionError(13, "denied", str(self.outputs)))
            walk.side_effect = unreadable
            code, report = self.prune("apply")
        self.assertEqual(code, 1)
        self.assertTrue(report["errors"])
        self.assertTrue(self.repo.exists())

    def test_report_is_saved_before_next_group_even_on_failure_or_interrupt(self):
        other = self.second_project()
        for failure, expected_code in [(None, 0), (pruning.InventoryError("later failure"), 1), (KeyboardInterrupt(), 130)]:
            with self.subTest(failure=failure):
                api = FakeAPI()
                api.repository = lambda slug: {"fork": False, "full_name": slug}
                def pulls(slug):
                    if slug == "owner/other":
                        self.assertIn("critérios (1)", self.markdown())
                        self.assertIn(str(self.repo), self.markdown())
                        self.assertTrue(self.repo.exists())
                        self.assertTrue(other.exists())
                        if failure is not None:
                            raise failure
                    return []
                api.pulls = pulls
                code, report = self.prune("apply", api)
                self.assertEqual(code, expected_code)
                self.assertEqual(report["summary"]["listed"], 2 if failure is None else 1)
                stored = json.loads(sorted((self.outputs / "cleanup_reports").glob("*.json"))[-1].read_text(encoding="utf-8"))
                self.assertEqual(stored["repositories"][0]["action"], "listed")

    def test_shared_project_uses_one_pr_query_and_preserves_both_copies(self):
        sibling = self.clones / "app_2.apk"
        self.run_git(self.clones, "clone", str(self.repo), str(sibling))
        self.run_git(sibling, "remote", "set-url", "origin", "https://github.com/owner/project.git")
        api = FakeAPI([pull(state="open")])
        api.pulls = Mock(return_value=api.prs)
        code, report = self.prune("report", api)
        self.assertEqual(code, 0)
        api.pulls.assert_called_once_with("owner/project")
        self.assertEqual(report["summary"]["listed"], 0)
        self.assertTrue(self.repo.exists())
        self.assertTrue(sibling.exists())

    def test_filter_does_not_scan_prs_of_unrelated_projects(self):
        other = self.second_project()
        api = FakeAPI()
        api.repository = lambda slug: {"fork": False, "full_name": slug}
        api.pulls = Mock(return_value=[])
        code, report = self.prune("report", api, project=self.repo.name)
        self.assertEqual(code, 0)
        self.assertTrue(self.repo.exists())
        self.assertTrue(other.exists())
        api.pulls.assert_called_once_with("owner/project")
        self.assertEqual(report["summary"]["listed"], 1)
        self.assertEqual(report["repositories"][1]["action"], "outside_project_filter")
        self.assertNotIn(str(other), self.markdown())

    def test_markdown_escapes_table_delimiters_and_html(self):
        self.assertEqual(pruning.markdown_cell("a|b\n<c>`d"), "a&#124;b<br>&lt;c&gt;&#96;d")

    def test_safe_paths_reject_root_outside_and_links(self):
        for path in (self.clones, self.root / "outside"):
            with self.assertRaises(pruning.InventoryError):
                pruning.safe_path(path, self.clones)
        with patch.object(pruning, "linked", side_effect=lambda p: p == self.repo):
            with self.assertRaises(pruning.InventoryError):
                pruning.safe_path(self.repo, self.clones)

    def test_lock_excludes_pipeline_and_report_and_releases(self):
        with RepositoryUsageLock(self.root):
            with self.assertRaises(RepositoryBusyError):
                with RepositoryUsageLock(self.root):
                    self.fail("must not acquire a second lock")
        with RepositoryUsageLock(self.root):
            pass


class ProgressTests(unittest.TestCase):
    def test_heartbeat_runs_during_a_blocked_stage_and_stops_on_exit(self):
        observed = threading.Event()
        class Output(io.StringIO):
            def write(self, text):
                result = super().write(text)
                if "Em andamento:" in text:
                    observed.set()
                return result
        output = Output()
        with contextlib.redirect_stdout(output):
            with pruning.ProgressReporter(interval=0.01) as reporter:
                reporter.update("consulta lenta")
                self.assertTrue(observed.wait(1))
        self.assertFalse(reporter.thread.is_alive())
        self.assertIn("consulta lenta", output.getvalue())


class CLITests(unittest.TestCase):
    def test_legacy_apply_with_dry_run_reaches_report_only_implementation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli, "ROOT", Path(directory)), \
                patch.object(cli, "prune", return_value=(0, {})) as run:
            self.assertEqual(cli.main(["--mode", "apply", "--dry-run"]), 0)
            self.assertEqual(run.call_args.args[4], "apply")

    def test_pipeline_mode_dispatch_and_conflicts(self):
        from cognalys.orchestration import run_pipeline
        for conflict in (["--only", "publish"], ["--start-from", "spec_generation"],
                         ["--publish-prs"], ["--cleanup"]):
            with self.subTest(conflict=conflict), patch.object(sys, "argv", ["run_pipeline", "--llm-provider", "openai", "--prune-unused-repos=preview", *conflict]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    run_pipeline.parse_args()
                self.assertEqual(caught.exception.code, 2)
        with patch.object(sys, "argv", ["run_pipeline", "--llm-provider", "openai", "--prune-unused-repos=report", "--dry-run"]), \
                patch.object(cli, "main", return_value=0) as run, \
                patch.object(run_pipeline, "_run_pipeline") as normal:
            self.assertEqual(run_pipeline.main(), 0)
            normal.assert_not_called()
            self.assertIn("--dry-run", run.call_args.args[0])
            # The step command is `python -m <module> ...`; only what follows
            # the module reaches the pruning entry point.
            self.assertTrue(str(run.call_args.args[0][0]).startswith("--"))
            self.assertNotIn("cognalys.maintenance.prune_unused_repositories",
                             run.call_args.args[0])

    def test_normal_pipeline_uses_same_lock_as_maintenance(self):
        from cognalys.orchestration import run_pipeline
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def check_lock(args):
                with self.assertRaises(RepositoryBusyError):
                    with RepositoryUsageLock(root):
                        pass
                return 0
            with patch.object(sys, "argv", ["run_pipeline", "--llm-provider", "openai"]), \
                    patch.object(run_pipeline, "project_root", return_value=root), \
                    patch.object(run_pipeline, "_run_pipeline", side_effect=check_lock):
                self.assertEqual(run_pipeline.main(), 0)


if __name__ == "__main__":
    unittest.main()

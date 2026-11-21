"""comfychair #43 was published by one run and offered again by the next.

Every run rebuilds its solutions, so a finding that already has a pull request
came back under a new branch and solution revision. The records the earlier run
wrote are what say so.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import pr_creator  # noqa: E402
from cognalys.prs.pr_outcomes import open_pull_request_for  # noqa: E402
from cognalys.prs.publication_checks import current_review_contract_version  # noqa: E402


METADATA = {
    "repo_owner": "legal-hkr", "repo_name": "comfychair",
    "spec": "WebViewSslErrorBypassSpec", "method_name": "BrowserAuthScreen",
    "csv_class": "ui.screens.BrowserAuthScreenKt", "finding_id": "8267eb61836d",
    "solution_revision": "d65f349e73",
    "branch": "fix/browserauthscreen-8267eb61836d-d65f349e73",
}
URL = "https://github.com/legal-hkr/comfychair/pull/43"


def publish_earlier(outputs: Path, run: str = "run_1", **created) -> Path:
    """What an earlier run leaves behind after opening a pull request."""
    directory = outputs / run / "pull_requests"
    directory.mkdir(parents=True)
    (directory / "app_Screen_pr.json").write_text(json.dumps({
        **METADATA, "solution_revision": "ecaebb83e8",
        "branch": "fix/browserauthscreen-8267eb61836d-ecaebb83e8",
    }), encoding="utf-8")
    record = directory / "app_Screen_pr_created.json"
    record.write_text(json.dumps({
        "html_url": URL, "state": "open", "merged_at": None,
        "head": {"ref": "fix/browserauthscreen-8267eb61836d-ecaebb83e8"},
        **created,
    }), encoding="utf-8")
    return record


class OpenPullRequestLookupTests(unittest.TestCase):
    def test_a_finding_already_published_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory))
            found = open_pull_request_for(METADATA, Path(directory))
        self.assertEqual(found["pull_request"], URL)
        self.assertEqual(found["solution_revision"], "ecaebb83e8")

    def test_another_finding_is_not_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory))
            other = {**METADATA, "finding_id": "000000000000",
                     "method_name": "OtherScreen"}
            self.assertIsNone(open_pull_request_for(other, Path(directory)))

    def test_the_finding_is_recognised_after_the_repository_was_renamed(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory))
            renamed = {**METADATA, "repo_name": "comfychair-app"}
            self.assertIsNotNone(open_pull_request_for(renamed, Path(directory)))

    def test_a_pull_request_known_to_be_closed_or_merged_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory))
            for state in ("closed", "merged"):
                with self.subTest(state=state):
                    self.assertIsNone(open_pull_request_for(
                        METADATA, Path(directory), live_state=lambda url: state,
                    ))

    def test_an_unreadable_live_state_keeps_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory))
            found = open_pull_request_for(
                METADATA, Path(directory), live_state=lambda url: None,
            )
        self.assertIsNotNone(found)

    def test_a_pull_request_closed_when_recorded_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            publish_earlier(Path(directory), state="closed")
            self.assertIsNone(open_pull_request_for(METADATA, Path(directory)))

    def test_records_of_first_runs_reruns_and_subsets_are_found(self):
        # 2026-10-31 audit: 19 real records sat in run/, runN/, rerun*/ and
        # subset_*/ folders the old run_* glob never read.
        for run in ("run", "run2", "rerun2", "subset_revisao_lacunas",
                    "rssreader/rerun2", "rerun_20261015/run_v3"):
            with self.subTest(run=run), tempfile.TemporaryDirectory() as directory:
                publish_earlier(Path(directory), run=run)
                found = open_pull_request_for(METADATA, Path(directory))
                self.assertEqual(found["pull_request"], URL)

    def test_the_search_root_is_the_outputs_directory_of_the_run(self):
        from cognalys.prs.pr_outcomes import publication_search_root

        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory) / "outputs"
            rerun = outputs / "rvsec_tls" / "rerun_20261015" / "run_v3" / "pull_requests"
            rerun.mkdir(parents=True)
            self.assertEqual(publication_search_root(rerun), outputs.resolve())
            elsewhere = Path(directory) / "kept" / "run_1" / "pull_requests"
            elsewhere.mkdir(parents=True)
            self.assertEqual(publication_search_root(elsewhere),
                             (Path(directory) / "kept").resolve())
            # A sibling rerun folder of the same app is searched too.
            publish_earlier(outputs / "rvsec_tls", run="session_20261015/run")
            self.assertIsNotNone(open_pull_request_for(
                METADATA, publication_search_root(rerun)))

    def test_the_runs_own_folder_is_read_fresh_when_outputs_is_listed_once(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory) / "outputs"
            app = outputs / "rvsec_keypass"
            (app / "run_v2" / "pull_requests").mkdir(parents=True)
            self.assertIsNone(open_pull_request_for(METADATA, outputs, run_root=app))
            publish_earlier(app, run="run")
            found = open_pull_request_for(METADATA, outputs, run_root=app)
        self.assertEqual(found["pull_request"], URL)

    def test_a_merge_recorded_by_pr_outcomes_does_not_read_as_open(self):
        from cognalys.prs.pr_outcomes import record_pr_outcome, recorded_pull_request_state

        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory) / "pr_outcomes"
            publish_earlier(Path(directory))
            self.assertIsNone(recorded_pull_request_state(URL, outcomes))
            record_pr_outcome(METADATA, {"html_url": URL}, {"status": "merged"}, [], outcomes)
            self.assertEqual(recorded_pull_request_state(URL, outcomes), "merged")
            self.assertIsNone(open_pull_request_for(
                METADATA, Path(directory),
                live_state=lambda url: recorded_pull_request_state(url, outcomes)))

    def test_a_dry_run_record_and_the_files_own_record_do_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            dry = publish_earlier(outputs, run="run_dry", dry_run=True)
            self.assertIsNone(open_pull_request_for(METADATA, outputs))
            dry.unlink()
            own = publish_earlier(outputs, run="run_own")
            self.assertIsNone(
                open_pull_request_for(METADATA, outputs, own_record=own)
            )


class PublicationGuardTests(unittest.TestCase):
    def prepare(self, outputs: Path) -> Path:
        directory = outputs / "run_2" / "pull_requests"
        directory.mkdir(parents=True)
        path = directory / "app_Screen_pr.json"
        path.write_text(json.dumps({
            **METADATA, "publishable": True,
            # Text a maintainer can read, so only the duplicate guard decides.
            "title": "Keep the browser login on HTTPS",
            "body": "## Summary\n\nThe login screen loaded its page over HTTP.",
            "build_validation": {"status": "success"},
            "review_contract_version": current_review_contract_version(),
            "repository": str(outputs), "repo_host": "github.com",
            "remote_url": "https://github.com/legal-hkr/comfychair.git",
        }), encoding="utf-8")
        return path

    def test_a_second_pull_request_for_the_same_finding_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            publish_earlier(outputs)
            path = self.prepare(outputs)
            creator = pr_creator.AutomatedPRCreator(
                pull_requests_dir=str(path.parent), dry_run=True,
            )
            self.assertEqual(creator.process_pr_file(path), "blocked")
            self.assertFalse((path.parent / "app_Screen_pr_created.json").exists())

    def test_the_override_lets_a_person_open_another_on_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = Path(directory)
            publish_earlier(outputs)
            path = self.prepare(outputs)
            creator = pr_creator.AutomatedPRCreator(
                pull_requests_dir=str(path.parent), dry_run=True,
                allow_duplicate_pr=True,
            )
            self.assertNotEqual(creator.process_pr_file(path), "blocked")


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import outcome_report  # noqa: E402

PULL = "https://github.com/VREMSoftwareDevelopment/WiFiAnalyzer/pull/618"


def _github(state: str, merged: bool):
    pulls = {"user": {"login": "jpantonow"}, "state": state, "title": "Fix calculateChildType",
             "merged_at": "2026-08-30T00:00:00Z" if merged else None,
             "closed_at": "2026-08-27T15:14:42Z", "created_at": "2026-08-24T00:00:00Z"}
    comments = [{"user": {"login": "jpantonow"}, "body": "I ran a dynamic analysis tool..."},
                {"user": {"login": "VREMSoftwareDevelopment"},
                 "body": "This is a false positive. MD5 is used here as a checksum."},
                {"user": {"login": "github-actions[bot]"}, "body": "CI passed"}]

    def get(url):
        if url.endswith("/pulls/618"):
            return pulls
        if url.endswith("/issues/618/comments"):
            return comments
        return []
    return get


class OutcomeReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.outputs = Path(self.directory.name) / "outputs"
        prs = self.outputs / "run_20260824" / "pull_requests"
        prs.mkdir(parents=True)
        (prs / "wifi_calculateChildType_pr.json").write_text(json.dumps({
            "title": "Fix calculateChildType", "spec": "MessageDigestSpec",
            "csv_class": "com.vrem.wifianalyzer.X", "method_name": "calculateChildType",
            "finding_id": "abc"}), encoding="utf-8")
        (prs / "wifi_calculateChildType_pr_created.json").write_text(json.dumps(
            {"pr_url": PULL, "branch": "fix/x"}), encoding="utf-8")
        (prs / "other_pr_created.json").write_text(json.dumps(
            {"dry_run": True, "branch": "fix/y"}), encoding="utf-8")
        self.records = Path(self.directory.name) / "pr_outcomes"

    def tearDown(self):
        self.directory.cleanup()

    def test_a_closed_pull_request_and_the_maintainers_reason_are_recorded(self):
        [outcome] = outcome_report.refresh(self.outputs, _github("closed", False), self.records)
        self.assertEqual((outcome.state, outcome.when), ("closed", "2026-08-27"))
        self.assertEqual([item["author"] for item in outcome.feedback], ["VREMSoftwareDevelopment"])
        [stored] = json.loads((self.records / "vremsoftwaredevelopment__wifianalyzer.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(stored["state"], "closed")
        self.assertIn("checksum", stored["maintainer_feedback"][0]["body"])
        text = "\n".join(outcome_report.summary_lines([outcome]))
        self.assertIn("closed", text)
        self.assertIn("MD5 is used here as a checksum", text)

    def test_merged_is_told_apart_from_closed(self):
        [outcome] = outcome_report.refresh(self.outputs, _github("closed", True), self.records)
        self.assertEqual(outcome.state, "merged")

    def _closed_with_the_change_upstream(self, events=(), comments=None):
        import base64

        record = self.outputs / "run_20260824" / "pull_requests" / "wifi_calculateChildType_pr.json"
        metadata = json.loads(record.read_text(encoding="utf-8"))
        metadata.update(base_branch="main", diff=(
            "diff --git a/A.java b/A.java\n--- a/A.java\n+++ b/A.java\n@@ -1,3 +1,3 @@\n"
            " class A {\n-    String h = md5(x);\n+    String h = sha256(x);\n }\n"))
        record.write_text(json.dumps(metadata), encoding="utf-8")
        github = _github("closed", False)

        def get(url):
            if "/contents/A.java" in url:
                return {"content": base64.b64encode(
                    b"class A {\n    String h = sha256(x);\n}\n").decode()}
            if url.endswith("/issues/618/events"):
                return list(events)
            if comments is not None and url.endswith("/issues/618/comments"):
                return comments
            return github(url)

        [outcome] = outcome_report.refresh(self.outputs, get, self.records)
        [stored] = json.loads((self.records / "vremsoftwaredevelopment__wifianalyzer.json")
                              .read_text(encoding="utf-8"))
        return outcome, stored

    def test_a_closed_pr_whose_change_a_commit_refers_to_was_incorporated(self):
        """BombusMod#316: closed, then 'merged (with a reworded commit message)'."""
        outcome, stored = self._closed_with_the_change_upstream(events=[
            {"event": "referenced", "commit_id": "9f1c2d3e4b5a69788796a5b4c3d2e1f0a9b8c7d6"}])
        self.assertEqual(outcome.state, "incorporated")
        self.assertEqual(outcome.incorporated_evidence["references"],
                         ["referenced by commit 9f1c2d3e4b5a"])
        self.assertEqual(stored["state"], "merged")
        # The maintainer's word is a reference too.
        outcome, _ = self._closed_with_the_change_upstream(comments=[
            {"user": {"login": "maintainer"}, "body": "merged (with a reworded commit message)"}])
        self.assertEqual(outcome.state, "incorporated")

    def test_the_same_change_made_upstream_without_a_reference_is_its_own_category(self):
        """giggity#543: "Oh, just made this change myself independently." (A11)"""
        outcome, stored = self._closed_with_the_change_upstream()
        self.assertEqual(outcome.state, "equivalent_upstream")
        self.assertEqual(outcome.incorporated_evidence,
                         {"diff_reverse_applies": True, "references": []})
        # Recorded as before (not a rejection), with the evidence beside it.
        self.assertEqual(stored["state"], "merged")
        self.assertEqual(stored["incorporated_evidence"]["references"], [])
        self.assertIn("equivalent_upstream 1", outcome_report.summary_lines([outcome])[-1])

    def test_an_open_pr_whose_last_word_is_the_maintainers_awaits_a_reply(self):
        """Auto-Shine#12: the maintainer asked for a toast."""
        github = _github("open", False)

        def get(url):
            if url.endswith("/issues/618/comments"):
                return [{"user": {"login": "jpantonow"}, "body": "Here is the fix.",
                         "created_at": "2026-09-25T10:00:00Z"},
                        {"user": {"login": "Valent-in"}, "body": "Could it show a toast?",
                         "created_at": "2026-09-26T10:00:00Z"}]
            return github(url)

        [outcome] = outcome_report.refresh(self.outputs, get, self.records)
        self.assertTrue(outcome.awaiting_reply)
        self.assertIn("[awaiting your reply]", "\n".join(outcome_report.summary_lines([outcome])))

    def test_a_list_is_read_to_its_last_page(self):
        """A12: GitHub returns 30 comments a page and names the next in Link."""
        class Response:
            def __init__(self, items, following=""):
                self.items = items
                self.links = {"next": {"url": following}} if following else {}

            def json(self):
                return self.items

        pages = {
            "https://api.github.com/x/comments": Response([{"id": 1}], "https://api.github.com/x/comments?page=2"),
            "https://api.github.com/x/comments?page=2": Response([{"id": 2}], "https://api.github.com/x/comments?page=3"),
            "https://api.github.com/x/comments?page=3": Response([{"id": 3}]),
            "https://api.github.com/x/pull": Response({"state": "open"}),
        }
        get = outcome_report.follow_pages(pages.__getitem__)
        self.assertEqual(get("https://api.github.com/x/comments"), [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual(get("https://api.github.com/x/pull"), {"state": "open"})
        # A page naming itself as the next one does not loop.
        pages["https://api.github.com/x/comments?page=3"] = Response(
            [{"id": 3}], "https://api.github.com/x/comments?page=3")
        self.assertEqual(len(get("https://api.github.com/x/comments")), 3)

    def test_dry_runs_are_not_publications(self):
        self.assertEqual([url for _, _, url in outcome_report.published(self.outputs)], [PULL])

    def test_a_pr_record_without_the_impact_class_gets_its_runs_adjudication(self):
        """M2: a PR published before its record carried the impact class is not
        rewritten as not_recorded when its run's adjudication has one."""
        solutions = self.outputs / "run_20260824" / "error_solutions"
        (solutions / "wifi").mkdir(parents=True)
        (solutions / "wifi" / "1_calculateChildType_solution.json").write_text(json.dumps({
            "solution_metadata": {"spec": "MessageDigestSpec", "csv_class": "com.vrem.wifianalyzer.X",
                                  "method_name": "calculateChildType"}}), encoding="utf-8")
        (solutions / "v2_artifacts" / "wifi").mkdir(parents=True)
        (solutions / "v2_artifacts" / "wifi" / "1_calculateChildType_adjudication.json").write_text(
            json.dumps({"runtime_security_impact": "non_security"}), encoding="utf-8")
        outcome_report.refresh(self.outputs, _github("closed", True), self.records)
        [stored] = json.loads((self.records / "vremsoftwaredevelopment__wifianalyzer.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(stored["impact_class"], "no_security_impact")
        self.assertEqual(stored["state"], "merged")


GROCY = "https://github.com/patzly/grocy-android/pull/1013"
_LOAD_UID = "x.X509KeyStoreFile:::load:::KeyStoreSpec:::Seq:::m"
_SAVE_UID = "x.X509KeyStoreFile:::save:::KeyStoreSpec:::Seq:::m"


class EarlierPullRequestTests(unittest.TestCase):
    """2026-10-31: Grocy's load/save were analysed again while #1013 was open."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.outputs, self.records = root / "outputs", root / "pr_outcomes"
        prs = self.outputs / "rvsec_grocy" / "run_v6" / "pull_requests"
        prs.mkdir(parents=True)
        (prs / "g_load_KeyStoreSpec_pr.json").write_text(json.dumps({
            "finding_id": outcome_report._short_finding_id(_LOAD_UID),
            "source_file": "app/X509KeyStoreFile.java", "csv_class": "x.X509KeyStoreFile",
            "method_name": "load", "spec": "KeyStoreSpec", "repo_owner": "patzly",
            "repo_name": "grocy-android"}), encoding="utf-8")
        (prs / "g_load_KeyStoreSpec_pr_created.json").write_text(json.dumps({
            "html_url": GROCY, "state": "open", "created_at": "2026-10-24T11:58:21Z",
            "head": {"ref": "fix/load"}}), encoding="utf-8")
        self.finding = {"unique_error_id": _SAVE_UID, "method_name": "save",
                        "spec": "KeyStoreSpec", "source_file_path": "app/X509KeyStoreFile.java",
                        "repository_url": "https://github.com/patzly/grocy-android",
                        "joint_findings": [{"unique_error_id": _LOAD_UID, "method": "load",
                                            "specification": "KeyStoreSpec"}]}

    def tearDown(self):
        self.directory.cleanup()

    def earlier(self, finding):
        return outcome_report.earlier_pull_request_for(
            finding, outcome_report.published(self.outputs), self.records)

    def test_an_open_pull_request_for_the_unit_is_found_by_a_joint_findings_id(self):
        self.assertEqual(self.earlier(self.finding), {
            "pull_request": GROCY, "state": "open", "created_at": "2026-10-24T11:58:21Z"})

    def test_the_same_file_method_and_specification_in_the_same_repository_match(self):
        finding = {**self.finding, "joint_findings": [], "unique_error_id": "other",
                   "method_name": "load"}
        self.assertEqual(self.earlier(finding)["state"], "open")
        self.assertEqual(self.earlier({**finding, "repository_url":
                                       "https://github.com/someone/fork"}), {})

    def test_the_recorded_state_wins_and_a_closed_one_is_not_returned(self):
        from cognalys.prs.pr_outcomes import record_pr_outcome

        metadata = {"repo_owner": "patzly", "repo_name": "grocy-android"}
        record_pr_outcome(metadata, {"html_url": GROCY}, {"status": "merged"}, [], self.records)
        self.assertEqual(self.earlier(self.finding)["state"], "merged")
        record_pr_outcome(metadata, {"html_url": GROCY}, {"status": "closed"}, [], self.records)
        self.assertEqual(self.earlier(self.finding), {})


if __name__ == "__main__":
    unittest.main()

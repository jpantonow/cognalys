import json
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.refresh_text import commits_pushed_after, refresh_published_text  # noqa: E402


def write_pair(directory: Path, name: str, finding: str, published: str, generated: str,
               number: int) -> None:
    (directory / f"{name}_pr.json").write_text(
        json.dumps({"finding_id": finding, "body": generated}), encoding="utf-8")
    (directory / f"{name}_pr_created.json").write_text(json.dumps({
        "url": f"https://api.github.com/repos/o/r/pulls/{number}",
        "html_url": f"https://github.com/o/r/pull/{number}", "body": published,
    }), encoding="utf-8")


class RefreshPublishedTextTests(unittest.TestCase):
    """rssreader#4 was published naming the rule but not RVSec; the regenerated
    body has to reach the open pull request."""

    def test_only_open_pull_requests_with_a_new_body_are_updated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_pair(root, "a", "f1", "old", "new, naming RVSec", 1)
            write_pair(root, "b", "f2", "same", "same", 2)
            write_pair(root, "c", "f3", "old", "new", 3)
            updates = []
            states = {"https://api.github.com/repos/o/r/pulls/1": "open",
                      "https://api.github.com/repos/o/r/pulls/3": "merged"}
            results = refresh_published_text(
                root, state=lambda pr: {"status": states[pr["url"]]},
                update=lambda url, fields: updates.append((url, fields)),
                approved=["f1", "f2", "f3"])
            self.assertEqual([item["result"] for item in results],
                             ["updated", "unchanged", "skipped_merged"])
            self.assertEqual(updates, [("https://api.github.com/repos/o/r/pulls/1",
                                        {"body": "new, naming RVSec"})])
            recorded = json.loads((root / "a_pr_created.json").read_text(encoding="utf-8"))
            self.assertEqual(recorded["body"], "new, naming RVSec")

    def test_a_dry_run_changes_nothing_and_a_finding_filter_applies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_pair(root, "a", "f1", "old", "new", 1)
            write_pair(root, "b", "f2", "old", "new", 2)
            updates = []
            results = refresh_published_text(
                root, ["f2"], dry_run=True, state=lambda pr: {"status": "open"},
                update=lambda url, fields: updates.append(url))
            self.assertEqual([(item["finding_id"], item["result"]) for item in results],
                             [("f2", "would_update")])
            self.assertEqual(updates, [])

    def test_only_a_named_finding_is_sent(self):
        # batch5 review (2026-10-30): `cognalys publish --refresh-text` with
        # no finding sent the new body of every open pull request of the run.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_pair(root, "a", "f1", "old", "new a", 1)
            write_pair(root, "b", "f2", "old", "new b", 2)
            updates = []
            unnamed = refresh_published_text(
                root, state=lambda pr: {"status": "open"},
                update=lambda url, fields: updates.append(url))
            self.assertEqual(updates, [])
            self.assertEqual([(item["result"], item.get("approval_needed")) for item in unnamed],
                             [("would_update", True), ("would_update", True)])
            self.assertEqual([item["body"] for item in unnamed], ["new a", "new b"])
            recorded = json.loads((root / "a_pr_created.json").read_text(encoding="utf-8"))
            self.assertEqual(recorded["body"], "old")
            named = refresh_published_text(
                root, state=lambda pr: {"status": "open"},
                update=lambda url, fields: updates.append(url), approved=["f2"])
            self.assertEqual([item["result"] for item in named], ["would_update", "updated"])
            self.assertEqual(updates, ["https://api.github.com/repos/o/r/pulls/2"])

    def test_the_cli_sends_nothing_without_a_named_finding(self):
        import argparse
        from unittest import mock

        from cognalys import cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_pair(root, "a", "f1", "old", "new a", 1)
            arguments = argparse.Namespace(run_dir=root, finding=[], dry_run=False,
                                           refresh_text=True)
            with mock.patch("cognalys.prs.pr_github.fetch_current_pr_state",
                            return_value={"status": "open"}), \
                    mock.patch("cognalys.prs.pr_github.update_pr_metadata") as update, \
                    mock.patch("builtins.print"):
                cli.publish(arguments)
                update.assert_not_called()
                arguments.finding = ["f1"]
                cli.publish(arguments)
                update.assert_called_once_with("https://api.github.com/repos/o/r/pulls/1",
                                               {"body": "new a"})

    def test_a_pull_request_with_follow_ups_pushed_after_its_record_is_held(self):
        # NotallyX#1167 (2026-10-30): the SHA-256 test-vector commit was
        # pushed after the record; its regenerated body leaves it out, and
        # sending it would undo the text --update-description revised.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, finding, number in (("a", "f1", 1), ("b", "f2", 2), ("c", "f3", 3)):
                write_pair(root, name, finding, "revised for the follow-up", "first commit",
                           number)
                record = json.loads((root / f"{name}_pr.json").read_text(encoding="utf-8"))
                record["commit_hash"] = "7841ba4ec4f3"
                (root / f"{name}_pr.json").write_text(json.dumps(record), encoding="utf-8")
            pushed = {"status": "PUSHED", "head_sha": "7841ba4ec4f3", "commit": "4d0297232d86"}
            (root / "a_followup.json").write_text(json.dumps(pushed), encoding="utf-8")
            (root / "b_followup.json").write_text(json.dumps(
                {"status": "VALIDATION_FAILED", "head_sha": "4d0297232d86",
                 "previous_rounds": [pushed]}), encoding="utf-8")
            # Pushed on top of another commit: not after this record.
            (root / "c_followup.json").write_text(json.dumps(
                {**pushed, "head_sha": "000000000000"}), encoding="utf-8")
            updates = []
            results = refresh_published_text(
                root, state=lambda pr: {"status": "open"},
                update=lambda url, fields: updates.append(url),
                approved=["f1", "f2", "f3"])
            self.assertEqual([(item["finding_id"], item["result"]) for item in results],
                             [("f1", "held_follow_ups"), ("f2", "held_follow_ups"),
                              ("f3", "updated")])
            self.assertEqual(updates, ["https://api.github.com/repos/o/r/pulls/3"])
        self.assertEqual(commits_pushed_after(Path("d/x_pr.json"), {}), [])


if __name__ == "__main__":
    unittest.main()

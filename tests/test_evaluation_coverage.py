"""Coverage numbers must carry their denominator, and say when they can't.

A pipeline that abstains from everything produces no wrong patch, so an
abstention count is not by itself a quality. These tests pin the two rules
that keep it from reading as one: every rate is reported with the
denominator it came from, and "no reviewer has labelled these findings" is
reported as unmeasured rather than as zero avoidable abstentions.
"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation.coverage import (  # noqa: E402
    action_counts, avoidable_abstention, coverage_report,
    known_positive_abstention, read_labels,
)
from cognalys.evaluation.decisions import ACTIONS  # noqa: E402


def _outcome(identity: str, decision: str, pull_request: str = "") -> dict:
    return {
        "unique_error_id": identity,
        "decision": decision,
        "pull_request": pull_request,
    }


class ActionCountTests(unittest.TestCase):

    def test_every_action_is_a_key_even_at_zero(self):
        counts = action_counts([_outcome("a", "NO_SAFE_FIX")])
        self.assertEqual(sorted(counts), sorted(ACTIONS))
        self.assertEqual(counts["abstain"], 1)

    def test_a_missing_decision_is_counted_as_invalid(self):
        counts = action_counts([_outcome("a", ""), _outcome("b", "WHAT")])
        self.assertEqual(counts["invalid"], 2)
        self.assertEqual(counts["repair_unattended"], 0)


class CoverageReportTests(unittest.TestCase):

    OUTCOMES = [
        _outcome("a", "FIX_SUPPORTED", pull_request="http://pr/1"),
        _outcome("b", "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"),
        _outcome("c", "NO_SAFE_FIX"),
        _outcome("d", "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX"),
    ]

    def test_rates_are_over_every_attributed_finding(self):
        report = coverage_report(self.OUTCOMES)
        self.assertEqual(report["findings_attributed"], 4)
        self.assertEqual(report["proposals"], 2)
        self.assertEqual(report["proposal_coverage"], 0.5)
        self.assertEqual(report["abstentions"], 1)
        self.assertEqual(report["published"], 1)
        self.assertEqual(report["publication_rate"], 0.25)

    def test_a_classification_is_not_counted_as_a_proposal(self):
        report = coverage_report([self.OUTCOMES[3]])
        self.assertEqual(report["proposals"], 0)
        self.assertEqual(report["actions"]["classify_no_change"], 1)

    def test_an_empty_run_reports_no_rate_rather_than_zero(self):
        report = coverage_report([])
        self.assertIsNone(report["proposal_coverage"])
        self.assertIsNone(report["abstention_rate"])


class KnownPositiveAbstentionTests(unittest.TestCase):
    """A published advisory at its vulnerable revision is a label nobody wrote."""

    @staticmethod
    def _known(identity, decision, advisory):
        outcome = _outcome(identity, decision)
        outcome["known_positive"] = {
            "advisories": [advisory], "pinned_revision": "abc"}
        return outcome

    def test_abstentions_on_known_positives_are_counted(self):
        report = known_positive_abstention([
            self._known("a", "NO_SAFE_FIX", "CVE-2023-41898"),
            self._known("b", "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "GHSL-2026-082"),
            _outcome("c", "NO_SAFE_FIX"),
        ])
        self.assertEqual(report["status"], "measured")
        self.assertEqual((report["known_positives"], report["abstained"]), (2, 1))
        self.assertEqual(report["advisories"], ["CVE-2023-41898"])

    def test_a_run_without_known_positives_says_so(self):
        self.assertEqual(
            known_positive_abstention([_outcome("c", "NO_SAFE_FIX")]),
            {"status": "none_in_run"},
        )


class PublishedDefinitionTests(unittest.TestCase):
    """Published means a pull request was opened, as the funnel counts it."""

    def test_a_local_draft_path_is_not_published(self):
        # seafile getMediaSource in run_20260920_175850: its pull_request
        # field held the path of a draft that was never opened, and the
        # coverage table reported three published against the funnel's two.
        report = coverage_report([_outcome(
            "a", "FIX_SUPPORTED",
            pull_request="/mnt/c/outputs/run_x/pull_requests/a_pr.json",
        )])
        self.assertEqual(report["published"], 0)

    def test_an_opened_pull_request_is_published(self):
        report = coverage_report([_outcome(
            "a", "FIX_SUPPORTED", pull_request="https://github.com/o/r/pull/1",
        )])
        self.assertEqual(report["published"], 1)

    def test_the_funnels_own_flag_wins_when_present(self):
        outcome = {**_outcome("a", "FIX_SUPPORTED",
                              pull_request="https://github.com/o/r/pull/1"),
                   "reached": {"published": False}}
        self.assertEqual(coverage_report([outcome])["published"], 0)


class AvoidableAbstentionTests(unittest.TestCase):

    def test_without_labels_it_is_unmeasured_not_zero(self):
        result = avoidable_abstention(
            [_outcome("a", "NO_SAFE_FIX")], labels={}
        )
        self.assertEqual(result["status"], "no_labels")
        self.assertNotIn("rate", result)

    def test_an_abstention_on_a_repairable_finding_is_avoidable(self):
        labels = {
            "a": {"local_repairability": "repairable"},
            "b": {"local_repairability": "not_locally_repairable"},
            "c": {"local_repairability": "repairable"},
        }
        result = avoidable_abstention([
            _outcome("a", "NO_SAFE_FIX"),
            _outcome("b", "NO_SAFE_FIX"),
            _outcome("c", "FIX_SUPPORTED"),
        ], labels)
        self.assertEqual(result["status"], "measured")
        self.assertEqual(result["labelled_repairable_in_this_run"], 2)
        self.assertEqual(result["abstained_anyway"], 1)
        self.assertEqual(result["finding_ids"], ["a"])
        self.assertEqual(result["rate"], 0.5)

    def test_a_classification_also_counts_as_walking_away(self):
        result = avoidable_abstention(
            [_outcome("a", "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX")],
            {"a": {"local_repairability": "repairable"}},
        )
        self.assertEqual(result["abstained_anyway"], 1)


class LabelReadingTests(unittest.TestCase):

    def test_an_unlabelled_worksheet_reads_as_no_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ground_truth.csv"
            path.write_text(
                "unique_msg,spec,apk,local_repairability\n"
                "finding-1,CipherSpec,app.apk,\n",
                encoding="utf-8",
            )
            self.assertEqual(read_labels(path), {})

    def test_a_filled_row_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ground_truth.csv"
            path.write_text(
                "unique_msg,spec,local_repairability,appropriate_action\n"
                "finding-1,CipherSpec,repairable,repair_for_review\n",
                encoding="utf-8",
            )
            labels = read_labels(path)
        self.assertEqual(
            labels["finding-1"]["local_repairability"], "repairable"
        )

    def test_a_missing_worksheet_is_not_an_error(self):
        self.assertEqual(read_labels(Path("does/not/exist.csv")), {})


if __name__ == "__main__":
    unittest.main()

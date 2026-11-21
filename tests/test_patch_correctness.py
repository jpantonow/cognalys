"""A patch is called correct only on all three kinds of evidence.

Each test changes one piece of a fully evidenced record, so a verdict that
tolerated the missing piece would fail exactly one test.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation.patch_correctness import (  # noqa: E402
    CORRECT, ENVIRONMENT_FAILURE, INCORRECT, UNVERIFIED, assess, tally,
)


def _record(**changes):
    record = {
        "status": "success",
        "phases": {"production": {"status": "success"}},
        "detector_replay": {"outcome": "repaired",
                            "baseline": {"exit_code": 0},
                            "patched": {"exit_code": 0}},
        "regression_tests": {"status": "passed"},
        "finding_revalidation": {"status": "not_supported"},
    }
    record.update(changes)
    return record


class VerdictTests(unittest.TestCase):

    def test_all_three_kinds_of_evidence_make_a_correct_patch(self):
        result = assess(_record())
        self.assertEqual(result["verdict"], CORRECT)
        self.assertEqual(result["missing"], [])

    def test_no_detector_coverage_leaves_it_unverified(self):
        result = assess(_record(detector_replay={"outcome": "no_detector_coverage"}))
        self.assertEqual(result["verdict"], UNVERIFIED)
        self.assertIn("no_executable_oracle_for_this_detector", result["missing"])

    def test_a_baseline_that_never_fired_leaves_it_unverified(self):
        result = assess(_record(detector_replay={"outcome": "not_reproduced"}))
        self.assertEqual(result["verdict"], UNVERIFIED)

    def test_an_alert_that_still_fires_is_incorrect(self):
        result = assess(_record(detector_replay={"outcome": "unchanged"}))
        self.assertEqual(result["verdict"], INCORRECT)

    def test_deleting_the_method_is_incorrect(self):
        result = assess(_record(detector_replay={"outcome": "method_removed"}))
        self.assertEqual(result["verdict"], INCORRECT)

    def test_a_build_broken_by_the_patch_is_incorrect(self):
        result = assess(_record(status="failed",
                                failure_attribution="generated_patch"))
        self.assertEqual(result["verdict"], INCORRECT)

    def test_a_recorded_repair_over_a_crashed_scan_is_not_correct(self):
        result = assess(_record(detector_replay={
            "outcome": "repaired", "baseline": {"exit_code": 0},
            "patched": {"exit_code": 2},
        }))
        self.assertEqual(result["verdict"], UNVERIFIED)
        self.assertIn("detector_replay_detector_error", result["missing"])

    def test_every_pass_the_validator_records_counts_as_a_build(self):
        # The default set is the pipeline's own, so a narrower pass is not
        # read as a failure "not attributed to the patch".
        for status in ("success_app_module_only", "success_on_analyzed_revision",
                       "success_production_only_test_build_preexisting"):
            with self.subTest(status=status):
                result = assess(_record(status=status))
                self.assertIn("builds", result["satisfied"])

    def test_an_infrastructure_failure_is_its_own_verdict(self):
        result = assess(_record(phases={
            "production": {"status": "infrastructure_failure"},
        }))
        self.assertEqual(result["verdict"], ENVIRONMENT_FAILURE)


class TallyTests(unittest.TestCase):

    def test_counts_every_verdict_and_ranks_the_missing_evidence(self):
        result = tally([
            _record(),
            _record(detector_replay={"outcome": "no_detector_coverage"}),
            _record(detector_replay={"outcome": "no_detector_coverage"}),
        ])
        self.assertEqual(result["verdicts"][CORRECT], 1)
        self.assertEqual(result["verdicts"][UNVERIFIED], 2)
        self.assertEqual(next(iter(result["missing_evidence"])),
                         "no_executable_oracle_for_this_detector")


if __name__ == "__main__":
    unittest.main()
